#!/usr/bin/env python3
"""Run a non-destructive, isolated restore drill for an Estate OS SQLite DB.

The source database is opened in URI read-only and query-only modes.  Every
writable database used by the drill lives under a fresh temporary directory.
The emitted measurement is deliberately unsigned; a separate approved evidence
provider must review and sign a production wrapper that binds its digest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.evidence_contract import (  # noqa: E402
    RESTORE_MEASUREMENT_SCHEMA,
    canonical_json_bytes,
    parse_timestamp,
    sha256_bytes,
    validate_restore_measurement,
)


SQLITE_SOURCE_SUFFIXES = ("-wal", "-shm", "-journal")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def file_attestation(path: Path) -> dict[str, Any]:
    """Capture a stable, path-free identity and content observation."""
    try:
        stat_before = path.stat()
    except FileNotFoundError:
        return {
            "exists": False,
            "sha256": None,
            "size_bytes": None,
            "mtime_ns": None,
            "device_id": None,
            "file_id": None,
        }
    if not stat.S_ISREG(stat_before.st_mode):
        raise RuntimeError("SQLite source or sidecar is not a regular file")
    digest = file_sha256(path)
    try:
        stat_after = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError("SQLite source or sidecar changed during attestation") from exc
    identity_before = (
        stat_before.st_size,
        stat_before.st_mtime_ns,
        stat_before.st_dev,
        stat_before.st_ino,
    )
    identity_after = (
        stat_after.st_size,
        stat_after.st_mtime_ns,
        stat_after.st_dev,
        stat_after.st_ino,
    )
    if identity_before != identity_after:
        raise RuntimeError("SQLite source or sidecar changed during attestation")
    return {
        "exists": True,
        "sha256": digest,
        "size_bytes": stat_after.st_size,
        "mtime_ns": stat_after.st_mtime_ns,
        "device_id": stat_after.st_dev,
        "file_id": stat_after.st_ino,
    }


def sidecar_attestations(database: Path) -> dict[str, dict[str, Any]]:
    return {
        suffix: file_attestation(Path(f"{database}{suffix}"))
        for suffix in SQLITE_SOURCE_SUFFIXES
    }


def open_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
        connection.close()
        raise RuntimeError("SQLite source connection is not query-only")
    return connection


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def normalized_sql_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"nonfinite_float": repr(value)}
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    return {"sqlite_text": str(value)}


def logical_database_state(
    connection: sqlite3.Connection,
) -> tuple[str, str, dict[str, int]]:
    schema_records = [
        dict(row)
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
    ]
    schema_sha256 = sha256_bytes(canonical_json_bytes(schema_records))
    tables = [
        str(record["name"])
        for record in schema_records
        if record["type"] == "table"
    ]
    row_counts: dict[str, int] = {}
    content = hashlib.sha256()
    for table in sorted(tables):
        rows = connection.execute(f"SELECT * FROM {quote_identifier(table)}").fetchall()
        normalized_rows = sorted(
            canonical_json_bytes([normalized_sql_value(value) for value in row])
            for row in rows
        )
        row_counts[table] = len(normalized_rows)
        content.update(table.encode("utf-8"))
        content.update(b"\x00")
        for row in normalized_rows:
            content.update(hashlib.sha256(row).digest())
    return schema_sha256, content.hexdigest(), row_counts


def receipt_chain_state(connection: sqlite3.Connection) -> tuple[bool, int]:
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='receipts'"
    ).fetchone()
    if table is None:
        return False, 0
    rows = connection.execute(
        """
        SELECT sequence, payload_json, payload_sha256, previous_hash,
               receipt_hash, signature_status
        FROM receipts
        ORDER BY sequence ASC
        """
    ).fetchall()
    previous = "GENESIS"
    valid = bool(rows)
    for row in rows:
        payload_sha256 = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
        receipt_hash = hashlib.sha256(
            f"{row['previous_hash']}\n{payload_sha256}".encode("utf-8")
        ).hexdigest()
        if (
            row["previous_hash"] != previous
            or row["payload_sha256"] != payload_sha256
            or row["receipt_hash"] != receipt_hash
            or row["signature_status"] not in {"UNSIGNED", "HMAC_SHA256"}
        ):
            valid = False
        previous = str(row["receipt_hash"])
    return valid, len(rows)


def corrupt_backup_is_rejected(backup_path: Path, scratch: Path) -> bool:
    corrupt_path = scratch / "corrupt-candidate.db"
    shutil.copyfile(backup_path, corrupt_path)
    size = corrupt_path.stat().st_size
    with corrupt_path.open("r+b") as handle:
        handle.truncate(max(1, size // 2))
    connection: sqlite3.Connection | None = None
    try:
        connection = open_read_only(corrupt_path)
        observed = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        return observed != "ok"
    except sqlite3.DatabaseError:
        return True
    finally:
        if connection is not None:
            connection.close()


def missing_backup_is_rejected(scratch: Path) -> bool:
    missing = scratch / "missing-backup.db"
    try:
        connection = open_read_only(missing)
    except sqlite3.OperationalError:
        return True
    connection.close()
    return False


def latest_recovery_point(connection: sqlite3.Connection) -> datetime:
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_runs'"
    ).fetchone()
    if table is None:
        raise RuntimeError("audit_runs table is unavailable")
    row = connection.execute("SELECT MAX(completed_at) FROM audit_runs").fetchone()
    observed = parse_timestamp(row[0] if row else None)
    if observed is None:
        raise RuntimeError("latest recovery point is unavailable")
    return observed


def run_restore_drill(
    database: Path,
    *,
    temporary_root: Path | None = None,
    max_rto_seconds: float = 900,
    max_rpo_seconds: float = 300,
) -> dict[str, Any]:
    source_path = database.resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"source database is unavailable: {source_path.name}")
    if max_rto_seconds <= 0 or max_rpo_seconds <= 0:
        raise ValueError("RTO and RPO ceilings must be positive")

    tool_sha256 = file_sha256(Path(__file__).resolve())
    run_id = f"restore-{uuid.uuid4().hex}"
    database_before = file_attestation(source_path)
    if database_before["exists"] is not True:
        raise FileNotFoundError(f"source database is unavailable: {source_path.name}")
    sidecars_before = sidecar_attestations(source_path)
    scratch_path: Path | None = None
    with tempfile.TemporaryDirectory(
        prefix="szl-estate-restore-",
        dir=str(temporary_root.resolve()) if temporary_root else None,
    ) as temporary:
        scratch_path = Path(temporary)
        snapshot_path = scratch_path / "source-snapshot.db"
        shutil.copyfile(source_path, snapshot_path)
        for suffix, observation in sidecars_before.items():
            if observation["exists"] is True:
                shutil.copyfile(
                    Path(f"{source_path}{suffix}"),
                    Path(f"{snapshot_path}{suffix}"),
                )
        if (
            file_attestation(source_path) != database_before
            or sidecar_attestations(source_path) != sidecars_before
        ):
            raise RuntimeError("SQLite source changed while creating its snapshot")

        source = open_read_only(snapshot_path)
        try:
            data_version_before = int(
                source.execute("PRAGMA data_version").fetchone()[0]
            )
            recovery_point = latest_recovery_point(source)
            source_schema_sha256, source_content_sha256, source_row_counts = (
                logical_database_state(source)
            )

            backup_path = scratch_path / "immutable-backup.db"
            backup_connection = sqlite3.connect(backup_path)
            try:
                source.backup(backup_connection)
            finally:
                backup_connection.close()
            backup_created_at = utc_now()
            backup_sha256 = file_sha256(backup_path)
            backup_size = backup_path.stat().st_size

            started_at = utc_now()
            restored_path = scratch_path / "isolated-restored.db"
            backup_source = open_read_only(backup_path)
            restored = sqlite3.connect(restored_path)
            restored.row_factory = sqlite3.Row
            try:
                backup_source.backup(restored)
                integrity_check = str(
                    restored.execute("PRAGMA integrity_check").fetchone()[0]
                )
                foreign_key_violations = len(
                    restored.execute("PRAGMA foreign_key_check").fetchall()
                )
                (
                    restored_schema_sha256,
                    restored_content_sha256,
                    restored_row_counts,
                ) = logical_database_state(restored)
                receipt_chain_valid, receipt_count = receipt_chain_state(restored)
            finally:
                restored.close()
                backup_source.close()

            corrupt_rejected = corrupt_backup_is_rejected(backup_path, scratch_path)
            missing_rejected = missing_backup_is_rejected(scratch_path)
            data_version_after = int(
                source.execute("PRAGMA data_version").fetchone()[0]
            )
        finally:
            source.close()

    assert scratch_path is not None
    database_after = file_attestation(source_path)
    sidecars_after = sidecar_attestations(source_path)
    completed_at = utc_now()
    source_unchanged = (
        database_before == database_after
        and sidecars_before == sidecars_after
        and data_version_before == data_version_after
    )
    rto_seconds = (completed_at - started_at).total_seconds()
    rpo_seconds = (started_at - recovery_point).total_seconds()
    passed = (
        source_unchanged
        and integrity_check == "ok"
        and foreign_key_violations == 0
        and source_schema_sha256 == restored_schema_sha256
        and source_content_sha256 == restored_content_sha256
        and source_row_counts == restored_row_counts
        and receipt_chain_valid
        and receipt_count > 0
        and corrupt_rejected
        and missing_rejected
        and 0 <= rto_seconds <= max_rto_seconds
        and 0 <= rpo_seconds <= max_rpo_seconds
    )
    measurement: dict[str, Any] = {
        "schema": RESTORE_MEASUREMENT_SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "run_id": run_id,
        "tool_sha256": tool_sha256,
        "recovery_point_at": timestamp(recovery_point),
        "started_at": timestamp(started_at),
        "completed_at": timestamp(completed_at),
        "rto_seconds": rto_seconds,
        "rpo_seconds": rpo_seconds,
        "source": {
            "database_sha256_before": database_before["sha256"],
            "database_sha256_after": database_after["sha256"],
            "size_bytes_before": database_before["size_bytes"],
            "size_bytes_after": database_after["size_bytes"],
            "mtime_ns_before": database_before["mtime_ns"],
            "mtime_ns_after": database_after["mtime_ns"],
            "data_version_before": data_version_before,
            "data_version_after": data_version_after,
            "sidecars": {
                suffix: {
                    "before": sidecars_before[suffix],
                    "after": sidecars_after[suffix],
                }
                for suffix in SQLITE_SOURCE_SUFFIXES
            },
            "query_only": True,
            "unchanged": source_unchanged,
        },
        "backup": {
            "sha256": backup_sha256,
            "size_bytes": backup_size,
            "created_at": timestamp(backup_created_at),
        },
        "restore_target": {
            "isolation": "EPHEMERAL_TEMP_DIRECTORY",
            "loopback_only": True,
            "production_writes": 0,
            "path_disclosed": False,
            "cleaned_up": not scratch_path.exists(),
        },
        "validation": {
            "integrity_check": integrity_check,
            "foreign_key_violation_count": foreign_key_violations,
            "source_schema_sha256": source_schema_sha256,
            "restored_schema_sha256": restored_schema_sha256,
            "source_content_sha256": source_content_sha256,
            "restored_content_sha256": restored_content_sha256,
            "source_row_counts": source_row_counts,
            "restored_row_counts": restored_row_counts,
            "receipt_chain_valid": receipt_chain_valid,
            "receipt_count": receipt_count,
        },
        "failure_scenarios": {
            "corrupt_backup_rejected": corrupt_rejected,
            "missing_backup_rejected": missing_rejected,
        },
    }
    return measurement


def validate_output_path(database: Path, output: Path) -> Path:
    """Resolve an evidence path and prove it cannot alias SQLite source files."""
    try:
        source_path = database.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("source database identity is unavailable") from exc
    if not source_path.is_file():
        raise ValueError("source database is not a regular file")

    try:
        output_path = output.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(
            "unable to verify output isolation from source database"
        ) from exc

    protected_paths = (source_path,) + tuple(
        Path(f"{source_path}{suffix}") for suffix in SQLITE_SOURCE_SUFFIXES
    )
    if output_path in protected_paths:
        raise ValueError(
            "output must not alias the source database or SQLite sidecars"
        )

    try:
        output_stat = output_path.stat()
    except FileNotFoundError:
        output_stat = None
    except OSError as exc:
        raise ValueError(
            "unable to verify output isolation from source database"
        ) from exc

    if output_stat is not None:
        for protected_path in protected_paths:
            try:
                protected_stat = protected_path.stat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ValueError(
                    "unable to verify output isolation from source database"
                ) from exc
            if os.path.samestat(output_stat, protected_stat):
                raise ValueError(
                    "output must not alias the source database or SQLite sidecars"
                )

    return output_path


def write_json_atomic(
    path: Path,
    value: dict[str, Any],
    *,
    protected_database: Path,
) -> None:
    output_path = validate_output_path(protected_database, path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(
        f".{output_path.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        temporary.write_bytes(canonical_json_bytes(value) + b"\n")
        output_path = validate_output_path(protected_database, output_path)
        temporary.replace(output_path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--temporary-root", type=Path)
    parser.add_argument("--max-rto-seconds", type=float, default=900)
    parser.add_argument("--max-rpo-seconds", type=float, default=300)
    args = parser.parse_args()
    try:
        output_path = validate_output_path(args.database, args.output)
        measurement = run_restore_drill(
            args.database,
            temporary_root=args.temporary_root,
            max_rto_seconds=args.max_rto_seconds,
            max_rpo_seconds=args.max_rpo_seconds,
        )
        write_json_atomic(
            output_path,
            measurement,
            protected_database=args.database,
        )
        state, detail = validate_restore_measurement(measurement)
        print(json.dumps({"status": state, "detail": detail, "output": str(output_path)}))
        return 0 if state == "PASS" else 1
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": type(exc).__name__,
                    "detail": str(exc)[:500],
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
