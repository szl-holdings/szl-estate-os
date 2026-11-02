"""Shared fail-closed contracts for Estate OS production evidence.

The module only parses and validates local evidence files.  It does not infer a
passing state from filenames, operator labels, or unverified references.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any


PRODUCTION_EVIDENCE_INDEX_SCHEMA = "szl.estate-production-evidence-index/v1"
RESTORE_MEASUREMENT_SCHEMA = "szl.sqlite-restore-measurement/v2"
MAX_EVIDENCE_BYTES = 5_000_000
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
RUN_ID_PATTERN = re.compile(r"restore-[a-z0-9][a-z0-9._-]{0,126}")
EVIDENCE_REFERENCE_KEYS = {"artifact_path", "artifact_sha256"}

RESTORE_MEASUREMENT_KEYS = {
    "schema",
    "status",
    "run_id",
    "tool_sha256",
    "recovery_point_at",
    "started_at",
    "completed_at",
    "rto_seconds",
    "rpo_seconds",
    "source",
    "backup",
    "restore_target",
    "validation",
    "failure_scenarios",
}
RESTORE_SOURCE_KEYS = {
    "database_sha256_before",
    "database_sha256_after",
    "size_bytes_before",
    "size_bytes_after",
    "mtime_ns_before",
    "mtime_ns_after",
    "data_version_before",
    "data_version_after",
    "sidecars",
    "query_only",
    "unchanged",
}
SQLITE_SIDECAR_SUFFIXES = {"-wal", "-shm", "-journal"}
RESTORE_SIDECAR_KEYS = {"before", "after"}
RESTORE_FILE_ATTESTATION_KEYS = {
    "exists",
    "sha256",
    "size_bytes",
    "mtime_ns",
    "device_id",
    "file_id",
}
RESTORE_BACKUP_KEYS = {"sha256", "size_bytes", "created_at"}
RESTORE_TARGET_KEYS = {
    "isolation",
    "loopback_only",
    "production_writes",
    "path_disclosed",
    "cleaned_up",
}
RESTORE_VALIDATION_KEYS = {
    "integrity_check",
    "foreign_key_violation_count",
    "source_schema_sha256",
    "restored_schema_sha256",
    "source_content_sha256",
    "restored_content_sha256",
    "source_row_counts",
    "restored_row_counts",
    "receipt_chain_valid",
    "receipt_count",
}
RESTORE_FAILURE_KEYS = {"corrupt_backup_rejected", "missing_backup_rejected"}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def load_evidence_bytes(
    relative_value: Any,
    expected_sha256: str,
    evidence_root: Path | None,
    *,
    label: str,
) -> tuple[bytes | None, str]:
    if not isinstance(relative_value, str) or not relative_value:
        return None, f"{label}_path is missing or invalid"
    relative = Path(relative_value)
    if evidence_root is None or not relative.parts or relative.is_absolute():
        return None, f"{label}_path must be relative to the audit directory"
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        return None, f"{label}_sha256 is missing or invalid"
    root = evidence_root.resolve()
    evidence_path = (root / relative).resolve()
    try:
        evidence_path.relative_to(root)
    except ValueError:
        return None, f"{label}_path escapes the audit directory"
    try:
        if not evidence_path.is_file():
            return None, f"{label} is not a regular file"
        # Bound the actual read: a file may grow or shrink after metadata checks.
        # One extra byte distinguishes an exact-limit file from an oversized one.
        with evidence_path.open("rb") as stream:
            evidence_bytes = stream.read(MAX_EVIDENCE_BYTES + 1)
    except OSError as exc:
        return None, f"{label} unavailable error={type(exc).__name__}"
    if not evidence_bytes:
        return None, f"{label} is empty"
    if len(evidence_bytes) > MAX_EVIDENCE_BYTES:
        return None, f"{label} exceeds byte limit limit={MAX_EVIDENCE_BYTES}"
    observed_digest = sha256_bytes(evidence_bytes)
    if not hmac.compare_digest(observed_digest, expected_sha256):
        return None, f"{label} digest mismatch observed={observed_digest}"
    return evidence_bytes, (
        f"verified {label}_path={relative.as_posix()} {label}_sha256={expected_sha256}"
    )


def load_indexed_artifact_set(
    audit: dict[str, Any],
    requirement: str,
    evidence_root: Path | None,
    expected_asset_ids: set[str],
) -> tuple[dict[str, dict[str, Any]] | None, str]:
    """Load the protected exact per-deployment production evidence index.

    Legacy single-artifact references deliberately fail: they cannot establish
    complete coverage of a multi-deployment critical surface.
    """

    if not expected_asset_ids:
        return None, "manifest contains no critical production deployments"
    evidence = audit.get("production_evidence")
    record = evidence.get(requirement) if isinstance(evidence, dict) else None
    if not isinstance(record, dict) or set(record) != {"schema", "artifacts"}:
        return None, "production evidence index is missing or invalid"
    if record.get("schema") != PRODUCTION_EVIDENCE_INDEX_SCHEMA:
        return None, (
            "production evidence index schema must be "
            f"{PRODUCTION_EVIDENCE_INDEX_SCHEMA}"
        )
    references = record.get("artifacts")
    if not isinstance(references, dict):
        return None, "production evidence artifacts must be an object keyed by asset_id"
    observed_asset_ids = set(references)
    if observed_asset_ids != expected_asset_ids:
        missing = sorted(expected_asset_ids - observed_asset_ids)
        extra = sorted(observed_asset_ids - expected_asset_ids)
        return None, f"critical deployment coverage mismatch missing={missing} extra={extra}"

    artifacts: dict[str, dict[str, Any]] = {}
    details: list[str] = []
    for asset_id in sorted(expected_asset_ids):
        reference = references.get(asset_id)
        if not isinstance(reference, dict) or set(reference) != EVIDENCE_REFERENCE_KEYS:
            return None, f"evidence reference shape is invalid asset_id={asset_id}"
        digest = reference.get("artifact_sha256")
        if not isinstance(digest, str):
            return None, f"artifact_sha256 is missing or invalid asset_id={asset_id}"
        artifact_bytes, detail = load_evidence_bytes(
            reference.get("artifact_path"),
            digest,
            evidence_root,
            label="artifact",
        )
        if artifact_bytes is None:
            return None, f"asset_id={asset_id} {detail}"
        try:
            artifact = json.loads(artifact_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, f"artifact is not valid UTF-8 JSON asset_id={asset_id}"
        if not isinstance(artifact, dict):
            return None, f"artifact must be a JSON object asset_id={asset_id}"
        artifacts[asset_id] = artifact
        details.append(f"{asset_id}:{digest}")
    return artifacts, "exact critical deployment coverage " + ",".join(details)


def _valid_nonnegative_number(value: Any) -> bool:
    try:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(value)
            and value >= 0
        )
    except OverflowError:
        # JSON integers can exceed the floating-point range used for durations.
        return False


def _valid_nonnegative_int(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _valid_row_counts(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            isinstance(name, str)
            and bool(name)
            and _valid_nonnegative_int(count)
            for name, count in value.items()
        )
    )


def _valid_file_attestation(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != RESTORE_FILE_ATTESTATION_KEYS:
        return False
    exists = value.get("exists")
    if not isinstance(exists, bool):
        return False
    detail_fields = ("sha256", "size_bytes", "mtime_ns", "device_id", "file_id")
    if exists is False:
        return all(value.get(field) is None for field in detail_fields)
    return (
        SHA256_PATTERN.fullmatch(str(value.get("sha256") or "")) is not None
        and all(
            _valid_nonnegative_int(value.get(field))
            for field in ("size_bytes", "mtime_ns", "device_id", "file_id")
        )
    )


def _valid_sidecar_attestations(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == SQLITE_SIDECAR_SUFFIXES
        and all(
            isinstance(record, dict)
            and set(record) == RESTORE_SIDECAR_KEYS
            and _valid_file_attestation(record.get("before"))
            and _valid_file_attestation(record.get("after"))
            for record in value.values()
        )
    )


def validate_restore_measurement(value: Any) -> tuple[str, str]:
    """Validate the machine-generated isolated SQLite restore transcript."""

    if not isinstance(value, dict) or set(value) != RESTORE_MEASUREMENT_KEYS:
        return "FAIL", "restore measurement shape is invalid"
    if (
        value.get("schema") != RESTORE_MEASUREMENT_SCHEMA
        or value.get("status") != "PASS"
        or RUN_ID_PATTERN.fullmatch(str(value.get("run_id") or "")) is None
        or SHA256_PATTERN.fullmatch(str(value.get("tool_sha256") or "")) is None
    ):
        return "FAIL", "restore measurement identity/status is invalid"

    recovery_point = parse_timestamp(value.get("recovery_point_at"))
    started = parse_timestamp(value.get("started_at"))
    completed = parse_timestamp(value.get("completed_at"))
    if (
        recovery_point is None
        or started is None
        or completed is None
        or started < recovery_point
        or completed < started
    ):
        return "FAIL", "restore measurement timestamps are missing or invalid"
    if not _valid_nonnegative_number(value.get("rto_seconds")) or not _valid_nonnegative_number(
        value.get("rpo_seconds")
    ):
        return "FAIL", "restore measurement RTO/RPO is missing or invalid"
    observed_rto = (completed - started).total_seconds()
    observed_rpo = (started - recovery_point).total_seconds()
    if not math.isclose(float(value["rto_seconds"]), observed_rto, abs_tol=1e-6):
        return "FAIL", "restore measurement RTO does not match its timestamps"
    if not math.isclose(float(value["rpo_seconds"]), observed_rpo, abs_tol=1e-6):
        return "FAIL", "restore measurement RPO does not match its timestamps"

    source = value.get("source")
    if not isinstance(source, dict) or set(source) != RESTORE_SOURCE_KEYS:
        return "FAIL", "restore measurement source shape is invalid"
    for field in ("database_sha256_before", "database_sha256_after"):
        if SHA256_PATTERN.fullmatch(str(source.get(field) or "")) is None:
            return "FAIL", f"restore measurement {field} is invalid"
    for field in (
        "size_bytes_before",
        "size_bytes_after",
        "mtime_ns_before",
        "mtime_ns_after",
        "data_version_before",
        "data_version_after",
    ):
        if not _valid_nonnegative_int(source.get(field)):
            return "FAIL", f"restore measurement {field} is invalid"
    sidecars = source.get("sidecars")
    if not _valid_sidecar_attestations(sidecars):
        return "FAIL", "restore measurement sidecar attestations are invalid"
    sidecars_unchanged = all(
        record["before"] == record["after"] for record in sidecars.values()
    )
    if not sidecars_unchanged:
        return "FAIL", "restore drill did not preserve every SQLite sidecar"
    source_unchanged = (
        source.get("query_only") is True
        and source.get("unchanged") is True
        and source["database_sha256_before"] == source["database_sha256_after"]
        and source["size_bytes_before"] == source["size_bytes_after"]
        and source["mtime_ns_before"] == source["mtime_ns_after"]
        and source["data_version_before"] == source["data_version_after"]
        and sidecars_unchanged
    )
    if not source_unchanged:
        return "FAIL", "restore drill did not prove the source database remained unchanged"

    backup = value.get("backup")
    if not isinstance(backup, dict) or set(backup) != RESTORE_BACKUP_KEYS:
        return "FAIL", "restore measurement backup shape is invalid"
    backup_created = parse_timestamp(backup.get("created_at"))
    if (
        SHA256_PATTERN.fullmatch(str(backup.get("sha256") or "")) is None
        or not _valid_nonnegative_int(backup.get("size_bytes"))
        or backup["size_bytes"] <= 0
        or backup_created is None
        or backup_created < recovery_point
        or backup_created > started
    ):
        return "FAIL", "restore measurement backup values are invalid"

    target = value.get("restore_target")
    if not isinstance(target, dict) or set(target) != RESTORE_TARGET_KEYS:
        return "FAIL", "restore measurement target shape is invalid"
    if not (
        target.get("isolation") == "EPHEMERAL_TEMP_DIRECTORY"
        and target.get("loopback_only") is True
        and target.get("production_writes") == 0
        and not isinstance(target.get("production_writes"), bool)
        and target.get("path_disclosed") is False
        and target.get("cleaned_up") is True
    ):
        return "FAIL", "restore target is not proven isolated and non-destructive"

    validation = value.get("validation")
    if not isinstance(validation, dict) or set(validation) != RESTORE_VALIDATION_KEYS:
        return "FAIL", "restore measurement validation shape is invalid"
    for field in (
        "source_schema_sha256",
        "restored_schema_sha256",
        "source_content_sha256",
        "restored_content_sha256",
    ):
        if SHA256_PATTERN.fullmatch(str(validation.get(field) or "")) is None:
            return "FAIL", f"restore measurement validation {field} is invalid"
    if not _valid_row_counts(validation.get("source_row_counts")) or not _valid_row_counts(
        validation.get("restored_row_counts")
    ):
        return "FAIL", "restore measurement row-count evidence is invalid"
    if not (
        validation.get("integrity_check") == "ok"
        and validation.get("foreign_key_violation_count") == 0
        and not isinstance(validation.get("foreign_key_violation_count"), bool)
        and validation["source_schema_sha256"]
        == validation["restored_schema_sha256"]
        and validation["source_content_sha256"]
        == validation["restored_content_sha256"]
        and validation["source_row_counts"] == validation["restored_row_counts"]
        and validation.get("receipt_chain_valid") is True
        and _valid_nonnegative_int(validation.get("receipt_count"))
        and validation["receipt_count"] > 0
    ):
        return "FAIL", "restored database integrity or logical equivalence failed"

    scenarios = value.get("failure_scenarios")
    if not isinstance(scenarios, dict) or set(scenarios) != RESTORE_FAILURE_KEYS:
        return "FAIL", "restore failure-scenario evidence shape is invalid"
    if not all(scenarios.get(field) is True for field in RESTORE_FAILURE_KEYS):
        return "FAIL", "restore failure scenarios were not rejected fail-closed"
    return "PASS", (
        f"isolated restore run_id={value['run_id']} rto_seconds={value['rto_seconds']} "
        f"rpo_seconds={value['rpo_seconds']}"
    )
