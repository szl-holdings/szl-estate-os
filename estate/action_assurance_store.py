"""Durable, fail-closed Action Assurance persistence for Estate OS.

This module stores validated Counterfactual Action Passports in the existing
Estate OS SQLite database. It never mutates external systems and never promotes
an unsigned or unverified signature to a verified state.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from estate.action_assurance import (
    canonical_json_bytes,
    compute_trust_factors,
    evaluate_citation_ledger,
    sha256_bytes,
    validate_passport,
)


STORE_SCHEMA = "szl.action-assurance-store/v1"
INGEST_SCHEMA = "szl.action-assurance-ingest/v1"

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS action_assurance_passports (
    passport_id TEXT PRIMARY KEY,
    recorded_at TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    action_state TEXT NOT NULL,
    outcome_state TEXT NOT NULL,
    signature_state TEXT NOT NULL,
    payload_sha3_256 TEXT NOT NULL,
    passport_sha256 TEXT NOT NULL,
    passport_json TEXT NOT NULL,
    first_ingest_id TEXT NOT NULL,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS action_assurance_ingests (
    ingest_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    source_label TEXT NOT NULL,
    status TEXT NOT NULL,
    loaded_count INTEGER NOT NULL,
    valid_count INTEGER NOT NULL,
    invalid_count INTEGER NOT NULL,
    conflict_count INTEGER NOT NULL,
    idempotent_count INTEGER NOT NULL,
    citation_status TEXT NOT NULL,
    failures_json TEXT NOT NULL,
    passport_results_json TEXT NOT NULL,
    citation_report_json TEXT NOT NULL,
    trust_report_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_passports_agent_recorded
ON action_assurance_passports(agent_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_action_passports_decision_recorded
ON action_assurance_passports(policy_decision, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_action_ingests_completed
ON action_assurance_ingests(completed_at DESC);
"""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    # Preserve subsecond precision for diagnostics. Latest-record selection also
    # uses SQLite rowid as the monotonic insertion-order tiebreaker so callers
    # that deliberately pass the same timestamp still observe the newest ingest.
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _json_text(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def connect_action_store(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA_SQL)
    return connection


def _full_passport_sha256(passport: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(passport))


def _stored_passports(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT passport_json FROM action_assurance_passports ORDER BY recorded_at, passport_id"
    ).fetchall()
    result: list[dict[str, Any]] = []
    for row in rows:
        value = json.loads(row["passport_json"])
        if isinstance(value, dict):
            result.append(value)
    return result


def ingest_action_assurance(
    db_path: Path,
    passports: Iterable[dict[str, Any]],
    citation_ledger: dict[str, Any],
    *,
    source_label: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and persist one immutable batch.

    Passport IDs are immutable. Re-ingesting the exact same canonical passport
    is idempotent; reusing an existing ID with different bytes is a hard
    conflict. Batch-local duplicate IDs also fail closed.
    """

    now = (now or _utc_now()).astimezone(timezone.utc)
    started_at = _iso(now)
    ingest_id = f"aa-{uuid.uuid4().hex}"
    values = list(passports)
    results: list[dict[str, Any]] = []
    valid: list[dict[str, Any]] = []
    failures: list[str] = []
    seen_ids: set[str] = set()

    for index, passport in enumerate(values):
        errors = validate_passport(passport)
        passport_id = passport.get("passport_id") if isinstance(passport, dict) else None
        if not errors and isinstance(passport_id, str):
            if passport_id in seen_ids:
                errors.append(f"passport.passport_id duplicated in ingest batch: {passport_id}")
            else:
                seen_ids.add(passport_id)
        status = "PASS" if not errors else "FAIL"
        results.append(
            {
                "index": index,
                "passport_id": passport_id,
                "status": status,
                "errors": list(errors),
            }
        )
        if errors:
            failures.append(f"passport[{index}] invalid")
        else:
            valid.append(passport)

    citation_report = evaluate_citation_ledger(citation_ledger, now=now)
    if citation_report.get("status") != "PASS":
        failures.append("citation_ledger_status=FAIL")
    if not valid:
        failures.append("no valid passports available")

    conflict_count = 0
    idempotent_count = 0
    inserted_count = 0
    connection = connect_action_store(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        existing = {
            row["passport_id"]: row["passport_sha256"]
            for row in connection.execute(
                "SELECT passport_id, passport_sha256 FROM action_assurance_passports"
            ).fetchall()
        }

        for passport in valid:
            passport_id = passport["passport_id"]
            digest = _full_passport_sha256(passport)
            prior = existing.get(passport_id)
            if prior is not None:
                if prior == digest:
                    idempotent_count += 1
                    continue
                conflict_count += 1
                failures.append(f"passport_id_conflict={passport_id}")
                continue

            identity = passport["identity"]
            action = passport["action"]
            outcome = passport["outcome"]
            signature = passport["signature"]
            connection.execute(
                """
                INSERT INTO action_assurance_passports (
                    passport_id, recorded_at, agent_id, principal_id,
                    policy_decision, action_state, outcome_state, signature_state,
                    payload_sha3_256, passport_sha256, passport_json,
                    first_ingest_id, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    passport_id,
                    passport["recorded_at"],
                    identity["agent_id"],
                    identity["principal_id"],
                    passport["policy_decision"],
                    action["state"],
                    outcome["state"],
                    signature["state"],
                    signature["payload_sha3_256"],
                    digest,
                    _json_text(passport),
                    ingest_id,
                    started_at,
                ),
            )
            inserted_count += 1
            existing[passport_id] = digest

        persisted = _stored_passports(connection)
        trust_report = compute_trust_factors(persisted, now=now)
        invalid_count = sum(1 for item in results if item["status"] != "PASS")
        status = "PASS" if not failures and conflict_count == 0 else "FAIL"
        completed_at = _iso(now)
        connection.execute(
            """
            INSERT INTO action_assurance_ingests (
                ingest_id, started_at, completed_at, source_label, status,
                loaded_count, valid_count, invalid_count, conflict_count,
                idempotent_count, citation_status, failures_json,
                passport_results_json, citation_report_json, trust_report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ingest_id,
                started_at,
                completed_at,
                source_label,
                status,
                len(values),
                len(valid),
                invalid_count,
                conflict_count,
                idempotent_count,
                str(citation_report.get("status") or "FAIL"),
                _json_text(failures),
                _json_text(results),
                _json_text(citation_report),
                _json_text(trust_report),
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return {
        "schema": INGEST_SCHEMA,
        "ingest_id": ingest_id,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "source_label": source_label,
        "loaded_count": len(values),
        "valid_count": len(valid),
        "invalid_count": invalid_count,
        "inserted_count": inserted_count,
        "idempotent_count": idempotent_count,
        "conflict_count": conflict_count,
        "citation_status": citation_report.get("status"),
        "failures": failures,
        "passport_results": results,
        "citation_report": citation_report,
        "trust_report": trust_report,
    }


def store_status(db_path: Path) -> dict[str, Any]:
    connection = connect_action_store(db_path)
    try:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS passport_count,
                COUNT(DISTINCT agent_id) AS agent_count,
                SUM(CASE WHEN signature_state = 'SIGNED_UNVERIFIED' THEN 1 ELSE 0 END)
                    AS signed_unverified_count,
                SUM(CASE WHEN signature_state = 'UNSIGNED' THEN 1 ELSE 0 END)
                    AS unsigned_count
            FROM action_assurance_passports
            """
        ).fetchone()
        latest = connection.execute(
            "SELECT * FROM action_assurance_ingests ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    finally:
        connection.close()

    latest_summary = None
    if latest is not None:
        latest_summary = {
            "ingest_id": latest["ingest_id"],
            "completed_at": latest["completed_at"],
            "source_label": latest["source_label"],
            "status": latest["status"],
            "loaded_count": latest["loaded_count"],
            "valid_count": latest["valid_count"],
            "invalid_count": latest["invalid_count"],
            "conflict_count": latest["conflict_count"],
            "idempotent_count": latest["idempotent_count"],
            "citation_status": latest["citation_status"],
        }
    return {
        "schema": STORE_SCHEMA,
        "database": str(db_path),
        "passport_count": int(totals["passport_count"] or 0),
        "agent_count": int(totals["agent_count"] or 0),
        "signed_unverified_count": int(totals["signed_unverified_count"] or 0),
        "unsigned_count": int(totals["unsigned_count"] or 0),
        "latest_ingest": latest_summary,
        "signature_verification": "NOT_IMPLEMENTED_IN_STORE",
        "claim_state": "PARTIAL",
    }


def list_passports(
    db_path: Path,
    *,
    limit: int = 100,
    agent_id: str | None = None,
    decision: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    clauses: list[str] = []
    params: list[Any] = []
    if agent_id:
        clauses.append("agent_id = ?")
        params.append(agent_id)
    if decision:
        clauses.append("policy_decision = ?")
        params.append(decision)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    query = (
        "SELECT passport_json FROM action_assurance_passports"
        + where
        + " ORDER BY recorded_at DESC, passport_id DESC LIMIT ?"
    )
    params.append(limit)
    connection = connect_action_store(db_path)
    try:
        rows = connection.execute(query, params).fetchall()
    finally:
        connection.close()
    return [json.loads(row["passport_json"]) for row in rows]


def current_trust_report(
    db_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    connection = connect_action_store(db_path)
    try:
        passports = _stored_passports(connection)
    finally:
        connection.close()
    return compute_trust_factors(passports, now=now)


def latest_citation_report(db_path: Path) -> dict[str, Any] | None:
    connection = connect_action_store(db_path)
    try:
        row = connection.execute(
            "SELECT citation_report_json FROM action_assurance_ingests "
            "ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    value = json.loads(row["citation_report_json"])
    return value if isinstance(value, dict) else None
