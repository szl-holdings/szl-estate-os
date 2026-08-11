"""Citation drift and modeled Trust Factor reporting for Action Assurance."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from estate.action_assurance_contract import (
    ASSURANCE_LABELS,
    CITATION_KEYS,
    CITATION_LEDGER_SCHEMA,
    CITATION_STATES,
    LEDGER_KEYS,
    _exact_keys,
    _valid_finite_number,
    _valid_identifier,
    _valid_string,
    parse_timestamp,
    reject_non_finite_json_constant,
)
from estate.action_assurance_passport import validate_passport


def _valid_https_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc) and not parsed.username


def evaluate_citation_ledger(
    value: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate and derive drift state for an external-claim ledger.

    This function does not make network requests.  It verifies only the local
    ledger contract and whether the declared review deadline has passed.
    """

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors: list[str] = []
    entries_report: list[dict[str, Any]] = []
    if not _exact_keys(value, LEDGER_KEYS, "citation_ledger", errors):
        return {
            "status": "FAIL",
            "generated_at": now.isoformat(),
            "errors": errors,
            "entries": entries_report,
            "counts": {},
        }
    assert isinstance(value, dict)
    if value.get("schema") != CITATION_LEDGER_SCHEMA:
        errors.append(f"citation_ledger.schema must be {CITATION_LEDGER_SCHEMA}")
    if parse_timestamp(value.get("generated_at")) is None:
        errors.append("citation_ledger.generated_at is invalid")
    if not _valid_string(value.get("drift_policy")):
        errors.append("citation_ledger.drift_policy must be a nonempty string")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("citation_ledger.entries must be a nonempty array")
        entries = []

    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"citation_ledger.entries[{index}]"
        entry_errors: list[str] = []
        if not _exact_keys(entry, CITATION_KEYS, label, entry_errors):
            errors.extend(entry_errors)
            entries_report.append({"index": index, "state": "INVALID", "errors": entry_errors})
            continue
        assert isinstance(entry, dict)
        claim_id = entry.get("claim_id")
        if not _valid_identifier(claim_id):
            entry_errors.append(f"{label}.claim_id is invalid")
        elif claim_id in seen_ids:
            entry_errors.append(f"{label}.claim_id is duplicated")
        else:
            seen_ids.add(claim_id)
        if not _valid_string(entry.get("claim_text")):
            entry_errors.append(f"{label}.claim_text is invalid")
        if not _valid_https_url(entry.get("source_url")):
            entry_errors.append(f"{label}.source_url must be an HTTPS URL")
        retrieved_at = parse_timestamp(entry.get("retrieved_at"))
        verified_at = parse_timestamp(entry.get("last_verified_at"))
        review_at = parse_timestamp(entry.get("next_review_at"))
        if retrieved_at is None:
            entry_errors.append(f"{label}.retrieved_at is invalid")
        elif retrieved_at > now:
            entry_errors.append(f"{label}.retrieved_at cannot be in the future")
        if verified_at is None:
            entry_errors.append(f"{label}.last_verified_at is invalid")
        elif verified_at > now:
            entry_errors.append(f"{label}.last_verified_at cannot be in the future")
        if review_at is None:
            entry_errors.append(f"{label}.next_review_at is invalid")
        if retrieved_at and verified_at and verified_at < retrieved_at:
            entry_errors.append(f"{label}.last_verified_at cannot precede retrieval")
        if verified_at and review_at and review_at <= verified_at:
            entry_errors.append(f"{label}.next_review_at must be after verification")
        if entry.get("evidence_label") not in ASSURANCE_LABELS:
            entry_errors.append(f"{label}.evidence_label is invalid")
        declared_state = entry.get("status")
        if declared_state not in CITATION_STATES:
            entry_errors.append(f"{label}.status is invalid")
        correction = entry.get("correction")
        if correction is not None and not _valid_string(correction):
            entry_errors.append(f"{label}.correction must be null or nonempty")
        if declared_state == "DIVERGENT" and not _valid_string(correction):
            entry_errors.append(f"{label}.correction is required for DIVERGENT claims")

        derived_state = "INVALID"
        if not entry_errors:
            if declared_state == "DIVERGENT":
                derived_state = "DIVERGENT"
            elif declared_state == "UNAVAILABLE":
                derived_state = "UNAVAILABLE"
            elif review_at is not None and now > review_at:
                derived_state = "STALE"
            else:
                derived_state = "CURRENT"
            if declared_state != derived_state:
                entry_errors.append(
                    f"{label}.status={declared_state} does not match derived state "
                    f"{derived_state}"
                )
        if entry_errors:
            errors.extend(entry_errors)
        entries_report.append(
            {
                "claim_id": claim_id,
                "declared_state": declared_state,
                "derived_state": derived_state,
                "next_review_at": entry.get("next_review_at"),
                "errors": entry_errors,
            }
        )

    counts = Counter(item.get("derived_state", "INVALID") for item in entries_report)
    failing_states = sum(
        counts.get(state, 0)
        for state in ("INVALID", "STALE", "DIVERGENT", "UNAVAILABLE")
    )
    return {
        "status": "PASS" if not errors and failing_states == 0 else "FAIL",
        "generated_at": now.isoformat(),
        "errors": errors,
        "entries": entries_report,
        "counts": dict(sorted(counts.items())),
    }


def _decision_event_score(passport: dict[str, Any]) -> float:
    decision = passport["policy_decision"]
    oversight = passport["human_oversight"]["state"]
    outcome = passport["outcome"]["state"]
    base = {
        "ALLOW": 100.0,
        "WARN": 70.0,
        "THROTTLE": 55.0,
        "BLOCK": 20.0,
        "REQUIRE_APPROVAL": {
            "APPROVED": 90.0,
            "REJECTED": 55.0,
            "PENDING": 75.0,
            "NOT_REQUIRED": 0.0,
        }[oversight],
    }[decision]
    adjustment = {
        "NOT_MEASURED": -5.0,
        "SUCCEEDED": 0.0,
        "FAILED": -20.0,
        "REFUSED": 0.0,
        "WITHHELD": 0.0,
    }[outcome]
    rollback = passport["rollback"]["state"]
    if rollback == "FAILED":
        adjustment -= 15.0
    return max(0.0, min(100.0, base + adjustment))


def compute_trust_factors(
    passports: Iterable[dict[str, Any]],
    *,
    now: datetime | None = None,
    half_life_days: float = 90.0,
) -> dict[str, Any]:
    """Derive transparent longitudinal per-agent Trust Factors.

    The score is explicitly ``MODELED``.  It is a recency-weighted average of
    policy-tier event scores and is not an identity credential, authorization
    decision, compliance certification, or substitute for raw passport data.
    """

    if not _valid_finite_number(half_life_days) or float(half_life_days) <= 0:
        raise ValueError("half_life_days must be a positive finite number")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    grouped: dict[str, list[tuple[dict[str, Any], float, float]]] = defaultdict(list)
    invalid: list[dict[str, Any]] = []

    for index, passport in enumerate(passports):
        errors = validate_passport(passport)
        agent_id = None
        if isinstance(passport, dict):
            identity = passport.get("identity")
            if isinstance(identity, dict) and isinstance(identity.get("agent_id"), str):
                agent_id = identity["agent_id"]
        if errors:
            invalid.append(
                {
                    "index": index,
                    "agent_id": agent_id,
                    "passport_id": passport.get("passport_id") if isinstance(passport, dict) else None,
                    "errors": errors,
                }
            )
            continue
        assert agent_id is not None
        recorded_at = parse_timestamp(passport["recorded_at"])
        assert recorded_at is not None
        if recorded_at > now:
            invalid.append(
                {
                    "index": index,
                    "agent_id": agent_id,
                    "passport_id": passport.get("passport_id"),
                    "errors": ["passport.recorded_at cannot be in the future for scoring"],
                }
            )
            continue
        age_days = (now - recorded_at).total_seconds() / 86400.0
        weight = max(0.05, 0.5 ** (age_days / float(half_life_days)))
        grouped[agent_id].append((passport, _decision_event_score(passport), weight))

    agents: dict[str, Any] = {}
    for agent_id, events in sorted(grouped.items()):
        weighted_total = sum(score * weight for _, score, weight in events)
        total_weight = sum(weight for _, _, weight in events)
        score = weighted_total / total_weight if total_weight else 0.0
        decision_counts = Counter(event[0]["policy_decision"] for event in events)
        action_counts = Counter(event[0]["action"]["state"] for event in events)
        outcome_counts = Counter(event[0]["outcome"]["state"] for event in events)
        agents[agent_id] = {
            "evidence_label": "MODELED",
            "score_0_to_100": round(score, 2),
            "sample_size": len(events),
            "confidence_0_to_1": round(min(1.0, len(events) / 20.0), 2),
            "half_life_days": float(half_life_days),
            "decision_counts": dict(sorted(decision_counts.items())),
            "action_counts": dict(sorted(action_counts.items())),
            "outcome_counts": dict(sorted(outcome_counts.items())),
            "limitations": [
                "Weights are policy-modeled and not externally calibrated.",
                "The score never expands authority and must not replace raw passports.",
            ],
        }

    invalid_by_agent = Counter(
        item["agent_id"] for item in invalid if isinstance(item.get("agent_id"), str)
    )
    for agent_id, count in invalid_by_agent.items():
        if agent_id in agents:
            agents[agent_id]["invalid_passport_count"] = count
        else:
            agents[agent_id] = {
                "evidence_label": "UNAVAILABLE",
                "score_0_to_100": None,
                "sample_size": 0,
                "confidence_0_to_1": 0.0,
                "half_life_days": float(half_life_days),
                "invalid_passport_count": count,
                "limitations": ["No valid passport was available for scoring."],
            }

    return {
        "schema": "szl.trust-factor-report/v1",
        "generated_at": now.isoformat(),
        "evidence_label": "MODELED" if grouped else "UNAVAILABLE",
        "agents": agents,
        "invalid_passports": invalid,
    }


def load_json_documents(directory: Path) -> tuple[list[dict[str, Any]], list[str]]:
    documents: list[dict[str, Any]] = []
    errors: list[str] = []
    if not directory.is_dir():
        return documents, [f"passport directory does not exist: {directory}"]
    for path in sorted(directory.glob("*.json")):
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                parse_constant=reject_non_finite_json_constant,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{path}: unreadable JSON error={type(exc).__name__}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}: root must be an object")
            continue
        documents.append(value)
    if not documents and not errors:
        errors.append(f"passport directory contains no JSON files: {directory}")
    return documents, errors
