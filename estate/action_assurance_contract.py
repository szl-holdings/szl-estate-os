"""Shared fail-closed contracts for Counterfactual Action Passports.

This dependency-free module defines exact shapes, deterministic hashing, and
timestamp helpers. It does not perform privileged mutations, ECDSA signing, or
online source verification.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any


PASSPORT_SCHEMA = "szl.counterfactual-action-passport/v1"
CITATION_LEDGER_SCHEMA = "szl.external-claim-ledger/v1"
DSSE_PAYLOAD_TYPE = (
    "application/vnd.szl.counterfactual-action-passport+json;version=1"
)

ASSURANCE_LABELS = frozenset(
    {
        "PROVED",
        "MEASURED",
        "VERIFIED",
        "OBSERVED",
        "REPORTED",
        "MODELED",
        "CONJECTURED",
        "UNAVAILABLE",
        "DIVERGENT",
    }
)
POLICY_DECISIONS = frozenset(
    {"ALLOW", "BLOCK", "REQUIRE_APPROVAL", "THROTTLE", "WARN"}
)
ACTION_STATES = frozenset(
    {"PROPOSED", "REFUSED", "EXECUTED", "FAILED", "WITHHELD"}
)
OUTCOME_STATES = frozenset(
    {"NOT_MEASURED", "SUCCEEDED", "FAILED", "REFUSED", "WITHHELD"}
)
OVERSIGHT_STATES = frozenset(
    {"NOT_REQUIRED", "PENDING", "APPROVED", "REJECTED"}
)
ROLLBACK_STATES = frozenset(
    {"NOT_REQUIRED", "READY", "EXECUTED", "FAILED", "UNAVAILABLE"}
)
SIGNATURE_STATES = frozenset({"UNSIGNED", "SIGNED_UNVERIFIED"})
CITATION_STATES = frozenset(
    {"CURRENT", "STALE", "DIVERGENT", "UNAVAILABLE"}
)

HEX64 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}")
SCOPE = re.compile(r"\*|[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}")

PASSPORT_REQUIRED_KEYS = {
    "schema",
    "passport_id",
    "recorded_at",
    "identity",
    "authority",
    "evidence",
    "policy_decision",
    "human_oversight",
    "expected_if_acted",
    "expected_if_withheld",
    "action",
    "outcome",
    "rollback",
    "signature",
}
PASSPORT_OPTIONAL_KEYS = {"trust_factor_delta"}
IDENTITY_KEYS = {"agent_id", "principal_id", "session_id", "delegation_chain"}
AUTHORITY_KEYS = {
    "parent_scopes",
    "child_scopes",
    "tool",
    "resource",
    "constraints",
}
EVIDENCE_KEYS = {"claims", "graph_sha3_256"}
CLAIM_KEYS = {
    "claim_id",
    "label",
    "source_refs",
    "observed_at",
    "digest_sha256",
}
OVERSIGHT_KEYS = {
    "state",
    "approver_id",
    "recorded_at",
    "approval_receipt_sha256",
}
COUNTERFACTUAL_KEYS = {
    "statement",
    "confidence_0_to_1",
    "evidence_claim_ids",
    "recorded_at",
}
ACTION_KEYS = {
    "action_id",
    "kind",
    "target",
    "parameters_sha3_256",
    "requested_at",
    "executed_at",
    "state",
}
OUTCOME_KEYS = {"state", "measured_at", "metrics", "evidence_sha3_256"}
ROLLBACK_KEYS = {"available", "plan_sha3_256", "state", "executed_at"}
SIGNATURE_KEYS = {
    "state",
    "algorithm",
    "digest_algorithm",
    "payload_sha3_256",
    "key_id",
    "signature_b64",
    "dsse_envelope_sha256",
    "w3c_vc_sha256",
}
LEDGER_KEYS = {"schema", "generated_at", "drift_policy", "entries"}
CITATION_KEYS = {
    "claim_id",
    "claim_text",
    "source_url",
    "retrieved_at",
    "last_verified_at",
    "next_review_at",
    "evidence_label",
    "status",
    "correction",
}


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes.

    This is a stable local canonicalization contract, not a claim of full RFC
    8785 JSON Canonicalization Scheme conformance.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha3_256_bytes(value: bytes) -> str:
    return hashlib.sha3_256(value).hexdigest()


def sha3_256_json(value: Any) -> str:
    return sha3_256_bytes(canonical_json_bytes(value))


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _exact_keys(
    value: Any,
    required: set[str],
    label: str,
    errors: list[str],
    optional: set[str] | None = None,
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label} must be an object")
        return False
    optional = optional or set()
    keys = set(value)
    missing = sorted(required - keys)
    extra = sorted(keys - required - optional)
    if missing:
        errors.append(f"{label} missing keys={missing}")
    if extra:
        errors.append(f"{label} unexpected keys={extra}")
    return not missing and not extra


def _valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _valid_hex64(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _valid_optional_hex64(value: Any) -> bool:
    return value is None or _valid_hex64(value)


def _valid_optional_identifier(value: Any) -> bool:
    return value is None or _valid_identifier(value)


def _valid_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _validate_string_list(
    value: Any,
    label: str,
    errors: list[str],
    *,
    pattern: re.Pattern[str] | None = None,
    require_nonempty: bool = True,
) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return []
    if require_nonempty and not value:
        errors.append(f"{label} must not be empty")
        return []
    if not all(isinstance(item, str) and item for item in value):
        errors.append(f"{label} must contain nonempty strings")
        return []
    if len(value) != len(set(value)):
        errors.append(f"{label} must not contain duplicates")
    if pattern is not None:
        invalid = [item for item in value if pattern.fullmatch(item) is None]
        if invalid:
            errors.append(f"{label} contains invalid values={invalid}")
    return list(value)


def passport_signing_payload(passport: dict[str, Any]) -> dict[str, Any]:
    """Return the passport content bound by the signature digest."""

    payload = dict(passport)
    payload.pop("signature", None)
    payload.pop("trust_factor_delta", None)
    return payload


def expected_signature_payload_digest(passport: dict[str, Any]) -> str:
    return sha3_256_json(passport_signing_payload(passport))


def _validate_counterfactual(
    value: Any,
    label: str,
    claim_ids: set[str],
    requested_at: datetime | None,
    passport_recorded_at: datetime | None,
    errors: list[str],
) -> None:
    if not _exact_keys(value, COUNTERFACTUAL_KEYS, label, errors):
        return
    if not _valid_string(value.get("statement")):
        errors.append(f"{label}.statement must be a nonempty string")
    confidence = value.get("confidence_0_to_1")
    if not _valid_finite_number(confidence) or not 0 <= float(confidence) <= 1:
        errors.append(f"{label}.confidence_0_to_1 must be between 0 and 1")
    references = _validate_string_list(
        value.get("evidence_claim_ids"),
        f"{label}.evidence_claim_ids",
        errors,
    )
    unknown = sorted(set(references) - claim_ids)
    if unknown:
        errors.append(f"{label} references unknown evidence claims={unknown}")
    recorded_at = parse_timestamp(value.get("recorded_at"))
    if recorded_at is None:
        errors.append(f"{label}.recorded_at must be a timezone-aware timestamp")
    if recorded_at is not None and requested_at is not None and recorded_at > requested_at:
        errors.append(f"{label} must be recorded no later than action.requested_at")
    if (
        recorded_at is not None
        and passport_recorded_at is not None
        and recorded_at > passport_recorded_at
    ):
        errors.append(f"{label}.recorded_at cannot be after passport.recorded_at")
