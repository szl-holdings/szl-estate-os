"""Semantic validation and unsigned interop for Counterfactual Action Passports."""

from __future__ import annotations

import base64
from typing import Any

from estate.action_assurance_contract import (
    ACTION_KEYS,
    ACTION_STATES,
    ASSURANCE_LABELS,
    AUTHORITY_KEYS,
    CLAIM_KEYS,
    DSSE_PAYLOAD_TYPE,
    EVIDENCE_KEYS,
    IDENTIFIER,
    IDENTITY_KEYS,
    OUTCOME_KEYS,
    OUTCOME_STATES,
    OVERSIGHT_KEYS,
    OVERSIGHT_STATES,
    PASSPORT_OPTIONAL_KEYS,
    PASSPORT_REQUIRED_KEYS,
    PASSPORT_SCHEMA,
    POLICY_DECISIONS,
    ROLLBACK_KEYS,
    ROLLBACK_STATES,
    SCOPE,
    SIGNATURE_KEYS,
    SIGNATURE_STATES,
    _exact_keys,
    _valid_finite_number,
    _valid_hex64,
    _valid_identifier,
    _valid_optional_hex64,
    _valid_optional_identifier,
    _valid_string,
    _validate_counterfactual,
    _validate_string_list,
    canonical_json_bytes,
    expected_signature_payload_digest,
    parse_timestamp,
    passport_signing_payload,
    sha3_256_json,
)


def validate_passport(value: Any) -> list[str]:
    """Validate one Counterfactual Action Passport.

    Validation is structural and semantic.  It proves neither the underlying
    claims nor an ECDSA signature.  A signed record remains
    ``SIGNED_UNVERIFIED`` until an independent cryptographic verifier is added.
    """

    errors: list[str] = []
    if not _exact_keys(
        value,
        PASSPORT_REQUIRED_KEYS,
        "passport",
        errors,
        PASSPORT_OPTIONAL_KEYS,
    ):
        return errors
    assert isinstance(value, dict)

    if value.get("schema") != PASSPORT_SCHEMA:
        errors.append(f"passport.schema must be {PASSPORT_SCHEMA}")
    if not _valid_identifier(value.get("passport_id")):
        errors.append("passport.passport_id is invalid")
    recorded_at = parse_timestamp(value.get("recorded_at"))
    if recorded_at is None:
        errors.append("passport.recorded_at must be a timezone-aware timestamp")
    trust_delta = value.get("trust_factor_delta")
    if trust_delta is not None and (
        not _valid_finite_number(trust_delta) or not -100 <= float(trust_delta) <= 100
    ):
        errors.append("passport.trust_factor_delta must be null or between -100 and 100")

    identity = value.get("identity")
    if _exact_keys(identity, IDENTITY_KEYS, "identity", errors):
        assert isinstance(identity, dict)
        for field in ("agent_id", "principal_id", "session_id"):
            if not _valid_identifier(identity.get(field)):
                errors.append(f"identity.{field} is invalid")
        chain = _validate_string_list(
            identity.get("delegation_chain"),
            "identity.delegation_chain",
            errors,
            pattern=IDENTIFIER,
        )
        if chain and _valid_identifier(identity.get("principal_id")):
            if chain[0] != identity["principal_id"]:
                errors.append("identity.delegation_chain must begin with principal_id")
        if chain and _valid_identifier(identity.get("agent_id")):
            if chain[-1] != identity["agent_id"]:
                errors.append("identity.delegation_chain must end with agent_id")

    authority = value.get("authority")
    if _exact_keys(authority, AUTHORITY_KEYS, "authority", errors):
        assert isinstance(authority, dict)
        parent_scopes = _validate_string_list(
            authority.get("parent_scopes"),
            "authority.parent_scopes",
            errors,
            pattern=SCOPE,
        )
        child_scopes = _validate_string_list(
            authority.get("child_scopes"),
            "authority.child_scopes",
            errors,
            pattern=SCOPE,
        )
        if "*" not in set(parent_scopes) and not set(child_scopes).issubset(parent_scopes):
            escalated = sorted(set(child_scopes) - set(parent_scopes))
            errors.append(f"authority child scopes exceed parent scopes={escalated}")
        if not _valid_identifier(authority.get("tool")):
            errors.append("authority.tool is invalid")
        if not _valid_string(authority.get("resource")):
            errors.append("authority.resource must be a nonempty string")
        if not isinstance(authority.get("constraints"), dict):
            errors.append("authority.constraints must be an object")

    evidence = value.get("evidence")
    claim_ids: set[str] = set()
    if _exact_keys(evidence, EVIDENCE_KEYS, "evidence", errors):
        assert isinstance(evidence, dict)
        claims = evidence.get("claims")
        if not isinstance(claims, list) or not claims:
            errors.append("evidence.claims must be a nonempty array")
        else:
            normalized_claims: list[dict[str, Any]] = []
            for index, claim in enumerate(claims):
                label = f"evidence.claims[{index}]"
                if not _exact_keys(claim, CLAIM_KEYS, label, errors):
                    continue
                assert isinstance(claim, dict)
                claim_id = claim.get("claim_id")
                if not _valid_identifier(claim_id):
                    errors.append(f"{label}.claim_id is invalid")
                elif claim_id in claim_ids:
                    errors.append(f"{label}.claim_id is duplicated")
                else:
                    claim_ids.add(claim_id)
                if claim.get("label") not in ASSURANCE_LABELS:
                    errors.append(f"{label}.label is invalid")
                _validate_string_list(
                    claim.get("source_refs"),
                    f"{label}.source_refs",
                    errors,
                )
                observed_at = parse_timestamp(claim.get("observed_at"))
                if observed_at is None:
                    errors.append(f"{label}.observed_at is invalid")
                elif recorded_at is not None and observed_at > recorded_at:
                    errors.append(f"{label}.observed_at cannot be after passport.recorded_at")
                if not _valid_hex64(claim.get("digest_sha256")):
                    errors.append(f"{label}.digest_sha256 is invalid")
                normalized_claims.append(claim)
            expected_graph = sha3_256_json(normalized_claims)
            if evidence.get("graph_sha3_256") != expected_graph:
                errors.append(
                    "evidence.graph_sha3_256 does not bind the exact ordered claims"
                )

    decision = value.get("policy_decision")
    if decision not in POLICY_DECISIONS:
        errors.append("policy_decision is invalid")

    oversight = value.get("human_oversight")
    oversight_state: str | None = None
    oversight_recorded_at: datetime | None = None
    if _exact_keys(oversight, OVERSIGHT_KEYS, "human_oversight", errors):
        assert isinstance(oversight, dict)
        oversight_state = oversight.get("state")
        if oversight_state not in OVERSIGHT_STATES:
            errors.append("human_oversight.state is invalid")
        approver = oversight.get("approver_id")
        oversight_recorded_at = parse_timestamp(oversight.get("recorded_at"))
        approval_receipt = oversight.get("approval_receipt_sha256")
        if oversight_state in {"APPROVED", "REJECTED"}:
            if not _valid_identifier(approver):
                errors.append("human_oversight.approver_id is required for a decision")
            if oversight_recorded_at is None:
                errors.append("human_oversight.recorded_at is required for a decision")
            if not _valid_hex64(approval_receipt):
                errors.append(
                    "human_oversight.approval_receipt_sha256 is required for a decision"
                )
        else:
            if not _valid_optional_identifier(approver):
                errors.append("human_oversight.approver_id is invalid")
            if oversight.get("recorded_at") is not None and oversight_recorded_at is None:
                errors.append("human_oversight.recorded_at is invalid")
            if not _valid_optional_hex64(approval_receipt):
                errors.append("human_oversight.approval_receipt_sha256 is invalid")

    action = value.get("action")
    action_state: str | None = None
    requested_at: datetime | None = None
    executed_at: datetime | None = None
    if _exact_keys(action, ACTION_KEYS, "action", errors):
        assert isinstance(action, dict)
        for field in ("action_id", "kind"):
            if not _valid_identifier(action.get(field)):
                errors.append(f"action.{field} is invalid")
        if not _valid_string(action.get("target")):
            errors.append("action.target must be a nonempty string")
        if not _valid_hex64(action.get("parameters_sha3_256")):
            errors.append("action.parameters_sha3_256 is invalid")
        requested_at = parse_timestamp(action.get("requested_at"))
        if requested_at is None:
            errors.append("action.requested_at is invalid")
        elif recorded_at is not None and requested_at > recorded_at:
            errors.append("action.requested_at cannot be after passport.recorded_at")
        executed_at = parse_timestamp(action.get("executed_at"))
        action_state = action.get("state")
        if action_state not in ACTION_STATES:
            errors.append("action.state is invalid")
        if action_state in {"EXECUTED", "FAILED"}:
            if executed_at is None:
                errors.append("action.executed_at is required for an execution attempt")
            elif requested_at is not None and executed_at < requested_at:
                errors.append("action.executed_at cannot precede action.requested_at")
            elif recorded_at is not None and executed_at > recorded_at:
                errors.append("action.executed_at cannot be after passport.recorded_at")
        elif action.get("executed_at") is not None:
            errors.append("action.executed_at must be null for a non-executed action")

    _validate_counterfactual(
        value.get("expected_if_acted"),
        "expected_if_acted",
        claim_ids,
        requested_at,
        recorded_at,
        errors,
    )
    _validate_counterfactual(
        value.get("expected_if_withheld"),
        "expected_if_withheld",
        claim_ids,
        requested_at,
        recorded_at,
        errors,
    )

    if decision == "BLOCK" and action_state != "REFUSED":
        errors.append("BLOCK decisions must produce action.state=REFUSED")
    if decision == "ALLOW" and oversight_state not in {"NOT_REQUIRED", "APPROVED"}:
        errors.append("ALLOW requires NOT_REQUIRED or APPROVED oversight")
    if decision == "REQUIRE_APPROVAL":
        if oversight_state == "NOT_REQUIRED":
            errors.append("REQUIRE_APPROVAL cannot use NOT_REQUIRED oversight")
        if action_state in {"EXECUTED", "FAILED"} and oversight_state != "APPROVED":
            errors.append("REQUIRE_APPROVAL cannot execute before approval")
        if (
            action_state in {"EXECUTED", "FAILED"}
            and oversight_recorded_at is not None
            and executed_at is not None
            and oversight_recorded_at > executed_at
        ):
            errors.append("approval must be recorded before execution")

    outcome = value.get("outcome")
    outcome_state: str | None = None
    if _exact_keys(outcome, OUTCOME_KEYS, "outcome", errors):
        assert isinstance(outcome, dict)
        outcome_state = outcome.get("state")
        if outcome_state not in OUTCOME_STATES:
            errors.append("outcome.state is invalid")
        measured_at = parse_timestamp(outcome.get("measured_at"))
        if outcome_state in {"SUCCEEDED", "FAILED"}:
            if measured_at is None:
                errors.append("outcome.measured_at is required for measured outcomes")
            if not _valid_hex64(outcome.get("evidence_sha3_256")):
                errors.append(
                    "outcome.evidence_sha3_256 is required for measured outcomes"
                )
        else:
            if outcome.get("measured_at") is not None and measured_at is None:
                errors.append("outcome.measured_at is invalid")
            if not _valid_optional_hex64(outcome.get("evidence_sha3_256")):
                errors.append("outcome.evidence_sha3_256 is invalid")
        if measured_at is not None:
            if executed_at is not None and measured_at < executed_at:
                errors.append("outcome.measured_at cannot precede action.executed_at")
            if recorded_at is not None and measured_at > recorded_at:
                errors.append("outcome.measured_at cannot be after passport.recorded_at")
        if not isinstance(outcome.get("metrics"), dict):
            errors.append("outcome.metrics must be an object")

    if action_state == "REFUSED" and outcome_state != "REFUSED":
        errors.append("a refused action must have outcome.state=REFUSED")
    if action_state == "WITHHELD" and outcome_state != "WITHHELD":
        errors.append("a withheld action must have outcome.state=WITHHELD")
    if action_state == "EXECUTED" and outcome_state not in {
        "NOT_MEASURED",
        "SUCCEEDED",
        "FAILED",
    }:
        errors.append("an executed action has an incompatible outcome state")
    if action_state == "FAILED" and outcome_state != "FAILED":
        errors.append("a failed action must have outcome.state=FAILED")

    rollback = value.get("rollback")
    if _exact_keys(rollback, ROLLBACK_KEYS, "rollback", errors):
        assert isinstance(rollback, dict)
        available = rollback.get("available")
        rollback_state = rollback.get("state")
        rollback_executed_at = parse_timestamp(rollback.get("executed_at"))
        if not isinstance(available, bool):
            errors.append("rollback.available must be a boolean")
        if rollback_state not in ROLLBACK_STATES:
            errors.append("rollback.state is invalid")
        if available is True and not _valid_hex64(rollback.get("plan_sha3_256")):
            errors.append("rollback.plan_sha3_256 is required when rollback is available")
        if available is False and rollback.get("plan_sha3_256") is not None:
            errors.append("rollback.plan_sha3_256 must be null when unavailable")
        if rollback_state in {"EXECUTED", "FAILED"}:
            if rollback_executed_at is None:
                errors.append("rollback.executed_at is required after rollback execution")
            elif recorded_at is not None and rollback_executed_at > recorded_at:
                errors.append("rollback.executed_at cannot be after passport.recorded_at")
        elif rollback.get("executed_at") is not None:
            errors.append("rollback.executed_at must be null unless rollback ran")

    signature = value.get("signature")
    if _exact_keys(signature, SIGNATURE_KEYS, "signature", errors):
        assert isinstance(signature, dict)
        signature_state = signature.get("state")
        if signature_state not in SIGNATURE_STATES:
            errors.append("signature.state is invalid")
        if signature.get("algorithm") != "ECDSA-P256":
            errors.append("signature.algorithm must be ECDSA-P256")
        if signature.get("digest_algorithm") != "SHA3-256":
            errors.append("signature.digest_algorithm must be SHA3-256")
        expected_payload_digest = expected_signature_payload_digest(value)
        if signature.get("payload_sha3_256") != expected_payload_digest:
            errors.append("signature.payload_sha3_256 does not bind the passport payload")
        signed_fields = (
            "key_id",
            "signature_b64",
            "dsse_envelope_sha256",
        )
        if signature_state == "UNSIGNED":
            if any(signature.get(field) is not None for field in signed_fields):
                errors.append("UNSIGNED passports cannot contain signing material")
            if signature.get("w3c_vc_sha256") is not None:
                errors.append("UNSIGNED passports cannot claim a signed W3C VC")
        elif signature_state == "SIGNED_UNVERIFIED":
            if not _valid_identifier(signature.get("key_id")):
                errors.append("signature.key_id is required when signed")
            signature_b64 = signature.get("signature_b64")
            if not isinstance(signature_b64, str) or not signature_b64:
                errors.append("signature.signature_b64 is required when signed")
            else:
                try:
                    decoded = base64.b64decode(signature_b64, validate=True)
                except (ValueError, TypeError):
                    decoded = b""
                if not decoded:
                    errors.append("signature.signature_b64 is invalid")
            if not _valid_hex64(signature.get("dsse_envelope_sha256")):
                errors.append("signature.dsse_envelope_sha256 is required when signed")
            if not _valid_optional_hex64(signature.get("w3c_vc_sha256")):
                errors.append("signature.w3c_vc_sha256 is invalid")

    return errors


def project_unsigned_interop(passport: dict[str, Any]) -> dict[str, Any]:
    """Emit unsigned DSSE and W3C VC projections without claiming verification."""

    errors = validate_passport(passport)
    if errors:
        raise ValueError("invalid passport: " + "; ".join(errors))
    payload_bytes = canonical_json_bytes(passport_signing_payload(passport))
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    identity = passport["identity"]
    action = passport["action"]
    outcome = passport["outcome"]
    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": [
            "VerifiableCredential",
            "CounterfactualActionPassportCredential",
        ],
        "issuer": f"urn:szl:principal:{identity['principal_id']}",
        "validFrom": passport["recorded_at"],
        "credentialSubject": {
            "id": f"urn:szl:passport:{passport['passport_id']}",
            "agentId": identity["agent_id"],
            "policyDecision": passport["policy_decision"],
            "actionId": action["action_id"],
            "actionState": action["state"],
            "outcomeState": outcome["state"],
            "payloadSha3_256": passport["signature"]["payload_sha3_256"],
        },
    }
    return {
        "state": "UNSIGNED_PROJECTION",
        "dsse": {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": payload_b64,
            "signatures": [],
        },
        "w3c_vc": vc,
        "limitations": [
            "No ECDSA signature was created or verified.",
            "The W3C VC projection has no proof and is not a verifiable credential yet.",
        ],
    }
