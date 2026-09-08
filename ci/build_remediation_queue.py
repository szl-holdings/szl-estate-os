#!/usr/bin/env python3
"""Compile readiness findings into a deterministic, non-authoritative work queue."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from typing import Any


READINESS_SCHEMA = "szl.estate-readiness-report/v1"
MANIFEST_SCHEMA = "szl.estate-critical-surface/v1"
QUEUE_SCHEMA = "szl.estate-remediation-queue/v1"
CHECK_STATES = {"PASS", "FAIL", "WARN", "UNAVAILABLE"}
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+%=-]{0,511}")
HTTP_HEADER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
KNOWN_SECURITY_HEADERS = {
    "content-security-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
}


class ContractError(ValueError):
    """Raised when an input cannot be trusted as a readiness contract."""


def read_json_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path}: top-level JSON must be an object")
    return value, raw


def sanitize_detail(value: Any) -> str:
    detail = str(value or "")
    replacements = (
        (
            r"(?is)-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
        ),
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@/\s]+@",
            r"\1[REDACTED]@",
        ),
        (r"(?i)\b(set-cookie|cookie)\s*[:=]\s*[^\r\n]+", r"\1=[REDACTED]"),
        (
            r"(?i)([\"']?(?:authorization|proxy[-_]?authorization|access[-_]?token|"
            r"refresh[-_]?token|client[-_]?secret|private[-_]?key|api[-_]?key|"
            r"aws[-_]?secret[-_]?access[-_]?key|aws[-_]?access[-_]?key[-_]?id|"
            r"aws[-_]?session[-_]?token|database[-_]?url|connection[-_]?string|"
            r"postgres[-_]?url|mysql[-_]?url|redis[-_]?url|"
            r"password|passwd|passphrase|secret|token|session(?:id)?)[\"']?"
            r"\s*[:=]\s*)"
            r"(?:[\"'][^\"']*[\"']|(?:Basic|Bearer|Digest|Token)\s+[^\s,;]+|"
            r"[^\s,;&}\]]+)",
            r"\1[REDACTED]",
        ),
        (
            r"(?i)\b(Basic|Bearer|Digest|Token)\s+[A-Za-z0-9._~+/=-]+",
            r"\1 [REDACTED]",
        ),
        (
            r"\b(?:github_pat_|gh[oprsu]_|hf_|xox[baprs]-|sk_(?:live|test)_|"
            r"AIza)[A-Za-z0-9_=-]{8,}",
            "[REDACTED]",
        ),
        (
            r"\b(?:A3T|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)"
            r"[A-Z0-9]{16}\b",
            "[REDACTED]",
        ),
    )
    for pattern, replacement in replacements:
        detail = re.sub(pattern, replacement, detail)
    return detail.replace("\r", " ").replace("\n", " ").strip()


def validate_identifier(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise ContractError(f"{label} must be a safe nonempty identifier")
    if sanitize_detail(value) != value:
        raise ContractError(f"{label} contains credential-like material")
    return value


def validate_readiness(readiness: dict[str, Any]) -> list[dict[str, str]]:
    if readiness.get("schema") != READINESS_SCHEMA:
        raise ContractError(f"readiness schema must be {READINESS_SCHEMA}")
    profile = readiness.get("profile")
    if profile not in {"baseline", "production"}:
        raise ContractError("readiness profile must be baseline or production")
    raw_checks = readiness.get("checks")
    if not isinstance(raw_checks, list):
        raise ContractError("readiness checks must be a list")

    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_checks):
        if not isinstance(item, dict):
            raise ContractError(f"readiness check {index} must be an object")
        check_id = item.get("id")
        state = item.get("state")
        detail = item.get("detail")
        check_id = validate_identifier(check_id, f"readiness check {index} identifier")
        assert check_id is not None
        if check_id in seen:
            raise ContractError(f"duplicate readiness check: {check_id}")
        if state not in CHECK_STATES:
            raise ContractError(f"readiness check {check_id} has invalid state={state!r}")
        if not isinstance(detail, str):
            raise ContractError(f"readiness check {check_id} detail must be a string")
        seen.add(check_id)
        checks.append({"id": check_id, "state": state, "detail": detail})

    failures = sum(item["state"] == "FAIL" for item in checks)
    warnings = sum(item["state"] in {"WARN", "UNAVAILABLE"} for item in checks)
    if readiness.get("failure_count") != failures:
        raise ContractError(
            f"failure_count={readiness.get('failure_count')!r} does not match observed={failures}"
        )
    if readiness.get("warning_count") != warnings:
        raise ContractError(
            f"warning_count={readiness.get('warning_count')!r} does not match observed={warnings}"
        )
    expected_status = "PASS" if failures == 0 else "FAIL"
    if readiness.get("status") != expected_status:
        raise ContractError(
            f"readiness status={readiness.get('status')!r} does not match expected={expected_status}"
        )
    validate_identifier(readiness.get("audit_id"), "readiness audit_id", allow_none=True)
    return checks


def validate_manifest(
    manifest: dict[str, Any],
) -> tuple[dict[str, str | None], frozenset[str]]:
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ContractError(f"manifest schema must be {MANIFEST_SCHEMA}")
    mappings = manifest.get("production_deployment_sources")
    if not isinstance(mappings, dict):
        raise ContractError("manifest production_deployment_sources must be an object")
    normalized: dict[str, str | None] = {}
    for target, source in mappings.items():
        safe_target = validate_identifier(target, "deployment source target")
        assert safe_target is not None
        safe_source = validate_identifier(
            source,
            f"deployment source for {safe_target}",
            allow_none=True,
        )
        normalized[safe_target] = safe_source
    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict):
        raise ContractError("manifest baseline must be an object")
    raw_headers = baseline.get("required_security_headers")
    if not isinstance(raw_headers, list) or not raw_headers:
        raise ContractError("manifest required_security_headers must be a nonempty list")
    required_headers: set[str] = set()
    for index, header in enumerate(raw_headers):
        if not isinstance(header, str):
            raise ContractError(f"required security header {index} must be a string")
        normalized_header = header.lower()
        if (
            not HTTP_HEADER_NAME.fullmatch(normalized_header)
            or normalized_header not in KNOWN_SECURITY_HEADERS
            or sanitize_detail(normalized_header) != normalized_header
        ):
            raise ContractError(f"required security header {index} is not allowlisted")
        if normalized_header in required_headers:
            raise ContractError(f"duplicate required security header: {normalized_header}")
        required_headers.add(normalized_header)
    return normalized, frozenset(required_headers)


def target_from_check(check_id: str) -> str | None:
    prefixes = (
        "headers.",
        "schema.asset.",
        "asset.",
        "alignment.",
        "freshness.asset.",
    )
    for prefix in prefixes:
        if check_id.startswith(prefix):
            return check_id[len(prefix) :]
    return None


def missing_headers(detail: str, *, allowed: frozenset[str]) -> list[str]:
    match = re.search(r"(?:^|\s)missing=([^;\s]+)", detail)
    if match is None:
        return []
    headers: set[str] = set()
    for item in match.group(1).split(","):
        header = item.strip().lower()
        if not header:
            continue
        if (
            not HTTP_HEADER_NAME.fullmatch(header)
            or header not in allowed
            or sanitize_detail(header) != header
        ):
            raise ContractError("readiness missing-header detail contains a non-allowlisted value")
        headers.add(header)
    return sorted(headers)


def classify(check_id: str, target: str | None, detail: str) -> tuple[str, str, str]:
    if check_id.startswith("headers."):
        return "provider", "APPLY_EDGE_RESPONSE_HEADERS", "EXTERNAL_ACTION_REQUIRED"
    if check_id.startswith("alignment."):
        return "provider", "RECONCILE_RUNTIME_SOURCE_BINDING", "EXTERNAL_ACTION_REQUIRED"
    if check_id == "production.requirement.authenticated_inventory":
        return "inventory", "COLLECT_AUTHENTICATED_INVENTORY", "MEASURED_READBACK_REQUIRED"
    if check_id == "production.requirement.critical_huggingface_alignment":
        return "provider", "RECONCILE_RUNTIME_SOURCE_BINDING", "EXTERNAL_ACTION_REQUIRED"
    if check_id.startswith(("source.", "scope.", "freshness.source.")):
        action = (
            "COLLECT_AUTHENTICATED_INVENTORY"
            if check_id in {"source.github", "source.huggingface", "scope.github", "scope.huggingface"}
            else "RECONCILE_INVENTORY_SOURCE"
        )
        return "inventory", action, "MEASURED_READBACK_REQUIRED"
    if (
        target
        and target.startswith("github:repo:")
        and "authenticated evidence is outside the public baseline" in detail.lower()
    ):
        return (
            "inventory",
            "COLLECT_AUTHENTICATED_INVENTORY",
            "MEASURED_READBACK_REQUIRED",
        )
    if target and target.startswith("github:repo:"):
        return "source", "REPAIR_SOURCE_CONTRACT", "SOURCE_CHANGE_REQUIRED"
    if check_id.startswith(("evidence.", "production.requirement.independent_")):
        return "evidence", "PRODUCE_INDEPENDENT_EVIDENCE", "INDEPENDENT_EVIDENCE_REQUIRED"
    if check_id.startswith(("audit.", "manifest.", "assets.", "schema.")):
        return "evidence", "REPAIR_EVIDENCE_CONTRACT", "EVIDENCE_CONTRACT_REQUIRED"
    if check_id.startswith(("freshness.", "production.", "gaps.")):
        return "evidence", "REFRESH_OR_COMPLETE_EVIDENCE", "INDEPENDENT_EVIDENCE_REQUIRED"
    if target and target.startswith(("domain:route:", "huggingface:space:")):
        return "provider", "RECONCILE_PROVIDER_TARGET", "EXTERNAL_ACTION_REQUIRED"
    return "evidence", "INVESTIGATE_UNCLASSIFIED_FINDING", "HUMAN_TRIAGE_REQUIRED"


def stable_id(
    *, check_id: str, plane: str, action: str, target: str | None, source: str | None
) -> str:
    identity = json.dumps(
        {
            "action": action,
            "check_id": check_id,
            "control_plane": plane,
            "source": source,
            "target": target,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"rem-{hashlib.sha256(identity).hexdigest()[:16]}"


def build_queue(
    readiness: dict[str, Any],
    manifest: dict[str, Any],
    *,
    readiness_sha256: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", readiness_sha256):
        raise ContractError("readiness_sha256 must be a lowercase SHA-256 digest")
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ContractError("manifest_sha256 must be a lowercase SHA-256 digest")
    checks = validate_readiness(readiness)
    deployment_sources, allowed_headers = validate_manifest(manifest)
    actions: list[dict[str, Any]] = []

    for check in checks:
        if check["state"] == "PASS":
            continue
        check_id = check["id"]
        target = target_from_check(check_id)
        source = deployment_sources.get(target) if target else None
        sanitized_detail = sanitize_detail(check["detail"])
        plane, action, authority = classify(check_id, target, sanitized_detail)
        headers = (
            missing_headers(sanitized_detail, allowed=allowed_headers)
            if action == "APPLY_EDGE_RESPONSE_HEADERS"
            else []
        )
        actions.append(
            {
                "id": stable_id(
                    check_id=check_id,
                    plane=plane,
                    action=action,
                    target=target,
                    source=source,
                ),
                "state": "BLOCKED" if check["state"] == "FAIL" else "PLANNED",
                "priority": "P1" if check["state"] == "FAIL" else "P2",
                "control_plane": plane,
                "check_id": check_id,
                "check_state": check["state"],
                "action": action,
                "authority": authority,
                "target": target,
                "source_repository": source,
                "required_headers": headers,
                "detail": sanitized_detail,
            }
        )

    actions.sort(key=lambda item: (item["priority"], item["control_plane"], item["check_id"]))
    failures = sum(item["check_state"] == "FAIL" for item in actions)
    warnings = sum(item["check_state"] in {"WARN", "UNAVAILABLE"} for item in actions)
    status = "BLOCKED" if failures else ("ACTION_REQUIRED" if actions else "CLEAR")
    return {
        "schema": QUEUE_SCHEMA,
        "status": status,
        "profile": readiness["profile"],
        "audit_id": readiness.get("audit_id"),
        "readiness_status": readiness["status"],
        "readiness_sha256": readiness_sha256,
        "manifest_sha256": manifest_sha256,
        "summary": {
            "action_count": len(actions),
            "blocked_count": failures,
            "warning_count": warnings,
            "provider_count": sum(item["control_plane"] == "provider" for item in actions),
            "source_count": sum(item["control_plane"] == "source" for item in actions),
            "inventory_count": sum(item["control_plane"] == "inventory" for item in actions),
            "evidence_count": sum(item["control_plane"] == "evidence" for item in actions),
        },
        "actions": actions,
    }


def markdown(queue: dict[str, Any]) -> str:
    summary = queue["summary"]
    lines = [
        "# Estate remediation queue",
        "",
        f"- Status: `{queue['status']}`",
        f"- Readiness: `{queue['readiness_status']}`",
        f"- Readiness SHA-256: `{queue['readiness_sha256']}`",
        f"- Manifest SHA-256: `{queue['manifest_sha256']}`",
        f"- Actions: `{summary['action_count']}` (`{summary['blocked_count']}` blocked)",
        "",
        "This queue is diagnostic evidence. It grants no source, provider, or deployment authority.",
        "",
        "| Priority | State | Plane | Check | Action | Target | Authority | Detail |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in queue["actions"]:
        values = [
            item["priority"],
            item["state"],
            item["control_plane"],
            item["check_id"],
            item["action"],
            item["target"] or "UNAVAILABLE",
            item["authority"],
            item["detail"],
        ]
        escaped = [
            html.escape(str(value), quote=False)
            .replace("|", "\\|")
            .replace("\r", " ")
            .replace("\n", " ")
            for value in values
        ]
        lines.append("| " + " | ".join(f"`{value}`" if index < 7 else value for index, value in enumerate(escaped)) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-markdown", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        readiness, readiness_bytes = read_json_bytes(args.readiness)
        manifest, manifest_bytes = read_json_bytes(args.manifest)
        queue = build_queue(
            readiness,
            manifest,
            readiness_sha256=hashlib.sha256(readiness_bytes).hexdigest(),
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )
    except (OSError, ContractError) as exc:
        print(f"remediation queue refused: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(queue, indent=2, sort_keys=True) + "\n"
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(rendered, encoding="utf-8")
    args.output_markdown.write_text(markdown(queue), encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
