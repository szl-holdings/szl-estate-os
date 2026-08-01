#!/usr/bin/env python3
"""Verify an Estate OS audit against the canonical critical-surface contract."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any


ALIGNMENT_READY = {"EXACT_HEAD", "EXACT_RUNTIME_HEAD"}
BASELINE_SIGNATURE_STATES = {
    "HMAC_SHA256": "PASS",
    "UNSIGNED": "WARN",
}
PRODUCTION_COMPLETE_SCOPES = {"AUTHENTICATED_COMPLETE"}
PRODUCTION_SIGNATURE_ALGORITHM = "RSA_PKCS1_V1_5_SHA256"
RSA_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40,64}")
KNOWN_PRODUCTION_REQUIREMENTS = {
    "authenticated_inventory",
    "critical_huggingface_alignment",
    "independent_asymmetric_evidence",
    "credential_backed_deployment_witness",
    "browser_e2e_and_accessibility",
    "restore_and_failure_domain_drill",
    "zero_active_critical_gaps",
}
MAX_PRODUCTION_ARTIFACT_BYTES = 5_000_000
PRODUCTION_ARTIFACT_SCHEMAS = {
    "credential_backed_deployment_witness": "szl.estate-deployment-witness/v1",
    "browser_e2e_and_accessibility": "szl.estate-browser-evidence/v1",
    "restore_and_failure_domain_drill": "szl.estate-restore-drill/v1",
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def result(check_id: str, state: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "state": state, "detail": detail}


def alignment_state(asset: dict[str, Any]) -> str:
    alignment = (asset.get("metadata") or {}).get("github_alignment") or {}
    if isinstance(alignment, dict):
        return str(alignment.get("status") or "UNAVAILABLE")
    return "UNAVAILABLE"


def signature_state(signature_status: str, profile: str) -> str:
    """Classify only signature states defined by the readiness contract."""
    if profile == "baseline":
        return BASELINE_SIGNATURE_STATES.get(signature_status, "FAIL")
    # Production never trusts a status label. verify_independent_signature validates
    # the signature bytes against a protected manifest-pinned public key.
    return "FAIL"


def canonical_audit_payload(audit: dict[str, Any]) -> bytes:
    """Return the exact JSON payload covered by the detached signature."""
    payload = json.loads(json.dumps(audit))
    receipt = payload.get("receipt")
    if isinstance(receipt, dict):
        receipt.pop("asymmetric_signature", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_independent_signature(
    audit: dict[str, Any], manifest: dict[str, Any]
) -> tuple[str, str]:
    receipt = audit.get("receipt") or {}
    signature = receipt.get("asymmetric_signature") or {}
    if not isinstance(signature, dict):
        return "FAIL", "detached asymmetric signature missing"
    key_id = str(signature.get("key_id") or "")
    algorithm = str(signature.get("algorithm") or "")
    encoded = str(signature.get("signature_base64") or "")
    keys = manifest.get("production_trusted_keys") or {}
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, dict):
        return "FAIL", f"trusted key unavailable key_id={key_id or 'UNAVAILABLE'}"
    if algorithm != PRODUCTION_SIGNATURE_ALGORITHM:
        return "FAIL", f"unsupported signature algorithm={algorithm or 'UNAVAILABLE'}"
    if str(key.get("algorithm") or "") != algorithm:
        return "FAIL", "signature and trusted-key algorithms differ"
    try:
        modulus = int(str(key["modulus_hex"]), 16)
        exponent = int(key["exponent"])
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        return "FAIL", "trusted key or signature encoding is invalid"
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
        return "FAIL", "trusted RSA key does not meet the production floor"
    width = (modulus.bit_length() + 7) // 8
    if len(signature_bytes) != width:
        return "FAIL", "signature width does not match trusted RSA modulus"
    payload = canonical_audit_payload(audit)
    digest_info = RSA_SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    padding_length = width - len(digest_info) - 3
    if padding_length < 8:
        return "FAIL", "trusted RSA key is too short for SHA-256"
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    observed = pow(int.from_bytes(signature_bytes, "big"), exponent, modulus).to_bytes(
        width, "big"
    )
    if not hmac.compare_digest(observed, expected):
        return "FAIL", f"signature verification failed key_id={key_id}"
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    return "PASS", f"verified key_id={key_id} payload_sha256={payload_sha256}"


def production_artifact_state(
    audit: dict[str, Any],
    manifest: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    requirement: str,
    evidence_root: Path | None,
) -> tuple[str, str]:
    evidence = audit.get("production_evidence") or {}
    record = evidence.get(requirement) if isinstance(evidence, dict) else None
    if not isinstance(record, dict):
        return "FAIL", "production evidence reference missing"
    digest = str(record.get("artifact_sha256") or "")
    if SHA256_PATTERN.fullmatch(digest) is None:
        return "FAIL", "artifact_sha256 is missing or invalid"
    relative = Path(str(record.get("artifact_path") or ""))
    if evidence_root is None or not relative.parts or relative.is_absolute():
        return "FAIL", "artifact_path must be relative to the audit directory"
    root = evidence_root.resolve()
    artifact_path = (root / relative).resolve()
    try:
        artifact_path.relative_to(root)
    except ValueError:
        return "FAIL", "artifact_path escapes the audit directory"
    try:
        size = artifact_path.stat().st_size
        if size > MAX_PRODUCTION_ARTIFACT_BYTES:
            return "FAIL", f"artifact exceeds byte limit size={size}"
        artifact_bytes = artifact_path.read_bytes()
    except OSError as exc:
        return "FAIL", f"artifact unavailable error={type(exc).__name__}"
    observed_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if not hmac.compare_digest(observed_digest, digest):
        return "FAIL", f"artifact digest mismatch observed={observed_digest}"
    try:
        artifact = json.loads(artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "FAIL", "artifact is not valid UTF-8 JSON"
    if not isinstance(artifact, dict):
        return "FAIL", "artifact must be a JSON object"
    expected_schema = PRODUCTION_ARTIFACT_SCHEMAS[requirement]
    if artifact.get("schema") != expected_schema or artifact.get("status") != "VERIFIED":
        return "FAIL", f"artifact schema/status invalid expected={expected_schema}"
    if requirement == "credential_backed_deployment_witness":
        required_witness_keys = {
            "schema",
            "status",
            "repository_asset_id",
            "deployment_asset_id",
            "deployment_revision",
            "deployed_artifact_sha256",
            "environment",
            "deployment_url",
            "owner",
            "credential_scope",
            "deployment_receipt",
        }
        if set(artifact) != required_witness_keys:
            missing = sorted(required_witness_keys - set(artifact))
            extra = sorted(set(artifact) - required_witness_keys)
            return "FAIL", f"deployment witness shape invalid missing={missing} extra={extra}"
        revision = str(artifact.get("deployment_revision") or "")
        scope = str(artifact.get("credential_scope") or "")
        if scope != "DEPLOYMENT_READ_ONLY":
            return "FAIL", f"credential_scope={scope or 'UNAVAILABLE'}"
        repository_asset_id = str(artifact.get("repository_asset_id") or "")
        deployment_asset_id = str(artifact.get("deployment_asset_id") or "")
        repository_asset = assets.get(repository_asset_id)
        deployment_asset = assets.get(deployment_asset_id)
        if not isinstance(repository_asset, dict):
            return "FAIL", "repository_asset_id is not present in the audited inventory"
        if (
            repository_asset.get("source") != "github"
            or repository_asset.get("asset_type") != "repo"
            or repository_asset.get("status_label") in {"ARCHIVED", "BROKEN"}
        ):
            return "FAIL", "repository_asset_id is not an active audited GitHub repository"
        if not isinstance(deployment_asset, dict):
            return "FAIL", "deployment_asset_id is not present in the audited inventory"
        if deployment_asset.get("status_label") != "LIVE":
            return "FAIL", "deployment_asset_id is not an audited LIVE deployment"
        repository_metadata = repository_asset.get("metadata")
        deployment_metadata = deployment_asset.get("metadata")
        if not isinstance(repository_metadata, dict) or not isinstance(
            deployment_metadata, dict
        ):
            return "FAIL", "audited deployment metadata is missing or invalid"
        repository_revision = str(repository_metadata.get("default_branch_sha") or "")
        if not hmac.compare_digest(repository_revision, revision):
            return "FAIL", "deployment revision does not match the audited repository head"
        owner = str(artifact.get("owner") or "")
        canonical = manifest.get("canonical_identities") or {}
        if not isinstance(canonical, dict):
            return "FAIL", "canonical identity contract is missing or invalid"
        github_owner = str(canonical.get("github_organization") or "")
        expected_repository_prefix = f"github:repo:{github_owner.lower()}/"
        if owner != github_owner or not repository_asset_id.startswith(
            expected_repository_prefix
        ):
            return "FAIL", "deployment owner is not bound to the canonical repository owner"
        deployment_url = str(artifact.get("deployment_url") or "")
        parsed_url = urllib.parse.urlparse(deployment_url)
        audited_urls = {
            str(value)
            for value in (
                deployment_asset.get("url"),
                deployment_metadata.get("final_url"),
            )
            if value
        }
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or deployment_url not in audited_urls
        ):
            return "FAIL", "deployment URL does not match the audited HTTPS deployment"
        environment = str(artifact.get("environment") or "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", environment) is None:
            return "FAIL", "deployment environment is missing or invalid"
        deployed_artifact_sha256 = str(
            artifact.get("deployed_artifact_sha256") or ""
        )
        if SHA256_PATTERN.fullmatch(deployed_artifact_sha256) is None:
            return "FAIL", "deployed artifact digest is missing or invalid"
        receipt = artifact.get("deployment_receipt")
        required_receipt_keys = {
            "schema",
            "status",
            "repository_asset_id",
            "deployment_asset_id",
            "deployment_revision",
            "deployed_artifact_sha256",
            "environment",
            "deployment_url",
            "owner",
        }
        if not isinstance(receipt, dict) or set(receipt) != required_receipt_keys:
            return "FAIL", "deployment receipt shape is invalid"
        if receipt.get("schema") != "szl.deployment-receipt/v1":
            return "FAIL", "deployment receipt schema is invalid"
        if receipt.get("status") != "VERIFIED":
            return "FAIL", "deployment receipt status is not VERIFIED"
        bindings = {
            "repository_asset_id": repository_asset_id,
            "deployment_asset_id": deployment_asset_id,
            "deployment_revision": revision,
            "deployed_artifact_sha256": deployed_artifact_sha256,
            "environment": environment,
            "deployment_url": deployment_url,
            "owner": owner,
        }
        mismatches = sorted(
            field for field, expected in bindings.items() if receipt.get(field) != expected
        )
        if mismatches:
            return "FAIL", f"deployment receipt binding mismatch={','.join(mismatches)}"
    elif requirement == "browser_e2e_and_accessibility":
        checks = artifact.get("checks") or {}
        required = {"browser_e2e", "keyboard", "mobile", "accessibility"}
        missing = sorted(name for name in required if checks.get(name) != "PASS")
        if missing:
            return "FAIL", f"required checks not passing={','.join(missing)}"
    elif requirement == "restore_and_failure_domain_drill":
        if artifact.get("restore_status") != "PASS":
            return "FAIL", "restore drill did not pass"
        if artifact.get("failure_domain_status") != "PASS":
            return "FAIL", "failure-domain drill did not pass"
    return "PASS", f"verified path={relative.as_posix()} artifact_sha256={digest}"


def verify(
    audit: dict[str, Any],
    manifest: dict[str, Any],
    profile: str,
    *,
    evidence_root: Path | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    assets = {
        str(item.get("asset_id")): item
        for item in audit.get("assets") or []
        if isinstance(item, dict) and item.get("asset_id")
    }
    source_reports = {
        str(item.get("source")): item
        for item in audit.get("source_reports") or []
        if isinstance(item, dict) and item.get("source")
    }
    baseline = manifest.get("baseline") or {}

    for source, minimum in (baseline.get("source_minimums") or {}).items():
        report = source_reports.get(source)
        if report is None:
            checks.append(result(f"source.{source}", "FAIL", "Source report missing"))
            continue
        status = str(report.get("status") or "UNAVAILABLE")
        count = int(report.get("count") or 0)
        observed_count = sum(
            1 for item in assets.values() if str(item.get("source") or "") == source
        )
        required = str(baseline.get("required_source_status") or "MEASURED")
        state = (
            "PASS"
            if status == required
            and count == observed_count
            and observed_count >= int(minimum)
            else "FAIL"
        )
        checks.append(
            result(
                f"source.{source}",
                state,
                f"status={status} reported_count={count} observed_count={observed_count} "
                f"required_status={required} minimum={minimum}",
            )
        )

    prohibited = set(baseline.get("prohibited_status_labels") or [])
    prohibited_assets = [
        item
        for item in assets.values()
        if str(item.get("status_label") or "UNAVAILABLE") in prohibited
    ]
    checks.append(
        result(
            "assets.prohibited_status",
            "PASS" if not prohibited_assets else "FAIL",
            "none observed"
            if not prohibited_assets
            else ", ".join(str(item.get("asset_id")) for item in prohibited_assets[:20]),
        )
    )

    critical_assets = manifest.get("critical_assets") or []
    for contract in critical_assets:
        if not isinstance(contract, dict) or not contract.get("asset_id"):
            continue
        asset_id = str(contract["asset_id"])
        public = bool(contract.get("public"))
        asset = assets.get(asset_id)
        if not public and profile == "baseline":
            checks.append(
                result(
                    f"asset.{asset_id}",
                    "UNAVAILABLE",
                    "Authenticated evidence is outside the public baseline",
                )
            )
            continue
        if asset is None:
            checks.append(result(f"asset.{asset_id}", "FAIL", "Critical asset missing"))
            continue
        observed = str(asset.get("status_label") or "UNAVAILABLE")
        required_status = contract.get("required_status")
        if required_status:
            state = "PASS" if observed == required_status else "FAIL"
            detail = f"status={observed} required={required_status}"
        else:
            state = "PASS" if observed not in {"BROKEN", "ARCHIVED"} else "FAIL"
            detail = f"status={observed}"
        checks.append(result(f"asset.{asset_id}", state, detail))

        if asset_id.startswith("domain:route:"):
            headers = (asset.get("metadata") or {}).get("security_headers") or {}
            missing = [
                header
                for header in baseline.get("required_security_headers") or []
                if not headers.get(header)
            ]
            checks.append(
                result(
                    f"headers.{asset_id}",
                    "PASS" if not missing else "FAIL",
                    "all required headers observed"
                    if not missing
                    else f"missing={','.join(missing)}",
                )
            )

        if profile == "production" and asset_id.startswith("huggingface:space:"):
            alignment = alignment_state(asset)
            checks.append(
                result(
                    f"alignment.{asset_id}",
                    "PASS" if alignment in ALIGNMENT_READY else "FAIL",
                    f"alignment={alignment}",
                )
            )

    receipt = audit.get("receipt") or {}
    signature_status = str(receipt.get("signature_status") or "UNAVAILABLE")
    signature_verification = (
        verify_independent_signature(audit, manifest)
        if profile == "production"
        else (
            signature_state(signature_status, profile),
            f"receipt_signature={signature_status}",
        )
    )
    checks.append(
        result(
            "evidence.independent_signature",
            signature_verification[0],
            signature_verification[1],
        )
    )

    if profile == "production":
        production_requirements = manifest.get("production_requirements") or {}
        if not isinstance(production_requirements, dict):
            production_requirements = {}
        for source in ("github", "huggingface"):
            scope = str((source_reports.get(source) or {}).get("scope") or "UNAVAILABLE")
            checks.append(
                result(
                    f"scope.{source}",
                    "PASS" if scope in PRODUCTION_COMPLETE_SCOPES else "FAIL",
                    f"scope={scope} required={','.join(sorted(PRODUCTION_COMPLETE_SCOPES))}",
                )
            )
        active_gaps = [
            gap
            for gap in manifest.get("known_gaps") or []
            if isinstance(gap, dict)
            and gap.get("status") == "ACTIVE"
            and gap.get("severity") in {"P0", "P1"}
        ]
        checks.append(
            result(
                "gaps.critical",
                "PASS" if not active_gaps else "FAIL",
                "none active"
                if not active_gaps
                else ", ".join(str(gap.get("id")) for gap in active_gaps),
            )
        )

        for requirement, configured in production_requirements.items():
            enabled = configured is True or (
                isinstance(configured, list) and bool(configured)
            )
            if not enabled:
                continue
            check_id = f"production.requirement.{requirement}"
            if requirement not in KNOWN_PRODUCTION_REQUIREMENTS:
                checks.append(result(check_id, "FAIL", "unknown enabled requirement"))
                continue
            if requirement == "authenticated_inventory":
                incomplete = [
                    source
                    for source in ("github", "huggingface")
                    if str((source_reports.get(source) or {}).get("scope") or "")
                    not in PRODUCTION_COMPLETE_SCOPES
                ]
                checks.append(
                    result(
                        check_id,
                        "PASS" if not incomplete else "FAIL",
                        "complete authenticated inventory"
                        if not incomplete
                        else f"incomplete={','.join(incomplete)}",
                    )
                )
            elif requirement == "critical_huggingface_alignment":
                allowed = {str(value) for value in configured}
                failed = []
                for contract in critical_assets:
                    if not isinstance(contract, dict):
                        continue
                    asset_id = str(contract.get("asset_id") or "")
                    if not asset_id.startswith("huggingface:space:"):
                        continue
                    asset = assets.get(asset_id)
                    if asset is None or alignment_state(asset) not in allowed:
                        failed.append(asset_id)
                checks.append(
                    result(
                        check_id,
                        "PASS" if not failed else "FAIL",
                        "all critical Hugging Face alignments verified"
                        if not failed
                        else f"failed={','.join(failed)}",
                    )
                )
            elif requirement == "independent_asymmetric_evidence":
                checks.append(result(check_id, *signature_verification))
            elif requirement in {
                "credential_backed_deployment_witness",
                "browser_e2e_and_accessibility",
                "restore_and_failure_domain_drill",
            }:
                artifact_state, artifact_detail = production_artifact_state(
                    audit, manifest, assets, requirement, evidence_root
                )
                if signature_verification[0] != "PASS":
                    artifact_state = "FAIL"
                    artifact_detail += "; audit signature is not verified"
                checks.append(result(check_id, artifact_state, artifact_detail))
            elif requirement == "zero_active_critical_gaps":
                checks.append(
                    result(
                        check_id,
                        "PASS" if not active_gaps else "FAIL",
                        "none active"
                        if not active_gaps
                        else ", ".join(str(gap.get("id")) for gap in active_gaps),
                    )
                )

    failure_count = sum(item["state"] == "FAIL" for item in checks)
    warning_count = sum(item["state"] in {"WARN", "UNAVAILABLE"} for item in checks)
    return {
        "schema": "szl.estate-readiness-report/v1",
        "profile": profile,
        "status": "PASS" if failure_count == 0 else "FAIL",
        "audit_id": (audit.get("meta") or {}).get("audit_id"),
        "failure_count": failure_count,
        "warning_count": warning_count,
        "checks": checks,
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Estate readiness report",
        "",
        f"- Profile: `{report['profile']}`",
        f"- Status: `{report['status']}`",
        f"- Audit: `{report.get('audit_id') or 'UNAVAILABLE'}`",
        f"- Failures: `{report['failure_count']}`",
        f"- Warnings/unavailable: `{report['warning_count']}`",
        "",
        "| State | Check | Detail |",
        "|---|---|---|",
    ]
    for item in report["checks"]:
        detail = str(item["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{item['state']}` | `{item['id']}` | {detail} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profile", choices=("baseline", "production"), default="baseline")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    args = parser.parse_args()

    report = verify(
        read_json(args.audit),
        read_json(args.manifest),
        args.profile,
        evidence_root=args.audit.resolve().parent,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered, encoding="utf-8")
    if args.output_markdown:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(markdown(report), encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
