#!/usr/bin/env python3
"""Verify an Estate OS audit against the canonical critical-surface contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ALIGNMENT_READY = {"EXACT_HEAD", "EXACT_RUNTIME_HEAD"}
BASELINE_SIGNATURE_STATES = {
    "HMAC_SHA256": "PASS",
    "UNSIGNED": "WARN",
}
PRODUCTION_SIGNATURE_STATES = {"ASYMMETRIC_VERIFIED"}


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
    return "PASS" if signature_status in PRODUCTION_SIGNATURE_STATES else "FAIL"


def verify(
    audit: dict[str, Any], manifest: dict[str, Any], profile: str
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
        required = str(baseline.get("required_source_status") or "MEASURED")
        state = "PASS" if status == required and count >= int(minimum) else "FAIL"
        checks.append(
            result(
                f"source.{source}",
                state,
                f"status={status} count={count} required_status={required} minimum={minimum}",
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
    checks.append(
        result(
            "evidence.independent_signature",
            signature_state(signature_status, profile),
            f"receipt_signature={signature_status}; asymmetric independent evidence is required for production",
        )
    )

    if profile == "production":
        for source in ("github", "huggingface"):
            scope = str((source_reports.get(source) or {}).get("scope") or "UNAVAILABLE")
            checks.append(
                result(
                    f"scope.{source}",
                    "FAIL" if scope == "PUBLIC_ONLY" or scope == "UNAVAILABLE" else "PASS",
                    f"scope={scope}",
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

    report = verify(read_json(args.audit), read_json(args.manifest), args.profile)
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
