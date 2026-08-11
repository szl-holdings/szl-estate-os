#!/usr/bin/env python3
"""Verify Counterfactual Action Passports and emit bounded evidence artifacts.

The verifier is deterministic and dependency-free. It performs no network
requests, privileged mutations, key access, ECDSA signing, or signature
promotion. Signed inputs remain SIGNED_UNVERIFIED.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.action_assurance import (  # noqa: E402
    compute_trust_factors,
    evaluate_citation_ledger,
    load_json_documents,
    parse_timestamp,
    project_unsigned_interop,
    validate_passport,
)
from estate.action_assurance_contract import (  # noqa: E402
    reject_non_finite_json_constant,
)

REPORT_SCHEMA = "szl.action-assurance-verification/v1"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )


def _read_json_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=reject_non_finite_json_constant,
        )
    except FileNotFoundError:
        return None, f"file does not exist: {path}"
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return None, f"unreadable JSON path={path} error={type(exc).__name__}"
    if not isinstance(value, dict):
        return None, f"JSON root must be an object: {path}"
    return value, None


def _parse_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    parsed = parse_timestamp(value)
    if parsed is None:
        raise ValueError("--now must be a timezone-aware ISO-8601 timestamp")
    return parsed


def verify(
    *,
    passport_dir: Path,
    citation_ledger_path: Path,
    output_dir: Path,
    now: datetime,
) -> tuple[dict[str, Any], int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    interop_dir = output_dir / "interop"
    if interop_dir.exists():
        shutil.rmtree(interop_dir)
    interop_dir.mkdir(parents=True, exist_ok=True)

    passports, load_errors = load_json_documents(passport_dir)
    passport_results: list[dict[str, Any]] = []
    valid_passports: list[dict[str, Any]] = []
    seen_passport_ids: set[str] = set()

    for index, passport in enumerate(passports):
        errors = validate_passport(passport)
        passport_id = passport.get("passport_id")
        if not errors:
            assert isinstance(passport_id, str)
            if passport_id in seen_passport_ids:
                errors.append(
                    f"passport.passport_id is duplicated across inputs: {passport_id}"
                )
            else:
                seen_passport_ids.add(passport_id)
        result = {
            "index": index,
            "passport_id": passport_id,
            "status": "PASS" if not errors else "FAIL",
            "errors": errors,
        }
        if not errors:
            valid_passports.append(passport)
            interop = project_unsigned_interop(passport)
            safe_id = str(passport_id).replace("/", "_").replace("\\", "_")
            interop_path = interop_dir / f"{safe_id}.json"
            _write_json(interop_path, interop)
            result["interop_artifact"] = interop_path.relative_to(output_dir).as_posix()
        passport_results.append(result)

    ledger, ledger_read_error = _read_json_object(citation_ledger_path)
    if ledger is None:
        citation_report: dict[str, Any] = {
            "status": "FAIL",
            "generated_at": now.isoformat(),
            "errors": [ledger_read_error],
            "entries": [],
            "counts": {},
        }
    else:
        citation_report = evaluate_citation_ledger(ledger, now=now)

    trust_report = compute_trust_factors(valid_passports, now=now)
    invalid_passport_count = sum(
        1 for result in passport_results if result["status"] != "PASS"
    )
    failures = list(load_errors)
    if invalid_passport_count:
        failures.append(f"invalid_passport_count={invalid_passport_count}")
    if citation_report.get("status") != "PASS":
        failures.append("citation_ledger_status=FAIL")
    if not valid_passports:
        failures.append("no valid passports were available")

    overall_status = "PASS" if not failures else "FAIL"
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": now.isoformat(),
        "status": overall_status,
        "inputs": {
            "passport_directory": str(passport_dir),
            "citation_ledger": str(citation_ledger_path),
        },
        "summary": {
            "loaded_passport_count": len(passports),
            "valid_passport_count": len(valid_passports),
            "invalid_passport_count": invalid_passport_count,
            "load_error_count": len(load_errors),
            "citation_status": citation_report.get("status"),
            "agent_count": len(trust_report.get("agents", {})),
        },
        "failures": failures,
        "passport_results": passport_results,
        "limitations": [
            "Validation proves contract consistency, not truth of external claims.",
            "No ECDSA signature is created or cryptographically verified.",
            "DSSE and W3C VC outputs are unsigned interoperability projections.",
            "Trust Factors are MODELED, non-authoritative, and never expand scope.",
        ],
    }

    _write_json(output_dir / "verification-report.json", report)
    _write_json(output_dir / "citation-drift-report.json", citation_report)
    _write_json(output_dir / "trust-factor-report.json", trust_report)
    return report, 0 if overall_status == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--passports",
        type=Path,
        default=ROOT / "fixtures" / "action_assurance" / "passports",
        help="Directory containing one passport JSON object per file.",
    )
    parser.add_argument(
        "--citations",
        type=Path,
        default=ROOT / "fixtures" / "action_assurance" / "citations.current.json",
        help="External claim ledger JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs" / "action-assurance",
        help="Directory for deterministic verification artifacts.",
    )
    parser.add_argument(
        "--now",
        help="Optional timezone-aware timestamp for deterministic drift checks.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        now = _parse_now(args.now)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    report, exit_code = verify(
        passport_dir=args.passports,
        citation_ledger_path=args.citations,
        output_dir=args.output_dir,
        now=now,
    )
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    print(f"Action assurance status: {report['status']}")
    print(f"Evidence directory: {args.output_dir}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
