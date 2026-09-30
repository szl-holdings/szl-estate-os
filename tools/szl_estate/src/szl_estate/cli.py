"""Local estate reports and an opt-in narrow Phase 0 setup acceptance gate."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Sequence

from .inputs import InventorySummary, load_backend_summary, load_hf_summary
from .model import (
    ClaimBasis, EvidenceCode, EvidenceFreshness, EvidenceRecord, EvidenceStatus,
    EstateState, EvidenceValidationError, ProofOrigin, Provenance,
    REQUIRED_ESTATE_SCOPES, utc_timestamp,
)
from .storage import StorageError, guard_output_alias, write_reports
from .setup import not_run_access, run_setup, write_setup_report

UNOBSERVED_TIME = "1970-01-01T00:00:00Z"


def build_state(
    summaries: Sequence[InventorySummary] = (), *, as_of: str | None = None
) -> EstateState:
    times = [utc_timestamp(item.observed_at_utc) for item in summaries if item.observed_at_utc]
    # A stable replay reference time; never an invented live observation.
    report_time = utc_timestamp(as_of) if as_of else max(
        times, key=lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")),
        default=UNOBSERVED_TIME,
    )
    records: list[EvidenceRecord] = []
    for index, scope in enumerate(REQUIRED_ESTATE_SCOPES):
        provenance = Provenance(
            source="offline-verifier", reference="fixture:no-live-observation",
            observed_at_utc=UNOBSERVED_TIME, scope=scope,
            digest=hashlib.sha256(b"NO_LIVE_OBSERVATION").hexdigest(),
            freshness=EvidenceFreshness.UNKNOWN, origin=ProofOrigin.UNKNOWN,
        )
        records.append(EvidenceRecord(
            evidence_id=f"unassessed-{index}", scope=scope,
            status=EvidenceStatus.NOT_RUN, provenance=provenance,
            code=EvidenceCode.OFFLINE_NOT_MEASURED,
        ))
    for index, summary in enumerate(summaries):
        github = summary.kind == "github_inventory"
        scope = "github:szl-holdings:historical" if github else "hf:SZLHOLDINGS:historical"
        expected_digest = (
            "f26d92aa8b7639d90c75c088c0974013bca0c3bc744c3a7ab073f6d20080b967"
            if github else "31d777345ac57b5eba1c78ce341c8cb513d2f8fdfe021482b6dc99ff82b43ded"
        )
        matches_supplied_receipt = summary.digest == expected_digest
        reference = (
            ("library:libfile_08cb638c15cc81918a4e80f484d3a47e/v2"
             if github else "library:libfile_28af9956bbdc8191baae24855c408d1a/v1")
            if matches_supplied_receipt else "file:supplied-summary"
        )
        provenance = Provenance(
            source="supplied-backend-bundle" if github else "supplied-hf-inventory",
            reference=reference, observed_at_utc=summary.observed_at_utc or UNOBSERVED_TIME,
            scope=scope, digest=summary.digest or hashlib.sha256(b"UNREADABLE_INPUT").hexdigest(),
            freshness=EvidenceFreshness.HISTORICAL,
            origin=ProofOrigin.LIBRARY if matches_supplied_receipt else ProofOrigin.UNKNOWN,
        )
        records.append(EvidenceRecord(
            evidence_id=f"historical-{index}", scope=scope,
            status=EvidenceStatus.FAIL if summary.error_code else EvidenceStatus.PARTIAL,
            provenance=provenance, claim_basis=ClaimBasis.FACT,
            code=EvidenceCode.INVALID_RESPONSE if summary.error_code else EvidenceCode.HISTORICAL_ONLY,
            counts=dict(summary.counts),
        ))
    return EstateState(evidence=tuple(records), generated_at_utc=report_time)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SZL estate evidence foundations and Phase 0 setup")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="Report bounded local summaries; optionally check narrow Phase 0 setup")
    verify.add_argument("--backend-bundle", type=Path)
    verify.add_argument("--hf-inventory", type=Path)
    verify.add_argument("--as-of", help="UTC report reference time; defaults to latest source time")
    verify.add_argument("--out", type=Path, default=Path("outputs/estate_phase0"))
    verify.add_argument("--check-setup", action="store_true", help="Run reviewed tests and four narrow existing-auth identity/org/membership reads")
    verify.add_argument("--package-root", type=Path, help="Reviewed tools/szl_estate checkout for source and test verification")
    verify.add_argument("--access-receipt", type=Path, help="Optional receipt context; always freshly revalidate, never trust file assertions")
    args = parser.parse_args(argv)
    if args.access_receipt and not args.check_setup:
        parser.error("--access-receipt requires --check-setup and fresh access revalidation")
    summaries = []
    sources = [Path.cwd() / "estate_state.json"]
    if args.backend_bundle:
        sources.append(args.backend_bundle)
        summaries.append(load_backend_summary(args.backend_bundle))
    if args.hf_inventory:
        sources.append(args.hf_inventory)
        summaries.append(load_hf_summary(args.hf_inventory))
    try:
        state = build_state(summaries, as_of=args.as_of)
        if args.access_receipt:
            sources.append(args.access_receipt)
        if args.check_setup:
            guard_output_alias(args.out / "phase0_state.json", sources)
            if args.package_root and args.out.resolve().is_relative_to(args.package_root.resolve()):
                raise EvidenceValidationError("SETUP_OUTPUT_MUST_BE_OUTSIDE_REVIEWED_PACKAGE")
        write_reports(args.out, state, source_paths=sources)
        setup = run_setup(args.package_root, args.out, access_receipt=args.access_receipt) if args.check_setup else None
        if setup is not None:
            write_setup_report(args.out / "phase0_state.json", setup)
    except (EvidenceValidationError, StorageError):
        print(json.dumps({"status": "FAIL", "code": "INVALID_INPUT_OR_OUTPUT", "setup_ready": False, "estate_ready": False}, sort_keys=True))
        return 2
    bad_input = any(item.error_code for item in summaries)
    setup_ready = bool(setup and setup.setup_ready)
    status = "FAIL" if bad_input else "PASS" if setup_ready else "FAIL" if setup else "NOT_RUN"
    print(json.dumps({
        "status": status, "setup_ready": setup_ready, "estate_ready": state.estate_ready,
        "historical_inputs": len(summaries), "generated_at_utc": state.generated_at_utc,
        "live_scope_verified": False,
        "setup_checked_at_utc": setup.checked_at_utc if setup else None,
        "access_matrix": [row.to_dict() for row in setup.access] if setup else [row.to_dict() for row in not_run_access()],
        "setup_checks": [check.to_dict() for check in setup.checks] if setup else [],
        "receipt_status": setup.receipt_status.value if setup else "NOT_RUN",
    }, sort_keys=True))
    return 0 if setup_ready and not bad_input else 1


if __name__ == "__main__":
    raise SystemExit(main())
