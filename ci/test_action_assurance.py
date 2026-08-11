from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "ci"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from estate.action_assurance import (  # noqa: E402
    compute_trust_factors,
    evaluate_citation_ledger,
    expected_signature_payload_digest,
    project_unsigned_interop,
    validate_passport,
)
from verify_action_assurance import verify  # noqa: E402

FIXTURE_ROOT = ROOT / "fixtures" / "action_assurance"
FIXED_NOW = datetime(2026, 8, 11, 4, 0, tzinfo=timezone.utc)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"fixture root must be object: {path}")
    return value


def rebind(passport: dict) -> dict:
    passport["signature"]["payload_sha3_256"] = expected_signature_payload_digest(
        passport
    )
    return passport


class ActionAssuranceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.execute = load_json(FIXTURE_ROOT / "passports" / "execute.json")
        cls.refuse = load_json(FIXTURE_ROOT / "passports" / "refuse.json")
        cls.ledger = load_json(FIXTURE_ROOT / "citations.current.json")

    def test_committed_passports_are_valid(self) -> None:
        self.assertEqual(validate_passport(self.execute), [])
        self.assertEqual(validate_passport(self.refuse), [])

    def test_authority_never_expands_silently(self) -> None:
        passport = copy.deepcopy(self.execute)
        passport["authority"]["child_scopes"].append(
            "repo:szl-holdings/szl-estate-os:admin"
        )
        rebind(passport)
        errors = validate_passport(passport)
        self.assertTrue(
            any("child scopes exceed parent scopes" in error for error in errors),
            errors,
        )

    def test_evidence_graph_detects_claim_tampering(self) -> None:
        passport = copy.deepcopy(self.execute)
        passport["evidence"]["claims"][0]["digest_sha256"] = "f" * 64
        rebind(passport)
        errors = validate_passport(passport)
        self.assertIn(
            "evidence.graph_sha3_256 does not bind the exact ordered claims",
            errors,
        )

    def test_counterfactuals_must_precede_action_request(self) -> None:
        passport = copy.deepcopy(self.execute)
        passport["expected_if_acted"]["recorded_at"] = "2026-08-01T12:00:01Z"
        rebind(passport)
        errors = validate_passport(passport)
        self.assertTrue(
            any("no later than action.requested_at" in error for error in errors),
            errors,
        )

    def test_required_approval_must_precede_execution(self) -> None:
        passport = copy.deepcopy(self.execute)
        passport["human_oversight"]["recorded_at"] = "2026-08-01T12:03:00Z"
        rebind(passport)
        errors = validate_passport(passport)
        self.assertIn("approval must be recorded before execution", errors)

    def test_block_decision_emits_refusal(self) -> None:
        passport = copy.deepcopy(self.refuse)
        passport["action"]["state"] = "WITHHELD"
        passport["outcome"]["state"] = "WITHHELD"
        rebind(passport)
        errors = validate_passport(passport)
        self.assertIn("BLOCK decisions must produce action.state=REFUSED", errors)

    def test_proposed_action_cannot_claim_a_measured_outcome(self) -> None:
        passport = copy.deepcopy(self.execute)
        passport["action"]["state"] = "PROPOSED"
        passport["action"]["executed_at"] = None
        rebind(passport)
        errors = validate_passport(passport)
        self.assertIn(
            "a proposed action must have outcome.state=NOT_MEASURED",
            errors,
        )

    def test_signature_digest_binds_trust_factor_delta(self) -> None:
        passport = copy.deepcopy(self.execute)
        original_digest = passport["signature"]["payload_sha3_256"]
        passport["trust_factor_delta"] = -99
        self.assertNotEqual(
            expected_signature_payload_digest(passport),
            original_digest,
        )
        self.assertIn(
            "signature.payload_sha3_256 does not bind the passport payload",
            validate_passport(passport),
        )

    def test_unsigned_interop_never_claims_a_signature(self) -> None:
        projection = project_unsigned_interop(self.execute)
        self.assertEqual(projection["state"], "UNSIGNED_PROJECTION")
        self.assertEqual(projection["dsse"]["signatures"], [])
        self.assertNotIn("proof", projection["w3c_vc"])
        limitations = " ".join(projection["limitations"])
        self.assertIn("No ECDSA signature", limitations)
        self.assertIn("no proof", limitations)

    def test_citation_ledger_passes_only_while_current(self) -> None:
        current = evaluate_citation_ledger(self.ledger, now=FIXED_NOW)
        self.assertEqual(current["status"], "PASS", current)

        stale = copy.deepcopy(self.ledger)
        stale["entries"][0]["status"] = "STALE"
        stale["entries"][0]["next_review_at"] = "2026-08-02T00:00:00Z"
        stale_report = evaluate_citation_ledger(stale, now=FIXED_NOW)
        self.assertEqual(stale_report["status"], "FAIL")
        self.assertEqual(stale_report["counts"].get("STALE"), 1)

    def test_citation_declared_state_must_match_derived_state(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["entries"][0]["status"] = "STALE"
        report = evaluate_citation_ledger(ledger, now=FIXED_NOW)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(
            any("does not match derived state CURRENT" in error for error in report["errors"]),
            report,
        )

    def test_citation_verification_timestamps_cannot_be_in_the_future(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["entries"][0]["retrieved_at"] = "2027-08-01T00:00:00Z"
        ledger["entries"][0]["last_verified_at"] = "2027-08-01T00:01:00Z"
        ledger["entries"][0]["next_review_at"] = "2027-08-02T00:00:00Z"
        report = evaluate_citation_ledger(ledger, now=FIXED_NOW)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(
            any("cannot be in the future" in error for error in report["errors"]),
            report,
        )

    def test_trust_factor_is_modeled_and_future_events_are_rejected(self) -> None:
        report = compute_trust_factors(
            [self.execute, self.refuse], now=FIXED_NOW, half_life_days=90
        )
        agent = report["agents"]["agent.fixture-01"]
        self.assertEqual(report["evidence_label"], "MODELED")
        self.assertEqual(agent["sample_size"], 2)
        self.assertGreaterEqual(agent["score_0_to_100"], 0)
        self.assertLessEqual(agent["score_0_to_100"], 100)
        self.assertIn("never expands authority", " ".join(agent["limitations"]))

        future = copy.deepcopy(self.execute)
        future["recorded_at"] = "2027-08-01T12:10:00Z"
        rebind(future)
        future_report = compute_trust_factors([future], now=FIXED_NOW)
        self.assertEqual(future_report["evidence_label"], "UNAVAILABLE")
        self.assertEqual(len(future_report["invalid_passports"]), 1)
        self.assertIn(
            "cannot be in the future",
            future_report["invalid_passports"][0]["errors"][0],
        )

    def test_verifier_emits_complete_evidence_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "evidence"
            report, exit_code = verify(
                passport_dir=FIXTURE_ROOT / "passports",
                citation_ledger_path=FIXTURE_ROOT / "citations.current.json",
                output_dir=output_dir,
                now=FIXED_NOW,
            )
            self.assertEqual(exit_code, 0, report)
            self.assertEqual(report["status"], "PASS")
            self.assertTrue((output_dir / "verification-report.json").is_file())
            self.assertTrue((output_dir / "citation-drift-report.json").is_file())
            self.assertTrue((output_dir / "trust-factor-report.json").is_file())
            interop_files = sorted((output_dir / "interop").glob("*.json"))
            self.assertEqual(len(interop_files), 2)

    def test_verifier_rejects_duplicate_passport_ids_before_artifact_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            passport_dir = root / "passports"
            passport_dir.mkdir()
            encoded = json.dumps(self.execute)
            (passport_dir / "one.json").write_text(encoded, encoding="utf-8")
            (passport_dir / "two.json").write_text(encoded, encoding="utf-8")
            output_dir = root / "evidence"
            report, exit_code = verify(
                passport_dir=passport_dir,
                citation_ledger_path=FIXTURE_ROOT / "citations.current.json",
                output_dir=output_dir,
                now=FIXED_NOW,
            )
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["summary"]["valid_passport_count"], 1)
            self.assertTrue(
                any(
                    "duplicated across inputs" in error
                    for error in report["passport_results"][1]["errors"]
                ),
                report,
            )
            self.assertEqual(len(list((output_dir / "interop").glob("*.json"))), 1)

    def test_verifier_reports_non_finite_json_as_a_load_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            passport_dir = root / "passports"
            passport_dir.mkdir()
            (passport_dir / "valid.json").write_text(
                json.dumps(self.execute),
                encoding="utf-8",
            )
            (passport_dir / "non-finite.json").write_text(
                '{"passport_id":"passport.invalid","metrics":{"score":NaN}}',
                encoding="utf-8",
            )
            output_dir = root / "evidence"
            report, exit_code = verify(
                passport_dir=passport_dir,
                citation_ledger_path=FIXTURE_ROOT / "citations.current.json",
                output_dir=output_dir,
                now=FIXED_NOW,
            )
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["summary"]["load_error_count"], 1)
            self.assertTrue((output_dir / "verification-report.json").is_file())


if __name__ == "__main__":
    unittest.main()
