from __future__ import annotations

import unittest

from verify_estate_readiness import signature_state, verify


class SignatureStateTests(unittest.TestCase):
    def test_baseline_accepts_only_known_local_evidence(self) -> None:
        self.assertEqual(signature_state("HMAC_SHA256", "baseline"), "PASS")
        self.assertEqual(signature_state("UNSIGNED", "baseline"), "WARN")

    def test_baseline_rejects_missing_or_invented_states(self) -> None:
        for status in ("UNAVAILABLE", "SIGNED", "VERIFIED", "UNKNOWN"):
            with self.subTest(status=status):
                self.assertEqual(signature_state(status, "baseline"), "FAIL")

    def test_production_requires_explicit_asymmetric_verification(self) -> None:
        self.assertEqual(
            signature_state("ASYMMETRIC_VERIFIED", "production"), "PASS"
        )
        for status in ("HMAC_SHA256", "UNSIGNED", "UNAVAILABLE", "SIGNED"):
            with self.subTest(status=status):
                self.assertEqual(signature_state(status, "production"), "FAIL")

    def test_report_uses_the_contract_classification(self) -> None:
        audit = {
            "assets": [],
            "source_reports": [],
            "receipt": {"signature_status": "ASYMMETRIC_VERIFIED"},
        }
        manifest = {
            "baseline": {"source_minimums": {}},
            "critical_assets": [],
            "known_gaps": [],
        }
        report = verify(audit, manifest, "production")
        evidence = next(
            item
            for item in report["checks"]
            if item["id"] == "evidence.independent_signature"
        )
        self.assertEqual(evidence["state"], "PASS")


if __name__ == "__main__":
    unittest.main()
