"""Stdlib report consistency checks; no candidate imports, tests or network."""
from collections import Counter
import csv
import io
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent


def load(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_KEY")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("NONFINITE_JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class ReportChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = load((ROOT / "evidence.json").read_bytes())
        cls.files = cls.e["files"]
        cls.by_source = {(f["repository_id"], f["snapshot_sha"], f["path"]): f for f in cls.files}

    def test_01_unique_pins_and_counts(self):
        self.assertEqual(len(self.files), 12)
        self.assertEqual(len(self.by_source), 12)
        self.assertEqual(len({f["blob_sha"] for f in self.files}), 12)
        self.assertEqual({f["file_id"] for f in self.files}, {f"R4-{i:03}" for i in range(1, 13)})

    def test_02_hashes_and_regular_leaf_membership(self):
        for f in self.files:
            for key in ("snapshot_sha", "blob_sha", "original_blob_sha1"):
                self.assertRegex(f[key], r"^[0-9a-f]{40}$")
            self.assertEqual(f["blob_sha"], f["original_blob_sha1"])
            self.assertRegex(f["original_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(f["membership"][-1]["entry_sha"], f["blob_sha"])
            self.assertIn(f["membership"][-1]["mode"], ("100644", "100755"))
            self.assertTrue(f["source_endpoint"].endswith("/git/blobs/" + f["blob_sha"]))

    def test_03_acquisition_and_byte_credit_are_separate(self):
        self.assertEqual(Counter(f["byte_status"] for f in self.files), {"COMPLETE": 11, "SKIPPED": 1})
        self.assertEqual(sum(f["size_bytes"] for f in self.files), 69187)
        self.assertEqual(self.e["coverage"]["acquired_hash_verified_objects"], 12)
        self.assertEqual(self.e["coverage"]["newly_credited_unique_paths"], 11)

    def test_04_static_completeness_respects_masks_and_withholding(self):
        self.assertEqual(Counter(f["static_status"] for f in self.files), {"COMPLETE": 10, "PARTIAL": 1, "SKIPPED": 1})
        for f in self.files:
            if f["static_status"] == "COMPLETE":
                self.assertFalse(f["withheld_entire_file"])
                self.assertEqual(f["excluded_line_numbers"], [])
                self.assertEqual(f["eligible_reviewed_lines"], f["available_lines"])

    def test_05_known_line_accounting(self):
        self.assertEqual(sum(f["available_lines"] or 0 for f in self.files), 906)
        self.assertEqual(sum(f["eligible_reviewed_lines"] for f in self.files), 902)
        self.assertEqual(sum(f["privacy_withheld_lines"] for f in self.files), 4)
        for f in self.files:
            if f["available_lines"] is not None:
                self.assertEqual(f["available_lines"], f["eligible_reviewed_lines"] + f["privacy_withheld_lines"])
        self.assertEqual(self.e["coverage"]["withheld_implementation_line_count"], "UNKNOWN")

    def test_06_withheld_file_cannot_gain_credit_or_leak_claim(self):
        f = self.by_source[("szl-holdings/szl-ci-witness", "f8102adf6e0e3214f5879dc16bea852394215d32", "tools/source_census.py")]
        self.assertEqual(f["withhold_reason"], "CREDENTIAL_BLOCK_WITHHELD")
        self.assertIsNone(f["available_lines"])
        self.assertIsNone(f["screened_cache_sha256"])
        self.assertEqual(f["eligible_reviewed_lines"], 0)
        self.assertIs(f["credential_leak_established"], False)
        self.assertFalse(any(x["path"] == f["path"] for x in self.e["findings"]))

    def test_07_partial_file_has_exact_masks(self):
        f = self.by_source[("szl-holdings/szl-ci-witness", "f8102adf6e0e3214f5879dc16bea852394215d32", "tests/test_source_census.py")]
        self.assertEqual(f["static_status"], "PARTIAL")
        self.assertEqual(f["excluded_line_numbers"], [129, 136, 144, 145])
        self.assertEqual((f["available_lines"], f["eligible_reviewed_lines"]), (170, 166))

    def test_08_historical_coverage_union(self):
        c = self.e["coverage"]
        self.assertEqual((c["prior_selected_identities"], c["prior_identity_overlap"], c["prior_blob_overlap"]), (147, 0, 0))
        self.assertEqual(c["historical_baseline"] + c["newly_credited_unique_paths"], c["combined_byte_accounted_paths"])
        self.assertEqual((c["combined_byte_accounted_paths"], c["remaining_unread_or_skipped_paths"]), (696, 32052))
        self.assertEqual(696 + 32052, c["historical_total_paths"])
        self.assertEqual(c["denominator_basis"], "DATED_HISTORICAL_BUNDLE_NOT_CURRENT_ESTATE")

    def test_09_read_only_collection_and_fresh_public_gate(self):
        c = self.e["collection"]
        self.assertEqual((c["api_requests"], c["tree_requests"], c["unique_fetched_objects"], c["unique_fetched_bytes"]), (26, 10, 12, 69187))
        self.assertEqual(c["failures"], [])
        self.assertEqual(len(c["repositories"]), 2)
        for r in c["repositories"]:
            self.assertEqual(r["http_status"], 200)
            self.assertIs(r["private"], False)
            self.assertEqual(r["visibility"], "public")
            self.assertTrue(r["observed_at_utc"])

    def test_10_provenance_and_stack(self):
        p = self.e["provenance"]
        self.assertEqual(p["execution_envelope_sha256"], "d15beb3a3f61ba31d528d665b8df5854eb5a96ecf3ea0bf76b2efddc01adb31c")
        self.assertEqual(p["prior_evidence_sha256"], "e043494679b3a14b78c93d7e4719b906175d9da8cbaa4ac6b36162662941eab7")
        self.assertEqual(p["proposal_sha256"], "a3da721d9307b61a3974bfb1da8cedd8ada797b64cd9ba00d6ad46b08e9e17d8")
        for key in ("plan_sha256", "source_reader_sha256", "source_screen_sha256", "source_index_sha256"):
            self.assertRegex(p[key], r"^[0-9a-f]{64}$")
        self.assertEqual(self.e["stack"]["base_sha"], "10407794b36a3f5df1a0793c78ffd57f47a1a691")
        self.assertEqual(self.e["stack"]["base_pull_request"], 56)
        self.assertIs(p["source_reader_changed"], False)
        self.assertIs(p["candidate_source_bodies_committed"], False)

    def test_11_findings_are_unique_bound_to_visible_source(self):
        findings = self.e["findings"]
        self.assertEqual(len(findings), 10)
        self.assertEqual(len({f["finding_id"] for f in findings}), 10)
        for f in findings:
            row = self.by_source[(f["repository_id"], f["snapshot_sha"], f["path"])]
            self.assertFalse(row["withheld_entire_file"])
            self.assertTrue(1 <= f["line_start"] <= f["line_end"] <= row["available_lines"])
            self.assertFalse(set(range(f["line_start"], f["line_end"] + 1)) & set(row["excluded_line_numbers"]))
            self.assertEqual(f["blob_sha"], row["blob_sha"])
            self.assertIn("/blob/" + f["snapshot_sha"] + "/", f["source_url"])
            self.assertIs(f["current_blob_revalidation_required"], True)

    def test_12_no_execution_repairs_assignment_or_readiness_promotion(self):
        for key in ("source_execution_performed", "phase2_ready", "estate_ready"):
            self.assertIs(self.e[key], False)
        self.assertEqual(self.e["runtime_status"], "NOT_RUN")
        self.assertEqual(self.e["novelty"], "NOT_ESTABLISHED")
        for f in self.e["findings"]:
            self.assertEqual(f["runtime_test_status"], "NOT_RUN")
            self.assertEqual(f["acceptance_test_basis"], "PROPOSAL")
            self.assertEqual(f["repairs_status"], "NOT_ATTEMPTED")
            self.assertEqual(f["owner_assignment_status"], "PROPOSED_NOT_ASSIGNED")

    def test_13_current_head_observations_do_not_claim_unexposed_http(self):
        for h in self.e["current_head_observations"]:
            self.assertEqual(h["http_status"], "UNKNOWN_UNEXPOSED")
            self.assertTrue(h["checked_at_utc"])
            self.assertIs(h["fresh_revalidation_required_before_repair"], True)
            self.assertIn(h["sha"], {f["snapshot_sha"] for f in self.files})
        self.assertEqual(self.e["active_owner_observation"]["unpublished_writers"], "UNKNOWN")

    def test_14_csv_exact_projection(self):
        rows = list(csv.DictReader(io.StringIO((ROOT / "files.csv").read_text())))
        self.assertEqual(len(rows), 12)
        for actual, expected in zip(rows, self.files):
            for key, value in actual.items():
                self.assertEqual(value, "" if expected[key] is None else str(expected[key]))

    def test_15_private_patterns_portable_bytes_and_seven_sections(self):
        names = (".gitattributes", "evidence.json", "files.csv", "report.md", "check_report.py")
        published = ""
        for name in names:
            raw = (ROOT / name).read_bytes()
            self.assertNotIn(b"\r", raw)
            if name != "check_report.py":
                published += raw.decode()
        for pattern in (r"(?i)[A-Z]:[\\/]Users[\\/]", r"/home/[^/\s]+/", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bhf_[A-Za-z0-9]{20,}\b", r"(?i)\bAuthorization\s*:", r"\b(?:libfile|connector|session|thread)_[0-9a-f]{12,}\b"):
            self.assertIsNone(re.search(pattern, published))
        text = (ROOT / "report.md").read_text()
        self.assertEqual(re.findall(r"^## ([1-7])\. ", text, re.MULTILINE), list("1234567"))
        self.assertIsNone(re.search(r"(?m)^\|[^\n]*\|\n\n\|", text))
        self.assertEqual(len(re.findall(r"(?m)^\| R4-\d{3} \|", text)), 12)

    def test_16_duplicate_and_nonfinite_json_rejected(self):
        with self.assertRaises(ValueError):
            load('{"state":"UNKNOWN","state":"PASS"}')
        with self.assertRaises(ValueError):
            load('{"count":NaN}')


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReportChecks))
    print(json.dumps({"report_checks": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped), "candidate_tests": "NOT_RUN"}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
