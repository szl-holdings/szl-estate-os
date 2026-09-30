"""Stdlib-only consistency checks for this frozen report; executes no candidate code."""
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
PIN = "482edd750f3354569ed417a5f443c43a1271ac91"
BASE = "5352659a023c20a34eacdb48e168064ea571e836"


def load_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_KEY")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("NONFINITE_VALUE")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class ReportChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = load_json((ROOT / "evidence.json").read_bytes())
        cls.files = cls.report["files"]
        cls.by_path = {f["path"]: f for f in cls.files}
        cls.coverage = cls.report["coverage"]

    def test_01_exact_unique_selected_identities(self):
        self.assertEqual(len(self.files), 48)
        self.assertEqual({f["file_id"] for f in self.files}, {f"H2-{i:03}" for i in range(1, 49)})
        identities = {(f["repository_id"], f["snapshot_sha"], f["path"], f["blob_sha"]) for f in self.files}
        self.assertEqual(len(identities), 48)
        self.assertEqual({f["snapshot_sha"] for f in self.files}, {PIN})

    def test_02_byte_counts_and_withholding(self):
        self.assertEqual(Counter(f["byte_status"] for f in self.files), {"COMPLETE": 47, "SKIPPED": 1})
        withheld = [f for f in self.files if f["byte_status"] == "SKIPPED"]
        self.assertEqual(withheld[0]["path"], ".gitleaks.toml")
        self.assertEqual(withheld[0]["byte_disposition"], "PRIVATE_KEY_WITHHELD")
        self.assertEqual(withheld[0]["available_cache_lines"], 0)

    def test_03_static_counts_preserve_exclusions(self):
        self.assertEqual(Counter(f["static_status"] for f in self.files), {"COMPLETE": 28, "PARTIAL": 18, "SKIPPED": 2})
        for f in self.files:
            if f["static_status"] == "COMPLETE":
                self.assertEqual(f["privacy_withheld_lines"] + f["operational_excluded_lines"], 0)
        whole_excluded = next(f for f in self.files if f["file_id"] == "H2-008")
        self.assertEqual((whole_excluded["byte_status"], whole_excluded["static_status"], whole_excluded["eligible_reviewed_lines"]), ("COMPLETE", "SKIPPED", 0))

    def test_04_line_and_byte_accounting(self):
        totals = {k: sum(f[k] for f in self.files) for k in ("declared_bytes", "available_cache_lines", "privacy_withheld_lines", "operational_excluded_lines", "eligible_reviewed_lines")}
        self.assertEqual(totals, {"declared_bytes": 354807, "available_cache_lines": 7960, "privacy_withheld_lines": 37, "operational_excluded_lines": 368, "eligible_reviewed_lines": 7555})
        for key, total in totals.items():
            self.assertEqual(self.coverage[key], total)
        for f in self.files:
            self.assertEqual(f["available_cache_lines"], f["privacy_withheld_lines"] + f["operational_excluded_lines"] + f["eligible_reviewed_lines"])

    def test_05_historical_union_not_double_counted(self):
        c = self.coverage
        self.assertEqual((c["historical_baseline"], c["newly_verified_unique_paths"], c["overlapping_prior_paths"]), (603, 47, 0))
        self.assertEqual(c["combined_byte_accounted_paths"], 650)
        self.assertEqual(c["remaining_unread_or_skipped_paths"], 32098)
        self.assertEqual(650 + 32098, c["historical_total_paths"])

    def test_06_distinct_input_provenance_roles(self):
        p = self.report["provenance"]
        self.assertEqual(p["published_proposal_sha256"], "6246966bae58d7042cfcdf38fb29a99420c87071b4960ab88e621239ef947e6b")
        self.assertEqual(p["normalized_execution_plan_sha256"], "93a7acc49a985b9a66218c93bc2ad17e37e93ec09ba96407c760bb3d7225815c")
        self.assertNotEqual(p["published_proposal_sha256"], p["normalized_execution_plan_sha256"])
        self.assertEqual(p["prior_batch_report_sha256"], "525b8574c57da4d2045679cf4e2c23204c96d2e433d72c32e340099ffff4bfff")

    def test_07_receipt_digest_shapes_and_original_binding(self):
        for f in self.files:
            self.assertRegex(f["blob_sha"], r"^[0-9a-f]{40}$")
            self.assertEqual(f["original_blob_sha1"], f["blob_sha"])
            self.assertRegex(f["original_sha256"], r"^[0-9a-f]{64}$")
            if f["byte_status"] == "COMPLETE":
                self.assertRegex(f["screened_cache_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(f["source_endpoint"].endswith("/git/blobs/" + f["blob_sha"]))

    def test_08_scope_projection_does_not_grant_fresh_credit(self):
        p = self.report["provenance"]["scope_projection"]
        self.assertEqual(p["source_origin"], "CACHE_SCOPE_RESCREEN")
        self.assertIs(p["source_refetched"], False)
        self.assertIs(p["fresh_source_proof"], False)
        self.assertIs(p["source_body_committed"], False)
        self.assertEqual(len(p["entries"]), 47)
        by_id = {f["file_id"]: f for f in self.files}
        for entry in p["entries"]:
            f = by_id[entry["file_id"]]
            self.assertEqual(entry["old_cache_sha256"], f["screened_cache_sha256"])
            self.assertEqual(entry["scope_view_sha256"], f["scope_view_sha256"])
            self.assertEqual(len(entry["operational_excluded_lines"]), f["operational_excluded_lines"])

    def test_09_findings_are_pinned_and_within_review_scope(self):
        findings = self.report["findings"]
        self.assertEqual(len(findings), 25)
        self.assertEqual(len({f["finding_id"] for f in findings}), 25)
        for finding in findings:
            self.assertEqual(finding["snapshot_sha"], PIN)
            for anchor in [finding] + finding["related_sources"]:
                row = self.by_path[anchor["path"]]
                self.assertTrue(1 <= anchor["line_start"] <= anchor["line_end"] <= row["available_cache_lines"])
                for interval in row["excluded_ranges"]:
                    self.assertFalse(anchor["line_start"] <= interval["line_end"] and interval["line_start"] <= anchor["line_end"])
            self.assertIn("/blob/" + PIN + "/", finding["source_url"])

    def test_10_candidate_fixtures_and_repairs_are_unrun(self):
        for f in self.files + self.report["findings"]:
            self.assertEqual(f.get("runtime_status", f.get("runtime_test_status")), "NOT_RUN")
            self.assertEqual(f["repairs_status"], "NOT_ATTEMPTED")
        for f in self.report["findings"]:
            self.assertEqual(f["acceptance_test_basis"], "PROPOSAL")
            self.assertEqual(f["owner_handoff_status"], "PROPOSED_NOT_ASSIGNED")
            self.assertTrue(f["acceptance_test"])

    def test_11_no_readiness_or_unexposed_http_promotion(self):
        r = self.report
        self.assertIs(r["phase2_ready"], False)
        self.assertIs(r["estate_ready"], False)
        self.assertIs(r["source_execution_performed"], False)
        self.assertEqual(r["runtime_status"], "NOT_RUN")
        self.assertEqual(r["novelty"], "NOT_ESTABLISHED")
        self.assertIsNone(r["claim_tier"])
        self.assertEqual(r["current_head_observation"]["http_status"], "UNKNOWN_UNEXPOSED")
        self.assertIs(r["current_head_observation"]["fresh_revalidation_required_before_repair"], True)

    def test_12_csv_matches_exact_report_projection(self):
        rows = list(csv.DictReader(io.StringIO((ROOT / "files.csv").read_text(encoding="utf-8"))))
        self.assertEqual(len(rows), 48)
        for actual, expected in zip(rows, self.files):
            for key, value in actual.items():
                self.assertEqual(value, "" if expected[key] is None else str(expected[key]))

    def test_13_published_metadata_has_no_sensitive_value_patterns(self):
        text = (ROOT / "report.md").read_text() + (ROOT / "evidence.json").read_text() + (ROOT / "files.csv").read_text()
        for pattern in (r"(?i)[A-Z]:[\\/]Users[\\/]", r"/home/[^/\s]+/", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bhf_[A-Za-z0-9]{20,}\b", r"(?i)\bAuthorization\s*:", r"\b(?:libfile|connector|session|thread)_[0-9a-f]{12,}\b"):
            self.assertIsNone(re.search(pattern, text))

    def test_14_report_provenance_sections_and_portable_bytes(self):
        text = (ROOT / "report.md").read_text()
        self.assertEqual(re.findall(r"^## ([1-7])\. ", text, re.MULTILINE), list("1234567"))
        self.assertIn("not proof of an actual key", text)
        for name in ("evidence.json", "files.csv", "report.md", "check_report.py", ".gitattributes"):
            self.assertNotIn(b"\r", (ROOT / name).read_bytes())

    def test_15_exact_additive_stack_and_historical_tests(self):
        self.assertEqual(self.report["audit_base_commit"], BASE)
        self.assertEqual(self.report["stack"]["base_sha"], BASE)
        self.assertEqual(self.report["stack"]["base_pull_request"], 54)
        historical = self.report["historical_tool_validation"]
        self.assertEqual(historical["head_sha"], BASE)
        self.assertIn("NOT rerun", historical["run_scope"])
        self.assertEqual((historical["package_cases"], historical["package_subtests"]), (564, 18))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportChecks)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    print(json.dumps({"report_checks": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped), "candidate_tests": "NOT_RUN"}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
