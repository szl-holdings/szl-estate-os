"""Offline consistency of published static evidence; candidate code is never run."""
import csv
from collections import Counter
import io
import json
from pathlib import Path
import re
import unittest

from szl_estate.content_review import ReviewReceipt

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "estate_reports"


class StaticContentReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (REPORTS / "content_batch1_review.json").read_bytes()
        if len(raw) > 512 * 1024:
            raise AssertionError("bounded report size exceeded")
        cls.raw = raw
        cls.report = json.loads(raw)
        cls.plan = json.loads((REPORTS / "phase2_inventory_summary.json").read_bytes())["state"]["github"]["batch"]
        cls.documents = cls.report["documents"]
        cls.by_path = {(d["receipt"]["pin"]["repository_id"], d["receipt"]["pin"]["snapshot_sha"], d["receipt"]["pin"]["path"]): d for d in cls.documents}

    def test_exact_proposal_identity_and_unique_file_matrix(self):
        expected = {(r["repository_id"], r["snapshot_sha"], r["path"], r["git_object_sha"], r["size_bytes"]) for r in self.plan}
        actual = {(d["receipt"]["pin"]["repository_id"], d["receipt"]["pin"]["snapshot_sha"], d["receipt"]["pin"]["path"], d["receipt"]["pin"]["blob_sha"], d["receipt"]["pin"]["size_bytes"]) for d in self.documents}
        self.assertEqual(expected, actual)
        self.assertEqual(len(actual), 64)
        self.assertEqual({d["file_id"] for d in self.documents}, {f"B1-{i:03d}" for i in range(1, 65)})

    def test_historical_union_preserves_denominator_and_failed_retry_not_double_counted(self):
        c = self.report["coverage"]
        self.assertEqual((c["historical_read_total"], c["newly_verified_read_paths"], c["historical_overlap_with_batch"]), (542, 61, 0))
        self.assertEqual(c["reconciled_read_total"], 542 + 61)
        self.assertEqual(c["remaining_unread_or_skipped_paths"], c["full_frozen_tracked_paths"] - c["reconciled_read_total"])
        self.assertEqual(c["remaining_unread_or_skipped_paths"], 32145)
        self.assertFalse(self.report["original_attempt"]["counted_separately"])

    def test_byte_and_static_statuses_remain_independent(self):
        byte = Counter(d["receipt"]["byte_read_status"] for d in self.documents)
        static = Counter(d["static_review"]["static_status"] for d in self.documents)
        self.assertEqual(byte, {"COMPLETE": 61, "SKIPPED": 3})
        self.assertEqual(static, self.report["coverage"]["static_contract_status_counts"])
        for d in self.documents:
            r = d["receipt"]
            self.assertEqual(r["static_contract_status"], d["static_review"]["static_status"])
            if r["redacted_lines"]:
                self.assertEqual(r["static_contract_status"], "PARTIAL")
            if r["byte_read_status"] == "SKIPPED":
                self.assertEqual(d["static_review"]["line_count"], 0)
                self.assertEqual(r["cache_disposition"], "WITHHELD")

    def test_serialized_receipts_cannot_grant_fresh_or_runtime_proof(self):
        for d in self.documents:
            receipt = ReviewReceipt.from_dict(d["receipt"])
            self.assertFalse(receipt.fresh_source_proof)
            self.assertFalse(receipt.byte_coverage_credit)
            self.assertEqual(receipt.runtime_status.value, "NOT_RUN")
        for flag in ("phase2_ready", "estate_ready", "source_execution_performed"):
            self.assertIs(self.report[flag], False)
        self.assertEqual(self.report["runtime_status"], "NOT_RUN")
        self.assertEqual(self.report["novelty_status"], "NOT_ESTABLISHED")

    def test_selected_tree_membership_reaches_exact_regular_blob(self):
        commits = {c["endpoint"].split("/git/commits/")[0].split("/repos/")[1]: c for c in self.report["commits"]}
        for d in self.documents:
            pin, chain = d["receipt"]["pin"], d["membership"]
            self.assertEqual([r["component"] for r in chain], pin["path"].split("/"))
            self.assertEqual(chain[0]["tree_sha"], commits[pin["repository_id"]]["tree_sha"])
            for current, following in zip(chain, chain[1:]):
                self.assertEqual(current["mode"], "040000")
                self.assertEqual(current["entry_sha"], following["tree_sha"])
            self.assertIn(chain[-1]["mode"], ("100644", "100755"))
            self.assertEqual(chain[-1]["entry_sha"], pin["blob_sha"])
            self.assertTrue(all(r["http_status"] == 200 for r in chain))

    def test_privacy_projection_retains_provenance_without_source_bodies(self):
        privacy = self.report["privacy_rescreen"]
        self.assertFalse(privacy["source_fetch_performed"])
        self.assertFalse(privacy["fresh_source_proof"])
        self.assertTrue(privacy["private_original_evidence_preserved"])
        rows = {r["file_id"]: r for r in privacy["documents"]}
        self.assertEqual(len(rows), 61)
        self.assertEqual(sum(bool(r["added_redacted_lines"]) for r in rows.values()), 8)
        self.assertEqual(sum(r["added_redacted_lines"] for r in rows.values()), 32)
        for d in self.documents:
            self.assertFalse(d["source_body_in_repository"])
            if d["file_id"] in rows:
                self.assertEqual(d["receipt"]["redacted_cache_sha256"], rows[d["file_id"]]["screened_cache_sha256"])
                self.assertFalse(rows[d["file_id"]]["fresh_source_proof"])
        text = self.raw.decode("utf-8")
        self.assertIsNone(re.search(r"(?:[A-Za-z]:[\\/]+Users[\\/]|/(?:home|Users)/|github_pat_[A-Za-z0-9_]+|hf_[A-Za-z0-9]{20,}|sediment://|libfile_)", text))

    def test_finding_anchors_and_unassigned_owner_tests_are_honest(self):
        findings = self.report["findings"]
        self.assertEqual(len({f["finding_id"] for f in findings}), len(findings))
        for f in findings:
            source = self.by_path[(f["repository_id"], f["snapshot_sha"], f["path"])]
            self.assertGreaterEqual(f["line_start"], 1)
            self.assertLessEqual(f["line_start"], f["line_end"])
            self.assertLessEqual(f["line_end"], source["static_review"]["line_count"])
            self.assertEqual(f["runtime_test_status"], "NOT_RUN")
            self.assertEqual(f["repair_status"], "NOT_ATTEMPTED")
            self.assertEqual(f["repair_task_status"], "UNASSIGNED")
            self.assertTrue(f["fresh_head_revalidation_required"])
            self.assertIn(f["basis"], ("FACT", "INFERENCE", "PROPOSAL"))

    def test_current_head_metadata_does_not_invent_http_or_behavior(self):
        metadata = self.report["current_head_metadata"]
        self.assertIsNone(metadata["http_status"])
        self.assertEqual(metadata["http_status_code"], "HTTP_STATUS_UNEXPOSED")
        self.assertFalse(metadata["runtime_validation_performed"])
        self.assertTrue(metadata["ongoing_revalidation_required_before_repair"])
        for item in metadata["observations"]:
            self.assertEqual(item["cli_exit_code"], 0)
            self.assertRegex(item["sha"], r"^[0-9a-f]{40}$")
        self.assertTrue(all(r["private"] is False and r["visibility"] == "public" and r["http_status"] == 200 for r in self.report["repositories"]))

    def test_csv_matches_json_and_next_batch_remains_unread_proposal(self):
        rows = list(csv.DictReader(io.StringIO((REPORTS / "content_batch1_files.csv").read_text(encoding="utf-8"))))
        self.assertEqual(len(rows), 64)
        for row, d in zip(rows, self.documents):
            self.assertEqual((row["file_id"], row["static_review_status"], row["blob_sha"]), (d["file_id"], d["static_review"]["static_status"], d["receipt"]["pin"]["blob_sha"]))
        proposal = json.loads((REPORTS / "content_batch1_next_plan.json").read_bytes())
        self.assertEqual((proposal["epistemic_status"], proposal["execution_status"]), ("PROPOSAL", "NOT_RUN"))
        self.assertEqual(len(proposal["paths"]), 48)
        self.assertEqual(sum(p["size_bytes"] for p in proposal["paths"]), 354807)
        prior = {(d["receipt"]["pin"]["repository_id"], d["receipt"]["pin"]["snapshot_sha"], d["receipt"]["pin"]["path"]) for d in self.documents}
        self.assertTrue(all((p["repository_id"], p["snapshot_sha"], p["path"]) not in prior and p["unread"] is True and p["source_read_status"] == "NOT_RUN" for p in proposal["paths"]))
        self.assertEqual(self.report["tests"]["main_cases_passed"], 564)
        self.assertEqual(self.report["tests"]["subtests_passed"], 18)
        self.assertEqual((self.report["tests"]["failures"], self.report["tests"]["errors"], self.report["tests"]["skips"]), (0, 0, 0))


if __name__ == "__main__":
    unittest.main()
