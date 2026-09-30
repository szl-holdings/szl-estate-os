"""Stdlib report-data checks only; no candidate imports, tests or network."""
from collections import Counter
import csv
import io
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
BASE = "1422dc8a7898aa7f4c8c7b873439a4c58469b3c4"


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
        cls.r = load((ROOT / "evidence.json").read_bytes())
        cls.d = load((ROOT / "requirements_delta.json").read_bytes())
        cls.files = cls.r["files"]
        cls.by_source = {(f["repository_id"], f["snapshot_sha"], f["path"]): f for f in cls.files}

    def test_01_unique_exact_identities_and_collection_counts(self):
        self.assertEqual(len(self.files), 35)
        self.assertEqual(len({(f["repository_id"], f["snapshot_sha"], f["path"], f["blob_sha"]) for f in self.files}), 35)
        self.assertEqual({f["file_id"] for f in self.files}, {f"R3-{i:03}" for i in range(1, 35)} | {"R3-D01"})
        self.assertEqual(Counter(f["collection"] for f in self.files), {"main": 34, "domain": 1})

    def test_02_byte_and_static_status_counts(self):
        self.assertEqual(Counter(f["byte_status"] for f in self.files), {"COMPLETE": 35})
        self.assertEqual(Counter(f["static_status"] for f in self.files), {"COMPLETE": 22, "PARTIAL": 13})
        for f in self.files:
            if f["static_status"] == "COMPLETE":
                self.assertEqual(f["privacy_withheld_lines"] + f["scope_excluded_lines"], 0)

    def test_03_exact_lines_bytes_and_scope_accounting(self):
        expected = {"size_bytes": 174560, "available_lines": 4217, "privacy_withheld_lines": 17, "scope_excluded_lines": 279, "eligible_reviewed_lines": 3921}
        for key, total in expected.items():
            self.assertEqual(sum(f[key] for f in self.files), total)
            self.assertEqual(self.r["coverage"][key], total)
        for f in self.files:
            self.assertEqual(f["available_lines"], f["privacy_withheld_lines"] + f["scope_excluded_lines"] + f["eligible_reviewed_lines"])

    def test_04_historical_union_and_denominator(self):
        c = self.r["coverage"]
        self.assertEqual((c["historical_baseline"], c["newly_verified_unique_paths"], c["prior_overlap"]), (650, 35, 0))
        self.assertEqual(c["combined_byte_accounted_paths"], 685)
        self.assertEqual(c["remaining_unread_or_skipped_paths"], 32063)
        self.assertEqual(685 + 32063, c["historical_total_paths"])

    def test_05_separate_input_and_execution_receipts(self):
        p = self.r["provenance"]
        self.assertEqual(p["proposal_sha256"], "ed54468e53538fe5d2ef929fd08e7c15a1a8f5776fb7cad9d340bd317ebe4927")
        self.assertEqual(p["normalized_main_plan_sha256"], "f81276b47217286883bfadc9885ad9a83e8885b376acaee781d6dd1d503dcb76")
        self.assertEqual(p["published_prior_batch_report_sha256"], "08918f62d52f711ce9ea308d0807b7134882e0221b3a3d7a01d582a029411f45")
        self.assertEqual(self.r["collections"]["main"]["execution_envelope_sha256"], "d7afa4f2e2f23fa7f2ca9e98df0325364a3daa1f07173f4aee0af5119ce53b07")
        self.assertEqual(self.r["collections"]["domain"]["execution_envelope_sha256"], "08c4c14cca63a047964e45518c72c6bc174b8f8c65c701b260b5b0b90483f87f")

    def test_06_full_hashes_and_original_object_binding(self):
        for f in self.files:
            self.assertRegex(f["snapshot_sha"], r"^[0-9a-f]{40}$")
            self.assertRegex(f["blob_sha"], r"^[0-9a-f]{40}$")
            self.assertEqual(f["original_blob_sha1"], f["blob_sha"])
            for key in ("original_sha256", "screened_cache_sha256", "scope_view_sha256"):
                self.assertRegex(f[key], r"^[0-9a-f]{64}$")
            self.assertTrue(f["source_endpoint"].endswith("/git/blobs/" + f["blob_sha"]))

    def test_07_scope_projection_cannot_grant_fresh_proof(self):
        p = self.r["provenance"]["scope_projection"]
        self.assertEqual(p["source_origin"], "CACHE_SCOPE_RESCREEN")
        for key in ("source_refetched", "fresh_source_proof", "source_body_committed"):
            self.assertIs(p[key], False)
        self.assertEqual(len(p["entries"]), 35)
        by_id = {f["file_id"]: f for f in self.files}
        for entry in p["entries"]:
            f = by_id[entry["file_id"]]
            self.assertEqual(entry["old_cache_sha256"], f["screened_cache_sha256"])
            self.assertEqual(entry["scope_view_sha256"], f["scope_view_sha256"])
            self.assertEqual(len(entry["scope_excluded_lines"]), f["scope_excluded_lines"])

    def test_08_unique_pinned_findings_and_allowed_primary_anchors(self):
        findings = self.r["findings"]
        self.assertEqual(len(findings), 24)
        self.assertEqual(len({f["finding_id"] for f in findings}), 24)
        self.assertIn("R3-CONTEXT-001", {f["finding_id"] for f in findings})
        for f in findings:
            row = self.by_source[(f["repository_id"], f["snapshot_sha"], f["path"])]
            self.assertTrue(1 <= f["line_start"] <= f["line_end"] <= row["available_lines"])
            for interval in row["excluded_ranges"]:
                self.assertFalse(f["line_start"] <= interval["line_end"] and interval["line_start"] <= f["line_end"])
            self.assertIn("/blob/" + f["snapshot_sha"] + "/", f["source_url"])

    def test_09_no_candidate_execution_repairs_or_readiness_promotion(self):
        self.assertIs(self.r["source_execution_performed"], False)
        self.assertIs(self.r["phase2_ready"], False)
        self.assertIs(self.r["estate_ready"], False)
        self.assertEqual(self.r["runtime_status"], "NOT_RUN")
        self.assertEqual(self.r["novelty"], "NOT_ESTABLISHED")
        for f in self.r["findings"]:
            self.assertEqual(f["runtime_test_status"], "NOT_RUN")
            self.assertEqual(f["repairs_status"], "NOT_ATTEMPTED")
            self.assertEqual(f["acceptance_test_basis"], "PROPOSAL")
            self.assertEqual(f["owner_assignment_status"], "PROPOSED_NOT_ASSIGNED")

    def test_10_csv_exact_projection(self):
        rows = list(csv.DictReader(io.StringIO((ROOT / "files.csv").read_text())))
        self.assertEqual(len(rows), 35)
        for actual, expected in zip(rows, self.files):
            for k, value in actual.items():
                self.assertEqual(value, "" if expected[k] is None else str(expected[k]))

    def test_11_domain_observation_keeps_unknowns(self):
        d = self.r["domain_observation"]
        self.assertEqual(d["declared_source_hostname"], "holdings.a-11-oy.com")
        self.assertEqual(d["requested_domain_source_binding"], "UNKNOWN_NOT_ESTABLISHED")
        self.assertEqual(d["current_ownership_hosting_configuration_error_cause"], "UNKNOWN")
        self.assertEqual(d["external_observation"]["http_response_status"], "UNKNOWN_UNEXPOSED")
        self.assertIs(d["external_observation"]["dns_or_universal_outage_claim"], False)
        self.assertEqual(self.r["failed_domain_preflight"]["source_coverage_credit"], 0)

    def test_12_current_heads_and_unexposed_http(self):
        heads = self.r["current_head_observations"]
        self.assertEqual(len(heads), 3)
        self.assertEqual(sum(h["equals_review_pin"] is False for h in heads), 2)
        for head in heads:
            self.assertEqual(head["http_status"], "UNKNOWN_UNEXPOSED")
            self.assertIs(head["fresh_revalidation_required_before_repair"], True)
            self.assertTrue(head["checked_at_utc"])

    def test_13_additive_stack_and_historical_tool_validation(self):
        self.assertEqual(self.r["stack"]["base_sha"], BASE)
        self.assertEqual(self.r["stack"]["base_pull_request"], 55)
        h = self.r["historical_tool_validation"]
        self.assertIs(h["rerun_for_this_batch"], False)
        self.assertEqual((h["package_cases"], h["subtests"]), (564, 18))

    def test_14_backlog_is_unimplemented_and_traceable(self):
        d = self.d
        self.assertEqual(d["base_requirements_sha256"], "07ee446171c475ac2d6ede2ee3093454dfb41852cccb4806bb7a7f1cd29da4ec")
        self.assertEqual(len(d["requirements"]), 20)
        self.assertEqual({r["id"] for r in d["requirements"]}, {f"DELTA-{i:03}" for i in range(1, 21)})
        for r in d["requirements"]:
            self.assertTrue(set(r["base_requirement_ids"]) <= set(d["base_requirement_ids"]))
            self.assertEqual(r["status"], "BACKLOG_UNIMPLEMENTED")
            self.assertEqual(r["acceptance_test_status"], "NOT_RUN")
            self.assertIs(r["automated_action_authorized"], False)
        quickstart = next(r for r in d["requirements"] if r["id"] == "DELTA-002")
        self.assertIn("<=60 seconds", quickstart["acceptance_criterion"])
        self.assertIn("unmet", quickstart["acceptance_criterion"])

    def test_15_summary_evidence_is_not_local_byte_or_implementation_proof(self):
        for source in self.d["sources"].values():
            self.assertIs(source["local_original_bytes_verified"], False)
            if "supplied_sha256" in source:
                self.assertRegex(source["supplied_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(source["payload_execution"], "NOT_RUN")
        self.assertEqual(self.d["implementation_status"], "BACKLOG_ONLY")
        self.assertEqual(self.d["numerical_ground_truth"], "UNVERIFIED")
        self.assertEqual(self.d["sources"]["FRONTIER1_SUPPLIED_PIN"]["coverage_credit"], 0)
        geh = next(r for r in self.d["requirements"] if r["id"] == "DELTA-018")
        self.assertIn("fixed three axioms", geh["desired_state"])

    def test_16_privacy_patterns_sections_and_portable_bytes(self):
        names = ("report.md", "evidence.json", "files.csv", "requirements_delta.json", "requirements_delta.md", "check_report.py", ".gitattributes")
        published = ""
        for name in names:
            raw = (ROOT / name).read_bytes()
            self.assertNotIn(b"\r", raw)
            if name != "check_report.py":
                published += raw.decode()
        for pattern in (r"(?i)[A-Z]:[\\/]Users[\\/]", r"/home/[^/\s]+/", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bhf_[A-Za-z0-9]{20,}\b", r"(?i)\bAuthorization\s*:", r"\b(?:libfile|connector|session|thread)_[0-9a-f]{12,}\b"):
            self.assertIsNone(re.search(pattern, published))
        self.assertEqual(re.findall(r"^## ([1-7])\. ", (ROOT / "report.md").read_text(), re.MULTILINE), list("1234567"))
        for name in ("report.md", "requirements_delta.md"):
            self.assertIsNone(re.search(r"(?m)^\|[^\n]*\|\n\n\|", (ROOT / name).read_text()))
        backlog = (ROOT / "requirements_delta.md").read_text()
        self.assertEqual(re.findall(r"(?m)^\| (DELTA-\d{3}) \|", backlog), [f"DELTA-{i:03}" for i in range(1, 21)])

    def test_17_duplicate_and_nonfinite_json_rejected(self):
        with self.assertRaises(ValueError):
            load('{"status":"UNKNOWN","status":"PASS"}')
        with self.assertRaises(ValueError):
            load('{"measurement":NaN}')

    def test_18_frontier_checkpoint_preserves_history_and_partial_execution(self):
        historical = self.d["sources"]["FRONTIER1_SUPPLIED_PIN"]
        checkpoint = self.d["sources"]["FRONTIER1_REPAIR_CHECKPOINT"]
        self.assertEqual(historical["commit"], "1071a3fe96a010f011274d2f820ca5351d0b4eff")
        self.assertEqual(checkpoint["commit"], "a060b82bc63ac99d4048a2a9e5da0535a3d54e84")
        self.assertEqual(checkpoint["predecessor_source_ref"], "FRONTIER1_SUPPLIED_PIN")
        self.assertEqual(checkpoint["work_orders"], {
            "WO1": "OWNER_PENDING", "WO2": "OWNER_PENDING",
            "WO3": "UNAVAILABLE_IN_REPORTED_RUNNER", "WO4": "OBSERVATION_COMPLETE",
            "WO5": "OWNER_PENDING", "WO6": "OWNER_PENDING", "WO7": "OBSERVATION_COMPLETE",
        })
        self.assertEqual(checkpoint["gpu_absence"], "UNKNOWN_NOT_ESTABLISHED")
        self.assertEqual(checkpoint["publication_gate"], "CLOSED")
        self.assertIs(checkpoint["all_work_orders_fully_executed"], False)
        self.assertEqual(checkpoint["coverage_credit"], 0)
        self.assertEqual(checkpoint["candidate_execution"], "NOT_RUN_BY_THIS_WORKER")
        self.assertEqual(checkpoint["exact_checked_at"], "UNKNOWN_UNSUPPLIED")
        self.assertEqual(checkpoint["validation"], {
            "basis": "OWNER_REPORTED_CHECKPOINT", "ci_passed": 3,
            "failure_error_counts": "UNKNOWN_UNSUPPLIED", "independently_rerun_by_this_worker": False,
            "local_passed": 31, "local_skipped": 1, "skip_reason": "Windows link skip",
        })
        self.assertEqual(checkpoint["receipt_path"], "payloads/evidence/frontier1-runs/public-observation-20260930")
        backlog = (ROOT / "requirements_delta.md").read_text()
        for key, value in checkpoint["work_orders"].items():
            self.assertIn(f"| {key} | {value} |", backlog)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReportChecks))
    print(json.dumps({"report_checks": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skips": len(result.skipped), "candidate_tests": "NOT_RUN"}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
