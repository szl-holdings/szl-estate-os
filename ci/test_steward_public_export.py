"""Synthetic export transaction tests; no provider, credentials or release claim."""
from __future__ import annotations

import copy
import datetime as dt
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import SZL_ONE_OF_ONE_ESTATE_OS as estate


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="steward-public-export-test-")
        self.root = Path(self.directory.name)
        self.db = self.root / "synthetic.db"
        self.plan = self.root / "synthetic-plan.json"
        self.output = self.root / "steward-public.json"
        self.revision = "a" * 40

    def tearDown(self):
        self.directory.cleanup()

    def seed(self, github_scope="PUBLIC_ONLY"):
        observed = dt.datetime.now(dt.timezone.utc).isoformat()
        sources = [
            {"source": "github", "scope": github_scope, "status": "MEASURED"},
            {"source": "huggingface", "scope": "PUBLIC_ONLY", "status": "MEASURED"},
            {"source": "domains", "scope": "PUBLIC_NETWORK", "status": "MEASURED"},
        ]
        audit_id = "audit-" + uuid.uuid4().hex
        connection = estate.connect_db(self.db)
        receipt = estate.append_receipt(connection, audit_id=audit_id, kind="ESTATE_AUDIT", payload={
            "audit_id": audit_id, "status": "MEASURED", "completed_at": observed,
            "asset_count": 0, "proposal_count": 0, "scope": {}, "sources": sources,
        })
        connection.execute(
            "INSERT INTO audit_runs (audit_id,started_at,completed_at,status,scope_json,source_reports_json,asset_count,proposal_count,receipt_hash,app_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (audit_id, observed, observed, "MEASURED", "{}", json.dumps(sources), 0, 0, receipt["receipt_hash"], estate.APP_VERSION),
        )
        connection.commit()
        connection.close()
        context = {
            "status": {
                "status": "MEASURED", "audit_id": audit_id, "completed_at": observed,
                "asset_count": 0, "proposal_count": 0, "source_reports": sources,
                "receipt_hash": receipt["receipt_hash"],
                "receipt_chain": {"chain_valid": True, "status": "CHAIN_VALID_UNSIGNED"},
                "audit_receipt_binding": {"valid": True, "state": "BOUND"},
                "mutation_policy": "READ_ONLY",
            },
            "assets": [], "proposals": [],
            "operating_fabric": {"summary": {}, "action_queue": []},
        }
        with mock.patch.object(estate, "steward_context", return_value=context):
            result = estate.command_steward_plan(
                self.db, mission="Map public estate evidence", provider="deterministic",
                model=None, timeout=10, output_path=self.plan,
            )
        self.assertTrue(result["readback"]["current_recorded_projection"])

    def export(self):
        with mock.patch.object(estate, "verify_steward_export_source"):
            return estate.command_steward_export_public(self.db, self.plan, self.output, self.revision)

    def test_recorded_public_export_has_bound_bytes_and_receipt(self):
        self.seed()
        result = self.export()
        content = self.output.read_bytes()
        self.assertEqual(estate.sha256_bytes(content), result["projection_sha256"])
        self.assertEqual(Path(result["immutable_artifact"]).read_bytes(), content)
        payload = json.loads(content)
        self.assertFalse(payload["production_ready"])
        self.assertEqual(payload["scope"], "PUBLIC_READ_ONLY")
        self.assertNotIn(str(self.root), content.decode())
        self.assertNotIn("synthetic.db", content.decode())
        self.assertEqual(result["receipt"]["kind"], "frontier_steward_public_export")
        self.assertTrue(estate.verify_receipt_chain(self.db, read_only=True)["chain_valid"])

    def test_authenticated_scope_is_refused_before_file_write(self):
        self.seed(github_scope="AUTHENTICATED_COMPLETE")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / "steward-public-artifacts").exists())

    def test_receipt_failure_preserves_previous_projection(self):
        self.seed()
        self.export()
        previous = self.output.read_bytes()
        with mock.patch.object(estate, "append_receipt", side_effect=RuntimeError("synthetic write failure")):
            with self.assertRaises(RuntimeError):
                self.export()
        self.assertEqual(previous, self.output.read_bytes())

    def test_transition_during_capture_is_refused_before_publication(self):
        self.seed()
        status = estate.load_steward_status(self.plan, self.db)
        changed = copy.deepcopy(status)
        changed["latest_plan"]["plan_id"] = "steward-plan-" + "b" * 24
        with mock.patch.object(estate, "load_steward_status", side_effect=[status, changed]):
            with self.assertRaises(ValueError):
                self.export()
        self.assertFalse(self.output.exists())

    def test_unrelated_output_is_not_overwritten(self):
        self.seed()
        self.output.write_text('{"private":"test sentinel"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            self.export()
        self.assertEqual(json.loads(self.output.read_text()), {"private": "test sentinel"})

    def test_source_revision_rejects_malformed_before_git(self):
        with mock.patch("subprocess.run") as runner:
            with self.assertRaises(ValueError):
                estate.verify_steward_export_source("main")
            runner.assert_not_called()

    def test_source_revision_must_equal_actual_head(self):
        with mock.patch("subprocess.run", return_value=mock.Mock(stdout=("b" * 40 + "\n").encode())):
            with self.assertRaises(ValueError):
                estate.verify_steward_export_source(self.revision)

    def test_parser_requires_source_revision(self):
        with self.assertRaises(SystemExit):
            estate.build_parser().parse_args(["steward-export-public"])
        args = estate.build_parser().parse_args(["steward-export-public", "--source-revision", self.revision])
        self.assertEqual(args.command, "steward-export-public")


if __name__ == "__main__":
    unittest.main()
