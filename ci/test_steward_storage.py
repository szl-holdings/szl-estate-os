"""Synthetic local proof tests; no provider credentials or network."""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import SZL_ONE_OF_ONE_ESTATE_OS as estate
import frontier_steward as steward


def context() -> dict:
    return {
        "status": {
            "status": "MEASURED", "audit_id": "audit-storage-test",
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "asset_count": 0, "proposal_count": 0,
            "source_reports": [], "receipt_hash": "a" * 64,
            "receipt_chain": {"chain_valid": True, "status": "CHAIN_VALID_UNSIGNED"},
            "audit_receipt_binding": {"valid": True, "state": "BOUND"},
            "mutation_policy": "READ_ONLY",
        },
        "assets": [], "proposals": [],
        "operating_fabric": {"summary": {}, "action_queue": []},
    }


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="steward-storage-")
        self.root = Path(self.directory.name)
        self.db = self.root / "isolated.db"
        self.plan = self.root / "custom-plan.json"

    def tearDown(self):
        self.directory.cleanup()

    def write_plan(self):
        with mock.patch.object(estate, "steward_context", return_value=context()):
            return estate.command_steward_plan(
                self.db, mission="Map safe estate provenance", provider="deterministic",
                model=None, timeout=10, output_path=self.plan,
            )

    def seed_audit(self, *, with_receipt=True):
        status = context()["status"]
        connection = estate.connect_db(self.db)
        receipt_hash = "b" * 64
        if with_receipt:
            receipt_hash = estate.append_receipt(connection, audit_id=status["audit_id"], kind="ESTATE_AUDIT", payload={
                "audit_id": status["audit_id"], "status": "MEASURED", "completed_at": status["completed_at"],
                "asset_count": 0, "proposal_count": 0, "scope": {}, "sources": [],
            })["receipt_hash"]
        connection.execute(
            "INSERT INTO audit_runs (audit_id,started_at,completed_at,status,scope_json,source_reports_json,asset_count,proposal_count,receipt_hash,app_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (status["audit_id"], status["completed_at"], status["completed_at"], "MEASURED", "{}", "[]", 0, 0, receipt_hash, estate.APP_VERSION),
        )
        connection.commit()
        connection.close()

    def test_fabricated_audit_with_empty_valid_chain_blocks_model(self):
        self.seed_audit(with_receipt=False)
        data = estate.steward_context(self.db)
        self.assertTrue(data["status"]["receipt_chain"]["chain_valid"])
        self.assertFalse(data["status"]["audit_receipt_binding"]["valid"])
        result = steward.compile_plan(mission="Map safe estate evidence", context=data, response_transport=lambda *a: self.fail("unbound audit reached provider"))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["model"]["invoked"])

    def test_audit_transition_during_capture_blocks_mixed_context(self):
        self.seed_audit()
        initial = estate.load_status(self.db)
        changed = dict(initial, audit_id="audit-concurrent-successor")
        with mock.patch.object(estate, "load_status", side_effect=[initial, changed]):
            data = estate.steward_context(self.db)
        self.assertFalse(data["status"]["audit_receipt_binding"]["valid"])
        self.assertEqual(data["status"]["audit_receipt_binding"]["state"], "SNAPSHOT_CHANGED_DURING_CAPTURE")
        plan = steward.compile_plan(mission="Map safe evidence", context=data, response_transport=lambda *a: self.fail("mixed audit reached provider"))
        self.assertEqual(plan["status"], "BLOCKED")

    def test_writer_emits_bound_readback(self):
        self.seed_audit()
        result = estate.command_steward_plan(self.db, mission="Map safe evidence", provider="deterministic", model=None, timeout=10, output_path=self.plan)
        self.assertTrue(result["readback"]["current_recorded_projection"])
        self.assertEqual(result["readback"]["artifact_sha256"], result["artifact_sha256"])

    def test_audit_metadata_tampering_hides_recorded_proposals(self):
        self.seed_audit()
        result = estate.command_steward_plan(self.db, mission="Map safe estate evidence", provider="deterministic", model=None, timeout=10, output_path=self.plan)
        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(estate.load_steward_status(self.plan, self.db)["latest_plan"]["state"], "RECORDED")
        for column, value in (("completed_at", "2999-01-01T00:00:00+00:00"), ("status", "PARTIAL"), ("receipt_hash", "c" * 64)):
            connection = sqlite3.connect(self.db)
            original = connection.execute(f"SELECT {column} FROM audit_runs").fetchone()[0]
            connection.execute(f"UPDATE audit_runs SET {column}=?", (value,))
            connection.commit()
            connection.close()
            status = estate.load_steward_status(self.plan, self.db)["latest_plan"]
            self.assertEqual(status["state"], "STALE_EVIDENCE")
            self.assertFalse(status["evidence_current"])
            self.assertEqual(status["proposals"], [])
            connection = sqlite3.connect(self.db)
            connection.execute(f"UPDATE audit_runs SET {column}=?", (original,))
            connection.commit()
            connection.close()

    def test_bytes_receipt_and_immutable_artifact_bound(self):
        result = self.write_plan()
        immutable = Path(result["immutable_artifact"])
        self.assertEqual(immutable.read_bytes(), self.plan.read_bytes())
        status = estate.load_steward_status(self.plan, self.db)["latest_plan"]
        self.assertTrue(status["recorded"])
        self.assertEqual(status["artifact_sha256"], result["artifact_sha256"])
        self.assertTrue(estate.verify_receipt_chain(self.db, read_only=True)["chain_valid"])
        immutable.write_bytes(b"{}")
        status = estate.load_steward_status(self.plan, self.db)["latest_plan"]
        self.assertEqual(status["state"], "BROKEN")
        self.assertFalse(status["recorded"])
        self.assertEqual(status["proposals"], [])

    def test_valid_but_unrecorded_file_never_green(self):
        payload = steward.compile_plan(mission="Map safe estate evidence", context=context(), provider="deterministic")
        self.plan.write_text(json.dumps(payload), encoding="utf-8")
        result = estate.load_steward_status(self.plan, self.db)
        self.assertEqual(result["latest_plan"]["state"], "UNRECORDED")
        self.assertFalse(self.db.exists(), "status must not create a database")

    def test_receipt_failure_preserves_latest_projection(self):
        self.write_plan()
        original = self.plan.read_bytes()
        with mock.patch.object(estate, "append_receipt", side_effect=sqlite3.OperationalError("injected disk failure")):
            with self.assertRaises(sqlite3.OperationalError):
                self.write_plan()
        self.assertEqual(self.plan.read_bytes(), original)
        self.assertTrue(estate.verify_receipt_chain(self.db, read_only=True)["chain_valid"])

    def test_broken_chain_is_not_appended_or_green(self):
        self.write_plan()
        original = self.plan.read_bytes()
        connection = sqlite3.connect(self.db)
        connection.execute("UPDATE receipts SET previous_hash='tampered'")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(ValueError, "broken receipt chain"):
            self.write_plan()
        self.assertEqual(self.plan.read_bytes(), original)
        self.assertFalse(estate.load_steward_status(self.plan, self.db)["latest_plan"]["recorded"])

    def test_output_alias_and_unrelated_file_rejected(self):
        for target in (self.db, Path(str(self.db) + "-wal")):
            with self.assertRaises(ValueError):
                estate.command_steward_plan(self.db, mission="safe", provider="deterministic", model=None, timeout=10, output_path=target)
        self.plan.write_text('{"unrelated":true}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unrelated artifact"):
            self.write_plan()
        self.assertEqual(self.plan.read_text(), '{"unrelated":true}')

    def test_malformed_and_oversized_files_return_broken(self):
        for data in ('[]', '{"schema_version":NaN}', '{"x":1,"x":2}', '{"evidence_snapshot":[]}'):
            self.plan.write_text(data, encoding="utf-8")
            self.assertEqual(estate.load_steward_status(self.plan, self.db)["latest_plan"]["state"], "BROKEN")
        self.plan.write_bytes(b" " * (estate.MAX_RESPONSE_BYTES + 1))
        self.assertEqual(estate.load_steward_status(self.plan, self.db)["latest_plan"]["state"], "BROKEN")

    def test_custom_api_path_and_get_does_not_mint_receipts(self):
        self.write_plan()
        before = estate.verify_receipt_chain(self.db, read_only=True)["receipt_count"]
        handler = type("TestHandler", (estate.EstateRequestHandler,), {"db_path": self.db, "steward_plan_path": self.plan})
        server = estate.EstateHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/api/v1/steward/status", timeout=5) as response:
                result = json.load(response)
            self.assertEqual(result["latest_plan"]["path"], str(self.plan))
            self.assertTrue(result["latest_plan"]["recorded"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(estate.verify_receipt_chain(self.db, read_only=True)["receipt_count"], before)


if __name__ == "__main__":
    unittest.main()
