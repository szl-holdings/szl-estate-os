from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.action_assurance import expected_signature_payload_digest
from estate.action_assurance_contract import reject_non_finite_json_constant
from estate.action_assurance_store import (
    current_trust_report,
    ingest_action_assurance,
    latest_citation_report,
    list_passports,
    store_status,
)

FIXTURE_DIR = ROOT / "fixtures" / "action_assurance"
NOW = datetime(2026, 8, 11, 5, 30, tzinfo=timezone.utc)


def load_object(path: Path) -> dict:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=reject_non_finite_json_constant,
    )
    assert isinstance(value, dict)
    return value


class ActionAssuranceRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "estate.db"
        self.execute = load_object(FIXTURE_DIR / "passports" / "execute.json")
        self.refuse = load_object(FIXTURE_DIR / "passports" / "refuse.json")
        self.citations = load_object(FIXTURE_DIR / "citations.current.json")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def ingest(self, passports: list[dict]) -> dict:
        return ingest_action_assurance(
            self.db,
            passports,
            self.citations,
            source_label="test",
            now=NOW,
        )

    def test_initial_ingest_persists_both_passports(self) -> None:
        result = self.ingest([self.execute, self.refuse])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["inserted_count"], 2)
        status = store_status(self.db)
        self.assertEqual(status["passport_count"], 2)
        self.assertEqual(status["agent_count"], 1)
        self.assertEqual(status["latest_ingest"]["status"], "PASS")

    def test_exact_reingest_is_idempotent(self) -> None:
        first = self.ingest([self.execute, self.refuse])
        second = self.ingest([self.execute, self.refuse])
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(second["status"], "PASS")
        self.assertEqual(second["inserted_count"], 0)
        self.assertEqual(second["idempotent_count"], 2)
        self.assertEqual(store_status(self.db)["passport_count"], 2)

    def test_conflicting_reuse_of_passport_id_fails_closed(self) -> None:
        self.assertEqual(self.ingest([self.execute])["status"], "PASS")
        changed = copy.deepcopy(self.execute)
        changed["authority"]["resource"] = "estate:test:changed"
        changed["signature"]["payload_sha3_256"] = expected_signature_payload_digest(changed)
        result = self.ingest([changed])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["conflict_count"], 1)
        self.assertEqual(store_status(self.db)["passport_count"], 1)

    def test_batch_duplicate_id_fails_without_overwriting(self) -> None:
        result = self.ingest([self.execute, copy.deepcopy(self.execute)])
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["invalid_count"], 1)
        self.assertEqual(store_status(self.db)["passport_count"], 1)

    def test_passport_filters_return_expected_records(self) -> None:
        self.assertEqual(self.ingest([self.execute, self.refuse])["status"], "PASS")
        approval_only = list_passports(self.db, decision="REQUIRE_APPROVAL")
        block_only = list_passports(self.db, decision="BLOCK")
        self.assertEqual(len(approval_only), 1)
        self.assertEqual(approval_only[0]["policy_decision"], "REQUIRE_APPROVAL")
        self.assertEqual(len(block_only), 1)
        self.assertEqual(block_only[0]["policy_decision"], "BLOCK")

    def test_trust_and_citation_reports_are_available(self) -> None:
        self.assertEqual(self.ingest([self.execute, self.refuse])["status"], "PASS")
        trust = current_trust_report(self.db, now=NOW)
        citations = latest_citation_report(self.db)
        self.assertEqual(trust["evidence_label"], "MODELED")
        self.assertEqual(len(trust["agents"]), 1)
        self.assertIsNotNone(citations)
        assert citations is not None
        self.assertEqual(citations["status"], "PASS")

    def test_stale_citation_batch_fails_but_keeps_truthful_ingest_record(self) -> None:
        stale = copy.deepcopy(self.citations)
        stale["entries"][0]["next_review_at"] = "2026-08-10T00:00:00+00:00"
        stale["entries"][0]["status"] = "STALE"
        result = ingest_action_assurance(
            self.db,
            [self.execute],
            stale,
            source_label="test-stale",
            now=NOW,
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["citation_status"], "FAIL")
        self.assertEqual(store_status(self.db)["latest_ingest"]["status"], "FAIL")

    def test_latest_ingest_uses_insertion_order_when_timestamps_match(self) -> None:
        first = self.ingest([self.execute])
        self.assertEqual(first["status"], "PASS")
        stale = copy.deepcopy(self.citations)
        stale["entries"][0]["next_review_at"] = "2026-08-10T00:00:00+00:00"
        stale["entries"][0]["status"] = "STALE"
        second = ingest_action_assurance(
            self.db,
            [self.execute],
            stale,
            source_label="same-clock-later",
            now=NOW,
        )
        self.assertEqual(second["status"], "FAIL")
        latest = store_status(self.db)["latest_ingest"]
        self.assertEqual(latest["ingest_id"], second["ingest_id"])
        self.assertEqual(latest["status"], "FAIL")
        citations = latest_citation_report(self.db)
        self.assertIsNotNone(citations)
        assert citations is not None
        self.assertEqual(citations["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
