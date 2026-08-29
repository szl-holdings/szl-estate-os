from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.anatomy_gate import body_blocks_action, evaluate_body_gate  # noqa: E402
from estate.khipu_number import decode_decimal, encode_decimal  # noqa: E402

VECTORS_PATH = ROOT / "fixtures" / "anatomy_gate_vectors.json"


class AnatomyGateTests(unittest.TestCase):
    def test_admit_denies_new_public_surface(self) -> None:
        ev = evaluate_body_gate(kind="estate.admit")
        self.assertEqual(ev["verdict"], "DENY")
        self.assertFalse(ev["reached"])
        self.assertIn("Wave 0 unsigned", ev["reasons"][0])
        self.assertEqual(ev["evidenceClass"], "MODELED")

    def test_wave_unlock_denies_while_skeleton_abstains(self) -> None:
        ev = evaluate_body_gate(kind="wave.unlock")
        self.assertEqual(ev["verdict"], "DENY")
        self.assertTrue(ev["skeletonAbstain"])

    def test_approve_of_leaking_sow_denies(self) -> None:
        ev = evaluate_body_gate(
            kind="lyte.approve",
            policy_verdict="DENY",
            policy_hits=["margin floor 22%"],
            rationale="18% is below the floor.",
        )
        self.assertEqual(ev["verdict"], "DENY")
        self.assertTrue(ev["willayVeto"])
        self.assertIsNotNone(ev["quorum"])
        self.assertGreaterEqual(ev["quorum"]["denyCount"], 2)

    def test_override_without_reason_is_willay_veto(self) -> None:
        ev = evaluate_body_gate(
            kind="lyte.override",
            policy_verdict="DENY",
            policy_hits=["margin floor 22%"],
            reason="",
        )
        self.assertEqual(ev["verdict"], "DENY")
        self.assertTrue(ev["willayVeto"])

    def test_override_with_written_reason_allows_modeled(self) -> None:
        ev = evaluate_body_gate(
            kind="lyte.override",
            policy_verdict="DENY",
            policy_hits=["margin floor 22%"],
            reason="VP-PS written hold pending legal.",
        )
        self.assertEqual(ev["verdict"], "ALLOW")
        self.assertIn("MODELED", ev["reasons"][0])

    def test_approve_of_accepted_work_allows(self) -> None:
        ev = evaluate_body_gate(
            kind="lyte.approve",
            policy_verdict="ALLOW",
            rationale="Acceptance evidence is present.",
        )
        self.assertEqual(ev["verdict"], "ALLOW")
        self.assertTrue(ev["reached"])
        self.assertEqual(ev["quorum"]["allowCount"], 3)
        self.assertTrue(ev["skeletonAbstain"])

    def test_body_blocks_approve_on_deny(self) -> None:
        blocked = body_blocks_action(
            "APPROVE",
            policy_verdict="DENY",
            policy_hits=["no invoice without acceptance"],
        )
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["verdict"], "DENY")

    def test_hold_is_never_blocked_by_body(self) -> None:
        self.assertIsNone(body_blocks_action("HOLD", policy_verdict="DENY"))

    def test_abstain_fails_closed(self) -> None:
        ev = evaluate_body_gate(
            kind="lyte.approve",
            policy_verdict="ABSTAIN",
            missing_evidence=["documented assumptions", "named owner"],
        )
        self.assertEqual(ev["verdict"], "ABSTAIN")
        self.assertFalse(ev["reached"])

    def test_escalate_approve_fails_closed(self) -> None:
        blocked = body_blocks_action("APPROVE", policy_verdict="ESCALATE")
        self.assertIsNotNone(blocked)
        self.assertEqual(blocked["verdict"], "ABSTAIN")

    def test_unknown_kind_raises(self) -> None:
        with self.assertRaises(ValueError):
            evaluate_body_gate(kind="public.mint")

    def test_inca_decimal_round_trips_modeled_held(self) -> None:
        held = 76500
        digits = encode_decimal(held)
        self.assertEqual(decode_decimal(digits), held)
        self.assertEqual([d["digit"] for d in digits], [0, 7, 6, 5, 0, 0])

    def test_honesty_labels(self) -> None:
        ev = evaluate_body_gate(kind="estate.admit")
        self.assertEqual(ev["runtimeState"], "DEMO")
        self.assertIn("Not production ATO", ev["limitation"])
        self.assertIn("szl-khipu", ev["limitation"])

    def test_golden_vectors(self) -> None:
        payload = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "szl.anatomy-gate.vectors/v1")
        self.assertEqual(payload["standingHeldUsd"], 76500)
        self.assertEqual(payload["evidenceClass"], "MODELED")
        for row in payload["vectors"]:
            with self.subTest(row["id"]):
                ev = evaluate_body_gate(
                    kind=row["kind"],
                    policy_verdict=row.get("policy_verdict", "ABSTAIN"),
                    policy_hits=row.get("policy_hits"),
                    missing_evidence=row.get("missing_evidence"),
                    rationale=row.get("rationale", ""),
                    reason=row.get("reason", ""),
                )
                self.assertEqual(ev["verdict"], row["expect"], row)
                if "willayVeto" in row:
                    self.assertEqual(ev["willayVeto"], row["willayVeto"], row)
                if "reached" in row:
                    self.assertEqual(ev["reached"], row["reached"], row)


if __name__ == "__main__":
    unittest.main()
