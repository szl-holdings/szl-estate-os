"""Commercial body gate for the estate control plane.

Distinct from ``szl_khipu.anatomy.evaluate_anatomy``, which answers organ
LIVE/DOWN (zero_heart, leak_canal, live_count). This module answers whether a
commercial action may pass the body.

Witnesses: HEART (policy), WILLAY (conscience, veto absolute), CIRCULATORY
(receipt liveness), SKELETON (Wave 0). Rule: 3-of-4 ALLOW; WILLAY veto cannot
be overridden by quorum; skeleton abstains while Wave 0 is unsigned.

MODELED. Khipu BFT remains Conjecture 2. Not live consensus. Not ATO.
Public freeze remains NO_MUTATION_READ_ONLY_STRATEGY.
"""

from __future__ import annotations

from typing import Any

KINDS = ("lyte.approve", "lyte.override", "estate.admit", "wave.unlock")

LIMITATION = (
    "evaluate_body_gate is MODELED. Distinct from szl-khipu evaluate_anatomy "
    "(organ LIVE/DOWN). Not production ATO. Khipu BFT remains Conjecture 2."
)

CONJECTURE = (
    "Khipu BFT 3-of-4 = Conjecture 2. MODELED in this OS — not a live "
    "multi-party consensus network."
)


def _vote(organ: str, name: str, vote: str, veto: bool, reason: str) -> dict[str, Any]:
    return {
        "organ": organ,
        "name": name,
        "vote": vote,
        "veto": bool(veto),
        "reason": reason,
    }


def heart_vote(policy_verdict: str, policy_hits: list[str], missing: list[str], rationale: str) -> dict[str, Any]:
    if policy_verdict == "DENY":
        reason = policy_hits[0] if policy_hits else "Policy deny."
    elif policy_verdict == "ABSTAIN":
        reason = missing[0] if missing else "Insufficient evidence."
    else:
        reason = (rationale[:140] if rationale else "Policy allows.")
    return _vote("heart", "HEART / Yuyay", policy_verdict, False, reason)


def willay_vote(policy_verdict: str, missing: list[str]) -> dict[str, Any]:
    empty = bool(missing) or policy_verdict == "ABSTAIN"
    if empty:
        return _vote(
            "willay",
            "WILLAY / conscience",
            "ABSTAIN",
            policy_verdict in ("ALLOW", "ESCALATE"),
            "Empty or thin evidence. Conscience vetoes ALLOW. Fail closed.",
        )
    if policy_verdict == "DENY":
        return _vote(
            "willay",
            "WILLAY / conscience",
            "DENY",
            True,
            "Fail-closed classifier agrees with the heart. Veto of any later override-without-reason.",
        )
    return _vote(
        "willay",
        "WILLAY / conscience",
        "ALLOW",
        False,
        "No conscience hit. Trust ceiling 0.97. Never 100%.",
    )


def circulatory_vote() -> dict[str, Any]:
    return _vote(
        "circulatory",
        "CIRCULATORY / Yawar",
        "ALLOW",
        False,
        "Receipt bus is up. Can seal whatever the heart emits. Liveness, not approval.",
    )


def skeleton_vote(*, wave0_unsigned: bool = True) -> dict[str, Any]:
    if wave0_unsigned:
        return _vote(
            "skeleton",
            "SKELETON / Khipu",
            "ABSTAIN",
            False,
            "Wave 0 unsigned. Admission gate holds. Skeleton will not authorize a new public surface or production ATO.",
        )
    return _vote("skeleton", "SKELETON / Khipu", "ALLOW", False, "Wave 0 signed. Skeleton may vote.")


def _finalize(votes: list[dict[str, Any]]) -> dict[str, Any]:
    allow_count = sum(1 for v in votes if v["vote"] == "ALLOW")
    deny_count = sum(1 for v in votes if v["vote"] == "DENY")
    abstain_count = sum(1 for v in votes if v["vote"] in ("ABSTAIN", "ESCALATE"))
    willay = next(v for v in votes if v["organ"] == "willay")
    heart = next(v for v in votes if v["organ"] == "heart")
    willay_veto = bool(willay["veto"])
    skeleton_abstain = next(v for v in votes if v["organ"] == "skeleton")["vote"] == "ABSTAIN"

    if heart["vote"] == "DENY" or willay["vote"] == "DENY":
        verdict = "DENY"
        reached = deny_count >= 2
        note = "Heart or conscience denied. The body will not pass a leaking action."
    elif willay_veto:
        verdict = "ABSTAIN"
        reached = False
        note = "WILLAY veto of ALLOW. Three-of-four cannot override conscience."
    elif allow_count >= 3 and not willay_veto:
        verdict = "ALLOW"
        reached = True
        note = "Three-of-four ALLOW and no conscience veto. MODELED — not a paid-pilot authorization."
    else:
        verdict = "ABSTAIN"
        reached = False
        note = "Quorum not reached for ALLOW. Fail closed to ABSTAIN. Skeleton still abstains while Wave 0 is unsigned."

    return {
        "verdict": verdict,
        "reached": reached,
        "allowCount": allow_count,
        "denyCount": deny_count,
        "abstainCount": abstain_count,
        "willayVeto": willay_veto,
        "skeletonAbstain": skeleton_abstain,
        "votes": votes,
        "evidenceClass": "MODELED",
        "conjecture": CONJECTURE,
        "note": note,
    }


def _eval(
    *,
    kind: str,
    verdict: str,
    reached: bool,
    willay_veto: bool,
    skeleton_abstain: bool,
    quorum: dict[str, Any] | None,
    reasons: list[str],
) -> dict[str, Any]:
    return {
        "kind": kind,
        "verdict": verdict,
        "reached": reached,
        "willayVeto": willay_veto,
        "skeletonAbstain": True if skeleton_abstain else skeleton_abstain,
        "quorum": quorum,
        "reasons": reasons,
        "evidenceClass": "MODELED",
        "runtimeState": "DEMO",
        "limitation": LIMITATION,
    }


def evaluate_body_gate(
    *,
    kind: str,
    policy_verdict: str = "ABSTAIN",
    policy_hits: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    rationale: str = "",
    reason: str = "",
    wave0_unsigned: bool = True,
) -> dict[str, Any]:
    """Gate a commercial action. Fail closed. MODELED."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind: {kind}")
    hits = list(policy_hits or [])
    missing = list(missing_evidence or [])

    if kind == "estate.admit":
        return _eval(
            kind=kind,
            verdict="DENY",
            reached=False,
            willay_veto=False,
            skeleton_abstain=True,
            quorum=None,
            reasons=["Wave 0 unsigned. Skeleton abstains. No new public surface."],
        )
    if kind == "wave.unlock":
        return _eval(
            kind=kind,
            verdict="DENY",
            reached=False,
            willay_veto=False,
            skeleton_abstain=True,
            quorum=None,
            reasons=["Skeleton abstains while the estate snapshot is unsigned. Later waves stay locked."],
        )

    quorum = _finalize(
        [
            heart_vote(policy_verdict, hits, missing, rationale),
            willay_vote(policy_verdict, missing),
            circulatory_vote(),
            skeleton_vote(wave0_unsigned=wave0_unsigned),
        ]
    )

    if kind == "lyte.override":
        ok = len((reason or "").strip()) >= 8
        if not ok:
            return _eval(
                kind=kind,
                verdict="DENY",
                reached=False,
                willay_veto=True,
                skeleton_abstain=True,
                quorum=quorum,
                reasons=["WILLAY veto of override-without-reason. Write the reason."],
            )
        return _eval(
            kind=kind,
            verdict="ALLOW",
            reached=False,
            willay_veto=quorum["willayVeto"],
            skeleton_abstain=True,
            quorum=quorum,
            reasons=["Human VP-PS overrides the body with a written reason. Receipt required. MODELED, not ROI."],
        )

    if quorum["verdict"] == "DENY" or quorum["willayVeto"] or policy_verdict == "DENY":
        return _eval(
            kind=kind,
            verdict="DENY",
            reached=quorum["reached"],
            willay_veto=quorum["willayVeto"],
            skeleton_abstain=True,
            quorum=quorum,
            reasons=[quorum["note"], "A leaking action cannot be approved. Override with a reason, or hold."],
        )
    if quorum["verdict"] == "ABSTAIN" or policy_verdict == "ABSTAIN":
        return _eval(
            kind=kind,
            verdict="ABSTAIN",
            reached=False,
            willay_veto=quorum["willayVeto"],
            skeleton_abstain=True,
            quorum=quorum,
            reasons=[quorum["note"], "Abstention is fail-closed. Close the evidence gap or hold."],
        )
    if not quorum["reached"]:
        return _eval(
            kind=kind,
            verdict="ABSTAIN",
            reached=False,
            willay_veto=quorum["willayVeto"],
            skeleton_abstain=True,
            quorum=quorum,
            reasons=["Three-of-four not reached for ALLOW."],
        )
    return _eval(
        kind=kind,
        verdict="ALLOW",
        reached=True,
        willay_veto=False,
        skeleton_abstain=True,
        quorum=quorum,
        reasons=["Body ALLOW. Engine ALLOW. Skeleton still abstains on new public surfaces."],
    )


def body_blocks_action(
    action: str,
    *,
    policy_verdict: str,
    policy_hits: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    rationale: str = "",
    reason: str = "",
    wave0_unsigned: bool = True,
) -> dict[str, Any] | None:
    if action in ("HOLD", "ROLLBACK"):
        return None
    kind = "lyte.override" if action == "OVERRIDE" else "lyte.approve"
    ev = evaluate_body_gate(
        kind=kind,
        policy_verdict=policy_verdict,
        policy_hits=policy_hits,
        missing_evidence=missing_evidence,
        rationale=rationale,
        reason=reason,
        wave0_unsigned=wave0_unsigned,
    )
    if action == "APPROVE" and ev["verdict"] != "ALLOW":
        return ev
    if action == "OVERRIDE" and ev["verdict"] == "DENY":
        return ev
    return None
