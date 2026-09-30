"""Offline PR triage only: no merge, write, or other mutation executor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re


class PRState(str, Enum):
    MERGE_NOW_GREEN = "MERGE_NOW_GREEN"
    WAIT_CHECKS = "WAIT_CHECKS"
    FIX_CHECKS = "FIX_CHECKS"
    CONFLICT_REBASE = "CONFLICT_REBASE"
    DOCS_ONLY = "DOCS_ONLY"
    DRAFT_PRESERVE = "DRAFT_PRESERVE"
    HOLD_PRESERVE = "HOLD_PRESERVE"
    NEEDS_OWNER_DECISION = "NEEDS_OWNER_DECISION"


class CheckState(str, Enum):
    PASS = "PASS"
    WAIT = "WAIT"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RequiredCheck:
    name: str
    state: CheckState


@dataclass(frozen=True)
class PRFacts:
    """Explicit snapshot facts; nullable flags express missing evidence.

    No default grants permission. Required checks are scoped by the caller to
    the current PR head and branch protection. A check's PASS is never inferred
    from the absence of a failure or from a merely completed run.
    """

    is_open: bool | None = None
    draft: bool | None = None
    hold: bool | None = None
    access_confirmed: bool | None = None
    mergeable: bool | None = None
    conflicting: bool | None = None
    protection_known: bool | None = None
    review_scope_known: bool | None = None
    reviews_satisfied: bool | None = None
    required_checks_known: bool | None = None
    docs_only: bool | None = None
    required_checks: tuple[RequiredCheck, ...] = ()
    invalid_fields: tuple[str, ...] = ()
    checked_at_utc: str | None = None
    head_sha: str | None = None


@dataclass(frozen=True)
class Classification:
    state: PRState
    reasons: tuple[str, ...]
    checked_at_utc: str | None = None
    head_sha: str | None = None


_FLAGS = (
    "is_open", "draft", "hold", "access_confirmed", "mergeable", "conflicting",
    "protection_known", "review_scope_known", "reviews_satisfied",
    "required_checks_known", "docs_only",
)

_CHECK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_HEAD_SHA = re.compile(r"[0-9a-fA-F]{40}")
_UTC_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)")


def _valid_checked_at(value: object) -> bool:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return False
    return timestamp.utcoffset() == timedelta(0)


def _valid_head_sha(value: object) -> bool:
    return isinstance(value, str) and _HEAD_SHA.fullmatch(value) is not None


def parse_pr_facts(payload: object) -> PRFacts:
    """Decode normalized fixture/adapter facts; malformed values stay unknown."""

    if not isinstance(payload, Mapping):
        return PRFacts(invalid_fields=("INVALID_FACTS_SHAPE",))
    flags: dict[str, bool | None] = {}
    invalid: list[str] = []
    for name in _FLAGS:
        value = payload.get(name)
        if value is None or type(value) is bool:
            flags[name] = value
        else:
            flags[name] = None
            invalid.append("INVALID_BOOLEAN_FACT")
    checks: list[RequiredCheck] = []
    raw_checks = payload.get("required_checks", [])
    if not isinstance(raw_checks, list):
        invalid.append("INVALID_CHECK_COLLECTION")
    else:
        for raw in raw_checks:
            if not isinstance(raw, Mapping):
                invalid.append("INVALID_CHECK_RECORD")
                continue
            name, state = raw.get("name"), raw.get("state")
            if not isinstance(name, str) or _CHECK_NAME.fullmatch(name) is None:
                invalid.append("INVALID_CHECK_NAME")
                continue
            try:
                parsed_state = CheckState(state)
            except (TypeError, ValueError):
                parsed_state = CheckState.UNKNOWN
                invalid.append("INVALID_CHECK_STATE")
            checks.append(RequiredCheck(name, parsed_state))
    checked_at, head_sha = payload.get("checked_at_utc"), payload.get("head_sha")
    if checked_at is not None and not _valid_checked_at(checked_at):
        invalid.append("INVALID_SNAPSHOT_TIME")
        checked_at = None
    if head_sha is not None and not _valid_head_sha(head_sha):
        invalid.append("INVALID_HEAD_SHA")
        head_sha = None
    return PRFacts(
        **flags, required_checks=tuple(checks), invalid_fields=tuple(dict.fromkeys(invalid)),
        checked_at_utc=checked_at, head_sha=head_sha,
    )


def classify_pr(facts: PRFacts) -> Classification:
    """Classify a snapshot conservatively; eligibility never performs an action.

    Human HOLD and draft markers take priority. Conflicts precede check triage.
    Green requires accessible, explicitly scoped protection/review/check facts,
    a nonempty set of passing required checks, and positive mergeability, all
    scoped to an immutable head SHA and UTC snapshot. Time is not compared to a
    wall clock: this is an as-of recommendation, never lasting authorization.
    Documentation-only PRs remain review work even when every check passes.
    """

    if not isinstance(facts, PRFacts):
        return Classification(PRState.NEEDS_OWNER_DECISION, ("INVALID_FACTS_SHAPE",))
    checked_at = facts.checked_at_utc if _valid_checked_at(facts.checked_at_utc) else None
    head_sha = facts.head_sha if _valid_head_sha(facts.head_sha) else None

    def result(state: PRState, reasons: tuple[str, ...]) -> Classification:
        return Classification(state, reasons, checked_at, head_sha)

    if facts.hold is True:
        return result(PRState.HOLD_PRESERVE, ("EXPLICIT_HOLD",))
    if facts.draft is True:
        return result(PRState.DRAFT_PRESERVE, ("EXPLICIT_DRAFT",))
    if facts.invalid_fields or any(
        getattr(facts, name) is not None and type(getattr(facts, name)) is not bool for name in _FLAGS
    ):
        return result(PRState.NEEDS_OWNER_DECISION, ("INVALID_FACTS",))
    if facts.is_open is not True:
        return result(PRState.NEEDS_OWNER_DECISION, ("OPEN_STATE_UNCONFIRMED",))
    if facts.hold is not False or facts.draft is not False:
        return result(PRState.NEEDS_OWNER_DECISION, ("PRESERVATION_STATE_UNKNOWN",))
    if facts.conflicting is True:
        return result(PRState.CONFLICT_REBASE, ("CONFLICT_CONFIRMED",))
    if facts.access_confirmed is not True:
        return result(PRState.NEEDS_OWNER_DECISION, ("ACCESS_UNCONFIRMED",))
    if checked_at is None or head_sha is None:
        return result(PRState.NEEDS_OWNER_DECISION, ("SNAPSHOT_SCOPE_UNKNOWN",))
    if facts.required_checks_known is not True:
        return result(PRState.NEEDS_OWNER_DECISION, ("REQUIRED_CHECK_SCOPE_UNKNOWN",))
    if not isinstance(facts.required_checks, tuple) or not facts.required_checks:
        return result(PRState.NEEDS_OWNER_DECISION, ("NO_REQUIRED_CHECK_EVIDENCE",))
    if any(
        not isinstance(check, RequiredCheck)
        or not isinstance(check.name, str)
        or _CHECK_NAME.fullmatch(check.name) is None
        or not isinstance(check.state, CheckState)
        for check in facts.required_checks
    ):
        return result(PRState.NEEDS_OWNER_DECISION, ("INVALID_CHECK_EVIDENCE",))
    names = tuple(check.name for check in facts.required_checks)
    if len(set(names)) != len(names):
        return result(PRState.NEEDS_OWNER_DECISION, ("DUPLICATE_REQUIRED_CHECK",))
    states = {check.state for check in facts.required_checks}
    if CheckState.FAIL in states:
        return result(PRState.FIX_CHECKS, ("REQUIRED_CHECK_FAILED",))
    if CheckState.WAIT in states:
        return result(PRState.WAIT_CHECKS, ("REQUIRED_CHECK_PENDING",))
    if CheckState.UNKNOWN in states:
        return result(PRState.NEEDS_OWNER_DECISION, ("REQUIRED_CHECK_RESULT_UNKNOWN",))
    missing: list[str] = []
    for field, reason in (
        ("protection_known", "PROTECTION_SCOPE_UNKNOWN"),
        ("review_scope_known", "REVIEW_SCOPE_UNKNOWN"),
        ("reviews_satisfied", "REVIEWS_UNSATISFIED_OR_UNKNOWN"),
        ("mergeable", "MERGEABILITY_UNKNOWN"),
    ):
        if getattr(facts, field) is not True:
            missing.append(reason)
    if missing:
        return result(PRState.NEEDS_OWNER_DECISION, tuple(missing))
    if facts.docs_only is True:
        return result(PRState.DOCS_ONLY, ("DOCUMENTATION_REVIEW_REQUIRED",))
    if facts.docs_only is not False:
        return result(PRState.NEEDS_OWNER_DECISION, ("CHANGE_SCOPE_UNKNOWN",))
    return result(PRState.MERGE_NOW_GREEN, ("EXPLICIT_REQUIRED_EVIDENCE_GREEN",))
