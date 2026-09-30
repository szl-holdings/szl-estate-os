"""Synthetic offline triage fixtures; no repository writes or live queries."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from szl_estate.classifier import CheckState, PRFacts, PRState, RequiredCheck, classify_pr, parse_pr_facts


FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "pr_states.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda case: case["name"])
def test_all_pr_states_and_fail_closed_cases(case):
    facts = parse_pr_facts(FIXTURES["base_facts"] | case["overrides"])
    result = classify_pr(facts)
    assert result.state.value == case["expected"]
    assert result.reasons


def test_fixture_covers_exact_user_state_names():
    assert {case["expected"] for case in FIXTURES["cases"]} == {state.value for state in PRState}


@pytest.mark.parametrize("field", [
    "is_open", "draft", "hold", "access_confirmed", "mergeable", "protection_known",
    "review_scope_known", "reviews_satisfied", "required_checks_known", "docs_only",
    "checked_at_utc", "head_sha",
])
def test_missing_decision_fact_never_means_green(field):
    raw = dict(FIXTURES["base_facts"])
    del raw[field]
    assert classify_pr(parse_pr_facts(raw)).state is PRState.NEEDS_OWNER_DECISION


@pytest.mark.parametrize("value", [0, 1, "true", "false", [], {}])
def test_boolean_coercion_cannot_grant_access(value):
    facts = parse_pr_facts(FIXTURES["base_facts"] | {"access_confirmed": value})
    assert facts.access_confirmed is None
    assert classify_pr(facts).state is PRState.NEEDS_OWNER_DECISION


@pytest.mark.parametrize("raw", [None, [], "green"])
def test_invalid_facts_shape_is_owner_decision(raw):
    assert classify_pr(parse_pr_facts(raw)).state is PRState.NEEDS_OWNER_DECISION


@pytest.mark.parametrize("checks", [
    None,
    {},
    [None],
    [{"name": "", "state": "PASS"}],
    [{"name": "x" * 129, "state": "PASS"}],
    [{"name": "unsafe\nname", "state": "PASS"}],
    [{"name": "focused-tests", "state": "completed"}],
    [{"name": "focused-tests", "state": True}],
    [{"name": "focused-tests", "state": "PASS"}, {"name": "focused-tests", "state": "PASS"}],
])
def test_malformed_or_ambiguous_required_checks_never_green(checks):
    facts = parse_pr_facts(FIXTURES["base_facts"] | {"required_checks": checks})
    assert classify_pr(facts).state is PRState.NEEDS_OWNER_DECISION


def test_failure_precedes_pending_and_unknown_checks():
    facts = parse_pr_facts(FIXTURES["base_facts"])
    facts = replace(facts, required_checks=(
        RequiredCheck("one", CheckState.UNKNOWN),
        RequiredCheck("two", CheckState.WAIT),
        RequiredCheck("three", CheckState.FAIL),
    ))
    assert classify_pr(facts).state is PRState.FIX_CHECKS


def test_unknown_facts_have_no_success_default():
    assert classify_pr(PRFacts()).state is PRState.NEEDS_OWNER_DECISION


def test_direct_dataclass_cannot_bypass_boolean_validation():
    facts = replace(parse_pr_facts(FIXTURES["base_facts"]), access_confirmed=1)
    assert classify_pr(facts).state is PRState.NEEDS_OWNER_DECISION


def test_direct_dataclass_cannot_bypass_check_validation():
    facts = replace(parse_pr_facts(FIXTURES["base_facts"]), required_checks=(RequiredCheck("test", "PASS"),))
    assert classify_pr(facts).state is PRState.NEEDS_OWNER_DECISION


def test_explicit_hold_survives_malformed_unrelated_fields():
    facts = parse_pr_facts(FIXTURES["base_facts"] | {"hold": True, "access_confirmed": "unknown"})
    assert classify_pr(facts).state is PRState.HOLD_PRESERVE


def test_classifier_is_only_a_state_and_reason_result():
    result = classify_pr(parse_pr_facts(FIXTURES["base_facts"]))
    assert set(result.__dataclass_fields__) == {"state", "reasons", "checked_at_utc", "head_sha"}
    assert result.checked_at_utc == FIXTURES["base_facts"]["checked_at_utc"]
    assert result.head_sha == FIXTURES["base_facts"]["head_sha"]


@pytest.mark.parametrize("value", [
    "2026-09-30", "2026-09-30T00:00:00", "2026-09-30T00:00:00+01:00",
    "2026-02-30T00:00:00Z", 1, "secret-snapshot-text",
])
def test_invalid_utc_snapshot_fails_closed_without_echo(value):
    result = classify_pr(parse_pr_facts(FIXTURES["base_facts"] | {"checked_at_utc": value}))
    assert result.state is PRState.NEEDS_OWNER_DECISION
    assert result.checked_at_utc is None
    assert str(value) not in result.reasons


@pytest.mark.parametrize("value", ["main", "0123456", "z" * 40, "a" * 41, 1])
def test_invalid_head_reference_fails_closed(value):
    result = classify_pr(parse_pr_facts(FIXTURES["base_facts"] | {"head_sha": value}))
    assert result.state is PRState.NEEDS_OWNER_DECISION
    assert result.head_sha is None
