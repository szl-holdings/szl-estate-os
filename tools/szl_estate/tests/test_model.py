"""Offline evidence/state invariants, including failed writes and proof boundaries."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from szl_estate.model import (
    ClaimBasis, ClaimMaturity, EstateState, EvidenceCode, EvidenceDimensions,
    EvidenceFreshness, EvidenceRecord, EvidenceStatus, EvidenceValidationError,
    ProofOrigin, Provenance, REQUIRED_ESTATE_SCOPES,
)
from szl_estate.storage import (
    StorageError, atomic_write, integrity_bytes, load_state, render_csv,
    render_json, render_markdown, save_state, write_reports,
)


NOW = "2026-09-30T12:00:00Z"


def record(scope=REQUIRED_ESTATE_SCOPES[0], **changes):
    evidence = EvidenceRecord(
        evidence_id=scope, scope=scope, status=EvidenceStatus.PASS,
        provenance=Provenance("fixture", "fixture://measured", NOW, scope, "0" * 64,
                              EvidenceFreshness.CURRENT, ProofOrigin.LIVE),
        complete=True,
        dimensions=EvidenceDimensions(
            EvidenceStatus.PASS, EvidenceStatus.PASS, EvidenceStatus.PASS,
            EvidenceStatus.PASS, (scope,),
        ),
        checked_at_utc=NOW,
    )
    return replace(evidence, **changes)


def state(*records, **changes):
    return EstateState(tuple(records), NOW, **changes)


def test_empty_or_subset_never_proves_whole_estate():
    assert not state().estate_ready
    assert not state(record()).estate_ready
    assert not state(record(), required_scopes=(REQUIRED_ESTATE_SCOPES[0],)).estate_ready


def test_readiness_requires_exact_complete_current_live_scopes_and_all_dimensions():
    records = tuple(record(scope) for scope in REQUIRED_ESTATE_SCOPES)
    assert state(*records).estate_ready  # synthetic fixture of the full conjunction
    for status in (EvidenceStatus.FAIL, EvidenceStatus.UNKNOWN, EvidenceStatus.PARTIAL, EvidenceStatus.INACCESSIBLE, EvidenceStatus.NOT_RUN):
        assert not state(replace(records[0], status=status), *records[1:]).estate_ready
    assert not state(replace(records[0], complete=False), *records[1:]).estate_ready
    assert not state(replace(records[0], code=EvidenceCode.REMOTE_ERROR), *records[1:]).estate_ready
    assert not state(replace(records[0], dimensions=EvidenceDimensions()), *records[1:]).estate_ready
    assert not state(replace(records[0], dimensions=replace(records[0].dimensions, proof_scope=("github:other:full",))), *records[1:]).estate_ready


@pytest.mark.parametrize("origin", [ProofOrigin.CACHE, ProofOrigin.LIBRARY, ProofOrigin.FIXTURE, ProofOrigin.UNKNOWN])
def test_recorded_replay_is_not_current_live_proof(origin):
    evidence = record()
    assert not replace(evidence, provenance=replace(evidence.provenance, origin=origin)).is_live_pass


def test_historical_or_unknown_freshness_never_live():
    evidence = record()
    for freshness in (EvidenceFreshness.HISTORICAL, EvidenceFreshness.UNKNOWN):
        changed = replace(evidence, provenance=replace(evidence.provenance, freshness=freshness))
        assert not changed.is_live_pass


@pytest.mark.parametrize("checked", [None, "2026-09-30T10:59:59Z", "2026-09-30T12:00:01Z"])
def test_access_check_unknown_old_or_future_fails_closed(checked):
    records = tuple(record(scope) for scope in REQUIRED_ESTATE_SCOPES)
    assert not state(replace(records[0], checked_at_utc=checked), *records[1:]).estate_ready


@pytest.mark.parametrize("observed", ["2026-09-30T10:59:59Z", "2026-09-30T12:00:01Z"])
def test_old_or_future_observation_not_promoted_by_fresh_check(observed):
    records = tuple(record(scope) for scope in REQUIRED_ESTATE_SCOPES)
    changed = replace(records[0], provenance=replace(records[0].provenance, observed_at_utc=observed))
    assert not state(changed, *records[1:]).estate_ready


def test_claim_maturity_and_basis_do_not_promote_unknown_dimensions():
    evidence = record(dimensions=EvidenceDimensions(), claim_maturity=ClaimMaturity.SHIPPING, claim_basis=ClaimBasis.FACT)
    assert evidence.dimensions.authorization is EvidenceStatus.UNKNOWN
    assert evidence.dimensions.cryptographic_integrity is EvidenceStatus.UNKNOWN
    assert not state(evidence).estate_ready
    changed = replace(evidence, claim_maturity=ClaimMaturity.ROADMAP, claim_basis=ClaimBasis.PROPOSAL)
    assert changed.dimensions == evidence.dimensions


@pytest.mark.parametrize("value", [True, -1, 1.5, "130"])
def test_counts_reject_invalid_numeric_evidence(value):
    with pytest.raises(EvidenceValidationError, match="^INVALID_COUNTS$"):
        record(counts={"repository_count": value})


def test_counts_keep_explicit_unknowns_and_are_immutable():
    counts = {"repository_count": 130, "unread_count": None}
    evidence = record(counts=counts)
    counts["repository_count"] = 0
    assert evidence.counts["repository_count"] == 130
    assert evidence.to_dict()["counts"]["unread_count"] is None
    with pytest.raises(TypeError):
        evidence.counts["repository_count"] = 0


@pytest.mark.parametrize("reference", ["https://user:password@example.com", "https://example.com?token=hidden", "fixture://ghp_1234567890123456789", "https://example.com\nAuthorization:Bearer-secret"])
def test_provenance_rejects_credential_paths_without_echoing_input(reference):
    with pytest.raises(EvidenceValidationError) as error:
        replace(record().provenance, reference=reference)
    assert reference not in str(error.value)
    assert "hidden" not in str(error.value)


def test_provenance_rejects_naive_and_invalid_times():
    for observed in ("2026-09-30T12:00:00", "2026-09-11T24:30:00Z", "unknown"):
        with pytest.raises(EvidenceValidationError, match="^INVALID_OBSERVATION_TIME$"):
            replace(record().provenance, observed_at_utc=observed)
    assert replace(record().provenance, observed_at_utc="2026-09-30T13:00:00+01:00").observed_at_utc == NOW


def test_reports_are_order_independent_and_csv_guards_formula_cells():
    first = record(REQUIRED_ESTATE_SCOPES[0], evidence_id="@formula")
    second = record(REQUIRED_ESTATE_SCOPES[1], counts={"asset_count": 3})
    left, right = state(first, second), state(second, first)
    assert render_json(left) == render_json(right)
    assert render_csv(left) == render_csv(right)
    assert render_markdown(left) == render_markdown(right)
    assert "'@formula" in render_csv(left)
    assert "recorded report time" in render_markdown(left)
    assert "cryptographic_integrity" in render_json(left)


@pytest.mark.parametrize("status", [EvidenceStatus.PASS, EvidenceStatus.UNKNOWN, EvidenceStatus.NOT_RUN, EvidenceStatus.INACCESSIBLE])
def test_state_roundtrip_and_digest_do_not_promote_proof(tmp_path, status):
    evidence = record(status=status, dimensions=EvidenceDimensions())
    original = state(evidence)
    destination = tmp_path / "estate_state.json"
    save_state(destination, original)
    assert load_state(destination) == original
    assert load_state(destination).evidence[0].status is status
    assert load_state(destination).evidence[0].dimensions.cryptographic_integrity is EvidenceStatus.UNKNOWN
    assert not load_state(destination).estate_ready


def test_corruption_and_readiness_forgery_are_not_success(tmp_path):
    destination = tmp_path / "estate_state.json"
    save_state(destination, state(record()))
    envelope = json.loads(destination.read_text())
    envelope["payload"]["evidence"][0]["status"] = "FAIL"
    destination.write_text(json.dumps(envelope))
    with pytest.raises(StorageError, match="^INTEGRITY_MISMATCH$"):
        load_state(destination)
    payload = state(record()).to_dict()
    payload["estate_ready"] = True
    destination.write_bytes(integrity_bytes(payload))
    with pytest.raises(StorageError, match="^INVALID_STATE$"):
        load_state(destination)


def test_duplicate_json_keys_rejected(tmp_path):
    destination = tmp_path / "estate_state.json"
    destination.write_text('{"payload":{},"payload":{}}')
    with pytest.raises(StorageError, match="^DUPLICATE_JSON_KEY$"):
        load_state(destination)


def test_atomic_failure_preserves_old_file_and_new_named_temporary(tmp_path, monkeypatch):
    destination = tmp_path / "estate_state.json"
    destination.write_bytes(b"original")
    def fail_replace(source, target):
        raise OSError("private remote error text must not be returned")
    monkeypatch.setattr("szl_estate.storage.os.replace", fail_replace)
    with pytest.raises(StorageError, match="^ATOMIC_WRITE_FAILED$") as error:
        atomic_write(destination, b"replacement")
    assert destination.read_bytes() == b"original"
    assert error.value.retained_path is not None
    assert error.value.retained_path.read_bytes() == b"replacement"


def test_output_alias_preflight_and_report_names(tmp_path):
    destination = tmp_path / "estate_state.json"
    destination.write_bytes(b"source")
    with pytest.raises(StorageError, match="^SOURCE_OUTPUT_ALIAS$"):
        write_reports(tmp_path, state(record()), source_paths=(destination,))
    assert destination.read_bytes() == b"source"
    assert not (tmp_path / "evidence.csv").exists()
    outputs = write_reports(tmp_path / "reports", state(record()), source_paths=(destination,))
    assert {path.name for path in outputs.values()} == {"estate_state.json", "evidence.csv", "report.md"}


def test_hardlink_output_alias_is_rejected(tmp_path):
    original = tmp_path / "source.json"
    original.write_bytes(b"source")
    alias = tmp_path / "alias.json"
    try:
        alias.hardlink_to(original)
    except OSError:
        pytest.skip("hard links unavailable in this filesystem")
    with pytest.raises(StorageError, match="^SOURCE_OUTPUT_ALIAS$"):
        atomic_write(alias, b"replacement", source_paths=(original,))
    assert original.read_bytes() == b"source"


def test_malformed_and_oversize_state_errors_are_fixed(tmp_path):
    destination = tmp_path / "estate_state.json"
    destination.write_bytes(b"credential text: not json")
    with pytest.raises(StorageError, match="^CORRUPT_JSON$"):
        load_state(destination)
    with pytest.raises(StorageError, match="^READ_FAILED$"):
        load_state(tmp_path / "absent.json")


def test_duplicates_and_scope_mismatch_are_rejected():
    with pytest.raises(EvidenceValidationError, match="^DUPLICATE_EVIDENCE_ID$"):
        state(record(), record())
    with pytest.raises(EvidenceValidationError, match="^PROVENANCE_SCOPE_MISMATCH$"):
        replace(record(), scope="github:other:full")
