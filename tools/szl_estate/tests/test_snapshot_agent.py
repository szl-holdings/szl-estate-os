"""Contract tests for the offline snapshot recommendation boundary."""

import hashlib
import json

import pytest

from szl_estate.cli import main
from szl_estate.snapshot_agent import ProjectionError, recommend_projection_bytes


def projection():
    return {
        "schema": "szl.estate-scout-projection.v1",
        "projected_at_utc": "2026-10-02T04:15:00+00:00",
        "source_observed_at_utc": "2026-10-02T03:00:00Z",
        "scope": "authenticated snapshot; numeric projection only",
        "authentic": False,
        "byte_consistent_with_unsigned_manifest": True,
        "github": {
            "repositories": 3,
            "private": 1,
            "archived": 0,
            "default_head_ci_states": {"SUCCESS": 1, "FAILURE": 1, "UNOBSERVED": 1},
        },
        "huggingface": {
            "spaces": 2,
            "models": 1,
            "datasets": 1,
            "private_spaces": 1,
            "private_models": 0,
            "private_datasets": 0,
            "provider_space_stages": {"RUNNING": 1, "RUNTIME_ERROR": 1},
        },
        "source_sha256": {"github.json": "a" * 64, "huggingface.json": "b" * 64},
        "functional_readiness": "NOT_VERIFIED",
        "model_qualification": "NOT_VERIFIED",
        "external_witness": "NOT_RUN",
    }


def encode(value):
    return json.dumps(value, sort_keys=True).encode("utf-8")


def test_recommendations_are_cited_proposals_with_no_promotion():
    raw = encode(projection())
    report = recommend_projection_bytes(raw)
    assert report["schema"] == "szl.estate-scout-recommendations.v1"
    assert report["citations"]["projection"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["citations"]["github"]["sha256"] == "a" * 64
    assert report["citations"]["huggingface"]["integrity"] == "UNSIGNED_SELF_REPORTED_DIGEST"
    assert report["source_observed_at_utc"] == "2026-10-02T03:00:00Z"
    assert report["snapshot_authenticity"] == "NOT_VERIFIED"
    assert report["live_verification"] == "NOT_RUN"
    assert report["estate_readiness"] == "UNKNOWN"
    assert report["model_qualification"] == "NOT_VERIFIED"
    by_id = {item["recommendation_id"]: item for item in report["recommendations"]}
    assert by_id["EXACT_HEAD_CHECK_REVIEW"]["observed_counts"]["default_heads_without_success_rollup"] == 2
    assert by_id["SPACE_RUNTIME_PROBES"]["observed_counts"]["error_stage_spaces"] == 1
    assert "MODEL_EVALUATION_PROTOCOL" in by_id
    assert "DATASET_LINEAGE_REVIEW" in by_id
    assert all(item["execution"] == "PROPOSE_ONLY" and item["authorization"] == "NOT_GRANTED"
               and item["claim_basis"] == "PROPOSAL" for item in report["recommendations"])


def test_green_default_heads_still_do_not_grant_merge_or_runtime_readiness():
    value = projection()
    value["github"]["default_head_ci_states"] = {"SUCCESS": 3}
    value["huggingface"]["provider_space_stages"] = {"RUNNING": 2}
    report = recommend_projection_bytes(encode(value))
    ids = {item["recommendation_id"] for item in report["recommendations"]}
    assert "PR_GATE_SCOPE_REVIEW" in ids
    assert "SPACE_RUNTIME_PROBES" in ids
    assert report["estate_readiness"] == "UNKNOWN"
    assert report["external_witness"] == "NOT_RUN"


@pytest.mark.parametrize("change,code", [
    (lambda p: p.update(authentic=True), "UNSUPPORTED_ASSERTION"),
    (lambda p: p.update(model_qualification="VERIFIED"), "UNSUPPORTED_ASSERTION"),
    (lambda p: p["github"].update(default_head_ci_states={"SUCCESS": 1}), "COUNT_CONFLICT"),
    (lambda p: p["huggingface"].update(private_models=2), "COUNT_CONFLICT"),
    (lambda p: p.update(secret="sensitive_user_value_123"), "INVALID_SHAPE"),
    (lambda p: p["huggingface"].update(provider_space_stages={"user_supplied_key": 2}), "INVALID_STATES"),
    (lambda p: p.update(source_observed_at_utc="2026-10-03T00:00:00Z"), "INVALID_TIME_ORDER"),
])
def test_bad_or_promotional_projection_fails_closed(change, code):
    value = projection()
    change(value)
    with pytest.raises(ProjectionError) as failure:
        recommend_projection_bytes(encode(value))
    assert str(failure.value) == code
    assert "secret" not in str(failure.value)


def test_duplicate_keys_and_oversize_are_rejected():
    raw = encode(projection()).replace(b'"authentic": false', b'"authentic": false, "authentic": true')
    with pytest.raises(ProjectionError, match="DUPLICATE_KEY"):
        recommend_projection_bytes(raw)
    with pytest.raises(ProjectionError, match="INPUT_TOO_LARGE_OR_INVALID"):
        recommend_projection_bytes(b"{" + b"x" * (64 * 1024) + b"}")


def test_cli_emits_only_validated_projection_or_fixed_error(tmp_path, capsys):
    path = tmp_path / "projection.json"
    path.write_bytes(encode(projection()))
    assert main(["recommend-scout", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["recommendations"][0]["recommendation_id"] == "PROVENANCE_AND_SCOPE_REVIEW"
    path.write_text('{"secret":"sensitive_user_value_123"}', encoding="utf-8")
    assert main(["recommend-scout", str(path)]) == 2
    output = capsys.readouterr().out
    assert json.loads(output) == {"code": "INVALID_SHAPE", "status": "FAIL"}
    assert "sensitive_user_value_123" not in output
