"""Offline cache redaction, boundedness, replay and corruption boundaries."""

from dataclasses import replace
import json

import pytest

from szl_estate.cache import MAX_CACHE_BYTES, MAX_PAGE_ITEMS, ResponseCache
from szl_estate.model import EvidenceCode, EvidenceFreshness, ProofOrigin, Provenance
from szl_estate.storage import StorageError, integrity_bytes, sha256_digest


def provenance():
    return Provenance("github", "https://api.github.com/orgs/szl-holdings/repos", "2026-09-30T12:00:00Z", "github:szl-holdings:full", "0" * 64, EvidenceFreshness.CURRENT, ProofOrigin.LIVE)


@pytest.mark.parametrize("visibility", ["unknown", "private"])
def test_nonpublic_bodies_are_withheld_and_secrets_not_in_receipts(tmp_path, visibility):
    cache = ResponseCache(tmp_path)
    result = cache.put("request", provenance(), 200, {"name": "secret-value", "token": "ghp_12345678901234567890", "Authorization": "Bearer do-not-log"}, visibility=visibility, projection_kind="github_repository")
    assert result.body is None
    assert result.body_disposition == "WITHHELD"
    raw = cache.path_for("request").read_text()
    assert "secret-value" not in raw and "ghp_" not in raw and "Bearer" not in raw
    assert cache.get("request").body is None


def test_default_no_projection_never_retains_arbitrary_text(tmp_path):
    cache = ResponseCache(tmp_path)
    cache.put("request", provenance(), 200, "private raw response", visibility="public")
    assert "private raw response" not in cache.path_for("request").read_text()
    assert cache.get("request").body is None


def test_explicit_public_projection_discards_unknown_headers_and_secret_values(tmp_path):
    cache = ResponseCache(tmp_path)
    body = {"id": 5, "name": "estate", "full_name": "szl-holdings/estate", "private": False,
            "description": "private free text", "headers": {"Authorization": "Bearer secret"},
            "default_branch": "ghp_12345678901234567890", "size": True}
    record = cache.put("request", provenance(), 200, body, visibility="public", projection_kind="github_repository")
    assert record.body == {"full_name": "szl-holdings/estate", "id": 5, "name": "estate", "private": False}
    raw = cache.path_for("request").read_text()
    assert "private free text" not in raw and "Bearer secret" not in raw and "ghp_" not in raw
    assert cache.get("request").body == record.body


def test_cache_digests_only_redacted_representation(tmp_path):
    cache = ResponseCache(tmp_path)
    first = cache.put("request", provenance(), 200, {"name": "estate", "private": False, "secret": "one"}, visibility="public", projection_kind="github_repository")
    second = cache.put("request", provenance(), 200, {"name": "estate", "private": False, "secret": "two"}, visibility="public", projection_kind="github_repository")
    assert first.provenance.digest == second.provenance.digest
    assert cache.get("request").provenance.digest == second.provenance.digest


@pytest.mark.parametrize("status,code", [(100, EvidenceCode.REMOTE_ERROR), (302, EvidenceCode.REMOTE_ERROR), (401, EvidenceCode.AUTH_FAILED), (403, EvidenceCode.AUTH_FAILED), (429, EvidenceCode.RATE_LIMITED), (503, EvidenceCode.REMOTE_ERROR), (None, EvidenceCode.ACCESS_UNVERIFIED)])
def test_error_bodies_always_withheld_with_fixed_codes(tmp_path, status, code):
    cache = ResponseCache(tmp_path)
    record = cache.put("request", provenance(), status, {"message": "private account error", "name": "secret-field"}, visibility="public", projection_kind="github_repository")
    assert record.error_code is code
    assert record.body is None
    assert "private account error" not in cache.path_for("request").read_text()
    assert cache.get("request").error_code is code


def test_object_list_distinctions_and_bounded_page_receipts(tmp_path):
    cache = ResponseCache(tmp_path)
    body = [{"id": i, "name": "estate", "private": False} for i in range(MAX_PAGE_ITEMS + 1)]
    result = cache.put("list-page", provenance(), 200, body, visibility="public", projection_kind="github_repository")
    assert isinstance(result.body, list) and len(result.body) == MAX_PAGE_ITEMS
    assert result.truncated and result.error_code is EvidenceCode.PARTIAL_RESULT
    assert cache.path_for("list-page").stat().st_size <= MAX_CACHE_BYTES
    assert cache.get("list-page").truncated
    result = cache.put("object-page", provenance(), 200, {"items": body[:2], "total_count": 2, "has_next_page": False, "cursor": "private-cursor"}, visibility="public", projection_kind="github_repository")
    assert result.body == {"items": [{"id": 0, "name": "estate", "private": False}, {"id": 1, "name": "estate", "private": False}], "total_count": 2, "has_next_page": False}
    assert cache.get("object-page").body == result.body


def test_hf_identifiers_and_sha_projection(tmp_path):
    cache = ResponseCache(tmp_path)
    result = cache.put("hf", provenance(), 200, {"id": "SZLHOLDINGS/model", "sha": "a" * 40, "downloads": 3, "private": False, "cardData": {"token": "secret"}}, visibility="public", projection_kind="hf_asset")
    assert result.body == {"id": "SZLHOLDINGS/model", "sha": "a" * 40, "downloads": 3, "private": False}
    assert cache.get("hf").body == result.body


def test_new_and_resumed_cache_receipts_are_never_live_proof(tmp_path):
    cache = ResponseCache(tmp_path)
    assert cache.get("missing") is None
    result = cache.put("request", provenance(), 200)
    assert not result.is_live_proof
    resumed = ResponseCache(tmp_path).get("request")
    assert resumed.provenance.origin is ProofOrigin.CACHE
    assert not resumed.is_live_proof


def test_secret_request_keys_are_hashed_and_never_logged(tmp_path):
    cache = ResponseCache(tmp_path)
    key = "https://example.com?token=do-not-store"
    cache.put(key, provenance(), 200)
    path = cache.path_for(key)
    assert "do-not-store" not in path.name
    assert key not in path.read_text()


def test_tamper_corruption_and_body_digest_mismatch_are_detected(tmp_path):
    cache = ResponseCache(tmp_path)
    cache.put("request", provenance(), 200, {"name": "estate", "private": False}, visibility="public", projection_kind="github_repository")
    path = cache.path_for("request")
    envelope = json.loads(path.read_text())
    envelope["payload"]["body"]["name"] = "modified"
    path.write_text(json.dumps(envelope))
    with pytest.raises(StorageError, match="^INTEGRITY_MISMATCH$"):
        cache.get("request")
    path.write_bytes(integrity_bytes(envelope["payload"]))
    with pytest.raises(StorageError, match="^CACHE_BODY_DIGEST_MISMATCH$"):
        cache.get("request")
    path.write_bytes(b"private malformed response")
    with pytest.raises(StorageError, match="^CORRUPT_JSON$"):
        cache.get("request")


def test_digest_match_cannot_admit_unknown_or_unsafe_body_fields(tmp_path):
    cache = ResponseCache(tmp_path)
    cache.put("request", provenance(), 200, {"name": "estate", "private": False}, visibility="public", projection_kind="github_repository")
    path = cache.path_for("request")
    payload = json.loads(path.read_text())["payload"]
    payload["body"]["token"] = "private-value"
    redacted = {key: payload[key] for key in ("body", "body_disposition", "projection_kind", "truncated")}
    payload["provenance"]["digest"] = sha256_digest(redacted)
    path.write_bytes(integrity_bytes(payload))
    with pytest.raises(StorageError, match="^UNSAFE_CACHE_BODY$"):
        cache.get("request")


def test_record_size_and_invalid_keys_fail_with_fixed_errors(tmp_path):
    cache = ResponseCache(tmp_path)
    with pytest.raises(StorageError, match="^INVALID_HTTP_STATUS$"):
        cache.put("request", provenance(), True)
    with pytest.raises(StorageError, match="^INVALID_CACHE_KEY$"):
        cache.get("")
    cache.path_for("request").write_bytes(b"x" * (MAX_CACHE_BYTES + 1))
    with pytest.raises(StorageError, match="^RECORD_TOO_LARGE$"):
        cache.get("request")


def test_cache_source_alias_prevents_overwrite(tmp_path):
    cache = ResponseCache(tmp_path)
    path = cache.path_for("request")
    path.write_bytes(b"source evidence")
    guarded = ResponseCache(tmp_path, source_paths=(path,))
    with pytest.raises(StorageError, match="^SOURCE_OUTPUT_ALIAS$"):
        guarded.put("request", provenance(), 200)
    assert path.read_bytes() == b"source evidence"


@pytest.mark.parametrize("kind", ["github_repository", "hf_asset"])
def test_public_request_does_not_override_private_or_unknown_row_visibility(tmp_path, kind):
    cache = ResponseCache(tmp_path)
    identity = "name" if kind == "github_repository" else "id"
    body = [
        {identity: "public-identity", "private": False},
        {identity: "private-identity", "private": True},
        {identity: "unknown-identity"},
    ]
    result = cache.put("mixed", provenance(), 200, body, visibility="public", projection_kind=kind)
    assert result.body == [{identity: "public-identity", "private": False}, {}, {}]
    assert result.truncated and result.error_code is EvidenceCode.PARTIAL_RESULT
    raw = cache.path_for("mixed").read_text()
    assert "private-identity" not in raw and "unknown-identity" not in raw
    assert cache.get("mixed").body == result.body


@pytest.mark.parametrize("kind", ["github_repository", "hf_asset"])
def test_contradictory_visibility_is_withheld_even_with_private_false(tmp_path, kind):
    cache = ResponseCache(tmp_path)
    identity = "name" if kind == "github_repository" else "id"
    result = cache.put("conflict", provenance(), 200, {identity: "private-identity", "private": False, "visibility": "private"}, visibility="public", projection_kind=kind)
    assert result.body == {}
    assert result.error_code is EvidenceCode.PARTIAL_RESULT
    assert "private-identity" not in cache.path_for("conflict").read_text()
    assert cache.get("conflict").body == {}


@pytest.mark.parametrize("field", ["projection_kind", "body_disposition"])
@pytest.mark.parametrize("malformed", [[], {}])
def test_integrity_valid_malformed_cache_enums_return_fixed_error(tmp_path, field, malformed):
    cache = ResponseCache(tmp_path)
    cache.put("request", provenance(), 200)
    path = cache.path_for("request")
    payload = json.loads(path.read_text())["payload"]
    payload[field] = malformed
    path.write_bytes(integrity_bytes(payload))
    with pytest.raises(StorageError, match="^INVALID_CACHE_RECORD$"):
        cache.get("request")


@pytest.mark.parametrize("kwargs,code", [({"visibility": []}, "INVALID_VISIBILITY"), ({"projection_kind": {}}, "INVALID_PROJECTION_KIND")])
def test_malformed_put_enum_types_return_fixed_error(tmp_path, kwargs, code):
    with pytest.raises(StorageError, match=f"^{code}$"):
        ResponseCache(tmp_path).put("request", provenance(), 200, **kwargs)
