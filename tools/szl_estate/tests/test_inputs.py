"""Synthetic evidence fixtures: no credentials, network, or production data."""

from __future__ import annotations

import hashlib
import json
import struct
import zipfile
from pathlib import Path

import pytest

from szl_estate import inputs


def _backend_documents() -> dict[str, dict]:
    return {
        "audit-summary.json": {
            "finalized_at": "2025-01-02T03:04:05+00:00",
            "repositories": 3,
            "tracked_entries_metadata_classified": 11,
            "content_read_or_statically_checked_paths": 4,
            "unread_or_skipped_paths": 7,
            "private_body": "MUST_NOT_APPEAR",
        },
        "current-content-summary.json": {
            "updated_at": "2025-01-03T03:04:05.000123Z",
            "tracked_paths": 11,
            "content_read_or_statically_checked_paths": 4,
            "unread_or_skipped_paths": 7,
        },
        "bundle-manifest.json": {
            "created_at": "2025-01-04T03:04:05Z",
            "coverage": {
                "metadata_source_snapshots": 3,
                "metadata_entries": 11,
                "content_read_or_statically_checked": 4,
                "unread_or_skipped": 7,
            },
        },
    }


def _write_zip(path: Path, documents: dict[str, object], **kwargs) -> Path:
    with zipfile.ZipFile(path, "w", **kwargs) as archive:
        for name, document in documents.items():
            payload = document if isinstance(document, bytes) else json.dumps(document)
            archive.writestr(name, payload)
    return path


def _hf_document() -> dict:
    return {
        "schema": "szl.hf-readonly-audit/v1",
        "generated_at_utc": "2024-12-01T01:02:03.004567+00:00",
        "summary": {
            "asset_count": 10,
            "repo_counts": {"datasets": 1, "kernels": 2, "models": 3, "spaces": 4},
            "listed_file_paths": 22,
            "card_content_inspected": 9,
            "http_probes": 2,
            "http_200": 2,
            "unrecognized_counter": 123456,
        },
        "assets": [{"id": "PRIVATE_NAME", "token": "PRIVATE_SECRET"}],
    }


def _write_hf(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_backend_reconciles_counts_and_preserves_content_snapshot_date(tmp_path):
    path = _write_zip(tmp_path / "bundle.zip", _backend_documents())
    summary = inputs.load_backend_summary(path)
    assert summary.kind == "github_inventory"
    assert summary.observed_at_utc == "2025-01-03T03:04:05.000123Z"
    assert summary.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert summary.error_code is None
    assert summary.counts == {
        "repositories": 3, "tracked_paths": 11, "content_inspected": 4,
        "unread_paths": 7, "metadata_source_snapshots": 3,
    }
    assert "MUST_NOT_APPEAR" not in repr(summary)


def test_backend_does_not_extract_or_read_other_members(tmp_path):
    documents = _backend_documents()
    documents["../../escape.py"] = b"raise RuntimeError('DO_NOT_EXECUTE')"
    documents["private-data.json"] = b"not valid JSON or public evidence"
    path = _write_zip(tmp_path / "bundle.zip", documents)
    assert inputs.load_backend_summary(path).error_code is None
    assert set(tmp_path.iterdir()) == {path}


def test_backend_partial_bundle_preserves_known_counts_without_success(tmp_path):
    documents = _backend_documents()
    del documents["bundle-manifest.json"]
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "partial.zip", documents))
    assert summary.error_code == "SUMMARY_MISSING"
    assert summary.counts["repositories"] == 3
    assert summary.counts["metadata_source_snapshots"] is None


def test_backend_conflicting_count_is_unknown(tmp_path):
    documents = _backend_documents()
    documents["current-content-summary.json"]["tracked_paths"] = 12
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "conflict.zip", documents))
    assert summary.error_code == "COUNT_CONFLICT"
    assert summary.counts["tracked_paths"] is None
    assert summary.counts["content_inspected"] == 4


def test_backend_repositories_and_snapshot_count_must_agree(tmp_path):
    documents = _backend_documents()
    documents["bundle-manifest.json"]["coverage"]["metadata_source_snapshots"] = 4
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "conflict.zip", documents))
    assert summary.error_code == "COUNT_CONFLICT"
    assert summary.counts["repositories"] is None
    assert summary.counts["metadata_source_snapshots"] is None


def test_backend_content_partition_must_reconcile(tmp_path):
    documents = _backend_documents()
    for name in ("audit-summary.json", "current-content-summary.json"):
        documents[name]["unread_or_skipped_paths"] = 6
    documents["bundle-manifest.json"]["coverage"]["unread_or_skipped"] = 6
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "bad-partition.zip", documents))
    assert summary.error_code == "COUNT_INCONSISTENT"
    assert all(summary.counts[key] is None for key in (
        "tracked_paths", "content_inspected", "unread_paths",
    ))


@pytest.mark.parametrize("invalid", [True, -1, 2.5, "4", None, 2**63])
def test_backend_invalid_counter_is_unknown_not_zero(tmp_path, invalid):
    documents = _backend_documents()
    documents["audit-summary.json"]["content_read_or_statically_checked_paths"] = invalid
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "invalid.zip", documents))
    assert summary.error_code == "INVALID_COUNT"
    assert summary.counts["content_inspected"] is None


def test_backend_missing_field_does_not_claim_complete_summary(tmp_path):
    documents = _backend_documents()
    del documents["audit-summary.json"]["repositories"]
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "incomplete.zip", documents))
    assert summary.error_code == "SUMMARY_INCOMPLETE"
    assert summary.counts["repositories"] is None


def test_backend_invalid_member_json_keeps_safe_partial_counts(tmp_path):
    documents = _backend_documents()
    documents["audit-summary.json"] = b"PRIVATE_RESPONSE_NOT_JSON"
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "invalid.zip", documents))
    assert summary.error_code == "INVALID_JSON"
    assert summary.counts["repositories"] is None
    assert summary.counts["tracked_paths"] == 11
    assert "PRIVATE_RESPONSE" not in repr(summary)


def test_backend_invalid_zip_keeps_entire_file_digest(tmp_path):
    path = tmp_path / "invalid.zip"
    path.write_bytes(b"PRIVATE_NOT_A_ZIP")
    summary = inputs.load_backend_summary(path)
    assert summary.error_code == "INVALID_ZIP"
    assert summary.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not summary.counts
    assert "PRIVATE_NOT_A_ZIP" not in repr(summary)


def test_backend_corrupt_compressed_summary_returns_fixed_error(tmp_path):
    path = _write_zip(
        tmp_path / "corrupt.zip", _backend_documents(), compression=zipfile.ZIP_DEFLATED,
    )
    with zipfile.ZipFile(path) as archive:
        header_offset = archive.getinfo("audit-summary.json").header_offset
    payload = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from("<HH", payload, header_offset + 26)
    compressed_offset = header_offset + 30 + name_length + extra_length
    # A reserved deflate block type provokes the codec's own error path.
    payload[compressed_offset] = 0xFF
    path.write_bytes(payload)
    summary = inputs.load_backend_summary(path)
    assert summary.error_code == "INVALID_ZIP"
    assert not summary.counts
    assert summary.digest == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA, 99])
def test_backend_rejects_unbounded_or_unsupported_summary_codecs(tmp_path, method):
    path = _write_zip(tmp_path / "codec.zip", _backend_documents())
    payload = bytearray(path.read_bytes())
    central_offset = payload.index(b"PK\x01\x02")
    # Change only the advertised codec; rejection must precede decompression.
    struct.pack_into("<H", payload, 8, method)
    struct.pack_into("<H", payload, central_offset + 10, method)
    path.write_bytes(payload)
    summary = inputs.load_backend_summary(path)
    assert summary.error_code == "ZIP_UNSUPPORTED_COMPRESSION"
    assert not summary.counts


def test_backend_invalid_content_timestamp_does_not_use_packaging_date(tmp_path):
    documents = _backend_documents()
    documents["current-content-summary.json"]["updated_at"] = "PRIVATE_INVALID_DATE"
    summary = inputs.load_backend_summary(_write_zip(tmp_path / "date.zip", documents))
    assert summary.error_code == "INVALID_TIMESTAMP"
    assert summary.observed_at_utc is None
    assert summary.counts["content_inspected"] == 4
    assert "PRIVATE_INVALID_DATE" not in repr(summary)


def test_backend_duplicate_desired_member_is_rejected(tmp_path):
    path = _write_zip(tmp_path / "duplicates.zip", _backend_documents())
    with zipfile.ZipFile(path, "a") as archive, pytest.warns(UserWarning):
        archive.writestr("audit-summary.json", "{}")
    summary = inputs.load_backend_summary(path)
    assert summary.error_code == "ZIP_SUMMARY_DUPLICATE"
    assert not summary.counts


@pytest.mark.parametrize("limit, value, expected", [
    ("MAX_ARCHIVE_MEMBERS", 2, "ZIP_MEMBER_LIMIT"),
    ("MAX_EXPANDED_BYTES", 8, "ZIP_EXPANDED_LIMIT"),
    ("MAX_SUMMARY_BYTES", 8, "ZIP_SUMMARY_TOO_LARGE"),
])
def test_backend_archive_limits_fail_closed(tmp_path, monkeypatch, limit, value, expected):
    path = _write_zip(tmp_path / "bounded.zip", _backend_documents())
    monkeypatch.setattr(inputs, limit, value)
    summary = inputs.load_backend_summary(path)
    assert summary.error_code == expected
    assert not summary.counts
    assert summary.digest == hashlib.sha256(path.read_bytes()).hexdigest()


def test_expanded_limit_includes_unselected_compressed_members(tmp_path, monkeypatch):
    documents = _backend_documents()
    documents["do-not-read.bin"] = b"x" * 4096
    path = _write_zip(tmp_path / "compressed.zip", documents, compression=zipfile.ZIP_DEFLATED)
    monkeypatch.setattr(inputs, "MAX_EXPANDED_BYTES", 2048)
    assert inputs.load_backend_summary(path).error_code == "ZIP_EXPANDED_LIMIT"


@pytest.mark.parametrize("reader", [inputs.load_backend_summary, inputs.load_hf_summary])
def test_input_file_limit_prevents_unbounded_reads(tmp_path, monkeypatch, reader):
    path = tmp_path / "large.dat"
    path.write_bytes(b"123456789")
    monkeypatch.setattr(inputs, "MAX_INPUT_BYTES", 8)
    summary = reader(path)
    assert summary.error_code == "INPUT_TOO_LARGE"
    assert summary.digest is None
    assert not summary.counts


@pytest.mark.parametrize("reader", [inputs.load_backend_summary, inputs.load_hf_summary])
def test_unreadable_file_does_not_expose_path_or_exception(tmp_path, reader):
    summary = reader(tmp_path / "PRIVATE_PATH_SECRET")
    assert summary.error_code == "INPUT_UNREADABLE"
    assert summary.digest is None
    assert "PRIVATE_PATH_SECRET" not in repr(summary)


def test_hf_preserves_historical_provenance_and_only_allowlisted_counters(tmp_path):
    path = _write_hf(tmp_path / "historical.json", _hf_document())
    summary = inputs.load_hf_summary(path)
    assert summary.kind == "hf_historical_inventory"
    assert summary.observed_at_utc == "2024-12-01T01:02:03.004567Z"
    assert summary.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert summary.error_code is None
    assert summary.counts["asset_count"] == 10
    assert summary.counts["models"] == 3
    assert summary.counts["listed_file_paths"] == 22
    assert "unrecognized_counter" not in summary.counts
    assert "PRIVATE_" not in repr(summary)


def test_hf_unknown_schema_fails_closed(tmp_path):
    document = _hf_document()
    document["schema"] = "PRIVATE_UNSUPPORTED_SCHEMA"
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "wrong-schema.json", document))
    assert summary.error_code == "HF_SCHEMA_UNSUPPORTED"
    assert not summary.counts
    assert "PRIVATE_UNSUPPORTED_SCHEMA" not in repr(summary)


@pytest.mark.parametrize("stamp", [
    None, "2025-01-01", "2025-01-01T01:00:00+01:00", "2025-02-30T01:00:00Z",
    "2025-01-01T01:00:00", "PRIVATE_BAD_DATE",
])
def test_hf_invalid_or_non_utc_timestamp_is_unknown(tmp_path, stamp):
    document = _hf_document()
    document["generated_at_utc"] = stamp
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "date.json", document))
    assert summary.error_code == "INVALID_TIMESTAMP"
    assert summary.observed_at_utc is None
    assert summary.counts["asset_count"] == 10


def test_hf_missing_counter_is_unknown(tmp_path):
    document = _hf_document()
    del document["summary"]["repo_counts"]["kernels"]
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "partial.json", document))
    assert summary.error_code == "SUMMARY_INCOMPLETE"
    assert summary.counts["kernels"] is None
    assert summary.counts["models"] == 3


def test_hf_missing_optional_counter_is_explicitly_unknown(tmp_path):
    document = _hf_document()
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "optional.json", document))
    assert summary.error_code is None
    assert summary.counts["files_inventoried_only"] is None
    assert summary.counts["space_container_running"] is None


@pytest.mark.parametrize("invalid", [True, 2**63])
def test_hf_boolean_or_oversized_counter_is_not_integer_evidence(tmp_path, invalid):
    document = _hf_document()
    document["summary"]["asset_count"] = invalid
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "boolean.json", document))
    assert summary.error_code == "INVALID_COUNT"
    assert summary.counts["asset_count"] is None


def test_hf_asset_total_must_match_categories(tmp_path):
    document = _hf_document()
    document["summary"]["asset_count"] = 11
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "mismatch.json", document))
    assert summary.error_code == "COUNT_INCONSISTENT"
    assert summary.counts["asset_count"] is None


def test_hf_successful_http_count_cannot_exceed_probes(tmp_path):
    document = _hf_document()
    document["summary"]["http_200"] = 3
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "mismatch.json", document))
    assert summary.error_code == "COUNT_INCONSISTENT"
    assert summary.counts["http_200"] is None


@pytest.mark.parametrize("document", [[], {"schema": "szl.hf-readonly-audit/v1", "summary": []}])
def test_hf_wrong_object_shapes_fail_closed(tmp_path, document):
    summary = inputs.load_hf_summary(_write_hf(tmp_path / "shape.json", document))
    assert summary.error_code == "INVALID_SUMMARY_SHAPE"
    assert not summary.counts


def test_hf_duplicate_json_keys_cannot_override_evidence(tmp_path):
    path = tmp_path / "duplicates.json"
    path.write_bytes(b'{"schema":"szl.hf-readonly-audit/v1","schema":"SECRET"}')
    summary = inputs.load_hf_summary(path)
    assert summary.error_code == "INVALID_JSON"
    assert "SECRET" not in repr(summary)


def test_hf_malformed_json_never_returns_parser_messages(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(b"PRIVATE_RESPONSE_SECRET")
    summary = inputs.load_hf_summary(path)
    assert summary.error_code == "INVALID_JSON"
    assert summary.digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert "PRIVATE_RESPONSE_SECRET" not in repr(summary)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_hf_nonstandard_json_constants_are_rejected_even_in_ignored_fields(tmp_path, constant):
    path = tmp_path / "nonstandard.json"
    payload = json.dumps(_hf_document())[:-1] + ', "ignored": ' + constant + "}"
    path.write_text(payload, encoding="utf-8")
    summary = inputs.load_hf_summary(path)
    assert summary.error_code == "INVALID_JSON"
    assert not summary.counts
