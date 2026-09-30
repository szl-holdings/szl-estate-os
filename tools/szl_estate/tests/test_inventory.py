"""Synthetic frozen metadata fixtures; no source execution or live requests."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import struct
import zipfile
from collections import Counter
from dataclasses import replace

import pytest

from szl_estate.inventory import InventoryConfiguration, InventoryLimits, build_frozen_inventory
from szl_estate.parsers import PageResponse, collect_pages, parse_rest_page


REPO_HEADER = "repo,snapshot_sha,snapshot_observed_at,archived,private,tracked_entries,tree_complete,content_read_or_checked,content_uninspected,content_read_errors,content_skipped,open_prs,configured_workflows,latest_workflows_observed_in_100_run_sample,workflows_without_run_in_sample,latest_failed_workflows_at_snapshot_sha,metadata_errors".split(",")
LATEST_HEADER = "repo,snapshot_sha,private,tracked_paths,content_read_or_statically_checked,unread_or_skipped".split(",")
FILE_HEADER = "repo,repo_archived,snapshot_commit,path,blob_sha,entry_type,mode,size_bytes,inferred_category,content_inspection,inspection_scope,selected_backend_inspection,findings_count,full_human_content_review,content_sha256,sample_reasons,additional_pass_id,additional_read_at,previous_content_inspection,historical_findings_count,incremental_public_read_at,incremental_transport,coverage_gap,targeted_publication_claim_review,prior_content_inspection".split(",")
REMAINING_HEADER = "repo,source_sha,path,blob_sha,category,inspection_status,reason".split(",")
TIME = "2026-09-30T03:07:06.747102Z"
REPO_SHA = "a" * 40
PUBLIC = "szl-holdings/public"
SECONDARY = "szl-holdings/secondary"
PRIVATE = "szl-holdings/private"
UNREAD = {"uninspected", "inspection_error", "skipped_size_limit"}


def row(path, *, repo=PUBLIC, status="uninspected", digest="", kind="blob"):
    values = dict.fromkeys(FILE_HEADER, "")
    values.update({
        "repo": repo, "repo_archived": "False", "snapshot_commit": REPO_SHA,
        "path": path, "blob_sha": "b" * 40, "entry_type": kind,
        "mode": "160000" if kind == "commit" else "100644",
        "size_bytes": "" if kind == "commit" else "20", "inferred_category": "source_code",
        "content_inspection": status, "full_human_content_review": "False", "content_sha256": digest,
        "sample_reasons": "private-body-not-to-be-exported",
    })
    return values


def base_rows():
    return [
        row("receipts/first.json"),
        row("src/science.py", status="python_parse_and_compile_pass", digest="c" * 64),
        row("README.md", status="targeted_publication_claim_review"),
        row(".env"),
        row("datasets/train.parquet"),
        row("vendor/submodule", kind="commit"),
        row("src/next.py", repo=SECONDARY),
        row("src/private.py", repo=PRIVATE, status="inspection_error"),
    ]


def csv_bytes(header, rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_bundle(tmp_path, *, files=None, mutate=None, unpinned_mutate=None, extras=None):
    files = files if files is not None else base_rows()
    repos = sorted({item["repo"] for item in files})
    repo_rows, latest_rows = [], []
    total_read = 0
    for repo in repos:
        entries = [item for item in files if item["repo"] == repo]
        read = sum(item["content_inspection"] not in UNREAD for item in entries)
        total_read += read
        legacy_read = min(read, 1)
        values = dict.fromkeys(REPO_HEADER, "0")
        values.update({
            "repo": repo, "snapshot_sha": REPO_SHA, "snapshot_observed_at": TIME,
            "archived": "False", "private": str(repo == PRIVATE), "tracked_entries": str(len(entries)),
            "tree_complete": "True", "content_read_or_checked": str(legacy_read),
            "content_uninspected": str(len(entries) - legacy_read),
        })
        repo_rows.append(values)
        latest_rows.append({
            "repo": repo, "snapshot_sha": REPO_SHA, "private": str(repo == PRIVATE),
            "tracked_paths": str(len(entries)), "content_read_or_statically_checked": str(read),
            "unread_or_skipped": str(len(entries) - read),
        })
    remaining_rows = [{
        "repo": item["repo"], "source_sha": item["snapshot_commit"], "path": item["path"],
        "blob_sha": item["blob_sha"], "category": item["inferred_category"],
        "inspection_status": item["content_inspection"], "reason": "private-error-text-not-to-export",
    } for item in files if item["content_inspection"] in UNREAD]
    statuses = dict(Counter(item["content_inspection"] for item in files))
    summary = {
        "updated_at": TIME, "tracked_paths": len(files), "content_read_or_statically_checked_paths": total_read,
        "unread_or_skipped_paths": len(files) - total_read, "inspection_status_counts": statuses,
        "full_semantic_review_claimed": False,
    }
    audit = {
        "finalized_at": TIME, "metadata_errors_remaining": [], "repositories": len(repos),
        "private_repositories": int(PRIVATE in repos), "tracked_entries_metadata_classified": len(files),
        "content_read_or_statically_checked_paths": total_read, "unread_or_skipped_paths": len(files) - total_read,
        "full_human_content_reviews": 0,
    }
    members = {
        "repository-coverage.csv": csv_bytes(REPO_HEADER, repo_rows),
        "current-repository-content-coverage.csv": csv_bytes(LATEST_HEADER, latest_rows),
        "file-coverage.csv": csv_bytes(FILE_HEADER, files),
        "remaining-unread-or-skipped.csv": csv_bytes(REMAINING_HEADER, remaining_rows),
        "current-content-summary.json": json_bytes(summary), "audit-summary.json": json_bytes(audit),
    }
    manifest = {
        "created_at": TIME, "source_revisions": [{"repo": repo, "commit": REPO_SHA} for repo in repos],
        "coverage": {"metadata_source_snapshots": len(repos), "metadata_entries": len(files),
                     "content_read_or_statically_checked": total_read, "unread_or_skipped": len(files) - total_read,
                     "full_human_semantic_review_claimed": False},
    }
    if mutate:
        mutate(members, manifest)
    manifest["artifact_files"] = {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "source": f"frozen org-audit/{name}"} for name, raw in members.items()}
    members["bundle-manifest.json"] = json_bytes(manifest)
    if unpinned_mutate:
        unpinned_mutate(members)
    path = tmp_path / "synthetic-evidence.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
        for name, raw in extras or []:
            archive.writestr(name, raw)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def build(tmp_path, *, configuration=None, **kwargs):
    path, digest = write_bundle(tmp_path, **kwargs)
    return build_frozen_inventory(path, expected_sha256=digest, configuration=configuration)


def assert_failed(result, code, *, status="FAIL"):
    assert result.payload["errors"] == [code]
    assert result.payload["status"] == status
    assert result.payload["report_ready"] is False
    assert result.payload["batch_ready"] is False
    assert result.payload["phase2_ready"] is False
    assert result.file_index == ()


def test_latest_coverage_preserves_legacy_without_using_it(tmp_path):
    result = build(tmp_path)
    payload = result.payload
    assert payload["report_ready"] and payload["batch_ready"]
    assert payload["phase2_ready"] is False
    assert payload["source_tracked_paths"] == 8
    assert payload["historically_inspected_paths"] == 2
    assert payload["legacy_inspected_paths"] == 1
    assert payload["legacy_counts_used_for_latest_coverage"] is False
    assert payload["unread_or_skipped_paths"] == 6
    assert payload["historical_inspected_content_digest_unknown"] == 1
    assert payload["gitlink_entries"] == 1
    assert payload["fresh_heads_verified"] is False
    assert payload["unread_reduction"] == payload["new_source_reads"] == 0


def test_visibility_and_exclusion_counts_preserved_without_private_paths(tmp_path):
    result = build(tmp_path)
    payload = result.payload
    assert (payload["repository_count"], payload["public_repository_count"], payload["private_repository_count"]) == (3, 2, 1)
    assert payload["excluded_path_counts"] == {"GITLINK_NO_BLOB": 1, "PRIVATE_PATHS_WITHHELD": 1, "SECRET_OR_SESSION_PATH_WITHHELD": 1, "WEIGHT_OR_DATASET_PATH": 1}
    assert payload["metadata_index_paths"] == 4
    assert payload["metadata_index_complete_for_all_source_paths"] is False
    exported = json.dumps(payload) + json.dumps(list(result.file_index_records()))
    assert PRIVATE not in exported
    assert "src/private.py" not in exported
    assert ".env" not in exported
    assert "private-body-not-to-be-exported" not in exported
    assert "private-error-text-not-to-export" not in exported
    private_repo = next(repo for repo in payload["repositories"] if repo["private"])
    assert private_repo["repository_id"] == "PRIVATE_001"
    assert private_repo["unread_or_skipped_paths"] == 1


def test_master_designation_stays_unassigned_and_priority_is_proposal(tmp_path):
    result = build(tmp_path)
    assert all(repo["master_designation"] == "UNASSIGNED" for repo in result.payload["repositories"])
    first = result.payload["batch"][0]
    assert first["path"] == "receipts/first.json"
    assert first["priority_reason"] == "RECEIPT_OR_ARTIFACT_PATH_INFERENCE"
    assert first["epistemic_status"] == "PROPOSAL"
    assert first["snapshot_sha"] == REPO_SHA
    assert first["source_observed_at_utc"] == TIME


def test_caller_priority_and_master_lists_are_explicit(tmp_path):
    configuration = InventoryConfiguration(batch_size=1, priority_repositories=(SECONDARY,), master_repositories=(PUBLIC,))
    result = build(tmp_path, configuration=configuration)
    assert result.payload["batch"][0]["repository_id"] == PUBLIC
    assert result.payload["batch"][0]["priority_reason"] == "CALLER_MASTER_SOURCE_PROPOSAL"
    public = next(repo for repo in result.payload["repositories"] if repo["repository_id"] == PUBLIC)
    assert public["master_designation"] == "CALLER_CONFIGURED"


def test_default_batch_is_bounded_and_leaves_unread_unchanged(tmp_path):
    files = [row(f"src/f{index:03d}.py") for index in range(70)]
    result = build(tmp_path, files=files)
    assert result.payload["batch_selected_paths"] == 64
    assert result.payload["public_safe_unread_candidate_paths"] == 70
    assert result.payload["unread_or_skipped_paths"] == 70
    assert len(result.file_index) == 70


def test_root_digest_mismatch_fails_closed(tmp_path):
    path, _ = write_bundle(tmp_path)
    assert_failed(build_frozen_inventory(path, expected_sha256="0" * 64), "BUNDLE_DIGEST_MISMATCH")


def test_unknown_root_pin_fails_closed(tmp_path):
    path, _ = write_bundle(tmp_path)
    assert_failed(build_frozen_inventory(path, expected_sha256="unknown"), "INVALID_SOURCE_PIN")


def test_missing_bundle_reports_attempted_read_inaccessible_without_path_echo(tmp_path):
    path = tmp_path / "missing-private-bundle.zip"
    result = build_frozen_inventory(path, expected_sha256="0" * 64)
    assert_failed(result, "FROZEN_INPUT_UNREADABLE", status="INACCESSIBLE")
    assert str(path) not in json.dumps(result.payload)


def test_replacing_bundle_path_after_hash_does_not_replace_verified_metadata(tmp_path, monkeypatch):
    path, digest = write_bundle(tmp_path)
    replacement_directory = tmp_path / "replacement"
    replacement_directory.mkdir()
    replacement, _ = write_bundle(replacement_directory, files=[row("src/replacement.py")])
    replacement_bytes = replacement.read_bytes()
    original_zipfile = zipfile.ZipFile

    def replace_path_before_parse(file, *args, **kwargs):
        path.write_bytes(replacement_bytes)
        return original_zipfile(file, *args, **kwargs)

    monkeypatch.setattr(zipfile, "ZipFile", replace_path_before_parse)
    result = build_frozen_inventory(path, expected_sha256=digest)
    assert result.payload["report_ready"]
    assert result.payload["source_bundle_sha256"] == digest
    assert result.payload["source_tracked_paths"] == 8
    assert hashlib.sha256(path.read_bytes()).hexdigest() != digest


def test_artifact_digest_cannot_be_replaced_by_root_digest(tmp_path):
    result = build(tmp_path, unpinned_mutate=lambda members: members.__setitem__("file-coverage.csv", members["file-coverage.csv"].replace(b"receipts/first.json", b"receipts/other.json")))
    assert_failed(result, "ARTIFACT_DIGEST_MISMATCH")


def test_duplicate_json_keys_are_rejected(tmp_path):
    def mutate(members):
        raw = members["bundle-manifest.json"]
        members["bundle-manifest.json"] = b'{"created_at":"2026-09-30T00:00:00Z",' + raw[1:]

    assert_failed(build(tmp_path, unpinned_mutate=mutate), "JSON_DUPLICATE_KEY")


def test_duplicate_repo_pin_fails_closed(tmp_path):
    def mutate(_, manifest):
        manifest["source_revisions"].append(dict(manifest["source_revisions"][0]))

    assert_failed(build(tmp_path, mutate=mutate), "DUPLICATE_REPOSITORY_PIN")


def test_missing_repo_pin_fails_closed(tmp_path):
    assert_failed(build(tmp_path, mutate=lambda _, manifest: manifest["source_revisions"].pop()), "REPOSITORY_PIN_MISMATCH")


def test_duplicate_repo_path_fails_even_when_object_identity_changes(tmp_path):
    files = base_rows()
    duplicate = dict(files[0], blob_sha="d" * 40)
    files.append(duplicate)
    assert_failed(build(tmp_path, files=files), "DUPLICATE_FILE_PATH")


def test_mismatched_file_commit_fails_closed(tmp_path):
    files = base_rows()
    files[0]["snapshot_commit"] = "d" * 40
    assert_failed(build(tmp_path, files=files), "FILE_PIN_MISMATCH")


def test_metadata_errors_are_not_silently_accepted(tmp_path):
    def mutate(members, _):
        values = list(csv.DictReader(io.StringIO(members["repository-coverage.csv"].decode())))
        values[0]["metadata_errors"] = "1"
        members["repository-coverage.csv"] = csv_bytes(REPO_HEADER, values)

    assert_failed(build(tmp_path, mutate=mutate), "METADATA_ERRORS_PRESENT")


def test_tree_truncation_fails_closed(tmp_path):
    def mutate(members, _):
        values = list(csv.DictReader(io.StringIO(members["repository-coverage.csv"].decode())))
        values[0]["tree_complete"] = "False"
        members["repository-coverage.csv"] = csv_bytes(REPO_HEADER, values)

    assert_failed(build(tmp_path, mutate=mutate), "TREE_INCOMPLETE")


def test_missing_remaining_row_fails_closed(tmp_path):
    def mutate(members, _):
        lines = members["remaining-unread-or-skipped.csv"].splitlines(keepends=True)
        members["remaining-unread-or-skipped.csv"] = b"".join(lines[:-1])

    assert_failed(build(tmp_path, mutate=mutate), "REMAINING_SET_INCOMPLETE")


def test_truncated_csv_row_fails_closed(tmp_path):
    def mutate(members, _):
        lines = members["file-coverage.csv"].splitlines(keepends=True)
        lines[1] = b"szl-holdings/public,False\n"
        members["file-coverage.csv"] = b"".join(lines)

    assert_failed(build(tmp_path, mutate=mutate), "CSV_ROW_TRUNCATED_OR_EXTRA")


def test_latest_ledger_truncated_repo_set_fails_closed(tmp_path):
    def mutate(members, _):
        members["current-repository-content-coverage.csv"] = b"".join(members["current-repository-content-coverage.csv"].splitlines(keepends=True)[:-1])

    assert_failed(build(tmp_path, mutate=mutate), "LATEST_REPOSITORY_SET_INVALID")


@pytest.mark.parametrize("status", ["UNKNOWN", "runtime_pass", "completed"])
def test_unknown_or_runtime_status_cannot_promote_static_evidence(tmp_path, status):
    assert_failed(build(tmp_path, files=[row("src/a.py", status=status)]), "UNKNOWN_INSPECTION_STATUS")


@pytest.mark.parametrize("path", ["../outside.py", "/outside.py", "C:/secret.py", "src\\unsafe.py"])
def test_unsafe_source_path_rejected(tmp_path, path):
    assert_failed(build(tmp_path, files=[row(path)]), "INVALID_FILE_PATH")


@pytest.mark.parametrize("path,reason", [
    (".ssh/id_ed25519", "SECRET_OR_SESSION_PATH_WITHHELD"),
    ("AppData/Local/session.log", "SECRET_OR_SESSION_PATH_WITHHELD"),
    ("config/api_key.json", "SECRET_OR_SESSION_PATH_WITHHELD"),
    (".netrc", "SECRET_OR_SESSION_PATH_WITHHELD"),
    (".codex/state.json", "INTERNAL_CONTEXT_PATH_WITHHELD"),
    (".agents/tasks/context.txt", "INTERNAL_CONTEXT_PATH_WITHHELD"),
    ("node_modules/pkg/a.js", "DEPENDENCY_ENVIRONMENT_PATH"),
    (".venv/lib/a.py", "DEPENDENCY_ENVIRONMENT_PATH"),
    ("weights/model.safetensors", "WEIGHT_OR_DATASET_PATH"),
    ("datasets/data.parquet", "WEIGHT_OR_DATASET_PATH"),
    ("finance/model.py", "OUT_OF_SCIENCE_SCOPE"),
    ("defense/targeting.py", "OUT_OF_SCIENCE_SCOPE"),
])
def test_policy_excluded_paths_are_counted_and_not_exported(tmp_path, path, reason):
    result = build(tmp_path, files=[row(path)])
    assert result.payload["excluded_path_counts"] == {reason: 1}
    assert result.payload["unread_or_skipped_paths"] == 1
    assert result.file_index == ()
    assert result.payload["batch"] == []


@pytest.mark.parametrize("prefix", ["hf_", "ghp_", "github_pat_", "sk-"])
def test_token_shaped_filename_is_withheld_without_echo(tmp_path, prefix):
    token = prefix + "A" * 32
    path = f"src/{token}.txt"
    result = build(tmp_path, files=[row(path)])
    assert result.payload["report_ready"]
    assert result.payload["excluded_path_counts"] == {"UNSAFE_PATH_IDENTIFIER_WITHHELD": 1}
    assert result.payload["unread_excluded_path_counts"] == {"UNSAFE_PATH_IDENTIFIER_WITHHELD": 1}
    assert result.file_index == ()
    assert result.payload["batch"] == []
    assert token not in json.dumps(result.payload)


def test_token_shaped_repository_identifier_fails_without_echo(tmp_path):
    token = "hf_" + "A" * 32
    result = build(tmp_path, files=[row("src/a.py", repo=f"szl-holdings/{token}")])
    assert_failed(result, "UNSAFE_REPOSITORY_IDENTIFIER")
    assert token not in json.dumps(result.payload)


def test_token_shaped_category_fails_without_echo(tmp_path):
    token = "hf_" + "A" * 32
    files = [row("src/a.py")]
    files[0]["inferred_category"] = token
    result = build(tmp_path, files=files)
    assert_failed(result, "UNSAFE_CATEGORY_IDENTIFIER")
    assert token not in json.dumps(result.payload)


def test_no_other_zip_member_is_read_or_extracted(tmp_path, monkeypatch):
    path, digest = write_bundle(tmp_path, extras=[("untrusted_source.py", b"raise RuntimeError('must not run')")])
    opened = []
    original = zipfile.ZipFile.open

    def observed(archive, name, *args, **kwargs):
        opened.append(name.filename if isinstance(name, zipfile.ZipInfo) else name)
        return original(archive, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", observed)
    result = build_frozen_inventory(path, expected_sha256=digest)
    assert result.payload["report_ready"]
    assert "untrusted_source.py" not in opened
    assert not (tmp_path / "untrusted_source.py").exists()


def test_duplicate_zip_member_name_fails_closed(tmp_path):
    with pytest.warns(UserWarning, match="Duplicate name"):
        result = build(tmp_path, extras=[("file-coverage.csv", b"invalid")])
    assert_failed(result, "ZIP_DUPLICATE_MEMBER")


def test_unsupported_compression_method_fails_before_metadata_read(tmp_path):
    path, _ = write_bundle(tmp_path)
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    local = struct.unpack_from("<I", raw, central + 42)[0]
    struct.pack_into("<H", raw, central + 10, 99)
    struct.pack_into("<H", raw, local + 8, 99)
    path.write_bytes(raw)
    result = build_frozen_inventory(path, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert_failed(result, "ZIP_UNSUPPORTED_COMPRESSION")


def test_corrupt_deflate_stream_is_fixed_validation_failure(tmp_path):
    path, _ = write_bundle(tmp_path)
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    local = struct.unpack_from("<I", raw, central + 42)[0]
    filename_length, extra_length = struct.unpack_from("<HH", raw, local + 26)
    data_start = local + 30 + filename_length + extra_length
    # DEFLATE BFINAL=1/BTYPE=3 is reserved and must fail decompression.
    raw[data_start] = (raw[data_start] & 0xF8) | 0x07
    path.write_bytes(raw)
    result = build_frozen_inventory(path, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert_failed(result, "FROZEN_INPUT_INVALID")


@pytest.mark.parametrize("error", [RuntimeError("private-decompressor-text"), NotImplementedError("private-method-text")])
def test_zip_open_runtime_failure_never_echoes_exception(tmp_path, monkeypatch, error):
    path, digest = write_bundle(tmp_path)

    def fail_open(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_open)
    result = build_frozen_inventory(path, expected_sha256=digest)
    assert_failed(result, "FROZEN_INPUT_INVALID")
    assert "private-" not in json.dumps(result.payload)


@pytest.mark.parametrize("field,value,code", [
    ("max_bundle_bytes", 1, "BUNDLE_BYTE_BOUND_EXCEEDED"),
    ("max_members", 1, "ZIP_MEMBER_BOUND_EXCEEDED"),
    ("max_expanded_bytes", 1, "ZIP_EXPANDED_BOUND_EXCEEDED"),
    ("max_member_bytes", 1, "MEMBER_BYTE_BOUND_EXCEEDED"),
    ("max_metadata_bytes", 1, "METADATA_BYTE_BOUND_EXCEEDED"),
    ("max_file_rows", 1, "CSV_ROW_BOUND_EXCEEDED"),
])
def test_bounded_input_limits_fail_before_partial_output(tmp_path, field, value, code):
    configuration = InventoryConfiguration(limits=replace(InventoryLimits(), **{field: value}))
    assert_failed(build(tmp_path, configuration=configuration), code)


def test_object_and_list_pagination_preserve_continuation_without_live_calls():
    pages = iter([PageResponse({"repositories": [{"id": 1}], "total_count": 2}, next_cursor="second"), PageResponse([{"id": 2}])])
    calls = []

    def fetch(cursor):
        calls.append(cursor)
        return next(pages)

    result = collect_pages(fetch, lambda response: parse_rest_page(response.payload, collection_key="repositories", next_cursor=response.next_cursor), identity_key="id")
    assert result.complete
    assert calls == [None, "second"]


def test_offline_pagination_cursor_loop_does_not_claim_inventory_completion():
    pages = iter([PageResponse([{"id": 1}], next_cursor="repeat"), PageResponse([{"id": 2}], next_cursor="repeat")])
    result = collect_pages(lambda _: next(pages), lambda response: parse_rest_page(response.payload, next_cursor=response.next_cursor))
    assert not result.complete
    assert result.errors == ("CURSOR_LOOP",)
