"""Offline source receipts only: fixtures do not execute candidate source or use network."""

from dataclasses import replace
import hashlib
import json

import pytest

from szl_estate.content_review import (
    MAX_SOURCE_BYTES,
    ContentReviewError,
    FilePin,
    ReviewReceipt,
    ReviewStatus,
    git_blob_sha1,
    reconcile_coverage,
    review_bytes,
    select_next_batch,
    source_endpoints,
)
from szl_estate.model import EvidenceStatus, ProofOrigin


NOW = "2026-09-30T12:00:00Z"
COMMIT = "a" * 40


def pin_for(raw=b"print('candidate source is not executed')\n", *, path="src/reader.py", commit=COMMIT):
    return FilePin("szl-holdings/audit", commit, path, git_blob_sha1(raw), len(raw))


def review(raw=b"print('candidate source is not executed')\n", *, pin=None, **kwargs):
    pin = pin or pin_for(raw)
    return review_bytes(pin, raw, source_endpoint=source_endpoints(pin)[0], read_at_utc=NOW, **kwargs)


def indexed(pin, *, historical=False):
    return {"repository_id": pin.repository_id, "snapshot_sha": pin.snapshot_sha,
            "path": pin.path, "git_object_sha": pin.blob_sha, "size_bytes": pin.size_bytes,
            "entry_type": "blob", "unread": not historical,
            "historical_inspection_status": "text_read_only" if historical else "unread"}


def test_git_blob_identity_is_git_framed_not_plain_sha1():
    assert git_blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert git_blob_sha1(b"hello\n") != hashlib.sha1(b"hello\n").hexdigest()


def test_exact_pinned_read_has_independent_static_runtime_and_source_posture():
    raw = b"print('candidate source is not executed')\n"
    result = review(raw, source_origin=ProofOrigin.LIVE)
    receipt = result.receipt
    assert receipt.byte_coverage_credit and receipt.fresh_source_proof
    assert receipt.byte_read_status is ReviewStatus.COMPLETE
    assert receipt.static_contract_status is ReviewStatus.SKIPPED
    assert receipt.runtime_status is EvidenceStatus.NOT_RUN
    assert receipt.coverage_scope == "PINNED_FILE_BYTES_ONLY"
    assert receipt.original_blob_sha1 == git_blob_sha1(raw)
    assert receipt.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.redacted_text.encode() == raw
    assert "_verified_bytes" not in receipt.to_dict()
    assert "candidate source" not in json.dumps(receipt.to_dict())


def test_static_contract_complete_requires_owner_reference_and_no_runtime_upgrade():
    with pytest.raises(ContentReviewError, match="^STATIC_REVIEW_REFERENCE_REQUIRED$"):
        review(static_contract_status=ReviewStatus.COMPLETE)
    receipt = review(static_contract_status=ReviewStatus.COMPLETE,
                     owner_findings_refs=("fixture:findings/contracts",)).receipt
    assert receipt.static_contract_status is ReviewStatus.COMPLETE
    assert receipt.runtime_status is EvidenceStatus.NOT_RUN
    assert not receipt.fresh_source_proof


@pytest.mark.parametrize("reference", ["person@example.com", "fixture:owners/@person", "https://example.com/private?token=foo"])
def test_owner_references_reject_personal_identity_or_unsafe_reference(reference):
    with pytest.raises(ContentReviewError, match="^INVALID_FINDING_REFERENCES$"):
        review(owner_findings_refs=(reference,))


@pytest.mark.parametrize("mutation,code", [({"size_bytes": 100}, "SIZE_MISMATCH"), ({"blob_sha": "b" * 40}, "BLOB_MISMATCH")])
def test_size_and_blob_mismatch_never_cache_or_credit(mutation, code):
    raw = b"safe source\n"
    pin = replace(pin_for(raw), **mutation)
    result = review(raw, pin=pin)
    assert result.receipt.code == code
    assert result.receipt.byte_read_status is ReviewStatus.ERROR
    assert not result.receipt.byte_coverage_credit
    assert result.redacted_text is None
    assert result.receipt.redacted_cache_sha256 is None


def test_partial_identity_mismatched_body_is_withheld_before_screening():
    full = b"complete file body\n"
    partial = b"ACCESS_TOKEN = 'synthetic-value'\n"
    result = review(partial, pin=pin_for(full), byte_read_status=ReviewStatus.PARTIAL,
                    static_contract_status=ReviewStatus.COMPLETE)
    assert result.receipt.byte_read_status is ReviewStatus.PARTIAL
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL
    assert result.receipt.original_sha256 == hashlib.sha256(partial).hexdigest()
    assert not result.receipt.byte_coverage_credit
    assert result.redacted_text is None and result.receipt.cache_disposition == "WITHHELD"


@pytest.mark.parametrize("status", [ReviewStatus.ERROR, ReviewStatus.SKIPPED])
def test_nonread_statuses_do_not_hash_cache_or_credit(status):
    result = review(byte_read_status=status)
    assert result.receipt.byte_read_status is status
    assert result.receipt.original_sha256 is None
    assert result.redacted_text is None and not result.receipt.byte_coverage_credit


@pytest.mark.parametrize("raw,code", [(b"\xff\xfe", "BINARY_WITHHELD"), (b"text\0hidden", "BINARY_WITHHELD"),
                                      (b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\n", "LFS_POINTER_WITHHELD"),
                                      (b"patient_records = {'patient_id': 7}\n", "SENSITIVE_RECORD_WITHHELD"),
                                      (b"weapon_guidance = 'operational instructions'\n", "SENSITIVE_RECORD_WITHHELD"),
                                      (b"-----BEGIN PRIVATE KEY-----\nQUJDREVGRw==\n-----END PRIVATE KEY-----\n", "PRIVATE_KEY_WITHHELD"),
                                      (b"-----BEGIN OPENSSH PRIVATE KEY-----\nQUJDREVGRw==\n", "PRIVATE_KEY_WITHHELD")])
def test_binary_lfs_sensitive_records_and_private_keys_withhold_entire_body(raw, code):
    result = review(raw)
    assert result.receipt.code == code
    assert result.receipt.byte_read_status is ReviewStatus.SKIPPED
    assert result.redacted_text is None and not result.receipt.byte_coverage_credit
    assert result.receipt.original_blob_sha1 == git_blob_sha1(raw)


@pytest.mark.parametrize("raw", [b"AWS_SECRET_ACCESS_KEY = 'synthetic-secret'\n", b"ACCESS_TOKEN = 'synthetic-token'\n",
                                 b"AZURE_CLIENT_SECRET_VALUE = 'synthetic-secret'\n", b"AWS_ACCESS_KEY_ID = 'synthetic-key'\n",
                                 b"AUTHORIZATION_HEADER = 'Basic synthetic-value'\n",
                                 b'{"api_key": "synthetic-key"}\n', b"Authorization: Bearer synthetic-secret-value\n",
                                 b"Bearer synthetic-secret-value\n", b"credential = 'ghp_ABCDEFGHIJKLMNO'\n",
                                 b"contact = 'person@example.com'\n"])
def test_literal_credentials_and_emails_redact_lines_after_original_hashing(raw):
    result = review(raw, static_contract_status=ReviewStatus.COMPLETE,
                    owner_findings_refs=("fixture:findings/contracts",))
    assert result.redacted_text == "[REDACTED]\n"
    assert result.receipt.original_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.receipt.redacted_cache_sha256 == hashlib.sha256(b"[REDACTED]\n").hexdigest()
    assert result.receipt.redacted_lines == 1 and result.receipt.byte_coverage_credit
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL
    assert "synthetic-secret" not in json.dumps(result.receipt.to_dict())


@pytest.mark.parametrize("raw", [b"token = os.environ.get('ACCESS_TOKEN', 'plaintext-fallback')\n",
                                 b"token = self.default + 'plaintext-suffix'\n",
                                 b"token = get_token() + 'plaintext-suffix'\n"])
def test_symbolic_prefix_does_not_exempt_plaintext_fallback_or_suffix(raw):
    result = review(raw)
    assert result.redacted_text == "[REDACTED]\n"
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL


@pytest.mark.parametrize("raw", [b"password:\n  plaintext-value\n", b"token: |\n  plaintext-value\n",
                                 b"token = '''\nplaintext-value\n'''\n",
                                 b"token = '''first-secret-line\nsecond-secret-line\n'''\n",
                                 b'token = """first-secret-line\nsecond-secret-line\n"""\n',
                                 b"token = os.environ.get(\n    'ACCESS_TOKEN', 'plaintext-fallback')\n"])
def test_multiline_credential_blocks_withhold_all_continuation_bytes(raw):
    result = review(raw)
    assert result.redacted_text is None and not result.receipt.byte_coverage_credit
    assert result.receipt.code == "CREDENTIAL_BLOCK_WITHHELD"
    assert "plaintext" not in json.dumps(result.receipt.to_dict())
    assert "secret-line" not in json.dumps(result.receipt.to_dict())


def test_codeowners_personal_handles_redacted_org_teams_preserved_and_line_endings_kept():
    raw = b"* @person\r\n/docs/ @szl-holdings/engineering\n/src/ person@example.com\r"
    result = review(raw, pin=pin_for(raw, path="CODEOWNERS"))
    assert result.redacted_text == "[REDACTED]\r\n/docs/ @szl-holdings/engineering\n[REDACTED]\r"
    assert result.receipt.redacted_lines == 2
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL


def test_personal_handles_in_explicit_ownership_context_only():
    raw = b"# maintainer: @person\n@staticmethod\ndef run(): pass\n@property\ndef value(): pass\n"
    result = review(raw)
    assert result.redacted_text == "[REDACTED]\n@staticmethod\ndef run(): pass\n@property\ndef value(): pass\n"


@pytest.mark.parametrize("path,raw", [("deploy/install.py", b"token = os.environ.get('ACCESS_TOKEN')\n"),
                                     (".github/workflows/ci.yml", b"token: ${{ secrets.GITHUB_TOKEN }}\n"),
                                     ("security/defensive.py", b"@staticmethod\ndef check(): pass\n"),
                                     ("web/style.css", b"@media print { color: black; }\n@font-face { font-family: Test; }\n")])
def test_ordinary_install_ci_security_decorators_css_and_symbolic_env_preserved(path, raw):
    result = review(raw, pin=pin_for(raw, path=path))
    assert result.redacted_text.encode() == raw
    assert result.receipt.byte_coverage_credit and result.receipt.redacted_lines == 0


@pytest.mark.parametrize("path", ["../README.md", "/README.md", "src//reader.py", "secrets/config.py", "contacts/list.txt",
                                  "weapons/guidance.py", "targeting/engine.py", "finance/ledger.py", "legal/policy.md",
                                  ".env", ".ssh/config", "private.pem", "data/rows.jsonl"])
def test_secret_personal_operational_and_unsafe_paths_rejected(path):
    with pytest.raises(ContentReviewError):
        pin_for(b"source\n", path=path)


@pytest.mark.parametrize("fields", [{"snapshot_sha": "a" * 39}, {"blob_sha": "A" * 40}, {"size_bytes": True},
                                   {"size_bytes": MAX_SOURCE_BYTES + 1}, {"repository_id": "another-org/audit"}])
def test_pin_exact_fields_strict_identity_and_source_size(fields):
    with pytest.raises(ContentReviewError):
        replace(pin_for(), **fields)


def test_pin_roundtrip_and_source_endpoint_exact_allowlist():
    pin = pin_for()
    assert FilePin.from_dict(pin.to_dict()) == pin
    with pytest.raises(ContentReviewError, match="^INVALID_FILE_PIN$"):
        FilePin.from_dict({**pin.to_dict(), "extra": "unknown"})
    with pytest.raises(ContentReviewError, match="^SOURCE_ENDPOINT_MISMATCH$"):
        review_bytes(pin, b"", source_endpoint="https://example.com/body", read_at_utc=NOW)


def test_real_dot_github_repository_is_valid_but_traversal_names_rejected():
    raw = b"ordinary config\n"
    pin = replace(pin_for(raw), repository_id="szl-holdings/.github")
    receipt = review(raw, pin=pin).receipt
    assert reconcile_coverage([indexed(pin)], [receipt]).newly_verified_read_paths == 1
    for repository in ("szl-holdings/.", "szl-holdings/..", "szl-holdings/../escape"):
        with pytest.raises(ContentReviewError, match="^INVALID_REPOSITORY_PIN$"):
            replace(pin, repository_id=repository)


@pytest.mark.parametrize("unsupported_path", ["docs/with space.md", "docs/naïve.md", "../escape.md"])
def test_unsupported_metadata_names_remain_unread_without_aborting_selected_coverage(unsupported_path):
    pin = pin_for(b"ordinary source\n")
    unsupported = {**indexed(pin), "path": unsupported_path}
    with pytest.raises(ContentReviewError, match="^INVALID_FILE_PATH$"):
        replace(pin, path=unsupported_path)
    coverage = reconcile_coverage([unsupported, indexed(pin)], [review(b"ordinary source\n", pin=pin).receipt], historical_read_count=542)
    assert coverage.newly_verified_read_paths == 1 and coverage.reconciled_read_total == 543
    assert coverage.indexed_completed_paths == 1
    assert select_next_batch([unsupported], []) == ()


def test_unredacted_cache_rehash_can_credit_bytes_never_fresh_live_proof():
    result = review(source_origin=ProofOrigin.LIVE)
    metadata_only = ReviewReceipt.from_dict(result.receipt.to_dict())
    assert not metadata_only.byte_coverage_credit and not metadata_only.fresh_source_proof
    cached = ReviewReceipt.from_dict(result.receipt.to_dict(), cached_text=result.redacted_text)
    assert cached.byte_coverage_credit and not cached.fresh_source_proof
    assert cached.source_origin is ProofOrigin.CACHE
    assert cached.runtime_status is EvidenceStatus.NOT_RUN


def test_redacted_cache_cannot_reconstruct_original_identity_or_credit_new_read():
    result = review(b"ACCESS_TOKEN = 'synthetic-value'\n", source_origin=ProofOrigin.LIVE)
    cached = ReviewReceipt.from_dict(result.receipt.to_dict(), cached_text=result.redacted_text)
    assert not cached.byte_coverage_credit and not cached.fresh_source_proof
    assert cached.static_contract_status is ReviewStatus.PARTIAL


def test_cached_size_forgery_rejected_even_with_matching_blob_and_sha256():
    result = review(b"safe\n")
    forged = result.receipt.to_dict()
    forged["pin"]["size_bytes"] += 1
    forged["bytes_read"] += 1
    with pytest.raises(ContentReviewError, match="^CACHE_SIZE_MISMATCH$"):
        ReviewReceipt.from_dict(forged, cached_text=result.redacted_text)


@pytest.mark.parametrize("line", [r'"error": "C:\\Users\\example-person\\AppData\\Temp\\trace"', r'path = "C:\Users\example-person\temp"', 'path = "/home/example-person/file"', '# Author: Example Person', '/* Copyright Example Person */', '# Created by Example Person', '* Attribution: ORCID synthetic-id', '/* End ORCID synthetic-id */', '(c) 2026 Example Person', '# Fixed by Example Person'])
def test_profile_paths_and_explicit_attribution_are_redacted_without_echoing_identity(line):
    result = review((line + "\nordinary source\n").encode())
    assert result.redacted_text == "[REDACTED]\nordinary source\n"
    assert result.receipt.redacted_lines == 1
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL
    assert "example-person" not in result.redacted_text


def test_cache_tamper_unsafe_content_and_serialized_verification_flags_rejected():
    result = review(b"safe\n")
    with pytest.raises(ContentReviewError, match="^CACHE_DIGEST_MISMATCH$"):
        ReviewReceipt.from_dict(result.receipt.to_dict(), cached_text="changed\n")
    with pytest.raises(ContentReviewError, match="^INVALID_REVIEW_RECEIPT$"):
        ReviewReceipt.from_dict({**result.receipt.to_dict(), "_verified_bytes": True})
    unsafe = "ACCESS_TOKEN = 'synthetic-value'\n"
    forged = result.receipt.to_dict()
    forged["redacted_cache_sha256"] = hashlib.sha256(unsafe.encode()).hexdigest()
    with pytest.raises(ContentReviewError, match="^UNSAFE_CACHE_TEXT$"):
        ReviewReceipt.from_dict(forged, cached_text=unsafe)


def test_expanding_short_redacted_lines_stay_bounded_and_roundtrip_without_text():
    raw = b"@x\n" * (MAX_SOURCE_BYTES // 3)
    result = review(raw, pin=pin_for(raw, path="CODEOWNERS"))
    assert result.redacted_text is None
    assert result.receipt.code == "SOURCE_SIZE_LIMIT"
    assert result.receipt.cache_disposition == "WITHHELD"
    assert result.receipt.byte_read_status is ReviewStatus.SKIPPED
    assert result.receipt.static_contract_status is ReviewStatus.PARTIAL
    cached = ReviewReceipt.from_dict(result.receipt.to_dict())
    assert not cached.byte_coverage_credit


def test_historical_overlap_duplicates_and_same_blob_different_paths_reconcile():
    raw = b"shared content\n"
    first, second = pin_for(raw, path="README.md"), pin_for(raw, path="docs/readme.md")
    first_receipt, second_receipt = review(raw, pin=first).receipt, review(raw, pin=second).receipt
    result = reconcile_coverage([indexed(first, historical=True), indexed(second)],
                                [first_receipt, first_receipt, second_receipt, second_receipt], historical_read_count=542)
    assert result.historical_indexed_read_paths == 1
    assert result.newly_verified_read_paths == 1 and result.reconciled_read_total == 543
    assert result.indexed_completed_paths == 2 and result.unique_completed_objects == 1
    assert result.byte_status_counts["COMPLETE"] == 2
    assert result.completed_file_keys == tuple(sorted((first.key, second.key)))
    assert result.to_dict()["runtime_status"] == "NOT_RUN" and not result.to_dict()["estate_ready"]
    assert select_next_batch([indexed(first, historical=True), indexed(second)], [second_receipt]) == ()


def test_error_partial_skip_or_metadata_only_cache_do_not_remove_next_batch():
    pin = pin_for()
    statuses = [review(pin=pin, byte_read_status=status).receipt for status in (ReviewStatus.ERROR, ReviewStatus.PARTIAL, ReviewStatus.SKIPPED)]
    statuses.append(ReviewReceipt.from_dict(review(pin=pin).receipt.to_dict()))
    coverage = reconcile_coverage([indexed(pin)], statuses, historical_read_count=542)
    assert coverage.newly_verified_read_paths == 0 and coverage.reconciled_read_total == 542
    assert coverage.indexed_completed_paths == 0
    assert coverage.byte_status_counts["COMPLETE"] == 0
    assert select_next_batch([indexed(pin)], statuses) == (pin,)


def test_next_batch_uses_exact_snapshot_path_blob_identity_and_is_deterministic():
    old = pin_for(b"source\n", path="src/old.py")
    changed = pin_for(b"source\n", path="src/old.py", commit="b" * 40)
    other = pin_for(b"other\n", path="README.md")
    rows = [indexed(changed), indexed(old), indexed(other)]
    receipts = [review(b"source\n", pin=old).receipt]
    assert select_next_batch(rows, receipts) == tuple(sorted((changed, other), key=lambda pin: pin.key))
    assert select_next_batch(reversed(rows), receipts, limit=1) == (other,)
    with pytest.raises(ContentReviewError, match="^INVALID_BATCH_LIMIT$"):
        select_next_batch(rows, receipts, limit=65)


def test_baseline_is_explicit_not_assumed_542_and_unknown_historical_status_does_not_credit():
    pin = pin_for()
    row = {**indexed(pin, historical=True), "historical_inspection_status": "unknown"}
    result = reconcile_coverage([row], [])
    assert result.historical_read_total is None and result.reconciled_read_total is None
    assert result.historical_indexed_read_paths == 0
    assert select_next_batch([row], []) == (pin,)
    with pytest.raises(ContentReviewError, match="^INVALID_HISTORICAL_BASELINE$"):
        reconcile_coverage([indexed(pin, historical=True)], [], historical_read_count=0)


def test_receipts_outside_index_or_conflicting_index_do_not_credit():
    pin = pin_for()
    receipt = review(pin=pin).receipt
    with pytest.raises(ContentReviewError, match="^RECEIPT_OUTSIDE_INDEX$"):
        reconcile_coverage([], [receipt])
    with pytest.raises(ContentReviewError, match="^CONFLICTING_FILE_INDEX$"):
        reconcile_coverage([indexed(pin), {**indexed(pin), "size_bytes": pin.size_bytes + 1}], [])


def test_excluded_index_paths_are_not_selected_and_malformed_status_is_safe():
    pin = pin_for()
    excluded = {**indexed(pin), "path": "secrets/config.py"}
    malformed_status = {**indexed(pin, historical=True), "historical_inspection_status": []}
    assert select_next_batch([excluded], []) == ()
    assert select_next_batch([malformed_status], []) == (pin,)


def test_file_index_generator_is_bounded_before_materialization():
    pin = pin_for()
    consumed = []

    def endless_rows():
        while True:
            consumed.append(None)
            yield indexed(pin)

    with pytest.raises(ContentReviewError, match="^FILE_INDEX_LIMIT$"):
        select_next_batch(endless_rows(), [])
    assert len(consumed) == 50001
