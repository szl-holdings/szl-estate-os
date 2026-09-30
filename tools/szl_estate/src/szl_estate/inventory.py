"""Bounded frozen metadata coverage and source-read proposals; no live access.

Only named CSV/JSON metadata members are read. ZIP contents are never extracted
or executed. Historical parse/read labels establish neither runtime readiness
nor semantic review, and source-read proposals do not reduce unread counts.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zipfile
import zlib
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from .model import EvidenceValidationError, safe_identifier


_SHA40 = re.compile(r"[0-9a-fA-F]{40}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_INSPECTED = frozenset({
    "python_parse_and_compile_pass", "workflow_yaml_parse_pass", "text_decoded_only",
    "text_read_only", "toml_parse_pass", "json_parse_pass", "yaml_parse_pass",
    "targeted_publication_claim_review", "readme_structural_triage",
})
_UNREAD = frozenset({"uninspected", "inspection_error", "skipped_size_limit"})
_REPO_HEADER = tuple("repo,snapshot_sha,snapshot_observed_at,archived,private,tracked_entries,tree_complete,content_read_or_checked,content_uninspected,content_read_errors,content_skipped,open_prs,configured_workflows,latest_workflows_observed_in_100_run_sample,workflows_without_run_in_sample,latest_failed_workflows_at_snapshot_sha,metadata_errors".split(","))
_LATEST_HEADER = tuple("repo,snapshot_sha,private,tracked_paths,content_read_or_statically_checked,unread_or_skipped".split(","))
_FILE_HEADER = tuple("repo,repo_archived,snapshot_commit,path,blob_sha,entry_type,mode,size_bytes,inferred_category,content_inspection,inspection_scope,selected_backend_inspection,findings_count,full_human_content_review,content_sha256,sample_reasons,additional_pass_id,additional_read_at,previous_content_inspection,historical_findings_count,incremental_public_read_at,incremental_transport,coverage_gap,targeted_publication_claim_review,prior_content_inspection".split(","))
_REMAINING_HEADER = tuple("repo,source_sha,path,blob_sha,category,inspection_status,reason".split(","))
_MEMBERS = (
    "repository-coverage.csv", "current-repository-content-coverage.csv", "file-coverage.csv",
    "remaining-unread-or-skipped.csv", "current-content-summary.json", "audit-summary.json",
)


class InventoryError(ValueError):
    """A fixed code only; raw values, paths and exception text are never emitted."""


@dataclass(frozen=True)
class InventoryLimits:
    max_bundle_bytes: int = 8 * 1024 * 1024
    max_expanded_bytes: int = 32 * 1024 * 1024
    max_member_bytes: int = 12 * 1024 * 1024
    max_metadata_bytes: int = 24 * 1024 * 1024
    max_members: int = 256
    max_file_rows: int = 50_000
    max_repository_rows: int = 1_000
    max_field_chars: int = 4_096


@dataclass(frozen=True)
class InventoryConfiguration:
    batch_size: int = 64
    priority_repositories: tuple[str, ...] = ()
    master_repositories: tuple[str, ...] = ()
    canonical_repositories: tuple[str, ...] = ("szl-holdings/szl-estate-os",)
    limits: InventoryLimits = InventoryLimits()


@dataclass(frozen=True)
class FileMetadata:
    repository_id: str
    snapshot_sha: str
    source_observed_at_utc: str
    path: str
    git_object_sha: str
    entry_type: str
    size_bytes: int | None
    category: str
    historical_inspection_status: str
    historical_content_sha256: str | None
    historical_read_observed_at_utc: str | None
    unread: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryMetadata:
    repository_id: str
    snapshot_sha: str
    source_observed_at_utc: str
    private: bool
    archived: bool
    tree_complete: bool
    tracked_paths: int
    historical_inspected_paths: int
    unread_or_skipped_paths: int
    legacy_inspected_paths: int
    master_designation: str


@dataclass(frozen=True)
class FrozenInventoryResult:
    payload: dict[str, Any]
    file_index: tuple[FileMetadata, ...] = ()

    def file_index_records(self) -> Iterator[dict[str, Any]]:
        return (record.to_dict() for record in self.file_index)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise InventoryError(code)


def _integer(value: object) -> int:
    if isinstance(value, str):
        _require(bool(value) and value.isascii() and value.isdecimal() and len(value) <= 19, "INVALID_COUNTER")
        value = int(value)
    _require(type(value) is int and 0 <= value <= 2**63 - 1, "INVALID_COUNTER")
    return value


def _boolean(value: object) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    _require(type(value) is bool, "INVALID_BOOLEAN")
    return value


def _timestamp(value: object) -> str:
    _require(isinstance(value, str) and _UTC.fullmatch(value) is not None, "INVALID_SOURCE_TIME")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InventoryError("INVALID_SOURCE_TIME") from None
    _require(parsed.utcoffset() == timedelta(0), "INVALID_SOURCE_TIME")
    return value


def _repository(value: object) -> str:
    _require(isinstance(value, str) and _REPOSITORY.fullmatch(value) is not None, "INVALID_REPOSITORY_ID")
    _require(all(part not in {".", ".."} for part in value.split("/")), "INVALID_REPOSITORY_ID")
    _require(_safe_metadata_identifier(value, limit=202), "UNSAFE_REPOSITORY_IDENTIFIER")
    return value


def _safe_metadata_identifier(value: str, *, limit: int) -> bool:
    try:
        safe_identifier(value, limit=limit)
    except EvidenceValidationError:
        return False
    return True


def _sha(value: object, *, content: bool = False) -> str:
    pattern = _SHA256 if content else _SHA40
    _require(isinstance(value, str) and pattern.fullmatch(value) is not None, "INVALID_SOURCE_PIN")
    return value.lower()


def _path(value: object) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 4096, "INVALID_FILE_PATH")
    _require(not any(ord(char) < 32 or ord(char) == 127 for char in value), "INVALID_FILE_PATH")
    _require(not value.startswith("/") and "\\" not in value and ":" not in value, "INVALID_FILE_PATH")
    _require(all(part not in {"", ".", ".."} for part in value.split("/")), "INVALID_FILE_PATH")
    return value


def _json(raw: bytes) -> dict[str, Any]:
    def pairs(values):
        result = {}
        for key, value in values:
            _require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_):
        raise InventoryError("JSON_INVALID_NUMBER")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except InventoryError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise InventoryError("INVALID_JSON") from None
    _require(isinstance(value, dict), "INVALID_JSON_SHAPE")
    return value


def _csv(raw: bytes, header: tuple[str, ...], row_limit: int, limits: InventoryLimits):
    try:
        reader = csv.reader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True)
        _require(tuple(next(reader, ())) == header, "CSV_HEADER_MISMATCH")
        for index, values in enumerate(reader):
            _require(index < row_limit, "CSV_ROW_BOUND_EXCEEDED")
            _require(len(values) == len(header), "CSV_ROW_TRUNCATED_OR_EXTRA")
            _require(all(len(value) <= limits.max_field_chars for value in values), "CSV_FIELD_BOUND_EXCEEDED")
            yield dict(zip(header, values, strict=True))
    except (UnicodeError, csv.Error):
        raise InventoryError("INVALID_CSV") from None


def _excluded(repository: str, path: str, private: bool, entry_type: str, mode: str) -> str | None:
    if private:
        return "PRIVATE_PATHS_WITHHELD"
    if not _safe_metadata_identifier(path, limit=4096):
        return "UNSAFE_PATH_IDENTIFIER_WITHHELD"
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    if set(parts).intersection({".codex", ".agents"}):
        return "INTERNAL_CONTEXT_PATH_WITHHELD"
    words = set(re.split(r"[^a-z0-9]+", repository.lower() + "/" + path.lower()))
    if (any(part.startswith(".env") for part in parts)
            or words.intersection({"credential", "credentials", "secret", "secrets", "token", "tokens", "session", "sessions", "sessionlogs", "password", "passwords", "auth", "authentication", "oauth", "apikey"})
            or {"api", "key"}.issubset(words)
            or set(parts).intersection({".ssh", ".aws", ".azure", ".config", "appdata", ".netrc", ".git-credentials", ".npmrc", ".pypirc"})
            or any(part in {"id_rsa", "id_ed25519", "session", "sessions", "sessionlogs"} for part in parts)
            or path.lower().endswith((".pem", ".key", ".p12", ".pfx", ".keystore"))):
        return "SECRET_OR_SESSION_PATH_WITHHELD"
    if set(parts).intersection({".venv", "venv", "env", "node_modules", "__pycache__", ".git", "site-packages"}):
        return "DEPENDENCY_ENVIRONMENT_PATH"
    if (set(parts).intersection({"weights", "checkpoints", "dataset", "datasets"})
            or path.lower().endswith((".safetensors", ".gguf", ".parquet", ".arrow", ".h5", ".pt", ".pth", ".onnx", ".bin", ".csv", ".jsonl"))):
        return "WEIGHT_OR_DATASET_PATH"
    if words.intersection({"finance", "financial", "trading", "legal", "defense", "weapons", "weapon"}):
        return "OUT_OF_SCIENCE_SCOPE"
    if entry_type == "commit":
        return "GITLINK_NO_BLOB"
    if mode == "120000":
        return "SYMLINK_METADATA_ONLY"
    return None


def _priority(record: FileMetadata, configuration: InventoryConfiguration) -> tuple[int, str]:
    if record.repository_id in configuration.canonical_repositories:
        return 0, "CANONICAL_TOOLING_SOURCE_PROPOSAL"
    if record.repository_id in configuration.priority_repositories:
        return 1, "CALLER_PRIORITY_REPOSITORY_PROPOSAL"
    if record.repository_id in configuration.master_repositories:
        return 1, "CALLER_MASTER_SOURCE_PROPOSAL"
    words = set(re.split(r"[^a-z0-9]+", record.path.lower()))
    if words.intersection({"receipt", "receipts", "provenance", "artifact", "artifacts"}):
        return 2, "RECEIPT_OR_ARTIFACT_PATH_INFERENCE"
    if words.intersection({"science", "ai4science", "experiment", "experiments", "calibration", "harness"}):
        return 3, "SCIENCE_PATH_INFERENCE"
    return 4, "OTHER_PUBLIC_UNREAD_METADATA_PROPOSAL"


def _configuration(configuration: InventoryConfiguration) -> None:
    _require(isinstance(configuration, InventoryConfiguration), "INVALID_CONFIGURATION")
    _require(type(configuration.batch_size) is int and 1 <= configuration.batch_size <= 256, "INVALID_BATCH_SIZE")
    _require(isinstance(configuration.limits, InventoryLimits), "INVALID_LIMITS")
    for value in asdict(configuration.limits).values():
        _require(type(value) is int and 0 < value <= 128 * 1024 * 1024, "INVALID_LIMITS")
    for values in (configuration.priority_repositories, configuration.master_repositories, configuration.canonical_repositories):
        _require(isinstance(values, tuple) and len(values) <= 1000 and len(set(values)) == len(values), "INVALID_REPOSITORY_CONFIGURATION")
        for value in values:
            _repository(value)


def _failure(expected_sha256: object, code: str, *, status: str = "FAIL") -> FrozenInventoryResult:
    pin = expected_sha256.lower() if isinstance(expected_sha256, str) and _SHA256.fullmatch(expected_sha256) else None
    return FrozenInventoryResult({
        "schema_version": "szl.frozen-inventory/v1", "source_bundle_sha256": pin,
        "status": status, "report_ready": False, "batch_ready": False, "phase2_ready": False,
        "evidence_kind": "HISTORICAL_STATIC_METADATA", "epistemic_status": "UNKNOWN",
        "errors": [code], "batch": [], "unread_reduction": 0,
    })


def build_frozen_inventory(
    bundle_path: str | Path,
    *,
    expected_sha256: str,
    configuration: InventoryConfiguration | None = None,
) -> FrozenInventoryResult:
    """Build controlled historical metadata and a bounded, unexecuted proposal.

    The root digest is mandatory. All selected members must have exact manifest
    byte/hash pins. Failure returns no file index and no raw exception text.
    ``report_ready``/``batch_ready`` refer only to proven collection controls.
    """

    configuration = configuration if configuration is not None else InventoryConfiguration()
    try:
        _configuration(configuration)
        expected = _sha(expected_sha256, content=True)
        limits = configuration.limits
        source = Path(bundle_path)
        _require(source.stat().st_size <= limits.max_bundle_bytes, "BUNDLE_BYTE_BOUND_EXCEEDED")
        with source.open("rb") as stream:
            raw_bundle = stream.read(limits.max_bundle_bytes + 1)
        _require(len(raw_bundle) <= limits.max_bundle_bytes, "BUNDLE_BYTE_BOUND_EXCEEDED")
        _require(hashlib.sha256(raw_bundle).hexdigest() == expected, "BUNDLE_DIGEST_MISMATCH")
        # Parse these exact verified bytes; never reopen a mutable source path.
        with zipfile.ZipFile(io.BytesIO(raw_bundle)) as archive:
            entries = archive.infolist()
            _require(len(entries) <= limits.max_members, "ZIP_MEMBER_BOUND_EXCEEDED")
            names: dict[str, zipfile.ZipInfo] = {}
            expanded = 0
            normalized: set[str] = set()
            for entry in entries:
                name = _path(entry.filename.rstrip("/"))
                _require(name.casefold() not in normalized, "ZIP_DUPLICATE_MEMBER")
                normalized.add(name.casefold())
                _require(not entry.flag_bits & 1, "ZIP_ENCRYPTED_MEMBER")
                _require(entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "ZIP_UNSUPPORTED_COMPRESSION")
                expanded += entry.file_size
                _require(expanded <= limits.max_expanded_bytes, "ZIP_EXPANDED_BOUND_EXCEEDED")
                names[entry.filename] = entry
            metadata_bytes = 0

            def read(name: str) -> bytes:
                nonlocal metadata_bytes
                _require(name in names and not names[name].is_dir(), "MISSING_METADATA_MEMBER")
                entry = names[name]
                _require(entry.file_size <= limits.max_member_bytes, "MEMBER_BYTE_BOUND_EXCEEDED")
                metadata_bytes += entry.file_size
                _require(metadata_bytes <= limits.max_metadata_bytes, "METADATA_BYTE_BOUND_EXCEEDED")
                with archive.open(entry) as stream:
                    raw = stream.read(limits.max_member_bytes + 1)
                _require(len(raw) == entry.file_size and len(raw) <= limits.max_member_bytes, "MEMBER_TRUNCATED_OR_OVERSIZED")
                return raw

            manifest_raw = read("bundle-manifest.json")
            manifest = _json(manifest_raw)
            created_at = _timestamp(manifest.get("created_at"))
            artifact_files = manifest.get("artifact_files")
            _require(isinstance(artifact_files, dict), "MISSING_ARTIFACT_PINS")
            raw_members: dict[str, bytes] = {}
            member_hashes: dict[str, str] = {"bundle-manifest.json": hashlib.sha256(manifest_raw).hexdigest()}
            for name in _MEMBERS:
                pin = artifact_files.get(name)
                _require(isinstance(pin, dict), "MISSING_ARTIFACT_PIN")
                raw = read(name)
                _require(_integer(pin.get("bytes")) == len(raw), "ARTIFACT_SIZE_MISMATCH")
                actual = hashlib.sha256(raw).hexdigest()
                _require(_sha(pin.get("sha256"), content=True) == actual, "ARTIFACT_DIGEST_MISMATCH")
                raw_members[name] = raw
                member_hashes[name] = actual
        return _assemble(manifest, raw_members, member_hashes, expected, created_at, configuration)
    except InventoryError as error:
        return _failure(expected_sha256, str(error))
    except OSError:
        return _failure(expected_sha256, "FROZEN_INPUT_UNREADABLE", status="INACCESSIBLE")
    except (ValueError, TypeError, KeyError, zipfile.BadZipFile, EOFError, RuntimeError, OverflowError, zlib.error):
        return _failure(expected_sha256, "FROZEN_INPUT_INVALID")


def _assemble(manifest, raw_members, member_hashes, expected, created_at, configuration):
    limits = configuration.limits
    revisions = manifest.get("source_revisions")
    _require(isinstance(revisions, list) and len(revisions) <= limits.max_repository_rows, "INVALID_SOURCE_REVISIONS")
    pins: dict[str, str] = {}
    for revision in revisions:
        _require(isinstance(revision, dict), "INVALID_SOURCE_REVISION")
        repo, commit = _repository(revision.get("repo")), _sha(revision.get("commit"))
        _require(repo not in pins, "DUPLICATE_REPOSITORY_PIN")
        pins[repo] = commit
    repositories: dict[str, dict[str, Any]] = {}
    for row in _csv(raw_members.pop("repository-coverage.csv"), _REPO_HEADER, limits.max_repository_rows, limits):
        repo = _repository(row["repo"])
        _require(repo not in repositories, "DUPLICATE_REPOSITORY")
        sha = _sha(row["snapshot_sha"])
        _require(pins.get(repo) == sha, "REPOSITORY_PIN_MISMATCH")
        _require(_boolean(row["tree_complete"]), "TREE_INCOMPLETE")
        _require(_integer(row["metadata_errors"]) == 0, "METADATA_ERRORS_PRESENT")
        tracked = _integer(row["tracked_entries"])
        legacy = _integer(row["content_read_or_checked"])
        _require(tracked == legacy + sum(_integer(row[key]) for key in ("content_uninspected", "content_read_errors", "content_skipped")), "LEGACY_COVERAGE_MISMATCH")
        repositories[repo] = {
            "sha": sha, "observed_at": _timestamp(row["snapshot_observed_at"]),
            "private": _boolean(row["private"]), "archived": _boolean(row["archived"]),
            "tracked": tracked, "legacy": legacy,
        }
    _require(bool(repositories) and set(repositories) == set(pins), "REPOSITORY_SET_MISMATCH")
    latest: dict[str, tuple[int, int, int]] = {}
    for row in _csv(raw_members.pop("current-repository-content-coverage.csv"), _LATEST_HEADER, limits.max_repository_rows, limits):
        repo = _repository(row["repo"])
        _require(repo in repositories and repo not in latest, "LATEST_REPOSITORY_SET_INVALID")
        source = repositories[repo]
        _require(_sha(row["snapshot_sha"]) == source["sha"], "LATEST_PIN_MISMATCH")
        _require(_boolean(row["private"]) == source["private"], "VISIBILITY_MISMATCH")
        counts = tuple(_integer(row[key]) for key in ("tracked_paths", "content_read_or_statically_checked", "unread_or_skipped"))
        _require(counts[0] == counts[1] + counts[2] and counts[0] == source["tracked"], "LATEST_COVERAGE_MISMATCH")
        latest[repo] = counts
    _require(set(latest) == set(repositories), "LATEST_REPOSITORY_SET_INVALID")
    summary = _json(raw_members.pop("current-content-summary.json"))
    updated_at = _timestamp(summary.get("updated_at"))
    _require(summary.get("full_semantic_review_claimed") is False, "SEMANTIC_CLAIM_INVALID")
    audit = _json(raw_members.pop("audit-summary.json"))
    finalized_at = _timestamp(audit.get("finalized_at"))
    _require(audit.get("metadata_errors_remaining") == [], "METADATA_ERRORS_PRESENT")
    coverage = manifest.get("coverage")
    _require(isinstance(coverage, dict) and coverage.get("full_human_semantic_review_claimed") is False, "INVALID_MANIFEST_COVERAGE")
    aliases = {repo: f"PRIVATE_{index:03d}" for index, repo in enumerate(sorted(repo for repo in repositories if repositories[repo]["private"]), 1)}
    safe_index: list[FileMetadata] = []
    identities: dict[tuple[str, str], tuple[str, str, str]] = {}
    counters: dict[str, Counter] = {repo: Counter() for repo in repositories}
    exclusions: Counter = Counter()
    unread_exclusions: Counter = Counter()
    per_repo_exclusions: dict[str, Counter] = {repo: Counter() for repo in repositories}
    status_counts: Counter = Counter()
    digest_unknown = 0
    gitlinks = 0
    for row in _csv(raw_members.pop("file-coverage.csv"), _FILE_HEADER, limits.max_file_rows, limits):
        repo, path = _repository(row["repo"]), _path(row["path"])
        _require(repo in repositories, "UNKNOWN_FILE_REPOSITORY")
        source = repositories[repo]
        sha, object_sha = _sha(row["snapshot_commit"]), _sha(row["blob_sha"])
        _require(sha == source["sha"], "FILE_PIN_MISMATCH")
        _require((repo, path) not in identities, "DUPLICATE_FILE_PATH")
        _require(_boolean(row["repo_archived"]) == source["archived"], "ARCHIVE_STATE_MISMATCH")
        entry_type, mode = row["entry_type"], row["mode"]
        _require((entry_type == "blob" and mode in {"100644", "100755", "120000"}) or (entry_type == "commit" and mode == "160000"), "INVALID_GIT_ENTRY")
        size = _integer(row["size_bytes"]) if row["size_bytes"] else None
        _require(entry_type == "commit" or size is not None, "MISSING_BLOB_SIZE")
        status = row["content_inspection"]
        _require(status in _INSPECTED | _UNREAD, "UNKNOWN_INSPECTION_STATUS")
        category = row["inferred_category"]
        _require(_LABEL.fullmatch(category) is not None, "INVALID_CATEGORY")
        _require(_safe_metadata_identifier(category, limit=64), "UNSAFE_CATEGORY_IDENTIFIER")
        _require(_boolean(row["full_human_content_review"]) is False, "SEMANTIC_CLAIM_INVALID")
        content_sha = _sha(row["content_sha256"], content=True) if row["content_sha256"] else None
        times = [_timestamp(row[key]) for key in ("additional_read_at", "incremental_public_read_at") if row[key]]
        read_at = max(times, key=datetime.fromisoformat) if times else None
        unread = status in _UNREAD
        if not unread and content_sha is None:
            digest_unknown += 1
        gitlinks += entry_type == "commit"
        identities[repo, path] = (object_sha, status, category)
        counters[repo]["tracked"] += 1
        counters[repo]["unread" if unread else "inspected"] += 1
        status_counts[status] += 1
        exclusion = _excluded(repo, path, source["private"], entry_type, mode)
        if exclusion:
            exclusions[exclusion] += 1
            per_repo_exclusions[repo][exclusion] += 1
            if unread:
                unread_exclusions[exclusion] += 1
        else:
            safe_index.append(FileMetadata(repo, sha, source["observed_at"], path, object_sha, entry_type, size, category, status, content_sha, read_at, unread))
    remaining: set[tuple[str, str]] = set()
    for row in _csv(raw_members.pop("remaining-unread-or-skipped.csv"), _REMAINING_HEADER, limits.max_file_rows, limits):
        repo, path = _repository(row["repo"]), _path(row["path"])
        _require(repo in repositories and _sha(row["source_sha"]) == repositories[repo]["sha"], "REMAINING_PIN_MISMATCH")
        key = repo, path
        _require(key not in remaining, "DUPLICATE_REMAINING_PATH")
        expected_record = identities.get(key)
        actual_record = _sha(row["blob_sha"]), row["inspection_status"], row["category"]
        _require(expected_record == actual_record and actual_record[1] in _UNREAD, "REMAINING_JOIN_MISMATCH")
        remaining.add(key)
    _require(remaining == {key for key, value in identities.items() if value[1] in _UNREAD}, "REMAINING_SET_INCOMPLETE")
    total = sum(counts[0] for counts in latest.values())
    inspected = sum(counts[1] for counts in latest.values())
    unread = sum(counts[2] for counts in latest.values())
    for repo, counts in latest.items():
        _require(counts == tuple(counters[repo][key] for key in ("tracked", "inspected", "unread")), "FILE_REPOSITORY_COVERAGE_MISMATCH")
    for key, expected_count in (("metadata_source_snapshots", len(repositories)), ("metadata_entries", total), ("content_read_or_statically_checked", inspected), ("unread_or_skipped", unread)):
        _require(_integer(coverage.get(key)) == expected_count, "MANIFEST_COVERAGE_MISMATCH")
    for key, expected_count in (("tracked_paths", total), ("content_read_or_statically_checked_paths", inspected), ("unread_or_skipped_paths", unread)):
        _require(_integer(summary.get(key)) == expected_count, "SUMMARY_COVERAGE_MISMATCH")
    summary_statuses = summary.get("inspection_status_counts")
    _require(isinstance(summary_statuses, dict), "STATUS_COUNTS_MISMATCH")
    _require(dict(status_counts) == {key: _integer(value) for key, value in summary_statuses.items()}, "STATUS_COUNTS_MISMATCH")
    private_count = sum(source["private"] for source in repositories.values())
    for key, expected_count in (("repositories", len(repositories)), ("private_repositories", private_count), ("tracked_entries_metadata_classified", total), ("content_read_or_statically_checked_paths", inspected), ("unread_or_skipped_paths", unread)):
        _require(_integer(audit.get(key)) == expected_count, "AUDIT_COVERAGE_MISMATCH")
    _require(_integer(audit.get("full_human_content_reviews")) == 0, "SEMANTIC_CLAIM_INVALID")
    candidates = sorted((record for record in safe_index if record.unread), key=lambda record: (_priority(record, configuration)[0], record.repository_id, record.path))
    batch_records = candidates[:configuration.batch_size]
    batch = [{**record.to_dict(), "epistemic_status": "PROPOSAL", "priority_order": _priority(record, configuration)[0], "priority_reason": _priority(record, configuration)[1]} for record in batch_records]
    selected: Counter = Counter(record.repository_id for record in batch_records)
    per_repository = []
    for repo in sorted(repositories):
        source = repositories[repo]
        repository_id = aliases.get(repo, repo)
        metadata = RepositoryMetadata(repository_id, source["sha"], source["observed_at"], source["private"], source["archived"], True, *latest[repo], source["legacy"], "CALLER_CONFIGURED" if repo in configuration.master_repositories else "UNASSIGNED")
        per_repository.append({**asdict(metadata), "excluded_path_counts": dict(sorted(per_repo_exclusions[repo].items())), "proposed_batch_paths": selected[repo], "priority_is_proposal": True})
    safe_index.sort(key=lambda record: (record.repository_id, record.path))
    payload = {
        "schema_version": "szl.frozen-inventory/v1", "source_bundle_sha256": expected,
        "source_member_sha256": dict(sorted(member_hashes.items())),
        "source_created_at_utc": created_at, "coverage_observed_at_utc": updated_at,
        "audit_source_finalized_at_utc": finalized_at, "status": "FROZEN_METADATA_VALIDATED",
        "report_ready": True, "batch_ready": True, "phase2_ready": False,
        "evidence_kind": "HISTORICAL_STATIC_METADATA", "epistemic_status": "FACT",
        "runtime_status": "UNKNOWN", "semantic_review_status": "NOT_ESTABLISHED",
        "fresh_heads_verified": False, "new_source_reads": 0, "unread_reduction": 0,
        "repository_count": len(repositories), "public_repository_count": len(repositories) - private_count,
        "private_repository_count": private_count, "source_tracked_paths": total,
        "historically_inspected_paths": inspected, "unread_or_skipped_paths": unread,
        "legacy_inspected_paths": sum(source["legacy"] for source in repositories.values()),
        "legacy_counts_used_for_latest_coverage": False,
        "historical_inspected_content_digest_unknown": digest_unknown, "gitlink_entries": gitlinks,
        "historical_inspection_status_counts": dict(sorted(status_counts.items())),
        "metadata_index_paths": len(safe_index), "metadata_index_complete_for_all_source_paths": not exclusions,
        "excluded_path_counts": dict(sorted(exclusions.items())),
        "unread_excluded_path_counts": dict(sorted(unread_exclusions.items())),
        "public_safe_unread_candidate_paths": len(candidates), "batch_limit": configuration.batch_size,
        "batch_selected_paths": len(batch), "batch_is_unexecuted_proposal": True,
        "batch": batch, "repositories": per_repository,
        "unmatched_configured_priority_count": len(set(configuration.priority_repositories) - set(repositories)),
        "unmatched_configured_master_count": len(set(configuration.master_repositories) - set(repositories)),
        "errors": [],
    }
    return FrozenInventoryResult(payload, tuple(safe_index))
