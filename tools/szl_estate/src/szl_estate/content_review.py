"""Offline pinned byte-read receipts; static review and runtime remain separate."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from .inventory import FileMetadata, _INSPECTED
from .model import EvidenceStatus, ProofOrigin, _SECRET, safe_identifier, safe_reference, utc_timestamp


SCHEMA_VERSION = "szl.source-review-receipt/v1"
MAX_SOURCE_BYTES = 256 * 1024
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_WORDS = {"credential", "credentials", "secret", "secrets", "token", "tokens", "session", "sessions", "sessionlogs", "password", "passwords", "auth", "authentication", "oauth", "apikey"}
_PERSONAL = {"personal", "private", "patient", "patients", "payroll", "personnel", "contacts", "customers", "employees", "pii", "ssn"}
_OPERATIONAL = {"finance", "financial", "trading", "legal", "defense", "defence", "military", "weapons", "weapon", "munitions", "targeting", "engagement"}
_HIDDEN = {".ssh", ".aws", ".azure", ".config", ".codex", ".agents", ".git", ".netrc", ".git-credentials", ".npmrc", ".pypirc", "appdata", "id_rsa", "id_ed25519", "node_modules", "site-packages", ".venv", "venv", "env", "__pycache__", "weights", "checkpoints", "datasets", "dataset_rows"}
_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".safetensors", ".gguf", ".pt", ".pth", ".onnx", ".bin", ".parquet", ".arrow", ".h5", ".csv", ".jsonl")
_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HANDLE = re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9][A-Za-z0-9_-]*)?")
_CREDENTIAL_NAME = r"\b[A-Za-z0-9_-]*(?:password|authorization|api[_-]?key|access[_-]?key|secret|token)[A-Za-z0-9_-]*[\"']?"
_ASSIGNMENT = re.compile(_CREDENTIAL_NAME + r"[ \t]*[:=][ \t]*(?P<value>[^\r\n]+)", re.I)
_SYMBOLIC_VALUE = re.compile(r"(?:None|False|True|null|os\.environ|os\.environ\[['\"][A-Za-z_][A-Za-z0-9_]*['\"]\]|(?:os\.environ\.get|(?:os\.)?getenv)\(['\"][A-Za-z_][A-Za-z0-9_]*['\"]\)|get_token\(\)|self\.[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{\{[ \t]*secrets\.[A-Za-z_][A-Za-z0-9_]*[ \t]*\}\})")
_CREDENTIAL_BLOCK = re.compile(_CREDENTIAL_NAME + r"[ \t]*[:=][ \t]*(?:[|>][-+]?|[\(\[{]|\"\"\"|''')?[ \t]*(?:#[^\r\n]*)?\r?$", re.I | re.M)
_CREDENTIAL_TRIPLE_QUOTE = re.compile(_CREDENTIAL_NAME + r"[ \t]*[:=][ \t]*(?:\"\"\"|''')", re.I)
_CREDENTIAL_CONTINUATION = re.compile(_CREDENTIAL_NAME + r"[ \t]*[:=][^\r\n]*[\(\[{][ \t]*\r?$", re.I | re.M)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
_BEARER_VALUE = re.compile(r"\bbearer\s+[A-Za-z0-9._~-]{12,}", re.I)
_OWNERSHIP_CONTEXT = re.compile(r"\b(?:owners?|maintainers?|authors?|contacts?|email|assignees?|reviewers?)\b", re.I)
_PERSONAL_RECORD = re.compile(r"\b(?:patient[_ -]?(?:id|name|record)|social[_ -]?security|ssn|date[_ -]?of[_ -]?birth)\b", re.I)
_OPERATIONAL_BODY = re.compile(r"\b(?:weapon[_ -]?(?:target|guidance|deployment)|live[_ -]?trading|patient[_ -]?records)\b", re.I)
_PROFILE_PATH = re.compile(r"(?:[A-Z]:[\\/]+Users[\\/]+[^\\/\s\"']+|/(?:home|Users)/[^/\s\"']+)", re.I)
_ATTRIBUTION = re.compile(r"(?:\bcopyright\b|©|\(c\)[ \t]*20\d{2}|\battribution\b|\bORCID\b|\b(?:author|maintainer|owner|contributor)[\"']?[ \t]*[:=]|\b(?:created|generated|written|maintained|fixed)[ \t]+(?:by|for)\b)", re.I)


class ContentReviewError(ValueError):
    """Fixed codes only; raw source text and rejected values are never echoed."""


class ReviewStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ContentReviewError(code)


def _eligible_path(repository: str, path: str) -> bool:
    parts = path.casefold().split("/")
    words = set(re.split(r"[^a-z0-9]+", repository.casefold() + "/" + path.casefold()))
    return not (words & (_SECRET_WORDS | _PERSONAL | _OPERATIONAL)
                or {"api", "key"}.issubset(words) or set(parts) & _HIDDEN
                or any(part.startswith(".env") for part in parts) or path.casefold().endswith(_SUFFIXES))


@dataclass(frozen=True, slots=True)
class FilePin:
    repository_id: str
    snapshot_sha: str
    path: str
    blob_sha: str
    size_bytes: int

    def __post_init__(self) -> None:
        _require(isinstance(self.repository_id, str) and bool(re.fullmatch(r"szl-holdings/[A-Za-z0-9_.-]{1,100}", self.repository_id)) and self.repository_id.rsplit("/", 1)[-1] not in {".", ".."}, "INVALID_REPOSITORY_PIN")
        _require(isinstance(self.snapshot_sha, str) and bool(_SHA1.fullmatch(self.snapshot_sha)), "INVALID_COMMIT_PIN")
        _require(isinstance(self.blob_sha, str) and bool(_SHA1.fullmatch(self.blob_sha)), "INVALID_BLOB_PIN")
        _require(isinstance(self.path, str) and 0 < len(self.path) <= 1024 and bool(re.fullmatch(r"[A-Za-z0-9_.\-/]+", self.path)), "INVALID_FILE_PATH")
        _require(not self.path.startswith("/") and all(part not in {"", ".", ".."} for part in self.path.split("/")), "INVALID_FILE_PATH")
        _require(type(self.size_bytes) is int and 0 <= self.size_bytes <= MAX_SOURCE_BYTES, "SOURCE_SIZE_LIMIT")
        _require(_eligible_path(self.repository_id, self.path), "EXCLUDED_SOURCE_PATH")
        try:
            safe_identifier(self.repository_id)
            safe_identifier(self.path, limit=1024)
        except ValueError:
            raise ContentReviewError("INVALID_FILE_PATH") from None

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.repository_id, self.snapshot_sha, self.path, self.blob_sha

    def to_dict(self) -> dict[str, Any]:
        return {"repository_id": self.repository_id, "snapshot_sha": self.snapshot_sha,
                "path": self.path, "blob_sha": self.blob_sha, "size_bytes": self.size_bytes}

    @classmethod
    def from_dict(cls, value: Any) -> FilePin:
        _require(isinstance(value, dict) and set(value) == {"repository_id", "snapshot_sha", "path", "blob_sha", "size_bytes"}, "INVALID_FILE_PIN")
        return cls(**value)


def source_endpoints(pin: FilePin) -> tuple[str, str]:
    return (f"https://api.github.com/repos/{pin.repository_id}/git/blobs/{pin.blob_sha}",
            f"https://raw.githubusercontent.com/{pin.repository_id}/{pin.snapshot_sha}/{quote(pin.path, safe='/')}")


def git_blob_sha1(raw: bytes) -> str:
    _require(isinstance(raw, bytes) and len(raw) <= MAX_SOURCE_BYTES, "SOURCE_SIZE_LIMIT")
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewReceipt:
    pin: FilePin
    source_endpoint: str
    read_at_utc: str
    source_origin: ProofOrigin
    byte_read_status: ReviewStatus
    static_contract_status: ReviewStatus
    bytes_read: int
    original_blob_sha1: str | None
    original_sha256: str | None
    redacted_cache_sha256: str | None
    redacted_lines: int
    cache_disposition: str
    code: str
    coverage_scope: str = "PINNED_FILE_BYTES_ONLY"
    owner_findings_refs: tuple[str, ...] = ()
    runtime_status: EvidenceStatus = EvidenceStatus.NOT_RUN
    _verified_bytes: bool = field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "source_origin", ProofOrigin(self.source_origin))
            object.__setattr__(self, "byte_read_status", ReviewStatus(self.byte_read_status))
            object.__setattr__(self, "static_contract_status", ReviewStatus(self.static_contract_status))
            object.__setattr__(self, "runtime_status", EvidenceStatus(self.runtime_status))
            object.__setattr__(self, "read_at_utc", utc_timestamp(self.read_at_utc))
        except (ValueError, TypeError):
            raise ContentReviewError("INVALID_REVIEW_RECEIPT") from None
        _require(isinstance(self.pin, FilePin) and self.source_endpoint in source_endpoints(self.pin), "SOURCE_ENDPOINT_MISMATCH")
        _require(self.runtime_status == EvidenceStatus.NOT_RUN and self.coverage_scope == "PINNED_FILE_BYTES_ONLY", "INVALID_REVIEW_SCOPE")
        _require(type(self.bytes_read) is int and 0 <= self.bytes_read <= MAX_SOURCE_BYTES, "INVALID_READ_SIZE")
        _require(type(self.redacted_lines) is int and 0 <= self.redacted_lines <= MAX_SOURCE_BYTES, "INVALID_REDACTION_COUNT")
        _require(isinstance(self.cache_disposition, str) and self.cache_disposition in {"SCREENED_TEXT", "WITHHELD"}, "INVALID_CACHE_DISPOSITION")
        _require(isinstance(self.code, str) and self.code in {"NONE", "READ_PARTIAL", "READ_SKIPPED", "READ_ERROR", "SIZE_MISMATCH", "BLOB_MISMATCH", "BINARY_WITHHELD", "LFS_POINTER_WITHHELD", "SENSITIVE_RECORD_WITHHELD", "PRIVATE_KEY_WITHHELD", "CREDENTIAL_BLOCK_WITHHELD", "REDACTED_TEXT", "SOURCE_SIZE_LIMIT"}, "INVALID_REVIEW_CODE")
        for digest, pattern in ((self.original_blob_sha1, _SHA1), (self.original_sha256, _SHA256), (self.redacted_cache_sha256, _SHA256)):
            _require(digest is None or isinstance(digest, str) and bool(pattern.fullmatch(digest)), "INVALID_CONTENT_DIGEST")
        if self.byte_read_status is ReviewStatus.COMPLETE:
            _require(self.bytes_read == self.pin.size_bytes and self.original_blob_sha1 == self.pin.blob_sha and self.original_sha256 is not None and self.cache_disposition == "SCREENED_TEXT" and self.redacted_cache_sha256 is not None, "FALSE_COMPLETE_READ")
        if self.redacted_lines:
            _require(self.static_contract_status is ReviewStatus.PARTIAL, "FALSE_COMPLETE_STATIC_REVIEW")
        if self.static_contract_status is ReviewStatus.COMPLETE:
            _require(self.byte_read_status is ReviewStatus.COMPLETE and bool(self.owner_findings_refs), "STATIC_REVIEW_REFERENCE_REQUIRED")
        _require(isinstance(self.owner_findings_refs, (tuple, list)) and len(self.owner_findings_refs) <= 32, "INVALID_FINDING_REFERENCES")
        try:
            refs = tuple(sorted(set(safe_reference(value) for value in self.owner_findings_refs)))
        except (ValueError, TypeError):
            raise ContentReviewError("INVALID_FINDING_REFERENCES") from None
        _require(not any(_EMAIL.search(value) or _HANDLE.search(value) for value in refs), "INVALID_FINDING_REFERENCES")
        object.__setattr__(self, "owner_findings_refs", refs)

    @property
    def byte_coverage_credit(self) -> bool:
        return self._verified_bytes and self.byte_read_status is ReviewStatus.COMPLETE

    @property
    def fresh_source_proof(self) -> bool:
        return self.byte_coverage_credit and self.source_origin is ProofOrigin.LIVE

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "pin": self.pin.to_dict(), "source_endpoint": self.source_endpoint,
                "read_at_utc": self.read_at_utc, "source_origin": self.source_origin.value,
                "byte_read_status": self.byte_read_status.value, "static_contract_status": self.static_contract_status.value,
                "bytes_read": self.bytes_read, "original_blob_sha1": self.original_blob_sha1, "original_sha256": self.original_sha256,
                "redacted_cache_sha256": self.redacted_cache_sha256, "redacted_lines": self.redacted_lines,
                "cache_disposition": self.cache_disposition, "code": self.code, "coverage_scope": self.coverage_scope,
                "owner_findings_refs": list(self.owner_findings_refs), "runtime_status": EvidenceStatus.NOT_RUN.value}

    @classmethod
    def from_dict(cls, value: Any, *, cached_text: str | None = None) -> ReviewReceipt:
        required = {"schema_version", "pin", "source_endpoint", "read_at_utc", "source_origin", "byte_read_status", "static_contract_status", "bytes_read", "original_blob_sha1", "original_sha256", "redacted_cache_sha256", "redacted_lines", "cache_disposition", "code", "coverage_scope", "owner_findings_refs", "runtime_status"}
        _require(isinstance(value, dict) and set(value) == required and value["schema_version"] == SCHEMA_VERSION, "INVALID_REVIEW_RECEIPT")
        fields = dict(value)
        fields.pop("schema_version")
        fields["pin"] = FilePin.from_dict(fields["pin"])
        try:
            ProofOrigin(fields["source_origin"])
        except (ValueError, TypeError):
            raise ContentReviewError("INVALID_REVIEW_RECEIPT") from None
        # Serialized labels are claims about a previous read, never new live proof.
        fields["source_origin"] = ProofOrigin.CACHE
        receipt = cls(**fields)
        if cached_text is not None:
            _require(isinstance(cached_text, str) and len(cached_text) <= MAX_SOURCE_BYTES, "INVALID_CACHE_TEXT")
            try:
                raw = cached_text.encode("utf-8")
            except UnicodeError:
                raise ContentReviewError("INVALID_CACHE_TEXT") from None
            _require(len(raw) <= MAX_SOURCE_BYTES and hashlib.sha256(raw).hexdigest() == receipt.redacted_cache_sha256, "CACHE_DIGEST_MISMATCH")
            screened, redacted, withheld = _screen(raw, receipt.pin.path)
            _require(not withheld and redacted == 0 and screened == cached_text, "UNSAFE_CACHE_TEXT")
            if receipt.redacted_lines == 0 and receipt.byte_read_status is ReviewStatus.COMPLETE:
                _require(len(raw) == receipt.pin.size_bytes == receipt.bytes_read, "CACHE_SIZE_MISMATCH")
                _require(git_blob_sha1(raw) == receipt.pin.blob_sha and hashlib.sha256(raw).hexdigest() == receipt.original_sha256, "CACHE_ORIGINAL_MISMATCH")
                object.__setattr__(receipt, "_verified_bytes", True)
        return receipt


@dataclass(frozen=True, slots=True)
class ReviewResult:
    receipt: ReviewReceipt
    redacted_text: str | None


def _screen(raw: bytes, path: str) -> tuple[str | None, int, str | None]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return None, 0, "BINARY_WITHHELD"
    if "\0" in text or any(ord(char) < 32 and char not in "\t\r\n" for char in text):
        return None, 0, "BINARY_WITHHELD"
    if text.startswith("version https://git-lfs.github.com/spec/v1"):
        return None, 0, "LFS_POINTER_WITHHELD"
    if _PRIVATE_KEY.search(text):
        return None, 0, "PRIVATE_KEY_WITHHELD"
    if _CREDENTIAL_BLOCK.search(text) or _CREDENTIAL_CONTINUATION.search(text) or _CREDENTIAL_TRIPLE_QUOTE.search(text):
        return None, 0, "CREDENTIAL_BLOCK_WITHHELD"
    if _PERSONAL_RECORD.search(text) or _OPERATIONAL_BODY.search(text):
        return None, 0, "SENSITIVE_RECORD_WITHHELD"
    lines, count = [], 0
    for line in text.splitlines(keepends=True):
        handles = [match.group() for match in _HANDLE.finditer(line)]
        assignments = list(_ASSIGNMENT.finditer(line))
        literal_secret = any(not _SYMBOLIC_VALUE.fullmatch(match["value"].strip()) for match in assignments)
        literal_token = any(not re.fullmatch(r"(?:bearer|password|authorization|api[_-]?key|token|secret)[=:]", match.group(), re.I) for match in _SECRET.finditer(line))
        personal_handles = (path.rsplit("/", 1)[-1].casefold() == "codeowners" or bool(_OWNERSHIP_CONTEXT.search(line))) and any(not handle.startswith("@szl-holdings/") for handle in handles)
        if literal_token or literal_secret or _BEARER_VALUE.search(line) or _EMAIL.search(line) or personal_handles or _PROFILE_PATH.search(line) or _ATTRIBUTION.search(line):
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else "\r" if line.endswith("\r") else ""
            lines.append("[REDACTED]" + ending)
            count += 1
        else:
            lines.append(line)
    return "".join(lines), count, None


def review_bytes(pin: FilePin, raw: bytes | None, *, source_endpoint: str, read_at_utc: str,
                 source_origin: ProofOrigin = ProofOrigin.UNKNOWN,
                 byte_read_status: ReviewStatus = ReviewStatus.COMPLETE,
                 static_contract_status: ReviewStatus = ReviewStatus.SKIPPED,
                 owner_findings_refs: tuple[str, ...] = ()) -> ReviewResult:
    _require(isinstance(pin, FilePin), "INVALID_FILE_PIN")
    try:
        byte_status, static_status = ReviewStatus(byte_read_status), ReviewStatus(static_contract_status)
    except (ValueError, TypeError):
        raise ContentReviewError("INVALID_REVIEW_STATUS") from None
    original_blob = original_sha = cache_sha = None
    text = None
    redacted = size = 0
    code = {ReviewStatus.COMPLETE: "NONE", ReviewStatus.PARTIAL: "READ_PARTIAL", ReviewStatus.SKIPPED: "READ_SKIPPED", ReviewStatus.ERROR: "READ_ERROR"}[byte_status]
    if byte_status in {ReviewStatus.COMPLETE, ReviewStatus.PARTIAL}:
        if not isinstance(raw, bytes):
            byte_status, code = ReviewStatus.ERROR, "READ_ERROR"
        elif len(raw) > MAX_SOURCE_BYTES:
            byte_status, code = ReviewStatus.ERROR, "SOURCE_SIZE_LIMIT"
        else:
            size = len(raw)
            original_blob, original_sha = git_blob_sha1(raw), hashlib.sha256(raw).hexdigest()
            if byte_status is ReviewStatus.COMPLETE and size != pin.size_bytes:
                byte_status, code = ReviewStatus.ERROR, "SIZE_MISMATCH"
            elif byte_status is ReviewStatus.COMPLETE and original_blob != pin.blob_sha:
                byte_status, code = ReviewStatus.ERROR, "BLOB_MISMATCH"
            elif byte_status is ReviewStatus.COMPLETE:
                text, redacted, withheld = _screen(raw, pin.path)
                if withheld:
                    byte_status, static_status, code = ReviewStatus.SKIPPED, ReviewStatus.SKIPPED, withheld
                elif text is not None:
                    screened_bytes = text.encode("utf-8")
                    if len(screened_bytes) > MAX_SOURCE_BYTES:
                        text, byte_status, static_status, code = None, ReviewStatus.SKIPPED, ReviewStatus.PARTIAL, "SOURCE_SIZE_LIMIT"
                    else:
                        cache_sha = hashlib.sha256(screened_bytes).hexdigest()
                    if redacted and text is not None:
                        static_status, code = ReviewStatus.PARTIAL, "REDACTED_TEXT"
    if byte_status is not ReviewStatus.COMPLETE and static_status is ReviewStatus.COMPLETE:
        static_status = ReviewStatus.PARTIAL
    receipt = ReviewReceipt(pin, source_endpoint, read_at_utc, source_origin, byte_status, static_status,
                            size, original_blob, original_sha, cache_sha, redacted,
                            "SCREENED_TEXT" if text is not None else "WITHHELD", code,
                            owner_findings_refs=owner_findings_refs)
    if byte_status is ReviewStatus.COMPLETE:
        object.__setattr__(receipt, "_verified_bytes", True)
    return ReviewResult(receipt, text)


def _index(file_index: Iterable[FileMetadata | Mapping[str, Any]]) -> tuple[dict[tuple[str, str, str, str], FilePin], set[tuple[str, str, str, str]]]:
    pins, historical = {}, set()
    for number, row in enumerate(file_index):
        _require(number < 50000, "FILE_INDEX_LIMIT")
        if isinstance(row, FileMetadata):
            fields = row.to_dict()
        else:
            _require(isinstance(row, Mapping), "INVALID_FILE_INDEX")
            fields = row
        _require(fields.get("entry_type") == "blob", "INVALID_FILE_INDEX")
        try:
            pin = FilePin(fields.get("repository_id"), fields.get("snapshot_sha"), fields.get("path"), fields.get("git_object_sha"), fields.get("size_bytes"))
        except ContentReviewError as error:
            # Metadata can describe names outside this reader's strict grammar.
            # They remain unread; selected plans/receipts still reject them.
            if str(error) in {"EXCLUDED_SOURCE_PATH", "SOURCE_SIZE_LIMIT", "INVALID_FILE_PATH"}:
                continue
            raise
        _require(pin.key not in pins or pins[pin.key] == pin, "CONFLICTING_FILE_INDEX")
        pins[pin.key] = pin
        inspection_status = fields.get("historical_inspection_status")
        if fields.get("unread") is False and isinstance(inspection_status, str) and inspection_status in _INSPECTED:
            historical.add(pin.key)
    return pins, historical


@dataclass(frozen=True, slots=True)
class CoverageResult:
    historical_read_total: int | None
    historical_indexed_read_paths: int
    newly_verified_read_paths: int
    indexed_completed_paths: int
    reconciled_read_total: int | None
    unique_completed_objects: int
    completed_file_keys: tuple[tuple[str, str, str, str], ...]
    byte_status_counts: Mapping[str, int]
    static_contract_status_counts: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {"historical_read_total": self.historical_read_total, "historical_indexed_read_paths": self.historical_indexed_read_paths,
                "newly_verified_read_paths": self.newly_verified_read_paths, "indexed_completed_paths": self.indexed_completed_paths,
                "reconciled_read_total": self.reconciled_read_total, "unique_completed_objects": self.unique_completed_objects,
                "completed_file_keys": [list(key) for key in self.completed_file_keys],
                "byte_status_counts": dict(self.byte_status_counts), "static_contract_status_counts": dict(self.static_contract_status_counts),
                "coverage_scope": "VERIFIED_PINNED_FILE_BYTES_AND_DECLARED_HISTORICAL_BASELINE", "runtime_status": "NOT_RUN", "estate_ready": False}


def reconcile_coverage(file_index: Iterable[FileMetadata | Mapping[str, Any]], receipts: Iterable[ReviewReceipt], *, historical_read_count: int | None = None) -> CoverageResult:
    pins, historical = _index(file_index)
    _require(historical_read_count is None or type(historical_read_count) is int and len(historical) <= historical_read_count <= 2**63 - 1, "INVALID_HISTORICAL_BASELINE")
    grouped: dict[tuple[str, str, str, str], list[ReviewReceipt]] = {}
    for number, receipt in enumerate(receipts):
        _require(number < 50000 and isinstance(receipt, ReviewReceipt), "INVALID_REVIEW_RECEIPT")
        _require(receipt.pin.key in pins and receipt.pin == pins[receipt.pin.key], "RECEIPT_OUTSIDE_INDEX")
        grouped.setdefault(receipt.pin.key, []).append(receipt)
    verified = {key for key, values in grouped.items() if any(item.byte_coverage_credit for item in values)}
    complete = historical | verified
    byte_counts = {status.value: 0 for status in ReviewStatus}
    static_counts = {status.value: 0 for status in ReviewStatus}
    for values in grouped.values():
        # Complete byte counts require verification, not a serialized status label.
        for name, counts in (("byte_read_status", byte_counts), ("static_contract_status", static_counts)):
            statuses = {ReviewStatus.PARTIAL if name == "byte_read_status" and item.byte_read_status is ReviewStatus.COMPLETE and not item.byte_coverage_credit else getattr(item, name) for item in values}
            best = next(status for status in ReviewStatus if status in statuses)
            counts[best.value] += 1
    new = verified - historical
    return CoverageResult(historical_read_count, len(historical), len(new), len(complete),
                          None if historical_read_count is None else historical_read_count + len(new),
                          len({pins[key].blob_sha for key in complete}), tuple(sorted(complete)), byte_counts, static_counts)


def select_next_batch(file_index: Iterable[FileMetadata | Mapping[str, Any]], receipts: Iterable[ReviewReceipt], *, limit: int = 64) -> tuple[FilePin, ...]:
    _require(type(limit) is int and 0 <= limit <= 64, "INVALID_BATCH_LIMIT")
    rows_list = []
    for number, row in enumerate(file_index):
        _require(number < 50000, "FILE_INDEX_LIMIT")
        rows_list.append(row)
    rows = tuple(rows_list)
    pins, _ = _index(rows)
    completed = set(reconcile_coverage(rows, receipts).completed_file_keys)
    return tuple(pins[key] for key in sorted(pins) if key not in completed)[:limit]
