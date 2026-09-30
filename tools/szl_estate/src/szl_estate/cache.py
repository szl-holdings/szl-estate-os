"""Small resumable response receipts, with private and unknown bodies withheld.

Only explicitly public, schema-allowlisted projections are retained. No header,
message, arbitrary README/body text, or unknown field is admitted. Integrity
detects accidental corruption; it does not authenticate the remote publisher.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import re
from typing import Any, Iterable

from .model import EvidenceCode, EvidenceValidationError, ProofOrigin, Provenance, safe_identifier
from .storage import StorageError, atomic_write, canonical_bytes, integrity_bytes, read_integrity_payload, sha256_digest


CACHE_SCHEMA_VERSION = "szl.response-cache/v1"
MAX_CACHE_BYTES = 64 * 1024
MAX_PAGE_ITEMS = 128
_KINDS = {"github_repository", "hf_asset", "domain_response", "access"}
_DISPOSITIONS = {"WITHHELD", "PUBLIC_PROJECTION"}


def _safe_scalar(name: str, value: Any, kind: str) -> Any:
    if name == "id" and kind == "hf_asset":
        try:
            return safe_identifier(value, limit=160)
        except EvidenceValidationError:
            return None
    integers = {"id", "size", "downloads", "likes", "total_count", "next_page", "page_size"}
    booleans = {"private", "archived", "fork", "disabled", "has_next_page", "readable", "authenticated"}
    if name in integers:
        return value if type(value) is int and 0 <= value <= 2**63 - 1 else None
    if name in booleans:
        return value if type(value) is bool else None
    choices = {
        "visibility": {"public", "private", "internal"},
        "type": {"model", "dataset", "space"},
        "access": {"READABLE", "INACCESSIBLE", "UNKNOWN"},
        "gated": {"auto", "manual", "false"},
        "content_type": {"text/html", "application/json", "text/plain", "application/octet-stream"},
    }
    if name in choices:
        if name == "gated" and type(value) is bool:
            return value
        return value if isinstance(value, str) and value in choices[name] else None
    if name == "http_status":
        return value if type(value) is int and 100 <= value <= 599 else None
    if name == "sha":
        return value if isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) else None
    if name in {"name", "full_name", "default_branch", "asset_id"}:
        try:
            return safe_identifier(value, limit=160)
        except EvidenceValidationError:
            return None
    return None


def _project_item(body: Any, kind: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    if kind in {"github_repository", "hf_asset"} and body.get("private") is not False:
        return {}
    if kind in {"github_repository", "hf_asset"} and "visibility" in body and body["visibility"] != "public":
        return {}
    allowed = {
        "github_repository": {"id", "name", "full_name", "private", "archived", "fork", "disabled", "visibility", "default_branch", "size"},
        "hf_asset": {"id", "asset_id", "private", "gated", "downloads", "likes", "type", "sha"},
        "domain_response": {"http_status", "content_type"},
        "access": {"readable", "authenticated", "access"},
    }[kind]
    projected = {}
    for key in sorted(allowed):
        if key in body:
            value = _safe_scalar(key, body[key], kind)
            if value is not None:
                projected[key] = value
    return projected


def _public_projection(body: Any, kind: str) -> tuple[dict[str, Any] | list[dict[str, Any]], bool]:
    if isinstance(body, list):
        items = [_project_item(item, kind) for item in body[:MAX_PAGE_ITEMS]]
        return items, len(body) > MAX_PAGE_ITEMS or any(not item for item in items)
    if isinstance(body, dict) and isinstance(body.get("items"), list):
        items, truncated = _public_projection(body["items"], kind)
        result: dict[str, Any] = {"items": items}
        for key in ("total_count", "next_page", "page_size", "has_next_page"):
            if key in body:
                value = _safe_scalar(key, body[key], kind)
                if value is not None:
                    result[key] = value
        return result, truncated
    item = _project_item(body, kind)
    return item, not bool(item)


def _http_code(status_code: int | None) -> EvidenceCode:
    if status_code is None:
        return EvidenceCode.ACCESS_UNVERIFIED
    if status_code in {401, 403}:
        return EvidenceCode.AUTH_FAILED
    if status_code == 429:
        return EvidenceCode.RATE_LIMITED
    if not 200 <= status_code <= 299:
        return EvidenceCode.REMOTE_ERROR
    return EvidenceCode.NONE


def _key_digest(key: str) -> str:
    if not isinstance(key, str) or not key or len(key) > 4096:
        raise StorageError("INVALID_CACHE_KEY")
    try:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise StorageError("INVALID_CACHE_KEY") from None


@dataclass(frozen=True, slots=True)
class CachedResponse:
    key_digest: str
    provenance: Provenance
    status_code: int | None
    body: dict[str, Any] | list[dict[str, Any]] | None
    body_disposition: str
    projection_kind: str | None
    error_code: EvidenceCode
    truncated: bool

    @property
    def is_live_proof(self) -> bool:
        # Both new writes and reads are receipt objects, never live authority.
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CACHE_SCHEMA_VERSION,
            "key_digest": self.key_digest,
            "provenance": self.provenance.to_dict(),
            "status_code": self.status_code,
            "body": self.body,
            "body_disposition": self.body_disposition,
            "projection_kind": self.projection_kind,
            "error_code": self.error_code.value,
            "truncated": self.truncated,
        }


class ResponseCache:
    def __init__(self, root: Path | str, *, source_paths: Iterable[Path | str] = ()):
        self.root = Path(root).resolve()
        self.source_paths = tuple(source_paths)

    def path_for(self, key: str) -> Path:
        return self.root / f"{_key_digest(key)}.json"

    def put(
        self, key: str, provenance: Provenance, status_code: int | None,
        body: Any = None, *, visibility: str = "unknown", projection_kind: str | None = None,
    ) -> CachedResponse:
        if not isinstance(provenance, Provenance):
            raise StorageError("INVALID_CACHE_PROVENANCE")
        if status_code is not None and (type(status_code) is not int or not 100 <= status_code <= 599):
            raise StorageError("INVALID_HTTP_STATUS")
        if not isinstance(visibility, str) or visibility not in {"public", "private", "unknown"}:
            raise StorageError("INVALID_VISIBILITY")
        if projection_kind is not None and (not isinstance(projection_kind, str) or projection_kind not in _KINDS):
            raise StorageError("INVALID_PROJECTION_KIND")
        projected = None
        truncated = False
        disposition = "WITHHELD"
        code = _http_code(status_code)
        # Error bodies are always withheld, including public API error text.
        if visibility == "public" and projection_kind is not None and code is EvidenceCode.NONE:
            projected, truncated = _public_projection(body, projection_kind)
            disposition = "PUBLIC_PROJECTION"
        if truncated:
            code = EvidenceCode.PARTIAL_RESULT
        redacted = {"body": projected, "body_disposition": disposition, "projection_kind": projection_kind, "truncated": truncated}
        receipt_provenance = replace(provenance, digest=sha256_digest(redacted), origin=ProofOrigin.CACHE)
        record = CachedResponse(_key_digest(key), receipt_provenance, status_code, projected, disposition, projection_kind, code, truncated)
        raw = integrity_bytes(record.to_dict())
        if len(raw) > MAX_CACHE_BYTES:
            # Retain a bounded withheld receipt rather than truncating JSON bytes.
            redacted = {"body": None, "body_disposition": "WITHHELD", "projection_kind": projection_kind, "truncated": True}
            record = replace(record, body=None, body_disposition="WITHHELD", truncated=True, error_code=EvidenceCode.PARTIAL_RESULT, provenance=replace(receipt_provenance, digest=sha256_digest(redacted)))
            raw = integrity_bytes(record.to_dict())
        if len(raw) > MAX_CACHE_BYTES:
            raise StorageError("RECORD_TOO_LARGE")
        atomic_write(self.path_for(key), raw, source_paths=self.source_paths)
        return record

    def get(self, key: str) -> CachedResponse | None:
        path = self.path_for(key)
        if not path.exists():
            return None
        payload = read_integrity_payload(path, max_bytes=MAX_CACHE_BYTES)
        required = {"schema_version", "key_digest", "provenance", "status_code", "body", "body_disposition", "projection_kind", "error_code", "truncated"}
        if set(payload) != required or payload["schema_version"] != CACHE_SCHEMA_VERSION or payload["key_digest"] != _key_digest(key):
            raise StorageError("INVALID_CACHE_RECORD")
        status = payload["status_code"]
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise StorageError("INVALID_CACHE_RECORD")
        kind = payload["projection_kind"]
        if kind is not None and (not isinstance(kind, str) or kind not in _KINDS):
            raise StorageError("INVALID_CACHE_RECORD")
        if not isinstance(payload["body_disposition"], str) or payload["body_disposition"] not in _DISPOSITIONS or type(payload["truncated"]) is not bool:
            raise StorageError("INVALID_CACHE_RECORD")
        try:
            provenance = Provenance.from_dict(payload["provenance"])
            code = EvidenceCode(payload["error_code"])
        except (EvidenceValidationError, ValueError, TypeError):
            raise StorageError("INVALID_CACHE_RECORD") from None
        body = payload["body"]
        if payload["body_disposition"] == "WITHHELD":
            if body is not None:
                raise StorageError("UNSAFE_CACHE_BODY")
        else:
            if kind is None or body is None or _http_code(status) is not EvidenceCode.NONE:
                raise StorageError("UNSAFE_CACHE_BODY")
            projected, truncated = _public_projection(body, kind)
            if canonical_bytes(body) != canonical_bytes(projected) or (truncated and not payload["truncated"]):
                raise StorageError("UNSAFE_CACHE_BODY")
        redacted = {"body": body, "body_disposition": payload["body_disposition"], "projection_kind": kind, "truncated": payload["truncated"]}
        if provenance.digest != sha256_digest(redacted):
            raise StorageError("CACHE_BODY_DIGEST_MISMATCH")
        expected_code = EvidenceCode.PARTIAL_RESULT if payload["truncated"] else _http_code(status)
        if code is not expected_code:
            raise StorageError("CACHE_ERROR_CODE_MISMATCH")
        return CachedResponse(_key_digest(key), replace(provenance, origin=ProofOrigin.CACHE), status, body, payload["body_disposition"], kind, code, payload["truncated"])
