"""Bounded, offline summary readers for existing inventory evidence.

These summaries describe historical observations. Reading one never proves
current access, runtime health, review completeness, or shipping readiness.
Archive files are never extracted or executed, and only three allowlisted
summary members are decompressed. Bodies, asset names, paths, and parser error
messages are never included in the returned model.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 256 * 1024
MAX_ARCHIVE_MEMBERS = 1_000
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_COUNT = 2**63 - 1

_SUMMARY_MEMBERS = (
    "audit-summary.json",
    "current-content-summary.json",
    "bundle-manifest.json",
)
_BACKEND_COUNTS = (
    "repositories",
    "tracked_paths",
    "content_inspected",
    "unread_paths",
    "metadata_source_snapshots",
)
_HF_REPO_COUNTS = ("datasets", "kernels", "models", "spaces")
_HF_COUNTS = (
    "asset_count",
    "listed_file_paths",
    "card_content_inspected",
    "other_contract_reads_attempted",
    "other_contract_content_inspected",
    "content_unavailable",
    "files_inventoried_only",
    "http_probes",
    "http_200",
    "space_container_running",
)
_UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
)
_ERROR_PRIORITY = (
    "INVALID_JSON",
    "INVALID_SUMMARY_SHAPE",
    "HF_SCHEMA_UNSUPPORTED",
    "COUNT_CONFLICT",
    "COUNT_INCONSISTENT",
    "INVALID_COUNT",
    "INVALID_TIMESTAMP",
    "SUMMARY_MISSING",
    "SUMMARY_INCOMPLETE",
)


@dataclass(frozen=True)
class InventorySummary:
    """Safe aggregate evidence, with unknowns represented by ``None``.

    ``digest`` is the SHA256 of the entire readable, bounded input file. An
    error preserves independently readable facts but must prevent a success
    claim. No timestamp is refreshed to the reader's current time.
    """

    kind: str
    observed_at_utc: str | None
    digest: str | None
    counts: Mapping[str, int | None]
    error_code: str | None = None


class _InputError(Exception):
    """Internal fixed codes; external exception messages are never retained."""


def _read_input(path: Path) -> tuple[bytes | None, str | None, str | None]:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            return None, None, "INPUT_TOO_LARGE"
        with path.open("rb") as stream:
            payload = stream.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError):
        return None, None, "INPUT_UNREADABLE"
    if len(payload) > MAX_INPUT_BYTES:
        return None, None, "INPUT_TOO_LARGE"
    return payload, hashlib.sha256(payload).hexdigest(), None


def _json_object(payload: bytes) -> dict[str, object]:
    def invalid_constant(value: str) -> object:
        raise _InputError("INVALID_JSON")

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _InputError("INVALID_JSON")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload, object_pairs_hook=unique_pairs, parse_constant=invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise _InputError("INVALID_JSON") from None
    if not isinstance(value, dict):
        raise _InputError("INVALID_SUMMARY_SHAPE")
    return value


def _timestamp(value: object) -> str | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.utcoffset() != timezone.utc.utcoffset(stamp):
        return None
    return stamp.isoformat().replace("+00:00", "Z")


def _error_code(errors: set[str]) -> str | None:
    return next((code for code in _ERROR_PRIORITY if code in errors), None)


def _count(value: object, errors: set[str]) -> int | None:
    if type(value) is int and 0 <= value <= MAX_COUNT:
        return value
    errors.add("INVALID_COUNT")
    return None


def _selected_zip_members(payload: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise _InputError("ZIP_MEMBER_LIMIT")
            if sum(info.file_size for info in infos) > MAX_EXPANDED_BYTES:
                raise _InputError("ZIP_EXPANDED_LIMIT")
            selected: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                if info.filename not in _SUMMARY_MEMBERS:
                    continue
                if info.filename in selected:
                    raise _InputError("ZIP_SUMMARY_DUPLICATE")
                if info.file_size > MAX_SUMMARY_BYTES:
                    raise _InputError("ZIP_SUMMARY_TOO_LARGE")
                if info.is_dir() or info.flag_bits & 1:
                    raise _InputError("INVALID_ZIP")
                # Other codecs can allocate unbounded output before ZipExtFile
                # applies a read limit. Deflate supports bounded decompression.
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise _InputError("ZIP_UNSUPPORTED_COMPRESSION")
                selected[info.filename] = info
            result: dict[str, bytes] = {}
            for name in _SUMMARY_MEMBERS:
                if name not in selected:
                    continue
                with archive.open(selected[name]) as stream:
                    member = stream.read(MAX_SUMMARY_BYTES + 1)
                if len(member) > MAX_SUMMARY_BYTES:
                    raise _InputError("ZIP_SUMMARY_TOO_LARGE")
                result[name] = member
            return result
    except _InputError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError,
            RuntimeError, NotImplementedError, EOFError, zlib.error):
        raise _InputError("INVALID_ZIP") from None


def _backend_counts(
    summaries: Mapping[str, dict[str, object]], errors: set[str]
) -> dict[str, int | None]:
    candidates: dict[str, list[int | None]] = {
        key: [] for key in _BACKEND_COUNTS
    }
    field_maps = (
        ("audit-summary.json", None, {
            "repositories": "repositories",
            "tracked_entries_metadata_classified": "tracked_paths",
            "content_read_or_statically_checked_paths": "content_inspected",
            "unread_or_skipped_paths": "unread_paths",
        }),
        ("current-content-summary.json", None, {
            "tracked_paths": "tracked_paths",
            "content_read_or_statically_checked_paths": "content_inspected",
            "unread_or_skipped_paths": "unread_paths",
        }),
        ("bundle-manifest.json", "coverage", {
            "metadata_source_snapshots": "metadata_source_snapshots",
            "metadata_entries": "tracked_paths",
            "content_read_or_statically_checked": "content_inspected",
            "unread_or_skipped": "unread_paths",
        }),
    )
    for name, nested_key, aliases in field_maps:
        if name not in summaries:
            continue
        source = summaries[name]
        if nested_key is not None:
            nested = source.get(nested_key)
            if not isinstance(nested, dict):
                errors.add("INVALID_SUMMARY_SHAPE")
                continue
            source = nested
        for original, canonical in aliases.items():
            if original in source:
                candidates[canonical].append(_count(source[original], errors))
            else:
                errors.add("SUMMARY_INCOMPLETE")

    counts: dict[str, int | None] = {}
    for key, values in candidates.items():
        if not values:
            counts[key] = None
            errors.add("SUMMARY_INCOMPLETE")
        elif None in values:
            counts[key] = None
        elif len(set(values)) != 1:
            counts[key] = None
            errors.add("COUNT_CONFLICT")
        else:
            counts[key] = values[0]

    repositories = counts["repositories"]
    snapshots = counts["metadata_source_snapshots"]
    if repositories is not None and snapshots is not None and repositories != snapshots:
        counts["repositories"] = counts["metadata_source_snapshots"] = None
        errors.add("COUNT_CONFLICT")
    tracked, inspected, unread = (
        counts[key] for key in ("tracked_paths", "content_inspected", "unread_paths")
    )
    if tracked is not None and inspected is not None and unread is not None:
        if tracked != inspected + unread:
            for key in ("tracked_paths", "content_inspected", "unread_paths"):
                counts[key] = None
            errors.add("COUNT_INCONSISTENT")
    return counts


def load_backend_summary(path: Path) -> InventorySummary:
    """Consume aggregate GitHub ZIP evidence, without extracting its files."""
    kind = "github_inventory"
    payload, digest, error = _read_input(path)
    if payload is None:
        return InventorySummary(kind, None, digest, {}, error)
    try:
        members = _selected_zip_members(payload)
    except _InputError as failure:
        return InventorySummary(kind, None, digest, {}, str(failure))
    errors: set[str] = set()
    summaries: dict[str, dict[str, object]] = {}
    for name in _SUMMARY_MEMBERS:
        if name not in members:
            errors.add("SUMMARY_MISSING")
            continue
        try:
            summaries[name] = _json_object(members[name])
        except _InputError as failure:
            errors.add(str(failure))

    # The content snapshot date takes precedence over packaging/finalization.
    timestamps: dict[str, str | None] = {}
    for name, key in (
        ("current-content-summary.json", "updated_at"),
        ("audit-summary.json", "finalized_at"),
        ("bundle-manifest.json", "created_at"),
    ):
        if name in summaries:
            stamp = _timestamp(summaries[name].get(key))
            if stamp is None:
                errors.add("INVALID_TIMESTAMP")
            timestamps[name] = stamp
    observed_at = next(iter(timestamps.values()), None)
    if observed_at is None:
        errors.add("INVALID_TIMESTAMP")
    counts = _backend_counts(summaries, errors)
    return InventorySummary(kind, observed_at, digest, counts, _error_code(errors))


def load_hf_summary(path: Path) -> InventorySummary:
    """Consume v1 HF historical counters; never treat them as runtime proof."""
    kind = "hf_historical_inventory"
    payload, digest, error = _read_input(path)
    if payload is None:
        return InventorySummary(kind, None, digest, {}, error)
    try:
        document = _json_object(payload)
    except _InputError as failure:
        return InventorySummary(kind, None, digest, {}, str(failure))
    if document.get("schema") != "szl.hf-readonly-audit/v1":
        return InventorySummary(kind, None, digest, {}, "HF_SCHEMA_UNSUPPORTED")
    errors: set[str] = set()
    observed_at = _timestamp(document.get("generated_at_utc"))
    if observed_at is None:
        errors.add("INVALID_TIMESTAMP")
    source = document.get("summary")
    if not isinstance(source, dict):
        return InventorySummary(kind, observed_at, digest, {}, "INVALID_SUMMARY_SHAPE")
    counts = {
        key: _count(source[key], errors) if key in source else None for key in _HF_COUNTS
    }
    if "asset_count" not in source:
        errors.add("SUMMARY_INCOMPLETE")
    repo_counts = source.get("repo_counts")
    if not isinstance(repo_counts, dict):
        repo_counts = {}
        errors.add("INVALID_SUMMARY_SHAPE")
    for key in _HF_REPO_COUNTS:
        if key in repo_counts:
            counts[key] = _count(repo_counts[key], errors)
        else:
            counts[key] = None
            errors.add("SUMMARY_INCOMPLETE")
    asset_count = counts["asset_count"]
    category_counts = [counts[key] for key in _HF_REPO_COUNTS]
    if asset_count is not None and all(value is not None for value in category_counts):
        if asset_count != sum(value for value in category_counts if value is not None):
            counts["asset_count"] = None
            errors.add("COUNT_INCONSISTENT")
    if (counts.get("http_probes") is not None and counts.get("http_200") is not None
            and counts["http_200"] > counts["http_probes"]):
        counts["http_200"] = None
        errors.add("COUNT_INCONSISTENT")
    return InventorySummary(kind, observed_at, digest, counts, _error_code(errors))
