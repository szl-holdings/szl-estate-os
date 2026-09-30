"""Deterministic reports and atomic, integrity-checked local state storage."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable

from .model import EstateState, EvidenceValidationError


ENVELOPE_SCHEMA_VERSION = "szl.integrity-envelope/v1"
MAX_STATE_BYTES = 8 * 1024 * 1024


class StorageError(ValueError):
    """Fixed errors, with a recoverable temporary path separate from the message."""

    def __init__(self, code: str, *, retained_path: Path | None = None):
        super().__init__(code)
        self.code = code
        self.retained_path = retained_path


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise StorageError("INVALID_SERIALIZABLE_DATA") from None


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def render_json(state: EstateState) -> str:
    return json.dumps(state.to_dict(), sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n"


def _csv_cell(value: Any) -> str:
    cell = str(value)
    if cell.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + cell
    return cell


def render_csv(state: EstateState) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("evidence_id", "scope", "status", "code", "complete", "claim_maturity", "claim_basis", "source", "reference", "observed_at_utc", "freshness", "origin", "digest", "checked_at_utc", "cryptographic_integrity", "scientific_validity", "authorization", "deployment", "proof_scope", "counts"))
    for item in state.evidence:
        p = item.provenance
        writer.writerow(tuple(_csv_cell(cell) for cell in (
            item.evidence_id, item.scope, item.status.value, item.code.value,
            str(item.complete).lower(), item.claim_maturity.value if item.claim_maturity else "",
            item.claim_basis.value if item.claim_basis else "", p.source, p.reference,
            p.observed_at_utc, p.freshness.value, p.origin.value, p.digest,
            item.checked_at_utc or "", item.dimensions.cryptographic_integrity.value,
            item.dimensions.scientific_validity.value, item.dimensions.authorization.value,
            item.dimensions.deployment.value, ";".join(item.dimensions.proof_scope),
            canonical_bytes(dict(item.counts or {})).decode("utf-8"),
        )))
    return stream.getvalue()


def render_markdown(state: EstateState) -> str:
    lines = [
        "# Estate evidence report", "",
        f"Observed report time: {state.generated_at_utc}", "",
        f"Estate ready: **{str(state.estate_ready).lower()}**", "",
        "Readiness is evaluated as of the recorded report time, not the time this file is opened.",
        "It requires complete, current live passes for every required estate scope,",
        "independent dimension passes, exact proof scope, and access checks within one hour.",
        "Historical bundles and cache replay do not establish current access.", "",
        "| Scope | Status | Code | Complete | Freshness | Origin | Evidence |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in state.evidence:
        lines.append(f"| {item.scope} | {item.status.value} | {item.code.value} | {str(item.complete).lower()} | {item.provenance.freshness.value} | {item.provenance.origin.value} | {item.evidence_id} |")
    lines.extend(("", "| Evidence | Checked at UTC | Cryptographic integrity | Scientific validity | Authorization | Deployment | Proof scope | Counts |", "| --- | --- | --- | --- | --- | --- | --- | --- |"))
    for item in state.evidence:
        d = item.dimensions
        counts = canonical_bytes(dict(item.counts or {})).decode("utf-8")
        lines.append(f"| {item.evidence_id} | {item.checked_at_utc or 'UNKNOWN'} | {d.cryptographic_integrity.value} | {d.scientific_validity.value} | {d.authorization.value} | {d.deployment.value} | {', '.join(d.proof_scope) or 'UNKNOWN'} | {counts} |")
    lines.extend(("", "Required scopes:", ""))
    lines.extend(f"- `{scope}`" for scope in state.required_scopes)
    return "\n".join(lines) + "\n"


def guard_output_alias(output: Path | str, source_paths: Iterable[Path | str] = ()) -> Path:
    target = Path(output).resolve()
    for source in source_paths:
        original = Path(source).resolve()
        if os.path.normcase(str(target)) == os.path.normcase(str(original)):
            raise StorageError("SOURCE_OUTPUT_ALIAS")
        try:
            if target.exists() and original.exists() and os.path.samefile(target, original):
                raise StorageError("SOURCE_OUTPUT_ALIAS")
        except OSError:
            raise StorageError("ALIAS_CHECK_FAILED") from None
    return target


def atomic_write(output: Path | str, data: bytes, *, source_paths: Iterable[Path | str] = ()) -> Path:
    target = guard_output_alias(output, source_paths)
    temp_path: Path | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        temp_path = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, target)
    except OSError:
        raise StorageError("ATOMIC_WRITE_FAILED", retained_path=temp_path) from None
    return target


def integrity_bytes(payload: dict[str, Any]) -> bytes:
    envelope = {"schema_version": ENVELOPE_SCHEMA_VERSION, "payload": payload, "sha256": sha256_digest(payload)}
    return json.dumps(envelope, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StorageError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def read_integrity_payload(path: Path | str, *, max_bytes: int = MAX_STATE_BYTES) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        raise StorageError("READ_FAILED") from None
    if len(raw) > max_bytes:
        raise StorageError("RECORD_TOO_LARGE")
    try:
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise StorageError("CORRUPT_JSON") from None
    if not isinstance(envelope, dict) or set(envelope) != {"schema_version", "payload", "sha256"}:
        raise StorageError("INVALID_INTEGRITY_ENVELOPE")
    if envelope["schema_version"] != ENVELOPE_SCHEMA_VERSION or not isinstance(envelope["payload"], dict):
        raise StorageError("INVALID_INTEGRITY_ENVELOPE")
    if not isinstance(envelope["sha256"], str) or envelope["sha256"] != sha256_digest(envelope["payload"]):
        raise StorageError("INTEGRITY_MISMATCH")
    return envelope["payload"]


def save_state(path: Path | str, state: EstateState, *, source_paths: Iterable[Path | str] = ()) -> Path:
    raw = integrity_bytes(state.to_dict())
    if len(raw) > MAX_STATE_BYTES:
        raise StorageError("RECORD_TOO_LARGE")
    return atomic_write(path, raw, source_paths=source_paths)


def load_state(path: Path | str) -> EstateState:
    try:
        return EstateState.from_dict(read_integrity_payload(path))
    except EvidenceValidationError:
        raise StorageError("INVALID_STATE") from None


def write_reports(output_dir: Path | str, state: EstateState, *, source_paths: Iterable[Path | str] = ()) -> dict[str, Path]:
    directory = Path(output_dir)
    sources = tuple(source_paths)
    outputs = {"state": directory / "estate_state.json", "csv": directory / "evidence.csv", "report": directory / "report.md"}
    # Preflight every alias before the first write; existing source evidence is immutable.
    for path in outputs.values():
        guard_output_alias(path, sources)
    save_state(outputs["state"], state, source_paths=sources)
    atomic_write(outputs["csv"], render_csv(state).encode("utf-8"), source_paths=sources)
    atomic_write(outputs["report"], render_markdown(state).encode("utf-8"), source_paths=sources)
    return {key: value.resolve() for key, value in outputs.items()}
