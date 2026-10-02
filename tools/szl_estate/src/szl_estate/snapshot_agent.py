"""Offline, proposal-only recommendations from the local estate scout projection.

The scout projection is an unsigned summary. This module validates its narrow
shape and preserves its source digests, but cannot authenticate the collector,
prove inventory completeness, or establish current provider/runtime state.
Importing and running this module performs no network or account operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .model import ClaimBasis, ClaimMaturity, EvidenceValidationError, utc_timestamp


MAX_PROJECTION_BYTES = 64 * 1024
SCHEMA = "szl.estate-scout-projection.v1"
REPORT_SCHEMA = "szl.estate-scout-recommendations.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_STATE = re.compile(r"[A-Z][A-Z_]{0,31}\Z")
_ROOT_KEYS = {
    "schema", "projected_at_utc", "source_observed_at_utc", "scope",
    "authentic", "byte_consistent_with_unsigned_manifest", "github",
    "huggingface", "source_sha256", "functional_readiness",
    "model_qualification", "external_witness",
}
_GITHUB_KEYS = {
    "repositories", "private", "archived", "default_head_ci_states",
}
_HF_KEYS = {
    "spaces", "models", "datasets", "private_spaces", "private_models",
    "private_datasets", "provider_space_stages",
}


class ProjectionError(ValueError):
    """A fixed error code. Rejected input and file paths are never echoed."""


@dataclass(frozen=True, slots=True)
class Citation:
    source_file: str
    observed_at_utc: str
    sha256: str
    integrity: str = "UNSIGNED_SELF_REPORTED_DIGEST"

    def to_dict(self) -> dict[str, str]:
        return {
            "source_file": self.source_file,
            "observed_at_utc": self.observed_at_utc,
            "sha256": self.sha256,
            "integrity": self.integrity,
        }


@dataclass(frozen=True, slots=True)
class Recommendation:
    recommendation_id: str
    priority: str
    action: str
    citations: tuple[str, ...]
    observed_counts: Mapping[str, int]
    basis: ClaimBasis = ClaimBasis.PROPOSAL
    maturity: ClaimMaturity = ClaimMaturity.ROADMAP

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "priority": self.priority,
            "action": self.action,
            "citations": list(self.citations),
            "observed_counts": dict(sorted(self.observed_counts.items())),
            "claim_basis": self.basis.value,
            "claim_maturity": self.maturity.value,
            "execution": "PROPOSE_ONLY",
            "authorization": "NOT_GRANTED",
        }


def _object(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProjectionError("INVALID_SHAPE")
    return value


def _count(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ProjectionError("INVALID_COUNT")
    return value


def _states(value: Any, total: int) -> dict[str, int]:
    if not isinstance(value, dict) or len(value) > 32:
        raise ProjectionError("INVALID_STATES")
    states: dict[str, int] = {}
    for name, count in value.items():
        if not isinstance(name, str) or not _STATE.fullmatch(name):
            raise ProjectionError("INVALID_STATES")
        states[name] = _count(count)
    if sum(states.values()) != total:
        raise ProjectionError("COUNT_CONFLICT")
    return states


def _timestamp(value: Any) -> str:
    try:
        return utc_timestamp(value)
    except EvidenceValidationError:
        raise ProjectionError("INVALID_TIME") from None


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ProjectionError("INVALID_DIGEST")
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ProjectionError("DUPLICATE_KEY")
        value[name] = item
    return value


def recommend_projection_bytes(raw: bytes) -> dict[str, Any]:
    """Validate one scout output and return deterministic, non-executable advice."""
    if not isinstance(raw, bytes) or len(raw) > MAX_PROJECTION_BYTES:
        raise ProjectionError("INPUT_TOO_LARGE_OR_INVALID")
    try:
        data = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
    except ProjectionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ProjectionError("INVALID_JSON") from None
    data = _object(data, _ROOT_KEYS)
    if (data["schema"] != SCHEMA
            or data["scope"] != "authenticated snapshot; numeric projection only"
            or data["authentic"] is not False
            or data["byte_consistent_with_unsigned_manifest"] is not True
            or data["functional_readiness"] != "NOT_VERIFIED"
            or data["model_qualification"] != "NOT_VERIFIED"
            or data["external_witness"] != "NOT_RUN"):
        raise ProjectionError("UNSUPPORTED_ASSERTION")

    observed = _timestamp(data["source_observed_at_utc"])
    projected = _timestamp(data["projected_at_utc"])
    if datetime.fromisoformat(projected.replace("Z", "+00:00")) < datetime.fromisoformat(observed.replace("Z", "+00:00")):
        raise ProjectionError("INVALID_TIME_ORDER")
    hashes = _object(data["source_sha256"], {"github.json", "huggingface.json"})
    github_digest = _digest(hashes["github.json"])
    hf_digest = _digest(hashes["huggingface.json"])

    github = _object(data["github"], _GITHUB_KEYS)
    repos = _count(github["repositories"])
    private_repos = _count(github["private"])
    archived = _count(github["archived"])
    if private_repos > repos or archived > repos:
        raise ProjectionError("COUNT_CONFLICT")
    ci = _states(github["default_head_ci_states"], repos)

    hub = _object(data["huggingface"], _HF_KEYS)
    spaces = _count(hub["spaces"])
    models = _count(hub["models"])
    datasets = _count(hub["datasets"])
    if (_count(hub["private_spaces"]) > spaces
            or _count(hub["private_models"]) > models
            or _count(hub["private_datasets"]) > datasets):
        raise ProjectionError("COUNT_CONFLICT")
    stages = _states(hub["provider_space_stages"], spaces)

    recommendations = [Recommendation(
        "PROVENANCE_AND_SCOPE_REVIEW", "P1",
        "Obtain a signed, source-bound census and verify account scope before treating these counts as complete.",
        ("projection", "github", "huggingface"),
        {"repositories": repos, "spaces": spaces, "models": models, "datasets": datasets},
    )]
    unobserved_ci = repos - ci.get("SUCCESS", 0)
    recommendations.append(Recommendation(
        "EXACT_HEAD_CHECK_REVIEW" if unobserved_ci else "PR_GATE_SCOPE_REVIEW",
        "P1" if unobserved_ci else "P2",
        "Inspect current PR heads, required checks, reviews, and protection before any merge decision.",
        ("github",), {"repositories": repos, "default_heads_without_success_rollup": unobserved_ci},
    ))
    if spaces:
        space_errors = sum(count for state, count in stages.items() if state.endswith("ERROR"))
        recommendations.append(Recommendation(
            "SPACE_RUNTIME_PROBES", "P1" if space_errors else "P2",
            "Obtain source-pinned functional probes for Spaces; a provider stage alone does not establish readiness.",
            ("huggingface",), {"spaces": spaces, "error_stage_spaces": space_errors},
        ))
    if models:
        recommendations.append(Recommendation(
            "MODEL_EVALUATION_PROTOCOL", "P2",
            "Identify actual weight artifacts and prepare pinned, independent evaluations before model qualification.",
            ("huggingface",), {"model_repositories": models},
        ))
    if datasets:
        recommendations.append(Recommendation(
            "DATASET_LINEAGE_REVIEW", "P2",
            "Review dataset provenance, rights, version pins, and evaluation use before agent integration.",
            ("huggingface",), {"datasets": datasets},
        ))

    citations = {
        "projection": Citation("scout-projection.json", projected, hashlib.sha256(raw).hexdigest(), "LOCAL_BYTES_ONLY"),
        "github": Citation("github.json", observed, github_digest),
        "huggingface": Citation("huggingface.json", observed, hf_digest),
    }
    return {
        "schema": REPORT_SCHEMA,
        "source_observed_at_utc": observed,
        "projected_at_utc": projected,
        "live_verification": "NOT_RUN",
        "estate_readiness": "UNKNOWN",
        "model_qualification": "NOT_VERIFIED",
        "external_witness": "NOT_RUN",
        "snapshot_authenticity": "NOT_VERIFIED",
        "citations": {name: citation.to_dict() for name, citation in citations.items()},
        "recommendations": [item.to_dict() for item in recommendations],
    }


def recommend_projection_file(path: Path) -> dict[str, Any]:
    """Read a bounded local file; never emit paths or rejected content."""
    if path.is_symlink() or not path.is_file():
        raise ProjectionError("INVALID_INPUT_FILE")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROJECTION_BYTES + 1)
    except OSError:
        raise ProjectionError("INPUT_UNREADABLE") from None
    return recommend_projection_bytes(raw)
