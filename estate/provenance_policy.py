"""Deterministic policy for artifact provenance and runtime currency.

The classifier is deliberately transport-free.  Callers retrieve evidence and
inject it here; this module never performs network or filesystem I/O.  That
keeps an immutable artifact's source provenance separate from whether a live
deployment currently matches the source repository's default branch.  Relevant
artifact-source evidence must also be complete: one verified observed claim
cannot mask another relevant document whose evidence is unavailable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


POLICY_SCHEMA = "szl.provenance-policy-decision/v1"
EXACT_GIT_SHA = re.compile(r"[0-9a-f]{40}")
SOURCE_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})"
)
COMPLETE_SCOPE_STATES = {"AUTHENTICATED_COMPLETE", "ORGANIZATION_COMPLETE"}
PARTIAL_SCOPE_STATES = {"AUTHENTICATED_VISIBILITY_UNKNOWN", "PUBLIC_ONLY"}
TARGET_EVIDENCE_STATES = {"OBSERVED", "PRIVATE_UNAVAILABLE", "UNKNOWN"}
COMMIT_FACT_STATES = {
    "VERIFIED_REACHABLE",
    "REACHABLE_UNVERIFIED",
    "UNREACHABLE",
    "UNAVAILABLE",
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _repository(value: Any) -> str:
    candidate = _text(value)
    return candidate.lower() if SOURCE_REPOSITORY.fullmatch(candidate) else ""


def _revision(value: Any) -> str:
    candidate = _text(value)
    return candidate if EXACT_GIT_SHA.fullmatch(candidate) else ""


def _scope_completeness(source_scope: str) -> str:
    if source_scope in COMPLETE_SCOPE_STATES:
        return "COMPLETE"
    if source_scope in PARTIAL_SCOPE_STATES:
        return "PARTIAL"
    return "UNAVAILABLE"


def _artifact_claim(
    documents: Iterable[Mapping[str, Any]],
) -> tuple[str, str, str]:
    """Return a fail-closed claim from all relevant artifact-source documents.

    Syntactically invalid or conflicting observed claims fail.  A valid observed
    claim mixed with unavailable relevant evidence is instead incomplete, so it
    retains the claim identity but cannot advance to commit verification.
    """

    relevant = [
        document
        for document in documents
        if isinstance(document, Mapping)
        and document.get("binding_kind") == "ARTIFACT_SOURCE"
    ]
    observed = [document for document in relevant if document.get("status") == "OBSERVED"]
    evidence_unavailable = any(
        document.get("status") != "OBSERVED" for document in relevant
    )
    malformed_observed = any(
        not _text(document.get("source_repository"))
        or not _text(document.get("source_revision"))
        for document in observed
    )
    claims = {
        (_text(document.get("source_repository")), _text(document.get("source_revision")))
        for document in observed
        if _text(document.get("source_repository"))
        and _text(document.get("source_revision"))
    }
    if malformed_observed:
        return "INVALID_DOCUMENT", "", ""
    if len(claims) > 1:
        return "CONFLICT", "", ""
    if not claims:
        if evidence_unavailable:
            return "EVIDENCE_UNAVAILABLE", "", ""
        return "NOT_DECLARED", "", ""
    raw_repository, raw_revision = next(iter(claims))
    repository = _repository(raw_repository)
    revision = _revision(raw_revision)
    if not repository:
        return "INVALID_REPOSITORY", "", revision
    if not revision:
        return "INVALID_REVISION", repository, ""
    if evidence_unavailable:
        return "EVIDENCE_PARTIAL", repository, revision
    return "DECLARED", repository, revision


def _commit_fact(
    facts: Iterable[Mapping[str, Any]], repository: str, revision: str
) -> str:
    states = {
        _text(fact.get("state"))
        for fact in facts
        if isinstance(fact, Mapping)
        and _repository(fact.get("source_repository")) == repository
        and _revision(fact.get("source_revision")) == revision
    }
    states.discard("")
    if not states:
        return "MISSING"
    if len(states) != 1:
        return "CONFLICT"
    state = next(iter(states))
    return state if state in COMMIT_FACT_STATES else "INVALID"


def _head_fact(
    source_head: Mapping[str, Any] | None, repository: str = ""
) -> tuple[str, str, str]:
    if not isinstance(source_head, Mapping):
        return "MISSING", "", ""
    if source_head.get("status") != "OBSERVED":
        return "UNAVAILABLE", "", ""
    head_repository = _repository(source_head.get("source_repository"))
    head_revision = _revision(source_head.get("source_revision"))
    if not head_repository or not head_revision:
        return "INVALID", head_repository, head_revision
    if repository and head_repository != repository:
        return "OTHER_REPOSITORY", head_repository, head_revision
    return "OBSERVED", head_repository, head_revision


def _runtime_currency(
    runtime_evidence: Mapping[str, Any] | None,
    source_head: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(runtime_evidence, Mapping):
        return {
            "state": "UNAVAILABLE",
            "evidence_state": "NOT_OBSERVED",
            "currency_state": "NOT_OBSERVED",
            "current": None,
            "source_repository": None,
            "source_revision": None,
            "head_revision": None,
        }
    if runtime_evidence.get("status") != "OBSERVED":
        return {
            "state": "UNAVAILABLE",
            "evidence_state": "RUNTIME_EVIDENCE_UNAVAILABLE",
            "currency_state": "UNKNOWN",
            "current": None,
            "source_repository": None,
            "source_revision": None,
            "head_revision": None,
        }

    raw_runtime_repository = _text(runtime_evidence.get("source_repository"))
    runtime_repository = _repository(raw_runtime_repository)
    runtime_revision = _revision(runtime_evidence.get("source_revision"))
    if raw_runtime_repository and not runtime_repository:
        return {
            "state": "FAIL",
            "evidence_state": "INVALID_RUNTIME_REPOSITORY",
            "currency_state": "UNKNOWN",
            "current": None,
            "source_repository": None,
            "source_revision": runtime_revision or None,
            "head_revision": None,
        }
    if not runtime_revision:
        return {
            "state": "FAIL",
            "evidence_state": "INVALID_RUNTIME_REVISION",
            "currency_state": "UNKNOWN",
            "current": None,
            "source_repository": runtime_repository or None,
            "source_revision": None,
            "head_revision": None,
        }

    head_state, head_repository, head_revision = _head_fact(source_head)
    effective_repository = runtime_repository or head_repository
    if head_state != "OBSERVED":
        return {
            "state": "UNAVAILABLE",
            "evidence_state": "SOURCE_HEAD_UNAVAILABLE",
            "currency_state": "UNKNOWN",
            "current": None,
            "source_repository": effective_repository or None,
            "source_revision": runtime_revision,
            "head_revision": head_revision or None,
        }
    if runtime_repository and runtime_repository != head_repository:
        return {
            "state": "FAIL",
            "evidence_state": "SOURCE_REPOSITORY_MISMATCH",
            "currency_state": "UNKNOWN",
            "current": None,
            "source_repository": runtime_repository,
            "source_revision": runtime_revision,
            "head_revision": head_revision,
        }
    if runtime_revision == head_revision:
        return {
            "state": "PASS",
            "evidence_state": "OBSERVED_RUNTIME_REVISION",
            "currency_state": "CURRENT",
            "current": True,
            "source_repository": effective_repository,
            "source_revision": runtime_revision,
            "head_revision": head_revision,
        }
    return {
        "state": "FAIL",
        "evidence_state": "OBSERVED_RUNTIME_REVISION",
        "currency_state": "PINNED_NON_HEAD",
        "current": False,
        "source_repository": effective_repository,
        "source_revision": runtime_revision,
        "head_revision": head_revision,
    }


def classify_provenance(
    *,
    target_id: str,
    source_scope: str,
    artifact_documents: Iterable[Mapping[str, Any]] = (),
    commit_facts: Iterable[Mapping[str, Any]] = (),
    source_head: Mapping[str, Any] | None = None,
    runtime_evidence: Mapping[str, Any] | None = None,
    target_evidence_state: str = "OBSERVED",
) -> dict[str, Any]:
    """Classify one target from already-retrieved, immutable evidence facts.

    ``commit_facts`` is the trust boundary for artifact provenance.  A declared
    40-character revision passes only when the matching fact has state
    ``VERIFIED_REACHABLE``.  Runtime observations are evaluated independently
    and can establish currency, never artifact provenance.  Every relevant
    artifact-source document must also be available; mixed observed and
    unavailable evidence remains unavailable even when the observed claim and
    commit fact would otherwise verify.
    """

    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id must be a nonempty string")
    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be a nonempty string")
    if target_evidence_state not in TARGET_EVIDENCE_STATES:
        raise ValueError("target_evidence_state is invalid")

    scope = {
        "state": source_scope,
        "completeness": _scope_completeness(source_scope),
    }
    if target_evidence_state != "OBSERVED":
        unavailable = (
            "PRIVATE_SCOPE_UNAVAILABLE"
            if target_evidence_state == "PRIVATE_UNAVAILABLE"
            else "TARGET_EVIDENCE_UNKNOWN"
        )
        return {
            "schema": POLICY_SCHEMA,
            "target": {"asset_id": target_id.strip(), "evidence_state": target_evidence_state},
            "scope": scope,
            "artifact_provenance": {
                "state": "UNAVAILABLE",
                "evidence_state": unavailable,
                "alignment_state": "UNAVAILABLE",
                "current": None,
                "source_repository": None,
                "source_revision": None,
                "head_revision": None,
            },
            "runtime_currency": {
                "state": "UNAVAILABLE",
                "evidence_state": unavailable,
                "currency_state": "UNKNOWN",
                "current": None,
                "source_repository": None,
                "source_revision": None,
                "head_revision": None,
            },
        }

    runtime = _runtime_currency(runtime_evidence, source_head)
    claim_state, repository, revision = _artifact_claim(artifact_documents)
    head_state, _, head_revision = _head_fact(source_head, repository)
    artifact: dict[str, Any] = {
        "state": "UNAVAILABLE",
        "evidence_state": "ARTIFACT_SOURCE_NOT_DECLARED",
        "alignment_state": "NOT_DECLARED",
        "current": None,
        "source_repository": repository or None,
        "source_revision": revision or None,
        "head_revision": head_revision or None,
    }

    if claim_state == "CONFLICT":
        artifact.update(
            state="FAIL",
            evidence_state="CONFLICTING_ARTIFACT_SOURCE_DOCUMENTS",
            alignment_state="CONFLICT",
        )
    elif claim_state == "EVIDENCE_UNAVAILABLE":
        artifact.update(
            evidence_state="ARTIFACT_SOURCE_EVIDENCE_UNAVAILABLE",
            alignment_state="UNAVAILABLE",
        )
    elif claim_state == "EVIDENCE_PARTIAL":
        artifact.update(
            evidence_state="ARTIFACT_SOURCE_EVIDENCE_PARTIAL",
            alignment_state="UNAVAILABLE",
        )
    elif claim_state == "NOT_DECLARED":
        if runtime["state"] != "UNAVAILABLE" or runtime_evidence is not None:
            artifact.update(
                evidence_state="RUNTIME_ONLY_NOT_ARTIFACT_PROVENANCE",
                alignment_state="NOT_DECLARED",
            )
    elif claim_state in {
        "INVALID_DOCUMENT",
        "INVALID_REPOSITORY",
        "INVALID_REVISION",
    }:
        artifact.update(
            state="FAIL",
            evidence_state=(
                "INVALID_ARTIFACT_SOURCE_DOCUMENT"
                if claim_state == "INVALID_DOCUMENT"
                else claim_state
            ),
            alignment_state=(
                "INVALID_ARTIFACT_SOURCE_DOCUMENT"
                if claim_state == "INVALID_DOCUMENT"
                else claim_state
            ),
        )
    else:
        fact_state = _commit_fact(commit_facts, repository, revision)
        artifact["evidence_state"] = fact_state
        if fact_state == "VERIFIED_REACHABLE":
            artifact["state"] = "PASS"
            if head_state == "OBSERVED" and revision == head_revision:
                artifact.update(alignment_state="EXACT_HEAD", current=True)
            elif head_state == "OBSERVED":
                artifact.update(alignment_state="PINNED_NON_HEAD", current=False)
            else:
                artifact.update(alignment_state="SOURCE_HEAD_UNAVAILABLE", current=None)
        elif fact_state == "UNREACHABLE":
            artifact.update(
                state="FAIL",
                evidence_state="SOURCE_COMMIT_UNREACHABLE",
                alignment_state="UNVERIFIED_SOURCE",
            )
        elif fact_state == "REACHABLE_UNVERIFIED":
            artifact.update(
                state="FAIL",
                evidence_state="SOURCE_COMMIT_UNVERIFIED",
                alignment_state="UNVERIFIED_SOURCE",
            )
        elif fact_state in {"CONFLICT", "INVALID"}:
            artifact.update(
                state="FAIL",
                evidence_state="SOURCE_COMMIT_EVIDENCE_CONFLICT"
                if fact_state == "CONFLICT"
                else "SOURCE_COMMIT_EVIDENCE_INVALID",
                alignment_state="UNVERIFIED_SOURCE",
            )
        else:
            artifact.update(
                evidence_state="SOURCE_COMMIT_EVIDENCE_MISSING"
                if fact_state == "MISSING"
                else "SOURCE_COMMIT_EVIDENCE_UNAVAILABLE",
                alignment_state="UNVERIFIED_SOURCE",
            )

    return {
        "schema": POLICY_SCHEMA,
        "target": {"asset_id": target_id.strip(), "evidence_state": "OBSERVED"},
        "scope": scope,
        "artifact_provenance": artifact,
        "runtime_currency": runtime,
    }
