#!/usr/bin/env python3
"""Verify an Estate OS audit against the canonical critical-surface contract."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from estate.evidence_contract import (  # noqa: E402
    PRODUCTION_EVIDENCE_INDEX_SCHEMA,
    load_evidence_bytes as contract_load_evidence_bytes,
    validate_restore_measurement,
)
from estate.provenance_policy import classify_provenance  # noqa: E402


ALIGNMENT_READY = {"EXACT_RUNTIME_HEAD"}
BASELINE_SIGNATURE_STATES = {
    "HMAC_SHA256": "PASS",
    "UNSIGNED": "WARN",
}
PRODUCTION_COMPLETE_SCOPES = {"AUTHENTICATED_COMPLETE"}
PRODUCTION_SIGNATURE_ALGORITHM = "RSA_PKCS1_V1_5_SHA256"
RSA_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40,64}")
KNOWN_PRODUCTION_REQUIREMENTS = {
    "authenticated_inventory",
    "critical_huggingface_alignment",
    "independent_asymmetric_evidence",
    "credential_backed_deployment_witness",
    "browser_e2e_and_accessibility",
    "restore_and_failure_domain_drill",
    "zero_active_critical_gaps",
}
PRODUCTION_ARTIFACT_SCHEMAS = {
    "credential_backed_deployment_witness": "szl.estate-deployment-witness/v1",
    "browser_e2e_and_accessibility": "szl.estate-browser-evidence/v1",
    "restore_and_failure_domain_drill": "szl.estate-restore-drill/v2",
}
BASELINE_SOURCES = {"github", "huggingface", "domains"}
BASELINE_PROHIBITED_STATUS_LABELS = {"BROKEN"}
BASELINE_REQUIRED_SECURITY_HEADERS = {
    "content-security-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
}
APPROVED_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
HSTS_MIN_MAX_AGE_SECONDS = 31_536_000
BASELINE_CONTRACT_KEYS = {
    "source_minimums",
    "required_source_status",
    "prohibited_status_labels",
    "required_security_headers",
}
CRITICAL_ASSET_REQUIRED_KEYS = {"asset_id", "tier", "role", "public"}
CRITICAL_ASSET_ALLOWED_KEYS = CRITICAL_ASSET_REQUIRED_KEYS | {
    "required_status",
    "evidence_requirement",
}


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def result(check_id: str, state: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "state": state, "detail": detail}


def alignment_state(asset: dict[str, Any]) -> str:
    alignment = (asset.get("metadata") or {}).get("github_alignment") or {}
    if isinstance(alignment, dict):
        return str(alignment.get("status") or "UNAVAILABLE")
    return "UNAVAILABLE"


def signature_state(signature_status: str, profile: str) -> str:
    """Classify only signature states defined by the readiness contract."""
    if profile == "baseline":
        return BASELINE_SIGNATURE_STATES.get(signature_status, "FAIL")
    # Production never trusts a status label. verify_independent_signature validates
    # the signature bytes against a protected manifest-pinned public key.
    return "FAIL"


def parsed_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return observed if observed.tzinfo is not None else None


def content_security_policy_state(value: Any) -> tuple[str, str]:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        return "FAIL", "content-security-policy is missing or invalid"
    directives: dict[str, list[str]] = {}
    for segment in value.split(";"):
        parts = segment.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives or re.fullmatch(r"[a-z][a-z0-9-]*", name) is None:
            return "FAIL", "content-security-policy contains duplicate or invalid directives"
        directives[name] = [token.lower() for token in parts[1:]]

    required = {"default-src", "object-src", "frame-ancestors", "base-uri", "form-action"}
    missing = sorted(required - set(directives))
    if missing:
        return "FAIL", f"content-security-policy missing directives={','.join(missing)}"
    default_sources = directives["default-src"]
    if not default_sources or any(
        "*" in token
        or token in {"'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'"}
        or token in {"data:", "blob:", "http:", "https:"}
        for token in default_sources
    ):
        return "FAIL", "content-security-policy default-src is not fail-closed"
    for directive in ("object-src", "frame-ancestors", "base-uri", "form-action"):
        sources = directives[directive]
        allowed = {"'none'"} if directive == "object-src" else {"'none'", "'self'"}
        if len(sources) != 1 or sources[0] not in allowed:
            return "FAIL", f"content-security-policy {directive} is not restrictive"
    for directive in ("script-src", "script-src-elem", "script-src-attr"):
        if directive not in directives:
            continue
        sources = directives[directive]
        if not sources or any(
            "*" in token
            or token
            in {
                "'unsafe-inline'",
                "'unsafe-eval'",
                "'wasm-unsafe-eval'",
                "data:",
                "blob:",
                "http:",
                "https:",
            }
            for token in sources
        ):
            return "FAIL", f"content-security-policy {directive} permits unsafe sources"
    if "script-src" not in directives and any(
        "*" in token
        or token
        in {
            "'unsafe-inline'",
            "'unsafe-eval'",
            "'wasm-unsafe-eval'",
            "data:",
            "blob:",
            "http:",
            "https:",
        }
        for token in default_sources
    ):
        return "FAIL", "content-security-policy permits unsafe script sources"
    return "PASS", "content-security-policy is fail-closed"


def security_header_values_state(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict):
        return "FAIL", "raw security header values are missing"
    normalized: dict[str, str] = {}
    for key, observed in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(observed, str)
            or "\n" in observed
            or "\r" in observed
        ):
            return "FAIL", "raw security header values are malformed"
        normalized_key = key.strip().lower()
        if not normalized_key or normalized_key in normalized:
            return "FAIL", "raw security header values are ambiguous"
        normalized[normalized_key] = observed.strip()
    missing = sorted(BASELINE_REQUIRED_SECURITY_HEADERS - set(normalized))
    if missing:
        return "FAIL", f"raw security header values missing={','.join(missing)}"

    csp_state, csp_detail = content_security_policy_state(
        normalized["content-security-policy"]
    )
    if csp_state != "PASS":
        return csp_state, csp_detail

    hsts_parts = [
        part.strip().lower()
        for part in normalized["strict-transport-security"].split(";")
        if part.strip()
    ]
    max_age_values = [part.split("=", 1)[1] for part in hsts_parts if part.startswith("max-age=")]
    if (
        len(max_age_values) != 1
        or re.fullmatch(r"[0-9]+", max_age_values[0]) is None
        or int(max_age_values[0]) < HSTS_MIN_MAX_AGE_SECONDS
    ):
        return "FAIL", "strict-transport-security max-age policy is insufficient"
    if normalized["x-content-type-options"].lower() != "nosniff":
        return "FAIL", "x-content-type-options must be nosniff"
    if normalized["referrer-policy"].lower() not in APPROVED_REFERRER_POLICIES:
        return "FAIL", "referrer-policy is not in the non-leaking allowlist"
    return "PASS", "required security header values are semantically safe"


def domain_route_identity(asset_id: str) -> tuple[str, str] | None:
    prefix = "domain:route:"
    if not asset_id.startswith(prefix):
        return None
    identity = asset_id[len(prefix) :]
    parsed = urllib.parse.urlparse(f"https://{identity}")
    try:
        port = parsed.port
    except ValueError:
        return None
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        return None
    return parsed.hostname.lower(), parsed.path or "/"


def huggingface_space_identity(asset_id: str) -> tuple[str, str] | None:
    prefix = "huggingface:space:"
    if not asset_id.startswith(prefix):
        return None
    parts = asset_id[len(prefix) :].split("/")
    if len(parts) != 2 or any(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", part) is None
        for part in parts
    ):
        return None
    return parts[0], parts[1]


def known_gap_contract_state(manifest: dict[str, Any]) -> tuple[str, str]:
    known_gaps = manifest.get("known_gaps")
    if not isinstance(known_gaps, list):
        return "FAIL", "known-gaps register is missing or invalid"
    gap_ids: set[str] = set()
    for gap in known_gaps:
        if not isinstance(gap, dict) or set(gap) != {
            "id",
            "severity",
            "status",
            "evidence",
        }:
            return "FAIL", "known-gap entry shape is invalid"
        gap_id = gap.get("id")
        evidence = gap.get("evidence")
        if (
            not isinstance(gap_id, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", gap_id) is None
            or gap_id in gap_ids
            or gap.get("severity") not in {"P0", "P1", "P2", "P3"}
            or gap.get("status") not in {"ACTIVE", "CLOSED"}
            or not isinstance(evidence, str)
            or not evidence.strip()
        ):
            return "FAIL", "known-gap entry values are invalid"
        gap_ids.add(gap_id)
    return "PASS", "known-gaps register verified"


def manifest_baseline_contract_state(manifest: dict[str, Any]) -> tuple[str, str]:
    if (
        manifest.get("schema") != "szl.estate-critical-surface/v1"
        or manifest.get("status") != "CONTROL_CONTRACT"
    ):
        return "FAIL", "manifest schema/status is missing or invalid"

    canonical = manifest.get("canonical_identities")
    if not isinstance(canonical, dict) or set(canonical) != {
        "github_organization",
        "huggingface_organization",
        "domains",
    }:
        return "FAIL", "canonical identity contract is missing or invalid"
    github_organization = canonical.get("github_organization")
    huggingface_organization = canonical.get("huggingface_organization")
    domains = canonical.get("domains")
    identity_pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}"
    if (
        not isinstance(github_organization, str)
        or re.fullmatch(identity_pattern, github_organization) is None
        or not isinstance(huggingface_organization, str)
        or re.fullmatch(identity_pattern, huggingface_organization) is None
        or not isinstance(domains, list)
        or not domains
        or any(
            not isinstance(domain, str)
            or re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain
            )
            is None
            for domain in domains
        )
        or len(set(domains)) != len(domains)
    ):
        return "FAIL", "canonical identity values are missing or invalid"

    baseline = manifest.get("baseline")
    if not isinstance(baseline, dict) or set(baseline) != BASELINE_CONTRACT_KEYS:
        return "FAIL", "baseline contract shape is missing or invalid"
    source_minimums = baseline.get("source_minimums")
    if (
        not isinstance(source_minimums, dict)
        or set(source_minimums) != BASELINE_SOURCES
        or any(
            isinstance(minimum, bool)
            or not isinstance(minimum, int)
            or minimum <= 0
            for minimum in source_minimums.values()
        )
    ):
        return "FAIL", "baseline source minimum contract is incomplete or invalid"
    if baseline.get("required_source_status") != "MEASURED":
        return "FAIL", "baseline required source status is invalid"
    prohibited = baseline.get("prohibited_status_labels")
    if (
        not isinstance(prohibited, list)
        or any(not isinstance(value, str) or not value for value in prohibited)
        or len(prohibited) != len(set(prohibited))
        or set(prohibited) != BASELINE_PROHIBITED_STATUS_LABELS
    ):
        return "FAIL", "baseline prohibited status contract is incomplete or invalid"
    headers = baseline.get("required_security_headers")
    if (
        not isinstance(headers, list)
        or any(not isinstance(value, str) or not value for value in headers)
        or len(headers) != len(set(headers))
        or set(headers) != BASELINE_REQUIRED_SECURITY_HEADERS
    ):
        return "FAIL", "baseline security-header contract is incomplete or invalid"

    critical_assets = manifest.get("critical_assets")
    if not isinstance(critical_assets, list) or not critical_assets:
        return "FAIL", "critical asset contract is missing or empty"
    critical_asset_ids: set[str] = set()
    observed_kinds: set[str] = set()
    canonical_domains = set(domains)
    for contract in critical_assets:
        if (
            not isinstance(contract, dict)
            or not CRITICAL_ASSET_REQUIRED_KEYS.issubset(contract)
            or not set(contract).issubset(CRITICAL_ASSET_ALLOWED_KEYS)
        ):
            return "FAIL", "critical asset entry shape is invalid"
        asset_id = contract.get("asset_id")
        tier = contract.get("tier")
        role = contract.get("role")
        public = contract.get("public")
        if (
            not isinstance(asset_id, str)
            or not asset_id
            or asset_id in critical_asset_ids
            or isinstance(tier, bool)
            or not isinstance(tier, int)
            or tier < 0
            or not isinstance(role, str)
            or not role.strip()
            or not isinstance(public, bool)
        ):
            return "FAIL", "critical asset entry values are invalid"
        critical_asset_ids.add(asset_id)
        domain_identity = domain_route_identity(asset_id)
        space_identity = huggingface_space_identity(asset_id)
        if asset_id.startswith("github:repo:"):
            repository = asset_id.removeprefix("github:repo:").split("/", 1)
            if (
                len(repository) != 2
                or repository[0].lower() != github_organization.lower()
                or not repository[1]
                or "required_status" in contract
                or (public and "evidence_requirement" in contract)
                or (
                    not public
                    and contract.get("evidence_requirement")
                    != "AUTHENTICATED_INVENTORY"
                )
            ):
                return "FAIL", "critical GitHub asset contract is invalid"
            observed_kinds.add("github")
        elif domain_identity is not None:
            if (
                domain_identity[0] not in canonical_domains
                or contract.get("required_status") != "LIVE"
                or public is not True
                or "evidence_requirement" in contract
            ):
                return "FAIL", "critical domain asset contract is invalid"
            observed_kinds.add("domains")
        elif space_identity is not None:
            if (
                space_identity[0].lower() != huggingface_organization.lower()
                or contract.get("required_status") != "LIVE"
                or public is not True
                or "evidence_requirement" in contract
            ):
                return "FAIL", "critical Hugging Face asset contract is invalid"
            observed_kinds.add("huggingface")
        else:
            return "FAIL", "critical asset identity is unsupported"
    if observed_kinds != BASELINE_SOURCES:
        return "FAIL", "critical asset contract does not cover every estate source"
    gap_contract_state, gap_contract_detail = known_gap_contract_state(manifest)
    if gap_contract_state != "PASS":
        return gap_contract_state, gap_contract_detail
    return "PASS", "baseline and critical-surface manifest contract verified"


def deployment_url_identity_state(
    manifest: dict[str, Any], asset_id: str, url: str
) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return "FAIL", "deployment URL identity is invalid"
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        return "FAIL", "deployment URL identity is invalid"

    canonical = manifest.get("canonical_identities")
    if not isinstance(canonical, dict):
        return "FAIL", "canonical identity contract is missing or invalid"
    domain_identity = domain_route_identity(asset_id)
    if domain_identity is not None:
        expected_host, expected_path = domain_identity
        canonical_domains = canonical.get("domains")
        if (
            not isinstance(canonical_domains, list)
            or expected_host not in canonical_domains
        ):
            return "FAIL", "deployment domain is outside the canonical manifest"
        if (
            parsed.hostname.lower() != expected_host
            or (parsed.path or "/") != expected_path
        ):
            return "FAIL", "deployment URL does not match the domain route identity"
        return "PASS", f"canonical domain route={expected_host}{expected_path}"

    space_identity = huggingface_space_identity(asset_id)
    if space_identity is None:
        return "FAIL", "deployment asset identity is unsupported"
    owner, space = space_identity
    canonical_owner = canonical.get("huggingface_organization")
    if not isinstance(canonical_owner, str) or owner.lower() != canonical_owner.lower():
        return "FAIL", "deployment Space is outside the canonical manifest"
    normalized_path = (parsed.path or "/").rstrip("/").lower()
    hub_path = f"/spaces/{owner}/{space}".lower()
    runtime_host = f"{owner}-{space}.hf.space".lower()
    hub_match = parsed.hostname.lower() == "huggingface.co" and normalized_path == hub_path
    runtime_match = (
        parsed.hostname.lower() == runtime_host and normalized_path == ""
    )
    if not hub_match and not runtime_match:
        return "FAIL", "deployment URL does not match the Hugging Face Space identity"
    return "PASS", f"canonical_huggingface_space={owner}/{space}"


def audited_live_target_state(
    assets: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    asset_id: str,
    url: str,
) -> tuple[str, str]:
    asset = assets.get(asset_id)
    if not isinstance(asset, dict):
        return "FAIL", "deployment asset is not present in the audited inventory"
    domain_identity = domain_route_identity(asset_id)
    space_identity = huggingface_space_identity(asset_id)
    expected_source_type = (
        ("domains", "route")
        if domain_identity is not None
        else (("huggingface", "space") if space_identity is not None else None)
    )
    expected_operational_status = (
        "REAL"
        if domain_identity is not None
        else ("RUNNING" if space_identity is not None else None)
    )
    if (
        asset.get("status_label") != "LIVE"
        or expected_source_type is None
        or (asset.get("source"), asset.get("asset_type")) != expected_source_type
        or asset.get("operational_status") != expected_operational_status
    ):
        return "FAIL", "deployment asset is not an audited operational LIVE deployment"
    critical_assets = manifest.get("critical_assets")
    critical_asset_ids = {
        str(contract.get("asset_id"))
        for contract in critical_assets
        if isinstance(contract, dict) and contract.get("asset_id")
    } if isinstance(critical_assets, list) else set()
    if asset_id not in critical_asset_ids:
        return "FAIL", "deployment asset is not a manifest critical asset"
    metadata = asset.get("metadata")
    if not isinstance(metadata, dict):
        return "FAIL", "audited deployment metadata is missing or invalid"
    parsed_url = urllib.parse.urlparse(url)
    audited_urls = {
        str(value) for value in (asset.get("url"), metadata.get("final_url")) if value
    }
    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or url not in audited_urls
    ):
        return "FAIL", "deployment URL does not match the audited HTTPS deployment"
    identity_state, identity_detail = deployment_url_identity_state(
        manifest, asset_id, url
    )
    if identity_state != "PASS":
        return identity_state, identity_detail
    return "PASS", f"bound deployment_asset_id={asset_id}"


def critical_deployment_asset_ids(manifest: dict[str, Any]) -> set[str]:
    critical_assets = manifest.get("critical_assets")
    if not isinstance(critical_assets, list):
        return set()
    return {
        str(contract.get("asset_id"))
        for contract in critical_assets
        if isinstance(contract, dict)
        and contract.get("required_status") == "LIVE"
        and (
            domain_route_identity(str(contract.get("asset_id") or "")) is not None
            or huggingface_space_identity(str(contract.get("asset_id") or ""))
            is not None
        )
    }


def critical_runtime_alignment_state(
    asset: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    github_organization: str,
) -> tuple[str, str]:
    metadata = asset.get("metadata")
    if not isinstance(metadata, dict):
        return "FAIL", "critical Space metadata is missing or invalid"
    alignment = metadata.get("github_alignment")
    runtime_build = metadata.get("runtime_build")
    documents = metadata.get("provenance_docs")
    if not isinstance(alignment, dict) or alignment.get("status") != "EXACT_RUNTIME_HEAD":
        return "FAIL", f"alignment={alignment_state(asset)}"
    repository = str(alignment.get("source_repository") or "").lower()
    canonical_prefix = f"{github_organization.lower()}/"
    if not github_organization or not repository.startswith(canonical_prefix):
        return "FAIL", "runtime source repository is outside the canonical organization"
    source_revision = str(alignment.get("source_revision") or "").lower()
    github_revision = str(alignment.get("github_default_revision") or "").lower()
    runtime_revision = (
        str(runtime_build.get("revision") or "").lower()
        if isinstance(runtime_build, dict)
        and runtime_build.get("status") == "OBSERVED"
        and runtime_build.get("state") == "OBSERVED"
        else ""
    )
    revisions = {source_revision, github_revision, runtime_revision}
    if any(REVISION_PATTERN.fullmatch(value) is None for value in revisions) or len(
        revisions
    ) != 1:
        return "FAIL", "source, GitHub, and runtime revisions are not exact and equal"
    repository_asset = assets.get(f"github:repo:{repository}")
    repository_metadata = (
        repository_asset.get("metadata") if isinstance(repository_asset, dict) else None
    )
    if (
        not isinstance(repository_asset, dict)
        or repository_asset.get("source") != "github"
        or repository_asset.get("asset_type") != "repo"
        or repository_asset.get("status_label") != "OBSERVED"
        or repository_asset.get("operational_status") != "ACTIVE"
        or not isinstance(repository_metadata, dict)
        or str(repository_metadata.get("default_branch_sha") or "").lower()
        != source_revision
    ):
        return "FAIL", "declared source repository does not bind the exact revision"
    commit_fact = repository_metadata.get("default_branch_commit_fact")
    if (
        not isinstance(commit_fact, dict)
        or commit_fact.get("state") != "VERIFIED_REACHABLE"
        or str(commit_fact.get("source_repository") or "").lower() != repository
        or str(commit_fact.get("source_revision") or "").lower() != source_revision
    ):
        return (
            "FAIL",
            "source repository commit is not independently verified and reachable",
        )
    if not isinstance(documents, list):
        return "FAIL", "artifact source declaration is missing"

    provenance_policy = metadata.get("provenance_policy")
    artifact_provenance = (
        provenance_policy.get("artifact_provenance")
        if isinstance(provenance_policy, dict)
        else None
    )
    runtime_currency = (
        provenance_policy.get("runtime_currency")
        if isinstance(provenance_policy, dict)
        else None
    )
    policy_target = (
        provenance_policy.get("target")
        if isinstance(provenance_policy, dict)
        else None
    )
    policy_scope = (
        provenance_policy.get("scope")
        if isinstance(provenance_policy, dict)
        else None
    )
    asset_id = str(asset.get("asset_id") or "")
    if (
        not isinstance(provenance_policy, dict)
        or provenance_policy.get("schema")
        != "szl.provenance-policy-decision/v1"
        or not isinstance(policy_target, dict)
        or policy_target.get("asset_id") != asset_id
        or policy_target.get("evidence_state") != "OBSERVED"
        or not isinstance(policy_scope, dict)
        or policy_scope.get("state") != "AUTHENTICATED_COMPLETE"
        or policy_scope.get("completeness") != "COMPLETE"
    ):
        return "FAIL", "Space provenance policy is missing or not bound to the asset"

    expected_policy = classify_provenance(
        target_id=asset_id,
        source_scope="AUTHENTICATED_COMPLETE",
        artifact_documents=documents,
        commit_facts=[commit_fact],
        source_head={
            "status": "OBSERVED",
            "source_repository": repository,
            "source_revision": source_revision,
        },
        runtime_evidence={
            "status": "OBSERVED",
            "source_repository": repository,
            "source_revision": runtime_revision,
        },
        target_evidence_state="OBSERVED",
    )
    if provenance_policy != expected_policy:
        return "FAIL", "stored Space provenance policy does not match raw evidence"
    if (
        not isinstance(artifact_provenance, dict)
        or artifact_provenance.get("state") != "PASS"
        or artifact_provenance.get("evidence_state") != "VERIFIED_REACHABLE"
        or artifact_provenance.get("alignment_state") != "EXACT_HEAD"
        or artifact_provenance.get("current") is not True
        or str(artifact_provenance.get("source_repository") or "").lower()
        != repository
        or str(artifact_provenance.get("source_revision") or "").lower()
        != source_revision
        or str(artifact_provenance.get("head_revision") or "").lower()
        != source_revision
    ):
        return "FAIL", "artifact provenance does not verify the exact runtime source"
    if (
        not isinstance(runtime_currency, dict)
        or runtime_currency.get("state") != "PASS"
        or runtime_currency.get("evidence_state") != "OBSERVED_RUNTIME_REVISION"
        or runtime_currency.get("currency_state") != "CURRENT"
        or runtime_currency.get("current") is not True
        or str(runtime_currency.get("source_repository") or "").lower()
        != repository
        or str(runtime_currency.get("source_revision") or "").lower()
        != source_revision
        or str(runtime_currency.get("head_revision") or "").lower()
        != source_revision
    ):
        return "FAIL", "runtime currency does not verify the current exact head"
    return "PASS", f"repository={repository} revision={source_revision}"


def canonical_audit_payload(audit: dict[str, Any]) -> bytes:
    """Return the exact JSON payload covered by the detached signature."""
    payload = json.loads(json.dumps(audit))
    receipt = payload.get("receipt")
    if isinstance(receipt, dict):
        receipt.pop("asymmetric_signature", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_deployment_receipt_payload(receipt: dict[str, Any]) -> bytes:
    """Return the provider-signed deployment-receipt payload."""
    payload = json.loads(json.dumps(receipt))
    payload.pop("provider_signature", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_restore_artifact_payload(artifact: dict[str, Any]) -> bytes:
    """Return the provider-signed isolated-restore wrapper payload."""

    payload = json.loads(json.dumps(artifact))
    payload.pop("provider_signature", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_rsa_signature(
    payload: bytes,
    signature: Any,
    keys: Any,
    *,
    expected_provider: str | None = None,
) -> tuple[str, str]:
    if not isinstance(signature, dict):
        return "FAIL", "detached asymmetric signature missing"
    if set(signature) != {"algorithm", "key_id", "signature_base64"}:
        return "FAIL", "detached asymmetric signature shape is invalid"
    key_id = str(signature.get("key_id") or "")
    algorithm = str(signature.get("algorithm") or "")
    encoded = str(signature.get("signature_base64") or "")
    key = keys.get(key_id) if isinstance(keys, dict) else None
    if not isinstance(key, dict):
        return "FAIL", f"trusted key unavailable key_id={key_id or 'UNAVAILABLE'}"
    if algorithm != PRODUCTION_SIGNATURE_ALGORITHM:
        return "FAIL", f"unsupported signature algorithm={algorithm or 'UNAVAILABLE'}"
    if str(key.get("algorithm") or "") != algorithm:
        return "FAIL", "signature and trusted-key algorithms differ"
    if expected_provider is not None and str(key.get("provider") or "") != expected_provider:
        return "FAIL", "provider identity does not match the manifest-pinned key"
    try:
        modulus = int(str(key["modulus_hex"]), 16)
        exponent = int(key["exponent"])
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error):
        return "FAIL", "trusted key or signature encoding is invalid"
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
        return "FAIL", "trusted RSA key does not meet the production floor"
    width = (modulus.bit_length() + 7) // 8
    if len(signature_bytes) != width:
        return "FAIL", "signature width does not match trusted RSA modulus"
    digest_info = RSA_SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    padding_length = width - len(digest_info) - 3
    if padding_length < 8:
        return "FAIL", "trusted RSA key is too short for SHA-256"
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    observed = pow(int.from_bytes(signature_bytes, "big"), exponent, modulus).to_bytes(
        width, "big"
    )
    if not hmac.compare_digest(observed, expected):
        return "FAIL", f"signature verification failed key_id={key_id}"
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    return "PASS", f"verified key_id={key_id} payload_sha256={payload_sha256}"


def verify_independent_signature(
    audit: dict[str, Any], manifest: dict[str, Any]
) -> tuple[str, str]:
    receipt = audit.get("receipt") or {}
    signature = receipt.get("asymmetric_signature") or {}
    keys = manifest.get("production_trusted_keys") or {}
    payload = canonical_audit_payload(audit)
    return verify_rsa_signature(payload, signature, keys)


def production_evidence_references(
    audit: dict[str, Any],
    requirement: str,
) -> tuple[dict[str, dict[str, Any]] | None, str]:
    evidence = audit.get("production_evidence")
    index = evidence.get(requirement) if isinstance(evidence, dict) else None
    if (
        not isinstance(index, dict)
        or set(index) != {"schema", "artifacts"}
        or index.get("schema") != PRODUCTION_EVIDENCE_INDEX_SCHEMA
    ):
        return None, "production evidence index is missing or invalid"
    references = index.get("artifacts")
    if not isinstance(references, dict) or any(
        not isinstance(asset_id, str)
        or not asset_id
        or not isinstance(record, dict)
        or set(record) != {"artifact_path", "artifact_sha256"}
        for asset_id, record in references.items()
    ):
        return None, "production evidence reference map is invalid"
    return references, f"indexed_targets={len(references)}"


def load_production_artifact(
    audit: dict[str, Any],
    requirement: str,
    target_asset_id: str,
    evidence_root: Path | None,
) -> tuple[dict[str, Any] | None, str]:
    references, index_detail = production_evidence_references(audit, requirement)
    if references is None:
        return None, index_detail
    record = references.get(target_asset_id)
    if not isinstance(record, dict):
        return None, f"production evidence reference missing target={target_asset_id}"
    digest = str(record.get("artifact_sha256") or "")
    if SHA256_PATTERN.fullmatch(digest) is None:
        return None, "artifact_sha256 is missing or invalid"
    artifact_bytes, file_detail = load_evidence_bytes(
        record.get("artifact_path"), digest, evidence_root, label="artifact"
    )
    if artifact_bytes is None:
        return None, file_detail
    try:
        artifact = json.loads(artifact_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "artifact is not valid UTF-8 JSON"
    if not isinstance(artifact, dict):
        return None, "artifact must be a JSON object"
    return artifact, f"{index_detail}; target={target_asset_id}; {file_detail}"


def load_evidence_bytes(
    relative_value: Any,
    expected_sha256: str,
    evidence_root: Path | None,
    *,
    label: str,
) -> tuple[bytes | None, str]:
    return contract_load_evidence_bytes(
        relative_value,
        expected_sha256,
        evidence_root,
        label=label,
    )


def report_file_state(
    artifact: dict[str, Any], evidence_root: Path | None, *, label: str
) -> tuple[str, str]:
    report_sha256 = str(artifact.get("report_sha256") or "")
    if SHA256_PATTERN.fullmatch(report_sha256) is None:
        return "FAIL", f"{label} report digest is missing or invalid"
    report_bytes, detail = load_evidence_bytes(
        artifact.get("report_path"), report_sha256, evidence_root, label="report"
    )
    if report_bytes is None:
        return "FAIL", f"{label} {detail}"
    if not report_bytes:
        return "FAIL", f"{label} report is empty"
    return "PASS", detail


def production_policies(manifest: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    policies = manifest.get("production_policies")
    if not isinstance(policies, dict):
        return None, "production policies are missing or invalid"
    required = {
        "max_audit_age_seconds",
        "max_deployment_age_seconds",
        "max_browser_age_seconds",
        "max_restore_age_seconds",
        "max_rto_seconds",
        "max_rpo_seconds",
    }
    if set(policies) != required:
        return None, "production policy shape is invalid"
    for field in required:
        value = policies.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            return None, f"production policy {field} is invalid"
    return policies, "production policies verified"


def audit_completed_at(
    audit: dict[str, Any],
    verification_time: datetime,
    max_audit_age_seconds: float,
) -> tuple[datetime | None, str]:
    meta = audit.get("meta")
    completed = parsed_timestamp(meta.get("completed_at")) if isinstance(meta, dict) else None
    if completed is None:
        return None, "audit completion timestamp is missing or invalid"
    if verification_time.tzinfo is None:
        return None, "verification timestamp is missing timezone information"
    if completed > verification_time:
        return None, "audit completion timestamp is later than verification time"
    age_seconds = (verification_time - completed).total_seconds()
    if age_seconds > max_audit_age_seconds:
        return None, f"audit evidence is stale age_seconds={age_seconds:g}"
    return completed, f"audit age_seconds={age_seconds:g}"


def production_requirement_enabled(requirement: str, configured: Any) -> bool:
    if requirement == "critical_huggingface_alignment":
        return isinstance(configured, list) and bool(configured)
    return configured is True


def timestamp_freshness_state(
    observed: datetime,
    completed: datetime,
    verification_time: datetime,
    max_age_seconds: float,
    *,
    label: str,
) -> tuple[str, str]:
    if observed > completed:
        return "FAIL", f"{label} timestamp is later than audit completion"
    if observed > verification_time:
        return "FAIL", f"{label} timestamp is later than verification time"
    age_seconds = (verification_time - observed).total_seconds()
    if age_seconds > max_age_seconds:
        return "FAIL", f"{label} evidence is stale age_seconds={age_seconds:g}"
    return "PASS", f"{label} age_seconds={age_seconds:g}"


def production_artifact_state(
    audit: dict[str, Any],
    manifest: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    requirement: str,
    target_asset_id: str,
    evidence_root: Path | None,
    verification_time: datetime,
) -> tuple[str, str]:
    policies, policy_detail = production_policies(manifest)
    if policies is None:
        return "FAIL", policy_detail
    completed_at, completed_detail = audit_completed_at(
        audit,
        verification_time,
        float(policies["max_audit_age_seconds"]),
    )
    if completed_at is None:
        return "FAIL", completed_detail
    artifact, reference_detail = load_production_artifact(
        audit, requirement, target_asset_id, evidence_root
    )
    if artifact is None:
        return "FAIL", reference_detail
    expected_schema = PRODUCTION_ARTIFACT_SCHEMAS[requirement]
    if artifact.get("schema") != expected_schema or artifact.get("status") != "VERIFIED":
        return "FAIL", f"artifact schema/status invalid expected={expected_schema}"
    if requirement == "credential_backed_deployment_witness":
        required_witness_keys = {
            "schema",
            "status",
            "repository_asset_id",
            "deployment_asset_id",
            "deployment_revision",
            "deployed_artifact_sha256",
            "deployed_at",
            "environment",
            "deployment_url",
            "owner",
            "credential_scope",
            "deployment_receipt",
        }
        if set(artifact) != required_witness_keys:
            missing = sorted(required_witness_keys - set(artifact))
            extra = sorted(set(artifact) - required_witness_keys)
            return "FAIL", f"deployment witness shape invalid missing={missing} extra={extra}"
        revision = str(artifact.get("deployment_revision") or "")
        deployed_at = str(artifact.get("deployed_at") or "")
        scope = str(artifact.get("credential_scope") or "")
        if REVISION_PATTERN.fullmatch(revision) is None:
            return "FAIL", "deployment revision is missing or invalid"
        deployed_timestamp = parsed_timestamp(deployed_at)
        if deployed_timestamp is None:
            return "FAIL", "deployment timestamp is missing or invalid"
        freshness_state, freshness_detail = timestamp_freshness_state(
            deployed_timestamp,
            completed_at,
            verification_time,
            float(policies["max_deployment_age_seconds"]),
            label="deployment",
        )
        if freshness_state != "PASS":
            return freshness_state, freshness_detail
        if scope != "DEPLOYMENT_READ_ONLY":
            return "FAIL", f"credential_scope={scope or 'UNAVAILABLE'}"
        repository_asset_id = str(artifact.get("repository_asset_id") or "")
        deployment_asset_id = str(artifact.get("deployment_asset_id") or "")
        if deployment_asset_id != target_asset_id:
            return "FAIL", "deployment witness target does not match its evidence index"
        repository_asset = assets.get(repository_asset_id)
        deployment_asset = assets.get(deployment_asset_id)
        if not isinstance(repository_asset, dict):
            return "FAIL", "repository_asset_id is not present in the audited inventory"
        if (
            repository_asset.get("source") != "github"
            or repository_asset.get("asset_type") != "repo"
            or repository_asset.get("status_label") != "OBSERVED"
            or repository_asset.get("operational_status") != "ACTIVE"
        ):
            return "FAIL", "repository_asset_id is not an active audited GitHub repository"
        if not isinstance(deployment_asset, dict):
            return "FAIL", "deployment_asset_id is not present in the audited inventory"
        if deployment_asset.get("status_label") != "LIVE":
            return "FAIL", "deployment_asset_id is not an audited LIVE deployment"
        repository_metadata = repository_asset.get("metadata")
        if not isinstance(repository_metadata, dict):
            return "FAIL", "audited deployment metadata is missing or invalid"
        repository_revision = str(repository_metadata.get("default_branch_sha") or "")
        if not hmac.compare_digest(repository_revision, revision):
            return "FAIL", "deployment revision does not match the audited repository head"
        owner = str(artifact.get("owner") or "")
        canonical = manifest.get("canonical_identities") or {}
        if not isinstance(canonical, dict):
            return "FAIL", "canonical identity contract is missing or invalid"
        github_owner = str(canonical.get("github_organization") or "")
        expected_repository_prefix = f"github:repo:{github_owner.lower()}/"
        if owner != github_owner or not repository_asset_id.startswith(
            expected_repository_prefix
        ):
            return "FAIL", "deployment owner is not bound to the canonical repository owner"
        if huggingface_space_identity(deployment_asset_id) is not None:
            alignment_state, alignment_detail = critical_runtime_alignment_state(
                deployment_asset, assets, github_owner
            )
            if alignment_state != "PASS":
                return "FAIL", f"deployment Space alignment is invalid: {alignment_detail}"
            deployment_metadata = deployment_asset.get("metadata")
            alignment = (
                deployment_metadata.get("github_alignment")
                if isinstance(deployment_metadata, dict)
                else None
            )
            source_repository = (
                str(alignment.get("source_repository") or "").lower()
                if isinstance(alignment, dict)
                else ""
            )
            source_revision = (
                str(alignment.get("source_revision") or "").lower()
                if isinstance(alignment, dict)
                else ""
            )
            if (
                repository_asset_id.lower() != f"github:repo:{source_repository}"
                or revision.lower() != source_revision
            ):
                return (
                    "FAIL",
                    "deployment Space witness does not match its verified runtime source",
                )
        deployment_url = str(artifact.get("deployment_url") or "")
        target_state, target_detail = audited_live_target_state(
            assets, manifest, deployment_asset_id, deployment_url
        )
        if target_state != "PASS":
            return target_state, target_detail
        environment = str(artifact.get("environment") or "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", environment) is None:
            return "FAIL", "deployment environment is missing or invalid"
        deployed_artifact_sha256 = str(
            artifact.get("deployed_artifact_sha256") or ""
        )
        if SHA256_PATTERN.fullmatch(deployed_artifact_sha256) is None:
            return "FAIL", "deployed artifact digest is missing or invalid"
        receipt = artifact.get("deployment_receipt")
        required_receipt_keys = {
            "schema",
            "status",
            "repository_asset_id",
            "deployment_asset_id",
            "deployment_revision",
            "deployed_artifact_sha256",
            "deployed_at",
            "environment",
            "deployment_url",
            "owner",
            "receipt_id",
            "provider",
            "provider_signature",
        }
        if not isinstance(receipt, dict) or set(receipt) != required_receipt_keys:
            return "FAIL", "deployment receipt shape is invalid"
        if receipt.get("schema") != "szl.deployment-receipt/v1":
            return "FAIL", "deployment receipt schema is invalid"
        if receipt.get("status") != "VERIFIED":
            return "FAIL", "deployment receipt status is not VERIFIED"
        receipt_id = str(receipt.get("receipt_id") or "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", receipt_id) is None:
            return "FAIL", "deployment receipt identity is missing or invalid"
        bindings = {
            "repository_asset_id": repository_asset_id,
            "deployment_asset_id": deployment_asset_id,
            "deployment_revision": revision,
            "deployed_artifact_sha256": deployed_artifact_sha256,
            "deployed_at": deployed_at,
            "environment": environment,
            "deployment_url": deployment_url,
            "owner": owner,
            "receipt_id": receipt_id,
        }
        mismatches = sorted(
            field for field, expected in bindings.items() if receipt.get(field) != expected
        )
        if mismatches:
            return "FAIL", f"deployment receipt binding mismatch={','.join(mismatches)}"
        provider = str(receipt.get("provider") or "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", provider) is None:
            return "FAIL", "deployment receipt provider identity is missing or invalid"
        provider_state, provider_detail = verify_rsa_signature(
            canonical_deployment_receipt_payload(receipt),
            receipt.get("provider_signature"),
            manifest.get("deployment_provider_trusted_keys") or {},
            expected_provider=provider,
        )
        if provider_state != "PASS":
            return "FAIL", f"deployment receipt provider authentication failed: {provider_detail}"
        deployment_metadata = deployment_asset.get("metadata")
        edge = (
            deployment_metadata.get("deployment")
            if isinstance(deployment_metadata, dict)
            else None
        )
        required_edge_keys = {"schema", *bindings}
        if not isinstance(edge, dict) or set(edge) != required_edge_keys:
            return "FAIL", "audited repository-to-deployment edge is missing or invalid"
        if edge.get("schema") != "szl.audit-deployment-edge/v1":
            return "FAIL", "audited deployment edge schema is invalid"
        edge_mismatches = sorted(
            field for field, expected in bindings.items() if edge.get(field) != expected
        )
        if edge_mismatches:
            return "FAIL", f"audited deployment edge mismatch={','.join(edge_mismatches)}"
    elif requirement == "browser_e2e_and_accessibility":
        required_artifact_keys = {
            "schema",
            "status",
            "deployment_asset_id",
            "tested_url",
            "tested_at",
            "deployment_revision",
            "deployed_artifact_sha256",
            "deployment_receipt_id",
            "browsers",
            "checks",
            "report_path",
            "report_sha256",
        }
        if set(artifact) != required_artifact_keys:
            return "FAIL", "browser evidence shape is invalid"
        deployment_asset_id = str(artifact.get("deployment_asset_id") or "")
        if deployment_asset_id != target_asset_id:
            return "FAIL", "browser target does not match its evidence index"
        tested_url = str(artifact.get("tested_url") or "")
        target_state, target_detail = audited_live_target_state(
            assets, manifest, deployment_asset_id, tested_url
        )
        if target_state != "PASS":
            return target_state, target_detail
        tested_at = parsed_timestamp(artifact.get("tested_at"))
        if tested_at is None:
            return "FAIL", "browser evidence timestamp is missing or invalid"
        freshness_state, freshness_detail = timestamp_freshness_state(
            tested_at,
            completed_at,
            verification_time,
            float(policies["max_browser_age_seconds"]),
            label="browser",
        )
        if freshness_state != "PASS":
            return freshness_state, freshness_detail
        witness_state, witness_detail = production_artifact_state(
            audit,
            manifest,
            assets,
            "credential_backed_deployment_witness",
            target_asset_id,
            evidence_root,
            verification_time,
        )
        if witness_state != "PASS":
            return "FAIL", f"promoted deployment witness invalid: {witness_detail}"
        witness, witness_reference = load_production_artifact(
            audit,
            "credential_backed_deployment_witness",
            target_asset_id,
            evidence_root,
        )
        if not isinstance(witness, dict):
            return "FAIL", f"promoted deployment witness unavailable: {witness_reference}"
        witness_receipt = witness.get("deployment_receipt")
        if not isinstance(witness_receipt, dict):
            return "FAIL", "promoted deployment receipt is missing"
        browser_bindings = {
            "deployment_asset_id": deployment_asset_id,
            "deployment_url": tested_url,
            "deployment_revision": str(artifact.get("deployment_revision") or ""),
            "deployed_artifact_sha256": str(artifact.get("deployed_artifact_sha256") or ""),
            "receipt_id": str(artifact.get("deployment_receipt_id") or ""),
        }
        mismatches = sorted(
            field
            for field, observed in browser_bindings.items()
            if not observed
            or (
                witness_receipt.get(field) if field == "receipt_id" else witness.get(field)
            )
            != observed
        )
        deployed_at = parsed_timestamp(witness.get("deployed_at"))
        if mismatches or deployed_at is None or tested_at < deployed_at:
            return "FAIL", (
                f"browser evidence does not bind the promoted deployment witness mismatch={','.join(mismatches)}"
            )
        browsers = artifact.get("browsers")
        if not isinstance(browsers, list) or len(browsers) < 2:
            return "FAIL", "browser evidence must include desktop and mobile runs"
        form_factors: set[str] = set()
        for browser in browsers:
            if not isinstance(browser, dict) or set(browser) != {
                "name",
                "form_factor",
                "status",
            }:
                return "FAIL", "browser run shape is invalid"
            if not str(browser.get("name") or "") or browser.get("status") != "PASS":
                return "FAIL", "browser run is unnamed or not passing"
            form_factors.add(str(browser.get("form_factor") or ""))
        if not {"desktop", "mobile"}.issubset(form_factors):
            return "FAIL", "browser evidence lacks desktop or mobile coverage"
        checks = artifact.get("checks")
        required = {
            "browser_e2e",
            "keyboard",
            "mobile",
            "accessibility",
            "console_errors",
            "network_errors",
            "screen_reader",
            "zoom_200",
            "contrast",
            "wcag_2_2_aa",
        }
        if not isinstance(checks, dict):
            return "FAIL", "browser checks must be a JSON object"
        missing = sorted(name for name in required if checks.get(name) != "PASS")
        if missing:
            return "FAIL", f"required checks not passing={','.join(missing)}"
        report_state, report_detail = report_file_state(
            artifact, evidence_root, label="browser"
        )
        if report_state != "PASS":
            return report_state, report_detail
    elif requirement == "restore_and_failure_domain_drill":
        required_artifact_keys = {
            "schema",
            "status",
            "source_deployment_asset_id",
            "deployment_url",
            "deployment_revision",
            "deployed_artifact_sha256",
            "deployment_receipt_id",
            "environment",
            "measurement_path",
            "measurement_sha256",
            "dependency_loss_scenarios",
            "corrective_actions",
            "failure_domain_status",
            "provider",
            "provider_signature",
        }
        if set(artifact) != required_artifact_keys:
            return "FAIL", "restore evidence shape is invalid"
        target_id = str(artifact.get("source_deployment_asset_id") or "")
        if target_id != target_asset_id:
            return "FAIL", "restore source does not match its evidence index"
        target_state, target_detail = audited_live_target_state(
            assets,
            manifest,
            target_id,
            str(artifact.get("deployment_url") or ""),
        )
        if target_state != "PASS":
            return "FAIL", f"source deployment is invalid: {target_detail}"

        measurement_sha256 = str(artifact.get("measurement_sha256") or "")
        measurement_bytes, measurement_detail = load_evidence_bytes(
            artifact.get("measurement_path"),
            measurement_sha256,
            evidence_root,
            label="restore_measurement",
        )
        if measurement_bytes is None:
            return "FAIL", measurement_detail
        try:
            measurement = json.loads(measurement_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "FAIL", "restore measurement is not valid UTF-8 JSON"
        measurement_state, measurement_validation = validate_restore_measurement(
            measurement
        )
        if measurement_state != "PASS":
            return "FAIL", measurement_validation
        assert isinstance(measurement, dict)
        started = parsed_timestamp(measurement.get("started_at"))
        completed = parsed_timestamp(measurement.get("completed_at"))
        assert started is not None and completed is not None
        freshness_state, freshness_detail = timestamp_freshness_state(
            completed,
            completed_at,
            verification_time,
            float(policies["max_restore_age_seconds"]),
            label="restore",
        )
        if freshness_state != "PASS":
            return freshness_state, freshness_detail
        observed_rto_seconds = float(measurement["rto_seconds"])
        observed_rpo_seconds = float(measurement["rpo_seconds"])
        if observed_rto_seconds > float(policies["max_rto_seconds"]):
            return "FAIL", "rto_seconds exceeds the production policy ceiling"
        if observed_rpo_seconds > float(policies["max_rpo_seconds"]):
            return "FAIL", "rpo_seconds exceeds the production policy ceiling"

        provider = str(artifact.get("provider") or "")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", provider) is None:
            return "FAIL", "restore evidence provider identity is missing or invalid"
        provider_state, provider_detail = verify_rsa_signature(
            canonical_restore_artifact_payload(artifact),
            artifact.get("provider_signature"),
            manifest.get("restore_provider_trusted_keys") or {},
            expected_provider=provider,
        )
        if provider_state != "PASS":
            return "FAIL", f"restore provider authentication failed: {provider_detail}"

        witness_state, witness_detail = production_artifact_state(
            audit,
            manifest,
            assets,
            "credential_backed_deployment_witness",
            target_asset_id,
            evidence_root,
            verification_time,
        )
        if witness_state != "PASS":
            return "FAIL", f"promoted deployment witness invalid: {witness_detail}"
        witness, witness_reference = load_production_artifact(
            audit,
            "credential_backed_deployment_witness",
            target_asset_id,
            evidence_root,
        )
        if not isinstance(witness, dict):
            return "FAIL", f"promoted deployment witness unavailable: {witness_reference}"
        witness_receipt = witness.get("deployment_receipt")
        if not isinstance(witness_receipt, dict):
            return "FAIL", "promoted deployment receipt is missing"
        restore_bindings = {
            "deployment_asset_id": target_id,
            "deployment_url": str(artifact.get("deployment_url") or ""),
            "deployment_revision": str(artifact.get("deployment_revision") or ""),
            "deployed_artifact_sha256": str(artifact.get("deployed_artifact_sha256") or ""),
            "receipt_id": str(artifact.get("deployment_receipt_id") or ""),
            "environment": str(artifact.get("environment") or ""),
        }
        restore_mismatches = sorted(
            field
            for field, observed in restore_bindings.items()
            if not observed
            or (
                witness_receipt.get(field) if field == "receipt_id" else witness.get(field)
            )
            != observed
        )
        deployed_at = parsed_timestamp(witness.get("deployed_at"))
        if restore_mismatches or deployed_at is None or started < deployed_at:
            return "FAIL", (
                "restore evidence does not bind the promoted deployment witness "
                f"mismatch={','.join(restore_mismatches)}"
            )

        if artifact.get("failure_domain_status") != "PASS":
            return "FAIL", "failure-domain drill did not pass"
        scenarios = artifact.get("dependency_loss_scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            return "FAIL", "witnessed dependency-loss scenarios are missing"
        for scenario in scenarios:
            if (
                not isinstance(scenario, dict)
                or set(scenario) != {"name", "status"}
                or not str(scenario.get("name") or "")
                or scenario.get("status") != "PASS"
            ):
                return "FAIL", "dependency-loss scenario is malformed or not passing"
        corrective_actions = artifact.get("corrective_actions")
        if not isinstance(corrective_actions, list) or not corrective_actions:
            return "FAIL", "corrective-action closure evidence is missing"
        for action in corrective_actions:
            if (
                not isinstance(action, dict)
                or set(action) != {"id", "status"}
                or not str(action.get("id") or "")
                or action.get("status") != "CLOSED"
            ):
                return "FAIL", "corrective action is malformed or not closed"
        return "PASS", (
            f"{reference_detail}; {measurement_detail}; {measurement_validation}; "
            f"{provider_detail}"
        )
    return "PASS", reference_detail


def production_artifact_requirement_state(
    audit: dict[str, Any],
    manifest: dict[str, Any],
    assets: dict[str, dict[str, Any]],
    requirement: str,
    evidence_root: Path | None,
    verification_time: datetime,
) -> tuple[str, str]:
    required_targets = critical_deployment_asset_ids(manifest)
    if not required_targets:
        return "FAIL", "critical deployment contract is missing or empty"
    references, reference_detail = production_evidence_references(audit, requirement)
    if references is None:
        return "FAIL", reference_detail
    missing_targets = sorted(required_targets - set(references))
    extra_targets = sorted(set(references) - required_targets)
    if missing_targets or extra_targets:
        return "FAIL", (
            f"critical deployment coverage mismatch missing={missing_targets} "
            f"extra={extra_targets}"
        )
    failures = []
    for target_asset_id in sorted(required_targets):
        state, detail = production_artifact_state(
            audit,
            manifest,
            assets,
            requirement,
            target_asset_id,
            evidence_root,
            verification_time,
        )
        if state != "PASS":
            failures.append(f"{target_asset_id}: {detail}")
    if failures:
        return "FAIL", "; ".join(failures)
    return "PASS", f"verified critical deployment targets={len(required_targets)}"


def verify(
    audit: dict[str, Any],
    manifest: dict[str, Any],
    profile: str,
    *,
    evidence_root: Path | None = None,
    verification_time: datetime | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    observed_verification_time = verification_time or datetime.now(timezone.utc)
    manifest_contract, manifest_detail = manifest_baseline_contract_state(manifest)
    checks.append(
        result("manifest.baseline_contract", manifest_contract, manifest_detail)
    )
    asset_records = audit.get("assets") or []
    if not isinstance(asset_records, list):
        asset_records = []
        invalid_asset_inventory = True
    else:
        invalid_asset_inventory = any(
            not isinstance(item, dict) or not str(item.get("asset_id") or "")
            for item in asset_records
        )
    asset_ids = [
        str(item.get("asset_id"))
        for item in asset_records
        if isinstance(item, dict) and item.get("asset_id")
    ]
    seen_asset_ids: set[str] = set()
    duplicate_asset_ids: set[str] = set()
    for asset_id in asset_ids:
        if asset_id in seen_asset_ids:
            duplicate_asset_ids.add(asset_id)
        seen_asset_ids.add(asset_id)
    assets = {
        str(item.get("asset_id")): item
        for item in asset_records
        if isinstance(item, dict) and item.get("asset_id")
    }
    source_reports = {
        str(item.get("source")): item
        for item in audit.get("source_reports") or []
        if isinstance(item, dict) and item.get("source")
    }
    configured_baseline = manifest.get("baseline")
    baseline = configured_baseline if isinstance(configured_baseline, dict) else {}
    canonical_identities = manifest.get("canonical_identities") or {}
    github_organization = (
        str(canonical_identities.get("github_organization") or "")
        if isinstance(canonical_identities, dict)
        else ""
    )
    checks.append(
        result(
            "assets.unique_ids",
            "PASS"
            if not invalid_asset_inventory and not duplicate_asset_ids
            else "FAIL",
            "all asset identifiers are nonempty and unique"
            if not invalid_asset_inventory and not duplicate_asset_ids
            else (
                "asset inventory shape is invalid"
                if invalid_asset_inventory
                else f"duplicate={','.join(sorted(duplicate_asset_ids))}"
            ),
        )
    )

    configured_source_minimums = baseline.get("source_minimums")
    source_minimums = (
        configured_source_minimums
        if isinstance(configured_source_minimums, dict)
        else {}
    )
    for source, minimum in source_minimums.items():
        report = source_reports.get(source)
        if report is None:
            checks.append(result(f"source.{source}", "FAIL", "Source report missing"))
            continue
        status = str(report.get("status") or "UNAVAILABLE")
        reported_count = report.get("count")
        count = (
            reported_count
            if isinstance(reported_count, int) and not isinstance(reported_count, bool)
            else -1
        )
        observed_count = sum(
            1 for item in assets.values() if str(item.get("source") or "") == source
        )
        required = str(baseline.get("required_source_status") or "MEASURED")
        state = (
            "PASS"
            if status == required
            and count == observed_count
            and isinstance(minimum, int)
            and not isinstance(minimum, bool)
            and observed_count >= minimum
            else "FAIL"
        )
        checks.append(
            result(
                f"source.{source}",
                state,
                f"status={status} reported_count={count} observed_count={observed_count} "
                f"required_status={required} minimum={minimum}",
            )
        )

    configured_prohibited = baseline.get("prohibited_status_labels")
    prohibited = (
        {
            value
            for value in configured_prohibited
            if isinstance(value, str) and value
        }
        if isinstance(configured_prohibited, list)
        else set()
    )
    prohibited_assets = [
        item
        for item in assets.values()
        if str(item.get("status_label") or "UNAVAILABLE") in prohibited
    ]
    checks.append(
        result(
            "assets.prohibited_status",
            "PASS" if not prohibited_assets else "FAIL",
            "none observed"
            if not prohibited_assets
            else ", ".join(str(item.get("asset_id")) for item in prohibited_assets[:20]),
        )
    )

    configured_critical_assets = manifest.get("critical_assets")
    critical_assets = (
        configured_critical_assets if isinstance(configured_critical_assets, list) else []
    )
    configured_security_headers = baseline.get("required_security_headers")
    required_security_headers = (
        [
            value
            for value in configured_security_headers
            if isinstance(value, str) and value
        ]
        if isinstance(configured_security_headers, list)
        else []
    )
    for contract in critical_assets:
        if not isinstance(contract, dict) or not contract.get("asset_id"):
            continue
        asset_id = str(contract["asset_id"])
        public = bool(contract.get("public"))
        asset = assets.get(asset_id)
        if not public and profile == "baseline":
            checks.append(
                result(
                    f"asset.{asset_id}",
                    "UNAVAILABLE",
                    "Authenticated evidence is outside the public baseline",
                )
            )
            continue
        if asset is None:
            checks.append(result(f"asset.{asset_id}", "FAIL", "Critical asset missing"))
            continue
        observed = str(asset.get("status_label") or "UNAVAILABLE")
        required_status = contract.get("required_status")
        if asset_id.startswith("github:repo:"):
            source = str(asset.get("source") or "UNAVAILABLE")
            asset_type = str(asset.get("asset_type") or "UNAVAILABLE")
            operational_status = str(
                asset.get("operational_status") or "UNAVAILABLE"
            )
            state = (
                "PASS"
                if source == "github"
                and asset_type == "repo"
                and observed == "OBSERVED"
                and operational_status == "ACTIVE"
                else "FAIL"
            )
            detail = (
                f"source={source} asset_type={asset_type} status={observed} "
                f"operational_status={operational_status}"
            )
        elif required_status:
            state = "PASS" if observed == required_status else "FAIL"
            detail = f"status={observed} required={required_status}"
        else:
            state = "PASS" if observed not in {"BROKEN", "ARCHIVED"} else "FAIL"
            detail = f"status={observed}"
        checks.append(result(f"asset.{asset_id}", state, detail))

        if asset_id.startswith("domain:route:"):
            metadata = asset.get("metadata")
            configured_headers = (
                metadata.get("security_headers") if isinstance(metadata, dict) else None
            )
            headers = configured_headers if isinstance(configured_headers, dict) else {}
            missing = [
                header
                for header in required_security_headers
                if headers.get(header) is not True
            ]
            header_values = (
                metadata.get("security_header_values")
                if isinstance(metadata, dict)
                else None
            )
            semantic_state, semantic_detail = security_header_values_state(
                header_values
            )
            header_state = "PASS" if not missing and semantic_state == "PASS" else "FAIL"
            header_detail = (
                semantic_detail
                if not missing
                else f"missing={','.join(missing)}"
            )
            checks.append(
                result(
                    f"headers.{asset_id}",
                    header_state,
                    header_detail,
                )
            )

        if profile == "production" and asset_id.startswith("huggingface:space:"):
            alignment, alignment_detail = critical_runtime_alignment_state(
                asset, assets, github_organization
            )
            checks.append(
                result(
                    f"alignment.{asset_id}",
                    alignment,
                    alignment_detail,
                )
            )

    receipt = audit.get("receipt") or {}
    signature_status = str(receipt.get("signature_status") or "UNAVAILABLE")
    signature_verification = (
        verify_independent_signature(audit, manifest)
        if profile == "production"
        else (
            signature_state(signature_status, profile),
            f"receipt_signature={signature_status}",
        )
    )
    checks.append(
        result(
            "evidence.independent_signature",
            signature_verification[0],
            signature_verification[1],
        )
    )

    if profile == "production":
        configured_requirements = manifest.get("production_requirements")
        requirements_shape_valid = isinstance(configured_requirements, dict)
        production_requirements = (
            configured_requirements if isinstance(configured_requirements, dict) else {}
        )
        missing_requirements = sorted(
            KNOWN_PRODUCTION_REQUIREMENTS - set(production_requirements)
        )
        extra_requirements = sorted(
            set(production_requirements) - KNOWN_PRODUCTION_REQUIREMENTS
        )
        invalid_requirement_values = sorted(
            requirement
            for requirement in KNOWN_PRODUCTION_REQUIREMENTS & set(production_requirements)
            if not production_requirement_enabled(
                requirement, production_requirements[requirement]
            )
        )
        requirements_contract_valid = (
            requirements_shape_valid
            and not missing_requirements
            and not extra_requirements
            and not invalid_requirement_values
        )
        checks.append(
            result(
                "production.requirements_contract",
                "PASS" if requirements_contract_valid else "FAIL",
                "all production requirements are explicitly enabled"
                if requirements_contract_valid
                else (
                    f"shape_valid={requirements_shape_valid} "
                    f"missing={missing_requirements} extra={extra_requirements} "
                    f"invalid_values={invalid_requirement_values}"
                ),
            )
        )
        if not requirements_shape_valid:
            production_requirements = {}
        policies, policy_detail = production_policies(manifest)
        completed_at = None
        completed_detail = policy_detail
        if policies is not None:
            completed_at, completed_detail = audit_completed_at(
                audit,
                observed_verification_time,
                float(policies["max_audit_age_seconds"]),
            )
        checks.append(
            result(
                "production.audit_freshness",
                "PASS" if completed_at is not None else "FAIL",
                completed_detail,
            )
        )
        for source in ("github", "huggingface"):
            scope = str((source_reports.get(source) or {}).get("scope") or "UNAVAILABLE")
            checks.append(
                result(
                    f"scope.{source}",
                    "PASS" if scope in PRODUCTION_COMPLETE_SCOPES else "FAIL",
                    f"scope={scope} required={','.join(sorted(PRODUCTION_COMPLETE_SCOPES))}",
                )
            )
        gap_contract, gap_contract_detail = known_gap_contract_state(manifest)
        checks.append(result("gaps.contract", gap_contract, gap_contract_detail))
        configured_known_gaps = manifest.get("known_gaps")
        known_gaps = (
            configured_known_gaps
            if gap_contract == "PASS" and isinstance(configured_known_gaps, list)
            else []
        )
        active_gaps = [
            gap
            for gap in known_gaps
            if gap.get("status") == "ACTIVE" and gap.get("severity") in {"P0", "P1"}
        ]
        critical_gaps_clear = gap_contract == "PASS" and not active_gaps
        checks.append(
            result(
                "gaps.critical",
                "PASS" if critical_gaps_clear else "FAIL",
                "none active"
                if critical_gaps_clear
                else (
                    gap_contract_detail
                    if gap_contract != "PASS"
                    else ", ".join(str(gap.get("id")) for gap in active_gaps)
                ),
            )
        )

        for requirement, configured in production_requirements.items():
            enabled = production_requirement_enabled(requirement, configured)
            if not enabled:
                continue
            check_id = f"production.requirement.{requirement}"
            if requirement not in KNOWN_PRODUCTION_REQUIREMENTS:
                checks.append(result(check_id, "FAIL", "unknown enabled requirement"))
                continue
            if requirement == "authenticated_inventory":
                incomplete = [
                    source
                    for source in ("github", "huggingface")
                    if str((source_reports.get(source) or {}).get("scope") or "")
                    not in PRODUCTION_COMPLETE_SCOPES
                ]
                checks.append(
                    result(
                        check_id,
                        "PASS" if not incomplete else "FAIL",
                        "complete authenticated inventory"
                        if not incomplete
                        else f"incomplete={','.join(incomplete)}",
                    )
                )
            elif requirement == "critical_huggingface_alignment":
                configured_states = (
                    {str(value) for value in configured}
                    if isinstance(configured, list)
                    else set()
                )
                failed = []
                for contract in critical_assets:
                    if not isinstance(contract, dict):
                        continue
                    asset_id = str(contract.get("asset_id") or "")
                    if not asset_id.startswith("huggingface:space:"):
                        continue
                    asset = assets.get(asset_id)
                    if asset is None or critical_runtime_alignment_state(
                        asset, assets, github_organization
                    )[0] != "PASS":
                        failed.append(asset_id)
                configuration_valid = configured_states == ALIGNMENT_READY
                checks.append(
                    result(
                        check_id,
                        "PASS" if configuration_valid and not failed else "FAIL",
                        "all critical Hugging Face alignments verified"
                        if configuration_valid and not failed
                        else (
                            f"invalid configured states={','.join(sorted(configured_states))}"
                            if not configuration_valid
                            else f"failed={','.join(failed)}"
                        ),
                    )
                )
            elif requirement == "independent_asymmetric_evidence":
                checks.append(result(check_id, *signature_verification))
            elif requirement in {
                "credential_backed_deployment_witness",
                "browser_e2e_and_accessibility",
                "restore_and_failure_domain_drill",
            }:
                artifact_state, artifact_detail = production_artifact_requirement_state(
                    audit,
                    manifest,
                    assets,
                    requirement,
                    evidence_root,
                    observed_verification_time,
                )
                if signature_verification[0] != "PASS":
                    artifact_state = "FAIL"
                    artifact_detail += "; audit signature is not verified"
                checks.append(result(check_id, artifact_state, artifact_detail))
            elif requirement == "zero_active_critical_gaps":
                checks.append(
                    result(
                        check_id,
                        "PASS" if critical_gaps_clear else "FAIL",
                        "none active"
                        if critical_gaps_clear
                        else (
                            gap_contract_detail
                            if gap_contract != "PASS"
                            else ", ".join(str(gap.get("id")) for gap in active_gaps)
                        ),
                    )
                )

    failure_count = sum(item["state"] == "FAIL" for item in checks)
    warning_count = sum(item["state"] in {"WARN", "UNAVAILABLE"} for item in checks)
    return {
        "schema": "szl.estate-readiness-report/v1",
        "profile": profile,
        "status": "PASS" if failure_count == 0 else "FAIL",
        "audit_id": (audit.get("meta") or {}).get("audit_id"),
        "failure_count": failure_count,
        "warning_count": warning_count,
        "checks": checks,
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Estate readiness report",
        "",
        f"- Profile: `{report['profile']}`",
        f"- Status: `{report['status']}`",
        f"- Audit: `{report.get('audit_id') or 'UNAVAILABLE'}`",
        f"- Failures: `{report['failure_count']}`",
        f"- Warnings/unavailable: `{report['warning_count']}`",
        "",
        "| State | Check | Detail |",
        "|---|---|---|",
    ]
    for item in report["checks"]:
        detail = str(item["detail"]).replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{item['state']}` | `{item['id']}` | {detail} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--profile", choices=("baseline", "production"), default="baseline")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    args = parser.parse_args()

    report = verify(
        read_json(args.audit),
        read_json(args.manifest),
        args.profile,
        evidence_root=args.audit.resolve().parent,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(rendered, encoding="utf-8")
    if args.output_markdown:
        args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.output_markdown.write_text(markdown(report), encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
