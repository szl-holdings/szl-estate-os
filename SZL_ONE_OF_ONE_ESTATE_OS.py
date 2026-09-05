#!/usr/bin/env python3
"""
SZL One-of-One Estate OS

A dependency-free, read-only estate control plane for:
  * GitHub organization inventory
  * Hugging Face organization inventory
  * Domain and route probes
  * Evidence-aware scoring and duplicate clustering
  * Gated fate proposals
  * SQLite history and hash-chained receipts
  * A local JSON API and dashboard

The program never mutates GitHub, Hugging Face, DNS, or deployed services.
External changes remain proposals until handled through the applicable
governance and deployment systems.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import html
import http.server
import json
import os
import re
import secrets
import sqlite3
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from estate.provenance_policy import classify_provenance
from operating_fabric import (
    LANE_ORDER,
    assess_web_security_headers,
    evaluate_operating_fabric,
    evidence_template,
    load_evidence_bundle,
)


APP_NAME = "SZL_ONE_OF_ONE_ESTATE_OS"
APP_VERSION = "2026.08.01"
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (+https://a-11-oy.com)"
DEFAULT_GITHUB_ORG = "szl-holdings"
DEFAULT_HF_ORG = "SZLHOLDINGS"
DEFAULT_DOMAINS = ("a-11-oy.com", "a11oy.net")
DEFAULT_TIMEOUT = 12.0
DEFAULT_WORKERS = 8
DEFAULT_REQUEST_QUEUE_SIZE = 128
GITHUB_COMPLETE_SCOPE = "AUTHENTICATED_COMPLETE"
GITHUB_PARTIAL_SCOPE = "AUTHENTICATED_VISIBILITY_UNKNOWN"
MAX_RESPONSE_BYTES = 2_000_000
ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = ROOT / "outputs"
DEFAULT_DB = DEFAULT_OUTPUT_DIR / "estate.db"
DEFAULT_EXPORT = DEFAULT_OUTPUT_DIR / "latest_audit.json"

DOMAIN_ROUTES = {
    "a-11-oy.com": ("/",),
    "a11oy.net": ("/",),
}
MAX_DISCOVERED_ROUTES_PER_DOMAIN = 40
NON_NAVIGATION_SUFFIXES = {
    ".avif",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}

PLACEHOLDER_MARKERS = (
    "coming soon",
    "under construction",
    "lorem ipsum",
    "placeholder",
    "work in progress",
    "site not found",
    "nothing here yet",
)

NARRATIVE_KEYWORDS = {
    "a11oy",
    "alloy",
    "audit",
    "bench",
    "calibration",
    "conformal",
    "drift",
    "estate",
    "governance",
    "kernel",
    "observability",
    "receipt",
    "replay",
    "runtime",
    "state",
    "telemetry",
    "truth",
    "verify",
}

SCORE_NAMES = (
    "operational_reality_score",
    "security_score",
    "documentation_score",
    "demo_score",
    "governance_score",
    "uniqueness_score",
    "frontier_potential_score",
    "duplication_penalty",
    "staleness_penalty",
    "narrative_fit_score",
)

SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS audit_runs (
    audit_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    status TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    source_reports_json TEXT NOT NULL,
    asset_count INTEGER NOT NULL,
    proposal_count INTEGER NOT NULL,
    receipt_hash TEXT,
    app_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_audit_id TEXT NOT NULL,
    latest_status_label TEXT NOT NULL,
    latest_operational_status TEXT NOT NULL,
    latest_metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_assets (
    audit_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    status_label TEXT NOT NULL,
    operational_status TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    score_json TEXT NOT NULL,
    duplicate_cluster_id TEXT,
    PRIMARY KEY (audit_id, asset_id),
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS proposals (
    proposal_id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    proposed_fate TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    status TEXT NOT NULL,
    rationale_json TEXT NOT NULL,
    execution_mode TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT UNIQUE NOT NULL,
    audit_id TEXT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    signature TEXT,
    signature_status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operating_lanes (
    audit_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    assessment TEXT NOT NULL,
    score REAL,
    coverage REAL NOT NULL,
    control_count INTEGER NOT NULL,
    critical_blockers_json TEXT NOT NULL,
    claim_state TEXT NOT NULL,
    PRIMARY KEY (audit_id, lane),
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id)
);

CREATE TABLE IF NOT EXISTS control_findings (
    audit_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    truth_label TEXT NOT NULL,
    critical INTEGER NOT NULL,
    severity TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    metric_json TEXT NOT NULL,
    response_json TEXT NOT NULL,
    PRIMARY KEY (audit_id, control_id),
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id)
);

CREATE TABLE IF NOT EXISTS fabric_actions (
    audit_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    lane TEXT NOT NULL,
    priority TEXT NOT NULL,
    state TEXT NOT NULL,
    owner_role TEXT NOT NULL,
    execution_mode TEXT NOT NULL,
    approval TEXT NOT NULL,
    playbook TEXT NOT NULL,
    PRIMARY KEY (audit_id, action_id),
    FOREIGN KEY (audit_id) REFERENCES audit_runs(audit_id)
);

CREATE INDEX IF NOT EXISTS idx_audit_assets_audit
ON audit_assets(audit_id);

CREATE INDEX IF NOT EXISTS idx_proposals_audit_status
ON proposals(audit_id, status);

CREATE INDEX IF NOT EXISTS idx_receipts_audit
ON receipts(audit_id);

CREATE INDEX IF NOT EXISTS idx_control_findings_audit_lane
ON control_findings(audit_id, lane, state);

CREATE INDEX IF NOT EXISTS idx_fabric_actions_audit_priority
ON fabric_actions(audit_id, priority);
"""


class SourceError(RuntimeError):
    """A source could not be retrieved or decoded."""

    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class HttpResult:
    requested_url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: int
    error: str | None = None
    truncated: bool = False


@dataclass
class Asset:
    asset_id: str
    asset_type: str
    source: str
    name: str
    url: str | None
    status_label: str
    operational_status: str
    observed_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class SourceReport:
    source: str
    status: str
    scope: str
    count: int
    observed_at: str
    elapsed_ms: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScoreCard:
    asset_id: str
    scores: dict[str, float | None]
    evidence: dict[str, str]
    proposed_fate: str
    rationale: list[str]

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class AuditConfig:
    github_org: str = DEFAULT_GITHUB_ORG
    hf_org: str = DEFAULT_HF_ORG
    hf_spaces: tuple[str, ...] = ()
    domains: tuple[str, ...] = DEFAULT_DOMAINS
    deep: bool = False
    timeout: float = DEFAULT_TIMEOUT
    workers: int = DEFAULT_WORKERS
    max_pages: int = 20

    def public_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def normalize_hf_spaces(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    pattern = re.compile(
        r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/"
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}$"
    )
    for value in values:
        candidate = str(value).strip()
        if pattern.fullmatch(candidate) is None:
            raise ValueError(f"Invalid Hugging Face Space identity: {value!r}")
        key = candidate.lower()
        if key not in seen:
            seen.add(key)
            normalized.append(candidate)
    return tuple(normalized)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return round(max(lower, min(upper, value)), 4)


def sanitize_error(value: Any, limit: int = 500) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:limit]


def normalize_http_header_value(value: Any) -> str | None:
    """Preserve an observed header value with only outer OWS removed."""

    if not isinstance(value, str) or "\r" in value or "\n" in value:
        return None
    normalized = value.strip(" \t")
    return normalized or None


def parse_datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def age_days(value: Any) -> float | None:
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    delta = dt.datetime.now(dt.timezone.utc) - parsed
    return max(0.0, delta.total_seconds() / 86400.0)


def env_token(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return None


def fetch(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> HttpResult:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            truncated = len(body) > max_bytes
            if truncated:
                body = body[:max_bytes]
            return HttpResult(
                requested_url=url,
                final_url=response.geturl(),
                status=int(getattr(response, "status", 200)),
                headers={key.lower(): value for key, value in response.headers.items()},
                body=body,
                elapsed_ms=elapsed_ms,
                truncated=truncated,
            )
    except urllib.error.HTTPError as exc:
        with contextlib.suppress(Exception):
            body = exc.read(max_bytes + 1)
        if "body" not in locals():
            body = b""
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        return HttpResult(
            requested_url=url,
            final_url=getattr(exc, "url", url),
            status=int(exc.code),
            headers={key.lower(): value for key, value in exc.headers.items()},
            body=body[:max_bytes],
            elapsed_ms=elapsed_ms,
            error=f"HTTP {exc.code}",
            truncated=len(body) > max_bytes,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        reason = getattr(exc, "reason", exc)
        return HttpResult(
            requested_url=url,
            final_url=url,
            status=0,
            headers={},
            body=b"",
            elapsed_ms=elapsed_ms,
            error=sanitize_error(reason),
        )


def get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[Any, HttpResult]:
    result = fetch(
        url,
        headers={**(headers or {}), "Accept": "application/json"},
        timeout=timeout,
    )
    if not 200 <= result.status < 300:
        detail = result.error or f"HTTP {result.status}"
        with contextlib.suppress(Exception):
            payload = json.loads(result.body.decode("utf-8", errors="replace"))
            if isinstance(payload, dict) and payload.get("message"):
                detail = str(payload["message"])
        raise SourceError("HTTP_ERROR", sanitize_error(detail), result.status)
    if result.truncated:
        raise SourceError("RESPONSE_TOO_LARGE", f"Response exceeded {MAX_RESPONSE_BYTES} bytes")
    try:
        return json.loads(result.body.decode("utf-8")), result
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError("INVALID_JSON", sanitize_error(exc), result.status) from exc


def github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def selected_security_state(repo: dict[str, Any]) -> dict[str, str]:
    raw = repo.get("security_and_analysis")
    if not isinstance(raw, dict):
        return {}
    selected: dict[str, str] = {}
    for key in (
        "advanced_security",
        "secret_scanning",
        "secret_scanning_push_protection",
        "dependabot_security_updates",
    ):
        value = raw.get(key)
        if isinstance(value, dict) and isinstance(value.get("status"), str):
            selected[key] = value["status"]
    return selected


def github_commit_fact_from_payload(
    repository: str, revision: str, payload: Any
) -> dict[str, Any]:
    """Normalize one exact GitHub Git Commit API response without inference."""

    normalized_repository = str(repository or "").strip().lower()
    normalized_revision = str(revision or "").strip().lower()
    fact: dict[str, Any] = {
        "source_repository": normalized_repository,
        "source_revision": normalized_revision,
        "state": "UNAVAILABLE",
        "evidence_source": "GITHUB_GIT_COMMIT_API",
        "verification_reason": None,
        "verified_at": None,
    }
    if (
        not normalized_repository
        or re.fullmatch(r"[0-9a-f]{40}", normalized_revision) is None
        or not isinstance(payload, dict)
    ):
        return fact
    payload_revision = str(payload.get("sha") or "").strip().lower()
    verification = payload.get("verification")
    if payload_revision != normalized_revision or not isinstance(verification, dict):
        return fact
    fact["verification_reason"] = verification.get("reason")
    fact["verified_at"] = verification.get("verified_at")
    if verification.get("verified") is True:
        fact["state"] = "VERIFIED_REACHABLE"
    elif verification.get("verified") is False:
        fact["state"] = "REACHABLE_UNVERIFIED"
    return fact


def reconcile_github_inventory_scope(
    *,
    token_present: bool,
    public_repositories: Any,
    private_repositories: Any,
    observed_repositories: int,
    unique_repositories: int,
    observed_public_repositories: int,
    observed_private_repositories: int,
    invalid_visibility_repositories: int,
    pagination_complete: bool,
    inventory_stable: bool,
    error_count: int,
) -> tuple[str, dict[str, Any]]:
    """Return authenticated-complete only for an exact, error-free inventory."""

    public_count_valid = (
        isinstance(public_repositories, int)
        and not isinstance(public_repositories, bool)
        and public_repositories >= 0
    )
    private_count_valid = (
        isinstance(private_repositories, int)
        and not isinstance(private_repositories, bool)
        and private_repositories >= 0
    )
    observed_count_valid = (
        isinstance(observed_repositories, int)
        and not isinstance(observed_repositories, bool)
        and observed_repositories >= 0
    )
    unique_count_valid = (
        isinstance(unique_repositories, int)
        and not isinstance(unique_repositories, bool)
        and unique_repositories >= 0
    )
    observed_public_count_valid = (
        isinstance(observed_public_repositories, int)
        and not isinstance(observed_public_repositories, bool)
        and observed_public_repositories >= 0
    )
    observed_private_count_valid = (
        isinstance(observed_private_repositories, int)
        and not isinstance(observed_private_repositories, bool)
        and observed_private_repositories >= 0
    )
    invalid_visibility_count_valid = (
        isinstance(invalid_visibility_repositories, int)
        and not isinstance(invalid_visibility_repositories, bool)
        and invalid_visibility_repositories == 0
    )
    error_count_valid = (
        isinstance(error_count, int)
        and not isinstance(error_count, bool)
        and error_count == 0
    )
    expected_repositories = (
        public_repositories + private_repositories
        if public_count_valid and private_count_valid
        else None
    )
    observed_composition_total = (
        observed_public_repositories
        + observed_private_repositories
        + invalid_visibility_repositories
        if observed_public_count_valid
        and observed_private_count_valid
        and isinstance(invalid_visibility_repositories, int)
        and not isinstance(invalid_visibility_repositories, bool)
        and invalid_visibility_repositories >= 0
        else None
    )
    visibility_reconciled = bool(
        public_count_valid
        and private_count_valid
        and observed_public_count_valid
        and observed_private_count_valid
        and invalid_visibility_count_valid
        and observed_public_repositories == public_repositories
        and observed_private_repositories == private_repositories
        and observed_composition_total == observed_repositories
    )
    reconciled = bool(
        token_present is True
        and pagination_complete is True
        and inventory_stable is True
        and error_count_valid
        and expected_repositories is not None
        and observed_count_valid
        and unique_count_valid
        and visibility_reconciled
        and observed_repositories == expected_repositories
        and unique_repositories == expected_repositories
    )
    if not token_present:
        scope = "PUBLIC_ONLY"
        reason = "No authenticated GitHub token was supplied"
    elif reconciled:
        scope = GITHUB_COMPLETE_SCOPE
        reason = "Authenticated public and private repository totals exactly reconciled"
    else:
        scope = GITHUB_PARTIAL_SCOPE
        reason = "Authenticated repository completeness was not established"
    return scope, {
        "inventory_reconciled": reconciled,
        "inventory_reconciliation_reason": reason,
        "expected_repository_count": expected_repositories,
        "observed_repository_count": observed_repositories,
        "unique_repository_count": unique_repositories,
        "expected_public_repository_count": (
            public_repositories if public_count_valid else None
        ),
        "expected_private_repository_count": (
            private_repositories if private_count_valid else None
        ),
        "observed_public_repository_count": observed_public_repositories,
        "observed_private_repository_count": observed_private_repositories,
        "invalid_visibility_repository_count": invalid_visibility_repositories,
        "visibility_composition_reconciled": visibility_reconciled,
        "pagination_complete": pagination_complete,
        "inventory_stable": inventory_stable,
        "inventory_error_count": error_count,
    }


def normalize_default_branch_rules(rules: Any) -> dict[str, Any] | None:
    """Normalize bounded rule fields used by defensive control evaluation."""

    if not isinstance(rules, list):
        return None
    rule_types: set[str] = set()
    rule_sources: set[str] = set()
    required_status_checks: set[str] = set()
    pull_request = {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": False,
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_review_thread_resolution": False,
    }
    pull_request_observed = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or not rule_type:
            continue
        rule_types.add(rule_type)
        source_type = rule.get("ruleset_source_type")
        source = rule.get("ruleset_source")
        ruleset_id = rule.get("ruleset_id")
        if isinstance(source_type, str) and isinstance(source, str):
            rule_sources.add(f"{source_type}:{source}:{ruleset_id}")
        parameters = rule.get("parameters")
        parameters = parameters if isinstance(parameters, dict) else {}
        if rule_type == "pull_request":
            pull_request_observed = True
            approvals = parameters.get("required_approving_review_count")
            if isinstance(approvals, int) and not isinstance(approvals, bool):
                pull_request["required_approving_review_count"] = max(
                    pull_request["required_approving_review_count"], approvals
                )
            for key in (
                "dismiss_stale_reviews_on_push",
                "require_code_owner_review",
                "require_last_push_approval",
                "required_review_thread_resolution",
            ):
                if parameters.get(key) is True:
                    pull_request[key] = True
        elif rule_type == "required_status_checks":
            checks = parameters.get("required_status_checks")
            if isinstance(checks, list):
                for check in checks:
                    context = (
                        check.get("context") if isinstance(check, dict) else check
                    )
                    if isinstance(context, str) and context:
                        required_status_checks.add(context)
    return {
        "types": sorted(rule_types),
        "sources": sorted(rule_sources),
        "pull_request": pull_request if pull_request_observed else None,
        "required_status_checks": sorted(required_status_checks),
    }


def collect_github(config: AuditConfig) -> tuple[list[Asset], SourceReport]:
    started = time.perf_counter()
    observed = utc_now()
    token = env_token("GH_TOKEN", "GITHUB_TOKEN")
    scope = GITHUB_PARTIAL_SCOPE if token else "PUBLIC_ONLY"
    headers = github_headers(token)
    assets: list[Asset] = []
    errors: list[str] = []
    warnings: list[str] = []
    metadata: dict[str, Any] = {"org": config.github_org, "deep_requested": config.deep}
    organization_metadata: dict[str, Any] = {}
    encoded_org = urllib.parse.quote(config.github_org, safe="")

    def repository_snapshot_row(repo: Any) -> tuple[str, str, str, str] | None:
        if not isinstance(repo, dict):
            return None
        full_name = str(repo.get("full_name") or repo.get("name") or "").strip()
        if not full_name:
            return None
        private = repo.get("private")
        if private is True:
            visibility = "PRIVATE"
        elif private is False:
            visibility = "PUBLIC"
        else:
            visibility = "INVALID"
        asset_id = f"github:repo:{full_name.lower()}"
        owner = repo.get("owner")
        owner_identity = (
            {
                "id": owner.get("id"),
                "login": owner.get("login"),
                "node_id": owner.get("node_id"),
            }
            if isinstance(owner, dict)
            else None
        )
        governance = {
            key: repo.get(key)
            for key in (
                "allow_auto_merge",
                "allow_forking",
                "allow_merge_commit",
                "allow_rebase_merge",
                "allow_squash_merge",
                "allow_update_branch",
                "delete_branch_on_merge",
                "squash_merge_commit_message",
                "squash_merge_commit_title",
                "use_squash_pr_title_as_default",
                "web_commit_signoff_required",
            )
        }
        fingerprint_payload = {
            "archived": repo.get("archived"),
            "asset_id": asset_id,
            "default_branch": repo.get("default_branch"),
            "disabled": repo.get("disabled"),
            "fork": repo.get("fork"),
            "full_name": full_name,
            "governance": governance,
            "id": repo.get("id"),
            "is_template": repo.get("is_template"),
            "name": repo.get("name"),
            "node_id": repo.get("node_id"),
            "owner": owner_identity,
            "private": private,
            "security_and_analysis": repo.get("security_and_analysis"),
            "visibility": repo.get("visibility"),
            "visibility_class": visibility,
        }
        fingerprint = sha256_text(canonical_json(fingerprint_payload))
        return full_name, asset_id, visibility, fingerprint

    try:
        org, org_result = get_json(
            f"https://api.github.com/orgs/{encoded_org}",
            headers=headers,
            timeout=config.timeout,
        )
        metadata["rate_limit_remaining"] = org_result.headers.get("x-ratelimit-remaining")
        metadata["rate_limit_limit"] = org_result.headers.get("x-ratelimit-limit")
        if isinstance(org, dict):
            organization_metadata = {
                key: org.get(key)
                for key in (
                    "login",
                    "name",
                    "description",
                    "is_verified",
                    "public_repos",
                    "total_private_repos",
                    "owned_private_repos",
                    "two_factor_requirement_enabled",
                    "default_repository_permission",
                    "web_commit_signoff_required",
                    "updated_at",
                )
                if key in org
            }
            assets.append(
                Asset(
                    asset_id=f"github:organization:{config.github_org.lower()}",
                    asset_type="organization",
                    source="github",
                    name=config.github_org,
                    url=org.get("html_url"),
                    status_label="OBSERVED",
                    operational_status="AVAILABLE",
                    observed_at=observed,
                    metadata=organization_metadata,
                )
            )
    except SourceError as exc:
        errors.append(f"organization: {exc.code}: {sanitize_error(exc)}")

    repo_type = "all" if token else "public"
    repository_assets: list[Asset] = []
    inventory_snapshot: list[tuple[str, str]] = []
    pagination_complete = False
    for page in range(1, config.max_pages + 1):
        query = urllib.parse.urlencode(
            {
                "type": repo_type,
                "sort": "full_name",
                "direction": "asc",
                "per_page": 100,
                "page": page,
            }
        )
        try:
            page_data, page_result = get_json(
                f"https://api.github.com/orgs/{encoded_org}/repos?{query}",
                headers=headers,
                timeout=config.timeout,
            )
        except SourceError as exc:
            errors.append(f"repositories page {page}: {exc.code}: {sanitize_error(exc)}")
            break
        metadata["rate_limit_remaining"] = page_result.headers.get("x-ratelimit-remaining")
        if not isinstance(page_data, list):
            errors.append(f"repositories page {page}: INVALID_SHAPE")
            break
        for item_index, repo in enumerate(page_data):
            snapshot_row = repository_snapshot_row(repo)
            if snapshot_row is None:
                errors.append(
                    f"repositories page {page} item {item_index}: INVALID_REPOSITORY_SHAPE"
                )
                continue
            full_name, asset_id, visibility, fingerprint = snapshot_row
            inventory_snapshot.append((asset_id, fingerprint))
            assert isinstance(repo, dict)
            security_state = selected_security_state(repo)
            repo_metadata = {
                "visibility": repo.get("visibility"),
                "private": repo.get("private"),
                "archived": repo.get("archived"),
                "disabled": repo.get("disabled"),
                "fork": repo.get("fork"),
                "default_branch": repo.get("default_branch"),
                "description": repo.get("description"),
                "homepage": repo.get("homepage"),
                "license": (repo.get("license") or {}).get("spdx_id")
                if isinstance(repo.get("license"), dict)
                else None,
                "language": repo.get("language"),
                "topics": repo.get("topics") if isinstance(repo.get("topics"), list) else [],
                "has_pages": repo.get("has_pages"),
                "open_issues_count": repo.get("open_issues_count"),
                "stargazers_count": repo.get("stargazers_count"),
                "forks_count": repo.get("forks_count"),
                "pushed_at": repo.get("pushed_at"),
                "updated_at": repo.get("updated_at"),
                "created_at": repo.get("created_at"),
                "web_commit_signoff_required": repo.get("web_commit_signoff_required"),
                "security_and_analysis": security_state,
                "branch_protection_enabled": None,
                "default_branch_commit_fact": None,
                "default_branch_rules": {
                    "status": "NOT_REQUESTED",
                    "types": [],
                    "sources": [],
                    "pull_request": None,
                    "required_status_checks": [],
                },
                "deep_status": "NOT_REQUESTED",
            }
            archived = bool(repo.get("archived"))
            disabled = bool(repo.get("disabled"))
            repository_assets.append(
                Asset(
                    asset_id=asset_id,
                    asset_type="repo",
                    source="github",
                    name=full_name,
                    url=repo.get("html_url"),
                    status_label="ARCHIVED" if archived else "OBSERVED",
                    operational_status=(
                        "DISABLED" if disabled else "ARCHIVED" if archived else "ACTIVE"
                    ),
                    observed_at=observed,
                    metadata=repo_metadata,
                )
            )
        if len(page_data) < 100:
            pagination_complete = True
            break
    else:
        warnings.append(f"Repository inventory stopped at max_pages={config.max_pages}")

    inventory_stable = False
    verification_pagination_complete = False
    if token and pagination_complete:
        verification_snapshot: list[tuple[str, str]] = []
        for page in range(1, config.max_pages + 1):
            query = urllib.parse.urlencode(
                {
                    "type": "all",
                    "sort": "full_name",
                    "direction": "asc",
                    "per_page": 100,
                    "page": page,
                }
            )
            try:
                page_data, page_result = get_json(
                    f"https://api.github.com/orgs/{encoded_org}/repos?{query}",
                    headers=headers,
                    timeout=config.timeout,
                )
            except SourceError as exc:
                errors.append(
                    f"repository verification page {page}: {exc.code}: {sanitize_error(exc)}"
                )
                break
            metadata["rate_limit_remaining"] = page_result.headers.get(
                "x-ratelimit-remaining"
            )
            if not isinstance(page_data, list):
                errors.append(f"repository verification page {page}: INVALID_SHAPE")
                break
            for item_index, repo in enumerate(page_data):
                snapshot_row = repository_snapshot_row(repo)
                if snapshot_row is None:
                    errors.append(
                        "repository verification page "
                        f"{page} item {item_index}: INVALID_REPOSITORY_SHAPE"
                    )
                    continue
                _, asset_id, _, fingerprint = snapshot_row
                verification_snapshot.append((asset_id, fingerprint))
            if len(page_data) < 100:
                verification_pagination_complete = True
                break
        else:
            warnings.append(
                "Repository verification inventory stopped at "
                f"max_pages={config.max_pages}"
            )
        inventory_stable = bool(
            verification_pagination_complete
            and sorted(verification_snapshot) == sorted(inventory_snapshot)
        )
        if verification_pagination_complete and not inventory_stable:
            warnings.append(
                "Authenticated repository inventory changed between verification snapshots"
            )

    if config.deep and repository_assets:
        if not token:
            warnings.append(
                "Deep GitHub checks skipped because no GH_TOKEN or GITHUB_TOKEN is present"
            )
            for asset in repository_assets:
                asset.metadata["deep_status"] = "UNAVAILABLE_NO_TOKEN"
        else:
            def enrich(asset: Asset) -> Asset:
                full_name = urllib.parse.quote(asset.name, safe="/")
                branch = asset.metadata.get("default_branch")
                asset.metadata["deep_status"] = "PARTIAL"
                if not branch:
                    asset.metadata["deep_error"] = "DEFAULT_BRANCH_UNAVAILABLE"
                    return asset
                encoded_branch = urllib.parse.quote(str(branch), safe="")
                deep_errors: list[str] = []
                branch_measured = False
                commit_verification_measured = False
                rules_measured = False
                profile_measured = False
                branch_revision = ""
                try:
                    branch_data, _ = get_json(
                        f"https://api.github.com/repos/{full_name}/branches/{encoded_branch}",
                        headers=headers,
                        timeout=config.timeout,
                    )
                    if isinstance(branch_data, dict):
                        asset.metadata["branch_protection_enabled"] = bool(
                            branch_data.get("protected")
                        )
                        branch_commit = branch_data.get("commit")
                        branch_revision = str(
                            branch_commit.get("sha")
                            if isinstance(branch_commit, dict)
                            else ""
                        ).strip().lower()
                        asset.metadata["default_branch_sha"] = branch_revision or None
                        branch_measured = True
                    else:
                        deep_errors.append("branch: INVALID_SHAPE")
                except SourceError as exc:
                    deep_errors.append(
                        f"branch: {exc.code}: {sanitize_error(exc)}"
                    )
                if re.fullmatch(r"[0-9a-f]{40}", branch_revision):
                    try:
                        commit_data, _ = get_json(
                            (
                                f"https://api.github.com/repos/{full_name}/git/commits/"
                                f"{branch_revision}"
                            ),
                            headers=headers,
                            timeout=config.timeout,
                        )
                        commit_fact = github_commit_fact_from_payload(
                            asset.name, branch_revision, commit_data
                        )
                        asset.metadata["default_branch_commit_fact"] = commit_fact
                        if commit_fact["state"] in {
                            "VERIFIED_REACHABLE",
                            "REACHABLE_UNVERIFIED",
                        }:
                            commit_verification_measured = True
                        else:
                            deep_errors.append("commit_verification: INVALID_SHAPE")
                    except SourceError as exc:
                        asset.metadata["default_branch_commit_fact"] = (
                            github_commit_fact_from_payload(
                                asset.name, branch_revision, None
                            )
                        )
                        deep_errors.append(
                            "commit_verification: "
                            f"{exc.code}: {sanitize_error(exc)}"
                        )
                else:
                    deep_errors.append(
                        "commit_verification: DEFAULT_BRANCH_SHA_INVALID"
                    )
                try:
                    rules_data, _ = get_json(
                        f"https://api.github.com/repos/{full_name}/rules/branches/{encoded_branch}",
                        headers=headers,
                        timeout=config.timeout,
                    )
                    normalized_rules = normalize_default_branch_rules(rules_data)
                    if normalized_rules is None:
                        deep_errors.append("rules: INVALID_SHAPE")
                        asset.metadata["default_branch_rules"] = {
                            "status": "UNAVAILABLE",
                            "types": [],
                            "sources": [],
                            "pull_request": None,
                            "required_status_checks": [],
                        }
                    else:
                        asset.metadata["default_branch_rules"] = {
                            "status": "MEASURED",
                            **normalized_rules,
                        }
                        rules_measured = True
                except SourceError as exc:
                    deep_errors.append(
                        f"rules: {exc.code}: {sanitize_error(exc)}"
                    )
                    asset.metadata["default_branch_rules"] = {
                        "status": "UNAVAILABLE",
                        "types": [],
                        "sources": [],
                        "pull_request": None,
                        "required_status_checks": [],
                    }
                try:
                    profile_data, _ = get_json(
                        f"https://api.github.com/repos/{full_name}/community/profile",
                        headers=headers,
                        timeout=config.timeout,
                    )
                    if isinstance(profile_data, dict):
                        files = profile_data.get("files")
                        asset.metadata["community_health_percentage"] = profile_data.get(
                            "health_percentage"
                        )
                        if isinstance(files, dict):
                            asset.metadata["community_files"] = {
                                key: bool(files.get(key))
                                for key in (
                                    "readme",
                                    "license",
                                    "contributing",
                                    "code_of_conduct",
                                    "security",
                                    "issue_template",
                                    "pull_request_template",
                                )
                            }
                        profile_measured = True
                    else:
                        deep_errors.append("community: INVALID_SHAPE")
                except SourceError as exc:
                    deep_errors.append(
                        f"community: {exc.code}: {sanitize_error(exc)}"
                    )
                asset.metadata["deep_status"] = (
                    "MEASURED"
                    if (
                        branch_measured
                        and commit_verification_measured
                        and rules_measured
                        and profile_measured
                    )
                    else "PARTIAL"
                )
                if deep_errors:
                    asset.metadata["deep_errors"] = deep_errors
                    asset.metadata["deep_error"] = "; ".join(deep_errors)
                return asset

            with ThreadPoolExecutor(max_workers=config.workers) as executor:
                futures = [executor.submit(enrich, asset) for asset in repository_assets]
                repository_assets = [future.result() for future in as_completed(futures)]
            repository_assets.sort(key=lambda item: item.asset_id)

    assets.extend(repository_assets)
    unique_repository_count = len({asset.asset_id for asset in repository_assets})
    observed_public_repository_count = sum(
        asset.metadata.get("private") is False for asset in repository_assets
    )
    observed_private_repository_count = sum(
        asset.metadata.get("private") is True for asset in repository_assets
    )
    invalid_visibility_repository_count = sum(
        not isinstance(asset.metadata.get("private"), bool)
        for asset in repository_assets
    )
    scope, reconciliation = reconcile_github_inventory_scope(
        token_present=bool(token),
        public_repositories=organization_metadata.get("public_repos"),
        private_repositories=organization_metadata.get("total_private_repos"),
        observed_repositories=len(repository_assets),
        unique_repositories=unique_repository_count,
        observed_public_repositories=observed_public_repository_count,
        observed_private_repositories=observed_private_repository_count,
        invalid_visibility_repositories=invalid_visibility_repository_count,
        pagination_complete=pagination_complete,
        inventory_stable=inventory_stable,
        error_count=len(errors),
    )
    reconciliation["verification_pagination_complete"] = (
        verification_pagination_complete
    )
    metadata.update(reconciliation)
    metadata["active_repository_count"] = sum(
        asset.operational_status == "ACTIVE" for asset in repository_assets
    )
    metadata["archived_repository_count"] = sum(
        asset.metadata.get("archived") is True for asset in repository_assets
    )
    metadata["disabled_repository_count"] = sum(
        asset.metadata.get("disabled") is True for asset in repository_assets
    )
    if not token:
        warnings.append("Private repositories and privileged organization controls are UNAVAILABLE")
    elif scope != GITHUB_COMPLETE_SCOPE:
        warnings.append(reconciliation["inventory_reconciliation_reason"])
    status = "MEASURED"
    if errors and assets:
        status = "PARTIAL"
    elif errors and not assets:
        status = "UNAVAILABLE"
    elif token and scope != GITHUB_COMPLETE_SCOPE:
        status = "PARTIAL"
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return assets, SourceReport(
        source="github",
        status=status,
        scope=scope,
        count=len(assets),
        observed_at=observed,
        elapsed_ms=elapsed_ms,
        errors=errors,
        warnings=warnings,
        metadata=metadata,
    )


def hf_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def hf_asset_identity(kind: str, item: dict[str, Any]) -> str | None:
    for key in ("id", "modelId", "repo_id", "slug"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def hf_truth_label(kind: str, item: dict[str, Any]) -> tuple[str, str]:
    if bool(item.get("private")):
        publication = "PRIVATE"
    else:
        publication = "PUBLISHED"
    if kind != "space":
        return "OBSERVED", publication
    runtime = item.get("runtime")
    stage = None
    if isinstance(runtime, dict):
        stage = runtime.get("stage")
    stage = stage or item.get("runtimeStage") or item.get("stage")
    normalized = str(stage or "").upper()
    if normalized in {"RUNNING", "RUNNING_BUILDING"}:
        return "LIVE", normalized
    if normalized in {"BUILD_ERROR", "RUNTIME_ERROR", "CONFIG_ERROR"}:
        return "BROKEN", normalized
    if normalized in {"PAUSED", "STOPPED", "SLEEPING"}:
        return "UNAVAILABLE", normalized
    return "OBSERVED", publication


HF_PROVENANCE_FILES = (
    "hf-deploy-manifest.json",
    "SPACE_PROVENANCE.json",
    "DATASET_PROVENANCE.json",
    "SZL_ESTATE_MANAGED.json",
    "a11oy-metadata.json",
    "publication.json",
    "publication-manifest.json",
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_SOURCE_RE = re.compile(
    r"https?://github\.com/(szl-holdings/[A-Za-z0-9_.-]+)(?:/|\b)",
    re.IGNORECASE,
)
EMBEDDED_SHA_RE = re.compile(
    r"(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])",
    re.IGNORECASE,
)


def normalize_github_repository(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    match = GITHUB_SOURCE_RE.search(candidate)
    if match:
        return match.group(1).lower()
    candidate = candidate.removeprefix("github.com/").strip("/").lower()
    if re.fullmatch(r"szl-holdings/[a-z0-9_.-]+", candidate):
        return candidate
    return None


def provenance_source(
    payload: Any,
    filename: str | None = None,
) -> tuple[str | None, str | None]:
    if not isinstance(payload, dict):
        return None, None
    repository = payload.get("source_repository")
    revision = payload.get("source_revision")
    source = payload.get("source")
    if isinstance(source, dict):
        repository = repository or source.get("repository")
        revision = (
            revision
            or source.get("commit")
            or source.get("mergedCommit")
            or source.get("revision")
        )
    if filename == "a11oy-metadata.json":
        repository = repository or payload.get("sourceRepository")
        revision = revision or payload.get("sourceCommit")
    if filename == "publication-manifest.json":
        managed_by = payload.get("managed_by")
        if not repository and isinstance(managed_by, str):
            repository = managed_by.split(":", 1)[0]
        revision = revision or payload.get("source_revision")
    normalized_repository = normalize_github_repository(repository)
    normalized_revision = (
        str(revision).strip().lower() if isinstance(revision, str) else None
    )
    return normalized_repository or None, normalized_revision or None


def strict_readme_source_binding(text: str) -> tuple[str, str] | None:
    repositories = {match.lower() for match in GITHUB_SOURCE_RE.findall(text)}
    revisions = {match.lower() for match in EMBEDDED_SHA_RE.findall(text)}
    if len(repositories) == 1 and len(revisions) == 1:
        return next(iter(repositories)), next(iter(revisions))
    return None


def collect_hf_asset_details(
    kind: str,
    endpoint: str,
    items: list[Any],
    *,
    headers: dict[str, str],
    timeout: float,
    workers: int,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    identities = sorted(
        {
            identity
            for item in items
            if isinstance(item, dict)
            if (identity := hf_asset_identity("space", item))
        }
    )
    details: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    def fetch_detail(identity: str) -> tuple[str, dict[str, Any]]:
        encoded_identity = urllib.parse.quote(identity, safe="/")
        payload, _ = get_json(
            f"https://huggingface.co/api/{endpoint}/{encoded_identity}",
            headers=headers,
            timeout=timeout,
        )
        if not isinstance(payload, dict):
            raise SourceError("INVALID_SHAPE", f"{kind} detail response was not an object")
        revision = str(payload.get("sha") or "").strip().lower()
        siblings = payload.get("siblings")
        paths = {
            str(item.get("rfilename") or "")
            for item in siblings
            if isinstance(item, dict)
        } if isinstance(siblings, list) else set()
        provenance_docs: list[dict[str, Any]] = []
        prefix = {"model": "", "dataset": "datasets/", "space": "spaces/"}[kind]
        if FULL_SHA_RE.fullmatch(revision):
            for filename in HF_PROVENANCE_FILES:
                if filename not in paths:
                    continue
                encoded_filename = urllib.parse.quote(filename, safe="/")
                try:
                    document, _ = get_json(
                        (
                            f"https://huggingface.co/{prefix}{encoded_identity}/resolve/"
                            f"{revision}/{encoded_filename}"
                        ),
                        headers=headers,
                        timeout=timeout,
                    )
                    repository, source_revision = provenance_source(document, filename)
                    provenance_docs.append(
                        {
                            "file": filename,
                            "schema": document.get("schema")
                            if isinstance(document, dict)
                            else None,
                            "source_repository": repository,
                            "source_revision": source_revision,
                            "binding_kind": (
                                "MANAGEMENT_ONLY"
                                if filename == "SZL_ESTATE_MANAGED.json"
                                else "ARTIFACT_SOURCE"
                            ),
                            "status": "OBSERVED",
                        }
                    )
                except SourceError as exc:
                    provenance_docs.append(
                        {
                            "file": filename,
                            "binding_kind": (
                                "MANAGEMENT_ONLY"
                                if filename == "SZL_ESTATE_MANAGED.json"
                                else "ARTIFACT_SOURCE"
                            ),
                            "status": "UNAVAILABLE",
                            "error": f"{exc.code}: {sanitize_error(exc)}",
                        }
                    )
            if not provenance_docs and "README.md" in paths:
                readme_url = (
                    f"https://huggingface.co/{prefix}{encoded_identity}/resolve/"
                    f"{revision}/README.md"
                )
                readme_result = fetch(
                    readme_url,
                    headers=headers,
                    timeout=timeout,
                    max_bytes=512_000,
                )
                if 200 <= readme_result.status < 300 and not readme_result.truncated:
                    readme_text = readme_result.body.decode("utf-8", errors="replace")
                    readme_binding = strict_readme_source_binding(readme_text)
                    if readme_binding is not None:
                        repository, source_revision = readme_binding
                        provenance_docs.append(
                            {
                                "file": "README.md",
                                "schema": "szl.strict-readme-source/v1",
                                "source_repository": repository,
                                "source_revision": source_revision,
                                "binding_kind": "ARTIFACT_SOURCE",
                                "status": "OBSERVED",
                            }
                        )
        runtime_source: dict[str, Any] | None = None
        runtime_build: dict[str, Any] | None = None
        runtime = payload.get("runtime")
        if kind == "space" and isinstance(runtime, dict):
            domains = runtime.get("domains")
            ready_domains = [
                str(item.get("domain") or "").lower()
                for item in domains
                if isinstance(item, dict)
                and str(item.get("stage") or "").upper() == "READY"
                and re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.hf\.space",
                    str(item.get("domain") or "").lower(),
                )
            ] if isinstance(domains, list) else []
            for domain in ready_domains:
                if runtime_source is None:
                    try:
                        source_payload, _ = get_json(
                            f"https://{domain}/.well-known/szl-source.json",
                            headers={
                                "Accept": "application/json",
                                "Cache-Control": "no-cache, no-store, max-age=0",
                                "Pragma": "no-cache",
                            },
                            timeout=timeout,
                        )
                        source_repository, source_revision = provenance_source(
                            source_payload
                        )
                        if source_repository or source_revision:
                            source_claims = source_payload.get("claims")
                            source_claims = (
                                source_claims
                                if isinstance(source_claims, dict)
                                else {}
                            )
                            source = source_payload.get("source")
                            source = source if isinstance(source, dict) else {}
                            runtime_source = {
                                "status": "OBSERVED",
                                "domain": domain,
                                "source_repository": source_repository,
                                "source_revision": source_revision,
                                "relation": source.get("relation"),
                                "alignment_state": source_payload.get(
                                    "alignment_state"
                                ),
                                "github_parity": source_claims.get("github_parity"),
                                "reproducible_build": source_claims.get(
                                    "reproducible_build"
                                ),
                            }
                    except SourceError:
                        pass
                try:
                    build_payload, _ = get_json(
                        (
                            f"https://{domain}/api/build-info?"
                            f"cache_bust={time.time_ns()}"
                        ),
                        headers={
                            "Accept": "application/json",
                            "Cache-Control": "no-cache, no-store, max-age=0",
                            "Pragma": "no-cache",
                        },
                        timeout=timeout,
                    )
                    build = (
                        build_payload.get("build")
                        if isinstance(build_payload, dict)
                        else None
                    )
                    if isinstance(build, dict):
                        runtime_build = {
                            "status": "OBSERVED",
                            "domain": domain,
                            "revision": str(build.get("revision") or "").lower(),
                            "state": str(build.get("state") or "").upper(),
                            "receipt_minted": build_payload.get("receipt_minted"),
                        }
                        break
                except SourceError:
                    continue
        payload["_provenance_docs"] = provenance_docs
        payload["_file_count"] = len(paths)
        payload["_runtime_build"] = runtime_build
        payload["_runtime_source"] = runtime_source
        return identity, payload

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as executor:
        futures = {
            executor.submit(fetch_detail, identity): identity for identity in identities
        }
        for future in as_completed(futures):
            identity = futures[future]
            try:
                detail_identity, payload = future.result()
                details[detail_identity] = payload
            except SourceError as exc:
                warnings.append(
                    f"{kind} detail {identity}: {exc.code}: {sanitize_error(exc)}"
                )
            except Exception as exc:
                warnings.append(
                    f"{kind} detail {identity}: UNEXPECTED: {sanitize_error(exc)}"
                )
    return details, warnings


def collect_huggingface(config: AuditConfig) -> tuple[list[Asset], SourceReport]:
    started = time.perf_counter()
    observed = utc_now()
    token = env_token("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")
    scope = "AUTHENTICATED_VISIBILITY_UNKNOWN" if token else "PUBLIC_ONLY"
    headers = hf_headers(token)
    assets: list[Asset] = []
    errors: list[str] = []
    warnings: list[str] = []
    explicit_spaces = normalize_hf_spaces(config.hf_spaces)
    metadata: dict[str, Any] = {
        "org": config.hf_org,
        "explicit_spaces": list(explicit_spaces),
    }
    kinds = (("model", "models"), ("dataset", "datasets"), ("space", "spaces"))
    for kind, endpoint in kinds:
        query = urllib.parse.urlencode(
            {"author": config.hf_org, "limit": 1000, "full": "true"}
        )
        try:
            page_data, _ = get_json(
                f"https://huggingface.co/api/{endpoint}?{query}",
                headers=headers,
                timeout=config.timeout,
            )
        except SourceError as exc:
            errors.append(f"{endpoint}: {exc.code}: {sanitize_error(exc)}")
            continue
        if not isinstance(page_data, list):
            errors.append(f"{endpoint}: INVALID_SHAPE")
            continue
        if kind == "space":
            observed_identities = {
                identity.lower()
                for item in page_data
                if isinstance(item, dict)
                if (identity := hf_asset_identity("space", item))
            }
            for identity in explicit_spaces:
                if identity.lower() in observed_identities:
                    continue
                encoded_identity = urllib.parse.quote(identity, safe="/")
                try:
                    explicit_item, _ = get_json(
                        f"https://huggingface.co/api/spaces/{encoded_identity}",
                        headers=headers,
                        timeout=config.timeout,
                    )
                except SourceError as exc:
                    errors.append(
                        f"spaces/{identity}: {exc.code}: {sanitize_error(exc)}"
                    )
                    continue
                explicit_identity = (
                    hf_asset_identity("space", explicit_item)
                    if isinstance(explicit_item, dict)
                    else None
                )
                if (
                    explicit_identity is None
                    or explicit_identity.lower() != identity.lower()
                ):
                    errors.append(f"spaces/{identity}: IDENTITY_MISMATCH")
                    continue
                page_data.append(explicit_item)
                observed_identities.add(identity.lower())
        if len(page_data) >= 1000:
            warnings.append(f"{endpoint} may be truncated at 1000 items")
        details_by_identity: dict[str, dict[str, Any]] = {}
        if config.deep:
            details_by_identity, detail_warnings = collect_hf_asset_details(
                kind,
                endpoint,
                page_data,
                headers=headers,
                timeout=config.timeout,
                workers=config.workers,
            )
            warnings.extend(detail_warnings)
            metadata[f"{kind}_detail_count"] = len(details_by_identity)
        for item in page_data:
            if not isinstance(item, dict):
                continue
            identity = hf_asset_identity(kind, item)
            if not identity:
                continue
            detail = details_by_identity.get(identity, {})
            truth_item = dict(item)
            if detail:
                truth_item.update(
                    {
                        key: detail[key]
                        for key in ("runtime", "sha", "cardData", "siblings")
                        if key in detail
                    }
                )
            status_label, operational_status = hf_truth_label(kind, truth_item)
            url_prefix = {
                "model": "",
                "dataset": "datasets/",
                "space": "spaces/",
            }[kind]
            card_data = truth_item.get("cardData")
            runtime = truth_item.get("runtime")
            asset_metadata = {
                "private": item.get("private"),
                "author": item.get("author"),
                "last_modified": item.get("lastModified") or item.get("last_modified"),
                "created_at": item.get("createdAt") or item.get("created_at"),
                "downloads": item.get("downloads"),
                "likes": item.get("likes"),
                "tags": item.get("tags") if isinstance(item.get("tags"), list) else [],
                "pipeline_tag": item.get("pipeline_tag"),
                "library_name": item.get("library_name"),
                "sdk": item.get("sdk"),
                "card_present": isinstance(card_data, dict) and bool(card_data),
                "card_data": card_data if isinstance(card_data, dict) else {},
                "runtime": runtime if isinstance(runtime, dict) else {},
                "revision": truth_item.get("sha"),
                "file_count": detail.get("_file_count") if detail else None,
                "provenance_docs": detail.get("_provenance_docs", [])
                if detail
                else [],
                "runtime_build": detail.get("_runtime_build") if detail else None,
                "runtime_source": detail.get("_runtime_source") if detail else None,
            }
            assets.append(
                Asset(
                    asset_id=f"huggingface:{kind}:{identity.lower()}",
                    asset_type=kind,
                    source="huggingface",
                    name=identity,
                    url=f"https://huggingface.co/{url_prefix}{identity}",
                    status_label=status_label,
                    operational_status=operational_status,
                    observed_at=observed,
                    metadata=asset_metadata,
                )
            )

    collection_query = urllib.parse.urlencode({"owner": config.hf_org, "limit": 100})
    try:
        collection_data, _ = get_json(
            f"https://huggingface.co/api/collections?{collection_query}",
            headers=headers,
            timeout=config.timeout,
        )
        if isinstance(collection_data, dict):
            collection_items = (
                collection_data.get("items")
                or collection_data.get("collections")
                or []
            )
        else:
            collection_items = collection_data
        if not isinstance(collection_items, list):
            raise SourceError("INVALID_SHAPE", "Collections response was not a list")
        for item in collection_items:
            if not isinstance(item, dict):
                continue
            identity = hf_asset_identity("collection", item)
            if not identity:
                continue
            assets.append(
                Asset(
                    asset_id=f"huggingface:collection:{identity.lower()}",
                    asset_type="collection",
                    source="huggingface",
                    name=identity,
                    url=f"https://huggingface.co/collections/{identity}",
                    status_label="OBSERVED",
                    operational_status="PUBLISHED",
                    observed_at=observed,
                    metadata={
                        "private": item.get("private"),
                        "title": item.get("title"),
                        "description": item.get("description"),
                        "last_modified": item.get("lastUpdated")
                        or item.get("last_updated"),
                        "upvotes": item.get("upvotes"),
                        "item_count": len(item.get("items") or [])
                        if isinstance(item.get("items"), list)
                        else None,
                    },
                )
            )
    except SourceError as exc:
        warnings.append(f"collections: {exc.code}: {sanitize_error(exc)}")

    if not token:
        warnings.append("Private/protected Hugging Face assets are UNAVAILABLE")
    status = "MEASURED"
    if errors and assets:
        status = "PARTIAL"
    elif errors and not assets:
        status = "UNAVAILABLE"
    elif warnings and not assets:
        status = "PARTIAL"
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return assets, SourceReport(
        source="huggingface",
        status=status,
        scope=scope,
        count=len(assets),
        observed_at=observed,
        elapsed_ms=elapsed_ms,
        errors=errors,
        warnings=warnings,
        metadata=metadata,
    )


def normalize_domain(value: str) -> tuple[str, str]:
    candidate = value.strip()
    if not re.match(r"^https?://", candidate, flags=re.IGNORECASE):
        candidate = f"https://{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    if not parsed.hostname:
        raise ValueError(f"Invalid domain: {value}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Domain URLs must not include credentials")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported domain scheme: {scheme}")
    netloc = parsed.netloc
    return f"{scheme}://{netloc}", parsed.hostname.lower()


def decode_body(result: HttpResult) -> str:
    content_type = result.headers.get("content-type", "")
    charset_match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return result.body.decode(charset, errors="replace")
    except LookupError:
        return result.body.decode("utf-8", errors="replace")


def content_title(text: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()[:200] or None


def classify_content(result: HttpResult, text: str) -> tuple[str, str]:
    if result.status == 0:
        return "BROKEN", "UNREACHABLE"
    if result.status in {401, 403}:
        return "UNAVAILABLE", "RESTRICTED"
    if not 200 <= result.status < 400:
        return "BROKEN", f"HTTP_{result.status}"
    visible = re.sub(r"<[^>]+>", " ", text)
    visible = html.unescape(re.sub(r"\s+", " ", visible)).strip()
    title = (content_title(text) or "").lower()
    leading = visible[:800].lower()
    placeholder_in_title = any(marker in title for marker in PLACEHOLDER_MARKERS)
    thin_placeholder = len(visible) < 1_200 and any(
        marker in leading for marker in PLACEHOLDER_MARKERS
    )
    if placeholder_in_title or thin_placeholder:
        return "MODELED", "PLACEHOLDER"
    if len(visible) < 40:
        return "MODELED", "EMPTY_OR_THIN"
    return "LIVE", "REAL"


def discover_domain_routes(
    base_url: str,
    hostname: str,
    timeout: float,
) -> tuple[set[str], list[str]]:
    warnings: list[str] = []
    routes = set(DOMAIN_ROUTES.get(hostname, ("/",)))
    root_url = base_url.rstrip("/") + "/"
    result = fetch(
        root_url,
        headers={"Accept": "text/html,application/xhtml+xml"},
        timeout=timeout,
        max_bytes=750_000,
    )
    if not 200 <= result.status < 400:
        warnings.append(
            f"{hostname}: route discovery unavailable (HTTP {result.status})"
        )
        return routes, warnings
    text = decode_body(result)
    candidates = re.findall(
        r"""href\s*=\s*["']([^"'#]+(?:#[^"']*)?)["']""",
        text,
        flags=re.IGNORECASE,
    )
    for candidate in candidates:
        absolute = urllib.parse.urljoin(root_url, html.unescape(candidate))
        parsed = urllib.parse.urlparse(absolute)
        if (parsed.hostname or "").lower() != hostname:
            continue
        path = parsed.path or "/"
        suffix = Path(path.rstrip("/")).suffix.lower()
        if suffix in NON_NAVIGATION_SUFFIXES:
            continue
        routes.add(path)
        if len(routes) >= MAX_DISCOVERED_ROUTES_PER_DOMAIN:
            warnings.append(
                f"{hostname}: discovered routes capped at "
                f"{MAX_DISCOVERED_ROUTES_PER_DOMAIN}"
            )
            break
    return routes, warnings


def probe_domain_route(
    base_url: str,
    hostname: str,
    route: str,
    timeout: float,
) -> Asset:
    observed = utc_now()
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
    if route == "/":
        url = base_url.rstrip("/") + "/"
    result = fetch(
        url,
        headers={"Accept": "text/html,application/xhtml+xml,application/json;q=0.8"},
        timeout=timeout,
        max_bytes=750_000,
    )
    text = decode_body(result)
    status_label, content_state = classify_content(result, text)
    security_header_values = {
        key: normalized
        for key in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        )
        if (normalized := normalize_http_header_value(result.headers.get(key)))
    }
    security_header_assessment = assess_web_security_headers(security_header_values)
    assert security_header_assessment is not None
    security_headers = {
        key: value["passed"] is True
        for key, value in security_header_assessment.items()
    }
    return Asset(
        asset_id=f"domain:route:{hostname}{route}".lower(),
        asset_type="route",
        source="domains",
        name=f"{hostname}{route}",
        url=url,
        status_label=status_label,
        operational_status=content_state,
        observed_at=observed,
        metadata={
            "domain": hostname,
            "route": route,
            "status_code": result.status,
            "latency_ms": result.elapsed_ms,
            "content_state": content_state,
            "final_url": result.final_url,
            "content_type": result.headers.get("content-type"),
            "content_length_observed": len(result.body),
            "content_sha256": sha256_bytes(result.body) if result.body else None,
            "title": content_title(text),
            "https": urllib.parse.urlparse(result.final_url).scheme.lower() == "https",
            "security_headers": security_headers,
            "security_header_values": security_header_values,
            "security_header_validation": security_header_assessment,
            "error": result.error,
            "truncated": result.truncated,
        },
    )


def collect_domains(config: AuditConfig) -> tuple[list[Asset], SourceReport]:
    started = time.perf_counter()
    observed = utc_now()
    assets: list[Asset] = []
    errors: list[str] = []
    warnings: list[str] = []
    tasks: list[tuple[str, str, str]] = []
    declared_route_count = 0
    discovered_route_count = 0
    for domain in config.domains:
        try:
            base_url, hostname = normalize_domain(domain)
        except ValueError as exc:
            errors.append(sanitize_error(exc))
            continue
        declared_routes = set(DOMAIN_ROUTES.get(hostname, ("/",)))
        declared_route_count += len(declared_routes)
        try:
            routes, discovery_warnings = discover_domain_routes(
                base_url, hostname, config.timeout
            )
            warnings.extend(discovery_warnings)
        except Exception as exc:
            routes = declared_routes
            warnings.append(
                f"{hostname}: route discovery failed: {sanitize_error(exc)}"
            )
        discovered_route_count += max(0, len(routes) - len(declared_routes))
        tasks.extend(
            (base_url, hostname, route)
            for route in sorted(routes, key=lambda value: (value != "/", value))
        )

    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = {
            executor.submit(probe_domain_route, base, hostname, route, config.timeout): (
                hostname,
                route,
            )
            for base, hostname, route in tasks
        }
        for future in as_completed(futures):
            hostname, route = futures[future]
            try:
                assets.append(future.result())
            except Exception as exc:
                errors.append(f"{hostname}{route}: {sanitize_error(exc)}")
    assets.sort(key=lambda item: item.asset_id)
    broken = sum(1 for asset in assets if asset.status_label == "BROKEN")
    modeled = sum(1 for asset in assets if asset.status_label == "MODELED")
    if broken:
        warnings.append(f"{broken} route probes are BROKEN")
    if modeled:
        warnings.append(f"{modeled} route probes are MODELED/placeholder")
    status = "MEASURED"
    if errors and assets:
        status = "PARTIAL"
    elif errors and not assets:
        status = "UNAVAILABLE"
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return assets, SourceReport(
        source="domains",
        status=status,
        scope="PUBLIC_NETWORK",
        count=len(assets),
        observed_at=observed,
        elapsed_ms=elapsed_ms,
        errors=errors,
        warnings=warnings,
        metadata={
            "domains": list(config.domains),
            "route_count": len(tasks),
            "declared_route_count": declared_route_count,
            "discovered_route_count": discovered_route_count,
            "broken_count": broken,
            "modeled_count": modeled,
        },
    )


def normalized_tokens(asset: Asset) -> set[str]:
    ownerless = asset.name.split("/", 1)[-1]
    tokens = set(re.findall(r"[a-z0-9]+", ownerless.lower()))
    stopwords = {
        "a",
        "an",
        "and",
        "api",
        "app",
        "com",
        "data",
        "dataset",
        "demo",
        "dev",
        "github",
        "hf",
        "holdings",
        "io",
        "model",
        "net",
        "of",
        "org",
        "repo",
        "service",
        "space",
        "szl",
        "the",
        "web",
    }
    return {token for token in tokens if token not in stopwords and len(token) > 1}


def duplicate_clusters(assets: list[Asset]) -> dict[str, str]:
    parent = {asset.asset_id: asset.asset_id for asset in assets}
    token_map = {asset.asset_id: normalized_tokens(asset) for asset in assets}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for index, left in enumerate(assets):
        left_tokens = token_map[left.asset_id]
        if not left_tokens:
            continue
        for right in assets[index + 1 :]:
            right_tokens = token_map[right.asset_id]
            if not right_tokens:
                continue
            intersection = left_tokens & right_tokens
            union_tokens = left_tokens | right_tokens
            similarity = len(intersection) / len(union_tokens)
            exact = left_tokens == right_tokens
            if exact or (len(intersection) >= 2 and similarity >= 0.72):
                union(left.asset_id, right.asset_id)

    groups: dict[str, list[str]] = {}
    for asset in assets:
        groups.setdefault(find(asset.asset_id), []).append(asset.asset_id)
    result: dict[str, str] = {}
    for members in groups.values():
        if len(members) < 2:
            continue
        digest = sha256_text("\n".join(sorted(members)))[:12]
        cluster_id = f"dup-{digest}"
        for member in members:
            result[member] = cluster_id
    return result


def staleness_score(days: float | None) -> float | None:
    if days is None:
        return None
    if days <= 90:
        return 0.05
    if days <= 180:
        return 0.2
    if days <= 365:
        return 0.45
    if days <= 730:
        return 0.75
    return 1.0


def enabled_state(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.lower()
        if normalized in {"enabled", "true", "active", "on"}:
            return True
        if normalized in {"disabled", "false", "inactive", "off"}:
            return False
    return None


def weighted_average(values: Iterable[tuple[float | None, float]]) -> float | None:
    available = [(value, weight) for value, weight in values if value is not None]
    if not available:
        return None
    numerator = sum(float(value) * weight for value, weight in available)
    denominator = sum(weight for _, weight in available)
    return clamp(numerator / denominator)


def score_asset(
    asset: Asset,
    cluster_size: int,
) -> ScoreCard:
    metadata = asset.metadata
    scores: dict[str, float | None] = {name: None for name in SCORE_NAMES}
    evidence: dict[str, str] = {name: "UNAVAILABLE" for name in SCORE_NAMES}
    rationale: list[str] = []

    updated_at = (
        metadata.get("pushed_at")
        or metadata.get("last_modified")
        or metadata.get("updated_at")
        or metadata.get("last_updated")
    )
    stale = staleness_score(age_days(updated_at))
    scores["staleness_penalty"] = stale
    evidence["staleness_penalty"] = "MEASURED" if stale is not None else "UNAVAILABLE"

    if asset.asset_type == "organization":
        operational = 1.0 if asset.operational_status == "AVAILABLE" else 0.0
    elif asset.asset_type == "repo":
        if metadata.get("disabled"):
            operational = 0.0
        elif metadata.get("archived"):
            operational = 0.15
        else:
            days = age_days(metadata.get("pushed_at"))
            if days is None:
                operational = 0.55
            elif days <= 90:
                operational = 0.95
            elif days <= 365:
                operational = 0.8
            elif days <= 730:
                operational = 0.6
            else:
                operational = 0.35
    elif asset.asset_type in {"model", "dataset", "collection"}:
        penalty = stale if stale is not None else 0.25
        operational = clamp(0.85 - (0.45 * penalty))
    elif asset.asset_type == "space":
        operational = {
            "LIVE": 1.0,
            "BROKEN": 0.0,
            "UNAVAILABLE": 0.15,
            "OBSERVED": 0.55,
        }.get(asset.status_label, 0.4)
    elif asset.asset_type == "route":
        operational = {
            "LIVE": 1.0,
            "MODELED": 0.35,
            "BROKEN": 0.0,
            "UNAVAILABLE": 0.15,
        }.get(asset.status_label, 0.25)
    else:
        operational = None
    scores["operational_reality_score"] = (
        clamp(operational) if operational is not None else None
    )
    evidence["operational_reality_score"] = (
        "MEASURED" if operational is not None else "UNAVAILABLE"
    )

    security: float | None = None
    if asset.asset_type == "repo":
        signals: list[bool] = []
        branch_protection = metadata.get("branch_protection_enabled")
        if isinstance(branch_protection, bool):
            signals.append(branch_protection)
        security_state = metadata.get("security_and_analysis")
        if isinstance(security_state, dict):
            for value in security_state.values():
                state = enabled_state(value)
                if state is not None:
                    signals.append(state)
        signoff = metadata.get("web_commit_signoff_required")
        if isinstance(signoff, bool):
            signals.append(signoff)
        if signals:
            security = sum(1.0 for signal in signals if signal) / len(signals)
    elif asset.asset_type == "organization":
        org_signals = [
            metadata.get("two_factor_requirement_enabled"),
            metadata.get("web_commit_signoff_required"),
        ]
        available = [value for value in org_signals if isinstance(value, bool)]
        if available:
            security = sum(1.0 for value in available if value) / len(available)
    elif asset.asset_type == "route":
        header_map = metadata.get("security_headers")
        header_values = (
            list(header_map.values()) if isinstance(header_map, dict) else []
        )
        measured = [value for value in header_values if isinstance(value, bool)]
        https_signal = 1.0 if metadata.get("https") else 0.0
        if measured:
            security = (https_signal * 0.35) + (
                sum(1.0 for value in measured if value) / len(measured) * 0.65
            )
    scores["security_score"] = clamp(security) if security is not None else None
    evidence["security_score"] = "MEASURED" if security is not None else "UNAVAILABLE"

    documentation: float | None = None
    if asset.asset_type == "repo":
        checks = [
            bool(metadata.get("description")),
            bool(metadata.get("license")),
            bool(metadata.get("homepage")),
            bool(metadata.get("topics")),
        ]
        community = metadata.get("community_files")
        if isinstance(community, dict):
            checks.extend(bool(value) for value in community.values())
        documentation = sum(1.0 for value in checks if value) / len(checks)
    elif asset.asset_type in {"model", "dataset", "space"}:
        checks = [
            bool(metadata.get("card_present")),
            bool(metadata.get("tags")),
        ]
        card_data = metadata.get("card_data")
        if isinstance(card_data, dict):
            checks.extend(
                [
                    bool(card_data.get("license")),
                    bool(card_data.get("datasets") or card_data.get("dataset")),
                ]
            )
        documentation = sum(1.0 for value in checks if value) / len(checks)
    elif asset.asset_type == "collection":
        checks = [bool(metadata.get("title")), bool(metadata.get("description"))]
        documentation = sum(1.0 for value in checks if value) / len(checks)
    elif asset.asset_type == "route":
        checks = [
            bool(metadata.get("title")),
            (metadata.get("content_length_observed") or 0) >= 500,
            metadata.get("content_state") == "REAL",
        ]
        documentation = sum(1.0 for value in checks if value) / len(checks)
    elif asset.asset_type == "organization":
        checks = [bool(metadata.get("name")), bool(metadata.get("description"))]
        documentation = sum(1.0 for value in checks if value) / len(checks)
    scores["documentation_score"] = (
        clamp(documentation) if documentation is not None else None
    )
    evidence["documentation_score"] = (
        "MEASURED" if documentation is not None else "UNAVAILABLE"
    )

    demo: float | None = None
    if asset.asset_type == "space":
        demo = scores["operational_reality_score"]
    elif asset.asset_type == "route":
        demo = 1.0 if asset.status_label == "LIVE" else operational
    elif asset.asset_type == "repo":
        if metadata.get("has_pages") or metadata.get("homepage"):
            demo = 0.75
        else:
            demo = 0.1
    scores["demo_score"] = clamp(demo) if demo is not None else None
    evidence["demo_score"] = "MEASURED" if demo is not None else "UNAVAILABLE"

    governance: float | None = None
    if asset.asset_type == "repo":
        gov_signals: list[bool] = []
        for value in (
            metadata.get("branch_protection_enabled"),
            metadata.get("web_commit_signoff_required"),
        ):
            if isinstance(value, bool):
                gov_signals.append(value)
        community = metadata.get("community_files")
        if isinstance(community, dict):
            for key in ("security", "contributing", "pull_request_template"):
                value = community.get(key)
                if isinstance(value, bool):
                    gov_signals.append(value)
        if gov_signals:
            governance = sum(1.0 for value in gov_signals if value) / len(gov_signals)
    elif asset.asset_type == "organization":
        gov_signals = []
        if isinstance(metadata.get("two_factor_requirement_enabled"), bool):
            gov_signals.append(bool(metadata.get("two_factor_requirement_enabled")))
        if "default_repository_permission" in metadata:
            gov_signals.append(metadata.get("default_repository_permission") in {"none", "read"})
        if gov_signals:
            governance = sum(1.0 for value in gov_signals if value) / len(gov_signals)
    elif asset.asset_type in {"model", "dataset"}:
        card_data = metadata.get("card_data")
        if isinstance(card_data, dict):
            gov_signals = [
                bool(metadata.get("card_present")),
                bool(card_data.get("license")),
            ]
            governance = sum(1.0 for value in gov_signals if value) / len(gov_signals)
    scores["governance_score"] = (
        clamp(governance) if governance is not None else None
    )
    evidence["governance_score"] = (
        "MEASURED" if governance is not None else "UNAVAILABLE"
    )

    uniqueness = 1.0 if cluster_size <= 1 else max(0.1, 1.0 / cluster_size)
    duplication = 0.0 if cluster_size <= 1 else min(1.0, 0.5 + 0.15 * cluster_size)
    scores["uniqueness_score"] = clamp(uniqueness)
    scores["duplication_penalty"] = clamp(duplication)
    evidence["uniqueness_score"] = "MEASURED"
    evidence["duplication_penalty"] = "MEASURED"

    narrative_text = " ".join(
        [
            asset.name,
            str(metadata.get("description") or ""),
            " ".join(str(value) for value in metadata.get("topics") or []),
            " ".join(str(value) for value in metadata.get("tags") or []),
        ]
    ).lower()
    matches = sorted(keyword for keyword in NARRATIVE_KEYWORDS if keyword in narrative_text)
    narrative = clamp(0.2 + min(0.8, len(matches) * 0.12))
    scores["narrative_fit_score"] = narrative
    evidence["narrative_fit_score"] = "MEASURED"

    frontier = weighted_average(
        (
            (scores["operational_reality_score"], 0.25),
            (scores["security_score"], 0.1),
            (scores["documentation_score"], 0.15),
            (scores["demo_score"], 0.15),
            (scores["governance_score"], 0.1),
            (scores["uniqueness_score"], 0.15),
            (scores["narrative_fit_score"], 0.1),
        )
    )
    scores["frontier_potential_score"] = frontier
    evidence["frontier_potential_score"] = (
        "MEASURED_COMPOSITE" if frontier is not None else "UNAVAILABLE"
    )

    operational_value = scores["operational_reality_score"]
    frontier_value = scores["frontier_potential_score"]
    proposed_fate = "hold"
    if asset.status_label == "ARCHIVED":
        rationale.append("Asset is already archived; no new mutation proposed")
    elif (
        operational_value is not None
        and operational_value > 0.8
        and scores["uniqueness_score"] > 0.8
        and frontier_value is not None
        and frontier_value > 0.85
        and scores["security_score"] is not None
        and scores["governance_score"] is not None
    ):
        proposed_fate = "promote"
        rationale.append("High measured operational reality, uniqueness, and frontier potential")
    elif scores["duplication_penalty"] > 0.7 and scores["uniqueness_score"] < 0.4:
        proposed_fate = "merge"
        rationale.append(f"Member of a measured duplicate cluster of size {cluster_size}")
    elif (
        stale is not None
        and stale > 0.8
        and operational_value is not None
        and operational_value < 0.3
    ):
        proposed_fate = "archive"
        rationale.append("Measured staleness is high and operational reality is low")
    elif (
        narrative > 0.7
        and operational_value is not None
        and operational_value < 0.4
    ):
        proposed_fate = "rebuild"
        rationale.append("Narrative fit is high while operational reality is low")
    elif (
        frontier_value is not None
        and frontier_value >= 0.72
        and operational_value is not None
        and operational_value >= 0.6
    ):
        proposed_fate = "benchmark"
        rationale.append("Measured frontier potential merits benchmark evaluation")
    else:
        rationale.append("No fate threshold is satisfied; continue observation")
    if matches:
        rationale.append(f"Narrative matches: {', '.join(matches[:6])}")
    return ScoreCard(
        asset_id=asset.asset_id,
        scores=scores,
        evidence=evidence,
        proposed_fate=proposed_fate,
        rationale=rationale,
    )


def build_analysis(
    audit_id: str,
    assets: list[Asset],
) -> tuple[dict[str, ScoreCard], dict[str, str], list[dict[str, Any]]]:
    clusters = duplicate_clusters(assets)
    cluster_counts: dict[str, int] = {}
    for cluster_id in clusters.values():
        cluster_counts[cluster_id] = cluster_counts.get(cluster_id, 0) + 1
    scorecards: dict[str, ScoreCard] = {}
    proposals: list[dict[str, Any]] = []
    created_at = utc_now()
    risk_by_fate = {
        "promote": "MEDIUM",
        "benchmark": "MEDIUM",
        "rebuild": "HIGH",
        "merge": "HIGH",
        "archive": "HIGH",
        "kill": "CRITICAL",
    }
    for asset in assets:
        cluster_id = clusters.get(asset.asset_id)
        cluster_size = cluster_counts.get(cluster_id, 1) if cluster_id else 1
        scorecard = score_asset(asset, cluster_size)
        scorecards[asset.asset_id] = scorecard
        if scorecard.proposed_fate == "hold":
            continue
        proposal_material = f"{audit_id}\n{asset.asset_id}\n{scorecard.proposed_fate}"
        proposals.append(
            {
                "proposal_id": f"proposal-{sha256_text(proposal_material)[:20]}",
                "audit_id": audit_id,
                "asset_id": asset.asset_id,
                "asset_name": asset.name,
                "proposed_fate": scorecard.proposed_fate,
                "risk_level": risk_by_fate[scorecard.proposed_fate],
                "status": "PROPOSED",
                "rationale": scorecard.rationale,
                "execution_mode": "MANUAL_GOVERNANCE_GATE",
                "created_at": created_at,
            }
        )
    proposals.sort(key=lambda item: (item["risk_level"], item["asset_id"]))
    return scorecards, clusters, proposals


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.executescript(SCHEMA)
    return connection


def append_receipt(
    connection: sqlite3.Connection,
    *,
    audit_id: str | None,
    kind: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    previous_row = connection.execute(
        "SELECT receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous_row["receipt_hash"] if previous_row else "GENESIS"
    payload_json = canonical_json(payload)
    payload_sha256 = sha256_text(payload_json)
    receipt_hash = sha256_text(f"{previous_hash}\n{payload_sha256}")
    signing_key = env_token("SZL_RECEIPT_SIGNING_KEY")
    signature = (
        hmac.new(signing_key.encode("utf-8"), receipt_hash.encode("ascii"), hashlib.sha256).hexdigest()
        if signing_key
        else None
    )
    signature_status = "HMAC_SHA256" if signature else "UNSIGNED"
    receipt_id = f"receipt-{uuid.uuid4().hex}"
    created_at = utc_now()
    connection.execute(
        """
        INSERT INTO receipts (
            receipt_id, audit_id, kind, payload_json, payload_sha256,
            previous_hash, receipt_hash, signature, signature_status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            receipt_id,
            audit_id,
            kind,
            payload_json,
            payload_sha256,
            previous_hash,
            receipt_hash,
            signature,
            signature_status,
            created_at,
        ),
    )
    return {
        "receipt_id": receipt_id,
        "audit_id": audit_id,
        "kind": kind,
        "payload_sha256": payload_sha256,
        "previous_hash": previous_hash,
        "receipt_hash": receipt_hash,
        "signature_status": signature_status,
        "created_at": created_at,
    }


def persist_audit(
    db_path: Path,
    *,
    audit_id: str,
    started_at: str,
    completed_at: str,
    status: str,
    config: AuditConfig,
    source_reports: list[SourceReport],
    assets: list[Asset],
    scorecards: dict[str, ScoreCard],
    clusters: dict[str, str],
    proposals: list[dict[str, Any]],
    operating_fabric: dict[str, Any],
) -> dict[str, Any]:
    connection = connect_db(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO audit_runs (
                audit_id, started_at, completed_at, status, scope_json,
                source_reports_json, asset_count, proposal_count, receipt_hash,
                app_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                audit_id,
                started_at,
                completed_at,
                status,
                canonical_json(config.public_dict()),
                canonical_json([report.to_dict() for report in source_reports]),
                len(assets),
                len(proposals),
                APP_VERSION,
            ),
        )
        for asset in assets:
            metadata_json = canonical_json(asset.metadata)
            connection.execute(
                """
                INSERT INTO assets (
                    asset_id, asset_type, source, name, url, first_seen_at,
                    last_seen_at, last_audit_id, latest_status_label,
                    latest_operational_status, latest_metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    asset_type = excluded.asset_type,
                    source = excluded.source,
                    name = excluded.name,
                    url = excluded.url,
                    last_seen_at = excluded.last_seen_at,
                    last_audit_id = excluded.last_audit_id,
                    latest_status_label = excluded.latest_status_label,
                    latest_operational_status = excluded.latest_operational_status,
                    latest_metadata_json = excluded.latest_metadata_json
                """,
                (
                    asset.asset_id,
                    asset.asset_type,
                    asset.source,
                    asset.name,
                    asset.url,
                    asset.observed_at,
                    asset.observed_at,
                    audit_id,
                    asset.status_label,
                    asset.operational_status,
                    metadata_json,
                ),
            )
            connection.execute(
                """
                INSERT INTO audit_assets (
                    audit_id, asset_id, status_label, operational_status,
                    observed_at, metadata_json, score_json, duplicate_cluster_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    asset.asset_id,
                    asset.status_label,
                    asset.operational_status,
                    asset.observed_at,
                    metadata_json,
                    canonical_json(scorecards[asset.asset_id].to_dict()),
                    clusters.get(asset.asset_id),
                ),
            )
        for proposal in proposals:
            connection.execute(
                """
                INSERT INTO proposals (
                    proposal_id, audit_id, asset_id, proposed_fate, risk_level,
                    status, rationale_json, execution_mode, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal["proposal_id"],
                    audit_id,
                    proposal["asset_id"],
                    proposal["proposed_fate"],
                    proposal["risk_level"],
                    proposal["status"],
                    canonical_json(proposal["rationale"]),
                    proposal["execution_mode"],
                    proposal["created_at"],
                ),
            )
        for lane in operating_fabric["lanes"]:
            connection.execute(
                """
                INSERT INTO operating_lanes (
                    audit_id, lane, assessment, score, coverage, control_count,
                    critical_blockers_json, claim_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    lane["lane"],
                    lane["assessment"],
                    lane["score"],
                    lane["coverage"],
                    lane["control_count"],
                    canonical_json(lane["critical_blockers"]),
                    lane["claim_state"],
                ),
            )
        for control in operating_fabric["controls"]:
            connection.execute(
                """
                INSERT INTO control_findings (
                    audit_id, control_id, lane, title, state, truth_label,
                    critical, severity, owner_role, observed_at, evidence_json,
                    metric_json, response_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    control["control_id"],
                    control["lane"],
                    control["title"],
                    control["state"],
                    control["truth_label"],
                    int(control["critical"]),
                    control["severity"],
                    control["owner_role"],
                    control["observed_at"],
                    canonical_json(control["evidence"]),
                    canonical_json(control["metric"]),
                    canonical_json(control["response"]),
                ),
            )
        for action in operating_fabric["action_queue"]:
            connection.execute(
                """
                INSERT INTO fabric_actions (
                    audit_id, action_id, control_id, lane, priority, state,
                    owner_role, execution_mode, approval, playbook
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    action["action_id"],
                    action["control_id"],
                    action["lane"],
                    action["priority"],
                    action["state"],
                    action["owner_role"],
                    action["execution_mode"],
                    action["approval"],
                    action["playbook"],
                ),
            )
        receipt_payload = {
            "audit_id": audit_id,
            "status": status,
            "scope": config.public_dict(),
            "sources": [report.to_dict() for report in source_reports],
            "asset_count": len(assets),
            "proposal_count": len(proposals),
            "operating_fabric_summary": operating_fabric["summary"],
            "operating_fabric_sha256": sha256_text(
                canonical_json(operating_fabric)
            ),
            "asset_snapshot_sha256": sha256_text(
                canonical_json(
                    [
                        {
                            "asset": asset.to_dict(),
                            "score": scorecards[asset.asset_id].to_dict(),
                            "cluster": clusters.get(asset.asset_id),
                        }
                        for asset in assets
                    ]
                )
            ),
            "completed_at": completed_at,
        }
        receipt = append_receipt(
            connection,
            audit_id=audit_id,
            kind="ESTATE_AUDIT",
            payload=receipt_payload,
        )
        connection.execute(
            "UPDATE audit_runs SET receipt_hash = ? WHERE audit_id = ?",
            (receipt["receipt_hash"], audit_id),
        )
        connection.commit()
        return receipt
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def verify_receipt_chain(db_path: Path) -> dict[str, Any]:
    connection = connect_db(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM receipts ORDER BY sequence ASC"
        ).fetchall()
    finally:
        connection.close()
    previous = "GENESIS"
    errors: list[str] = []
    unsigned = 0
    verified_signatures = 0
    signing_key = env_token("SZL_RECEIPT_SIGNING_KEY")
    for row in rows:
        sequence = row["sequence"]
        if row["previous_hash"] != previous:
            errors.append(f"sequence {sequence}: previous_hash mismatch")
        payload_sha = sha256_text(row["payload_json"])
        if payload_sha != row["payload_sha256"]:
            errors.append(f"sequence {sequence}: payload hash mismatch")
        calculated = sha256_text(f"{row['previous_hash']}\n{payload_sha}")
        if calculated != row["receipt_hash"]:
            errors.append(f"sequence {sequence}: receipt hash mismatch")
        if row["signature_status"] == "UNSIGNED":
            unsigned += 1
        elif row["signature_status"] == "HMAC_SHA256":
            if not signing_key:
                errors.append(f"sequence {sequence}: signing key unavailable")
            else:
                expected = hmac.new(
                    signing_key.encode("utf-8"),
                    row["receipt_hash"].encode("ascii"),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(expected, row["signature"] or ""):
                    errors.append(f"sequence {sequence}: signature mismatch")
                else:
                    verified_signatures += 1
        else:
            errors.append(f"sequence {sequence}: unknown signature status")
        previous = row["receipt_hash"]
    if errors:
        status = "INVALID"
    elif unsigned:
        status = "CHAIN_VALID_UNSIGNED"
    else:
        status = "VERIFIED"
    return {
        "status": status,
        "chain_valid": not errors,
        "receipt_count": len(rows),
        "unsigned_count": unsigned,
        "verified_signature_count": verified_signatures,
        "latest_hash": previous if rows else None,
        "errors": errors,
    }


def audit_status(source_reports: list[SourceReport], asset_count: int) -> str:
    if asset_count == 0:
        return "UNAVAILABLE"
    statuses = {report.status for report in source_reports}
    if statuses == {"MEASURED"}:
        return "MEASURED"
    return "PARTIAL"


def attach_cross_estate_alignment(
    assets: list[Asset], *, source_scope: str = "UNAVAILABLE"
) -> dict[str, int]:
    policy_source_scope = (
        source_scope.strip()
        if isinstance(source_scope, str) and source_scope.strip()
        else "UNAVAILABLE"
    )
    github_repositories = {
        asset.name.lower(): asset
        for asset in assets
        if asset.source == "github" and asset.asset_type == "repo"
    }
    github_repositories_by_revision: dict[str, list[Asset]] = {}
    commit_facts: list[dict[str, Any]] = []
    for github_asset in github_repositories.values():
        revision = str(github_asset.metadata.get("default_branch_sha") or "").lower()
        if FULL_SHA_RE.fullmatch(revision):
            github_repositories_by_revision.setdefault(revision, []).append(github_asset)
        commit_fact = github_asset.metadata.get("default_branch_commit_fact")
        if isinstance(commit_fact, dict):
            commit_facts.append(commit_fact)
    counts: dict[str, int] = {}
    for asset in assets:
        if asset.source != "huggingface" or asset.asset_type not in {
            "model",
            "dataset",
            "space",
        }:
            continue
        documents = asset.metadata.get("provenance_docs")
        documents = documents if isinstance(documents, list) else []
        observed_documents = [
            document
            for document in documents
            if isinstance(document, dict) and document.get("status") == "OBSERVED"
        ]
        artifact_source_documents = [
            document
            for document in observed_documents
            if document.get("binding_kind") != "MANAGEMENT_ONLY"
        ]
        claims = {
            (
                str(document.get("source_repository") or "").lower(),
                str(document.get("source_revision") or "").lower(),
            )
            for document in artifact_source_documents
            if document.get("source_repository") and document.get("source_revision")
        }
        repositories = {
            str(document.get("source_repository") or "").lower()
            for document in artifact_source_documents
            if document.get("source_repository")
        }
        alignment: dict[str, Any] = {
            "status": "NOT_DECLARED",
            "evidence": "No supported source-binding document was observed",
            "source_repository": None,
            "source_revision": None,
            "github_default_revision": None,
        }
        runtime_build = asset.metadata.get("runtime_build")
        runtime_source = asset.metadata.get("runtime_source")
        runtime_revision = (
            str(runtime_build.get("revision") or "").lower()
            if isinstance(runtime_build, dict)
            and runtime_build.get("status") == "OBSERVED"
            and runtime_build.get("state") == "OBSERVED"
            else ""
        )
        runtime_matches = (
            github_repositories_by_revision.get(runtime_revision, [])
            if FULL_SHA_RE.fullmatch(runtime_revision)
            else []
        )
        if len(runtime_matches) == 1:
            github_asset = runtime_matches[0]
            alignment.update(
                {
                    "status": "EXACT_RUNTIME_HEAD",
                    "evidence": (
                        "The running Space exposed an exact build revision equal to "
                        "one observed GitHub default-branch revision"
                    ),
                    "source_repository": github_asset.name.lower(),
                    "source_revision": runtime_revision,
                    "github_default_revision": runtime_revision,
                    "runtime_domain": runtime_build.get("domain"),
                    "receipt_minted": runtime_build.get("receipt_minted"),
                }
            )
        elif len(runtime_matches) > 1:
            alignment["status"] = "RUNTIME_REVISION_AMBIGUOUS"
            alignment["source_revision"] = runtime_revision
            alignment["evidence"] = (
                "The running Space revision matched multiple observed GitHub "
                "default branches"
            )
        elif FULL_SHA_RE.fullmatch(runtime_revision):
            alignment["status"] = "RUNTIME_SOURCE_UNRESOLVED"
            alignment["source_revision"] = runtime_revision
            alignment["runtime_domain"] = runtime_build.get("domain")
            alignment["receipt_minted"] = runtime_build.get("receipt_minted")
            alignment["evidence"] = (
                "The running Space exposed an exact revision that did not match an "
                "observed GitHub default branch"
            )
        elif any(document.get("status") == "UNAVAILABLE" for document in documents):
            alignment["status"] = "EVIDENCE_UNAVAILABLE"
            alignment["evidence"] = "A declared source-binding document could not be read"
        elif len(claims) > 1:
            alignment["status"] = "CONFLICT"
            alignment["evidence"] = "Source-binding documents disagree"
        elif len(claims) == 1:
            repository, revision = next(iter(claims))
            alignment["source_repository"] = repository
            alignment["source_revision"] = revision
            if FULL_SHA_RE.fullmatch(revision) is None:
                alignment["status"] = "INVALID_REVISION"
                alignment["evidence"] = "Source revision is not an exact Git SHA"
            else:
                github_asset = github_repositories.get(repository)
                if github_asset is None:
                    alignment["status"] = "SOURCE_REPOSITORY_UNAVAILABLE"
                    alignment["evidence"] = "Declared source repository was not observed"
                else:
                    default_revision = str(
                        github_asset.metadata.get("default_branch_sha") or ""
                    ).lower()
                    alignment["github_default_revision"] = default_revision or None
                    if FULL_SHA_RE.fullmatch(default_revision) is None:
                        alignment["status"] = "SOURCE_HEAD_UNAVAILABLE"
                        alignment["evidence"] = (
                            "Declared source repository was observed without an exact "
                            "default-branch revision"
                        )
                    elif default_revision == revision:
                        alignment["status"] = "EXACT_HEAD"
                        alignment["evidence"] = (
                            "Declared Hub source revision equals the observed GitHub "
                            "default-branch revision"
                        )
                    else:
                        alignment["status"] = "PINNED_NON_HEAD"
                        alignment["evidence"] = (
                            "Hub artifact is pinned, but not to the observed GitHub "
                            "default-branch revision"
                        )
        elif repositories:
            alignment["status"] = "REPOSITORY_ONLY"
            alignment["source_repository"] = sorted(repositories)[0]
            alignment["evidence"] = (
                "A source repository is declared without an exact source revision"
            )
        elif (
            isinstance(runtime_source, dict)
            and runtime_source.get("status") == "OBSERVED"
            and (
                runtime_source.get("source_repository")
                or runtime_source.get("source_revision")
            )
        ):
            repository = str(
                runtime_source.get("source_repository") or ""
            ).lower()
            revision = str(runtime_source.get("source_revision") or "").lower()
            alignment["status"] = "SOURCE_REFERENCE_ONLY"
            alignment["source_repository"] = repository or None
            alignment["source_revision"] = revision or None
            alignment["runtime_domain"] = runtime_source.get("domain")
            alignment["source_relation"] = runtime_source.get("relation")
            alignment["declared_alignment_state"] = runtime_source.get(
                "alignment_state"
            )
            alignment["evidence"] = (
                "The running Space exposes a structural source reference, not an "
                "artifact-equivalence or reproducible-build claim"
            )
            github_asset = github_repositories.get(repository)
            if github_asset is not None:
                alignment["github_default_revision"] = (
                    str(
                        github_asset.metadata.get("default_branch_sha") or ""
                    ).lower()
                    or None
                )
        elif observed_documents:
            alignment["status"] = "MANAGED_UNBOUND"
            alignment["evidence"] = (
                "Management provenance exists without an artifact source binding"
            )
        asset.metadata["github_alignment"] = alignment
        policy_repositories = {
            str(document.get("source_repository") or "").strip().lower()
            for document in documents
            if isinstance(document, dict)
            and document.get("binding_kind") == "ARTIFACT_SOURCE"
            and document.get("status") == "OBSERVED"
            and document.get("source_repository")
        }
        artifact_repository = (
            next(iter(policy_repositories)) if len(policy_repositories) == 1 else ""
        )
        runtime_repository = (
            runtime_matches[0].name.lower()
            if len(runtime_matches) == 1
            else artifact_repository
        )
        policy_repository = artifact_repository or runtime_repository
        source_head: dict[str, Any] | None = None
        policy_github_asset = github_repositories.get(policy_repository)
        if policy_github_asset is not None:
            policy_head_revision = str(
                policy_github_asset.metadata.get("default_branch_sha") or ""
            ).strip().lower()
            if FULL_SHA_RE.fullmatch(policy_head_revision):
                source_head = {
                    "status": "OBSERVED",
                    "source_repository": policy_repository,
                    "source_revision": policy_head_revision,
                }
        runtime_evidence: dict[str, Any] | None = None
        if isinstance(runtime_build, dict):
            runtime_evidence = {
                "status": (
                    "OBSERVED"
                    if runtime_build.get("status") == "OBSERVED"
                    and runtime_build.get("state") == "OBSERVED"
                    else "UNAVAILABLE"
                ),
                "source_repository": runtime_repository or None,
                "source_revision": str(
                    runtime_build.get("revision") or ""
                ).strip().lower(),
            }
        asset.metadata["provenance_policy"] = classify_provenance(
            target_id=asset.asset_id,
            source_scope=policy_source_scope,
            artifact_documents=documents,
            commit_facts=commit_facts,
            source_head=source_head,
            runtime_evidence=runtime_evidence,
            target_evidence_state="OBSERVED",
        )
        status = str(alignment["status"])
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(pretty_json(payload) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_audit(
    config: AuditConfig,
    db_path: Path,
    export_path: Path,
    evidence_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    audit_id = f"audit-{uuid.uuid4().hex}"
    started_at = utc_now()
    collectors = (
        ("github", collect_github),
        ("huggingface", collect_huggingface),
        ("domains", collect_domains),
    )
    collected_assets: list[Asset] = []
    reports_by_source: dict[str, SourceReport] = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(collector, config): source
            for source, collector in collectors
        }
        for future in as_completed(futures):
            source = futures[future]
            try:
                assets, report = future.result()
            except Exception as exc:
                report = SourceReport(
                    source=source,
                    status="UNAVAILABLE",
                    scope="UNKNOWN",
                    count=0,
                    observed_at=utc_now(),
                    elapsed_ms=0,
                    errors=[f"UNHANDLED: {sanitize_error(exc)}"],
                )
                assets = []
            collected_assets.extend(assets)
            reports_by_source[source] = report
    assets = sorted(collected_assets, key=lambda item: item.asset_id)
    source_reports = [reports_by_source[source] for source, _ in collectors]
    github_report = reports_by_source.get("github")
    github_source_scope = (
        github_report.scope
        if github_report is not None
        and isinstance(github_report.scope, str)
        and github_report.scope.strip()
        else "UNAVAILABLE"
    )
    alignment_counts = attach_cross_estate_alignment(
        assets, source_scope=github_source_scope
    )
    scorecards, clusters, proposals = build_analysis(audit_id, assets)
    completed_at = utc_now()
    status = audit_status(source_reports, len(assets))
    operating_fabric = evaluate_operating_fabric(
        audit_id,
        assets,
        source_reports,
        proposals,
        completed_at,
        receipt_chain=verify_receipt_chain(db_path),
        evidence_bundle=evidence_bundle,
    )
    receipt = persist_audit(
        db_path,
        audit_id=audit_id,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        config=config,
        source_reports=source_reports,
        assets=assets,
        scorecards=scorecards,
        clusters=clusters,
        proposals=proposals,
        operating_fabric=operating_fabric,
    )
    payload = {
        "schema": "szl.estate-audit/v1",
        "meta": {
            "name": APP_NAME,
            "version": APP_VERSION,
            "audit_id": audit_id,
            "status": status,
            "started_at": started_at,
            "completed_at": completed_at,
            "truth_rule": "Never mark green what was not directly retrieved and observed",
            "mutation_policy": "READ_ONLY; external actions are proposals only",
        },
        "scope": config.public_dict(),
        "source_reports": [report.to_dict() for report in source_reports],
        "summary": {
            "asset_count": len(assets),
            "proposal_count": len(proposals),
            "duplicate_cluster_count": len(set(clusters.values())),
            "status_counts": count_by(asset.status_label for asset in assets),
            "type_counts": count_by(asset.asset_type for asset in assets),
            "github_alignment_counts": alignment_counts,
            "fate_counts": count_by(
                scorecard.proposed_fate for scorecard in scorecards.values()
            ),
        },
        "assets": [
            {
                **asset.to_dict(),
                "duplicate_cluster_id": clusters.get(asset.asset_id),
                "scorecard": scorecards[asset.asset_id].to_dict(),
            }
            for asset in assets
        ],
        "proposals": proposals,
        "operating_fabric": operating_fabric,
        "receipt": receipt,
    }
    write_json_atomic(export_path, payload)
    return payload


def count_by(values: Iterable[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def json_load(value: str) -> Any:
    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(value)
    return None


def latest_audit_id(connection: sqlite3.Connection) -> str | None:
    row = connection.execute(
        "SELECT audit_id FROM audit_runs ORDER BY completed_at DESC LIMIT 1"
    ).fetchone()
    return row["audit_id"] if row else None


def load_status(db_path: Path) -> dict[str, Any]:
    connection = connect_db(db_path)
    try:
        audit_id = latest_audit_id(connection)
        if audit_id is None:
            return {
                "status": "UNAVAILABLE",
                "reason": "No audit has been recorded",
                "app_version": APP_VERSION,
            }
        run = connection.execute(
            "SELECT * FROM audit_runs WHERE audit_id = ?", (audit_id,)
        ).fetchone()
        type_rows = connection.execute(
            """
            SELECT a.asset_type, COUNT(*) AS count
            FROM audit_assets aa
            JOIN assets a ON a.asset_id = aa.asset_id
            WHERE aa.audit_id = ?
            GROUP BY a.asset_type
            ORDER BY a.asset_type
            """,
            (audit_id,),
        ).fetchall()
        status_rows = connection.execute(
            """
            SELECT status_label, COUNT(*) AS count
            FROM audit_assets
            WHERE audit_id = ?
            GROUP BY status_label
            ORDER BY status_label
            """,
            (audit_id,),
        ).fetchall()
        fate_rows = connection.execute(
            """
            SELECT proposed_fate, COUNT(*) AS count
            FROM proposals
            WHERE audit_id = ?
            GROUP BY proposed_fate
            ORDER BY proposed_fate
            """,
            (audit_id,),
        ).fetchall()
        chain = verify_receipt_chain(db_path)
        operating_fabric = load_operating_fabric(db_path)
        return {
            "status": run["status"],
            "audit_id": audit_id,
            "started_at": run["started_at"],
            "completed_at": run["completed_at"],
            "asset_count": run["asset_count"],
            "proposal_count": run["proposal_count"],
            "scope": json_load(run["scope_json"]),
            "source_reports": json_load(run["source_reports_json"]),
            "type_counts": {row["asset_type"]: row["count"] for row in type_rows},
            "status_counts": {row["status_label"]: row["count"] for row in status_rows},
            "fate_counts": {row["proposed_fate"]: row["count"] for row in fate_rows},
            "receipt_hash": run["receipt_hash"],
            "receipt_chain": chain,
            "operating_fabric": operating_fabric["summary"],
            "app_version": run["app_version"],
            "mutation_policy": "READ_ONLY",
        }
    finally:
        connection.close()


def load_assets(
    db_path: Path,
    *,
    asset_type: str | None = None,
    status_label: str | None = None,
    limit: int = 250,
) -> list[dict[str, Any]]:
    connection = connect_db(db_path)
    try:
        audit_id = latest_audit_id(connection)
        if audit_id is None:
            return []
        clauses = ["aa.audit_id = ?"]
        parameters: list[Any] = [audit_id]
        if asset_type:
            clauses.append("a.asset_type = ?")
            parameters.append(asset_type)
        if status_label:
            clauses.append("aa.status_label = ?")
            parameters.append(status_label)
        parameters.append(max(1, min(limit, 1000)))
        rows = connection.execute(
            f"""
            SELECT
                a.asset_id, a.asset_type, a.source, a.name, a.url,
                aa.status_label, aa.operational_status, aa.observed_at,
                aa.metadata_json, aa.score_json, aa.duplicate_cluster_id
            FROM audit_assets aa
            JOIN assets a ON a.asset_id = aa.asset_id
            WHERE {' AND '.join(clauses)}
            ORDER BY a.asset_type, a.name
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [
            {
                "asset_id": row["asset_id"],
                "asset_type": row["asset_type"],
                "source": row["source"],
                "name": row["name"],
                "url": row["url"],
                "status_label": row["status_label"],
                "operational_status": row["operational_status"],
                "observed_at": row["observed_at"],
                "metadata": json_load(row["metadata_json"]),
                "scorecard": json_load(row["score_json"]),
                "duplicate_cluster_id": row["duplicate_cluster_id"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def load_proposals(
    db_path: Path,
    *,
    status: str | None = None,
    limit: int = 250,
) -> list[dict[str, Any]]:
    connection = connect_db(db_path)
    try:
        audit_id = latest_audit_id(connection)
        if audit_id is None:
            return []
        clauses = ["p.audit_id = ?"]
        parameters: list[Any] = [audit_id]
        if status:
            clauses.append("p.status = ?")
            parameters.append(status)
        parameters.append(max(1, min(limit, 1000)))
        rows = connection.execute(
            f"""
            SELECT p.*, a.name AS asset_name, a.url AS asset_url
            FROM proposals p
            JOIN assets a ON a.asset_id = p.asset_id
            WHERE {' AND '.join(clauses)}
            ORDER BY
                CASE p.risk_level
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                p.created_at,
                p.asset_id
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [
            {
                "proposal_id": row["proposal_id"],
                "audit_id": row["audit_id"],
                "asset_id": row["asset_id"],
                "asset_name": row["asset_name"],
                "asset_url": row["asset_url"],
                "proposed_fate": row["proposed_fate"],
                "risk_level": row["risk_level"],
                "status": row["status"],
                "rationale": json_load(row["rationale_json"]),
                "execution_mode": row["execution_mode"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def load_receipts(db_path: Path, limit: int = 100) -> list[dict[str, Any]]:
    connection = connect_db(db_path)
    try:
        rows = connection.execute(
            """
            SELECT sequence, receipt_id, audit_id, kind, payload_sha256,
                   previous_hash, receipt_hash, signature_status, created_at
            FROM receipts
            ORDER BY sequence DESC
            LIMIT ?
            """,
            (max(1, min(limit, 1000)),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def load_operating_fabric(
    db_path: Path,
    *,
    lane: str | None = None,
    state: str | None = None,
) -> dict[str, Any]:
    connection = connect_db(db_path)
    try:
        audit_id = latest_audit_id(connection)
        if audit_id is None:
            return {
                "status": "UNAVAILABLE",
                "reason": "No operating-fabric evaluation has been recorded",
                "summary": {
                    "lane_count": 0,
                    "control_count": 0,
                    "action_count": 0,
                    "readiness_to_claim_fully_operational": "BLOCKED",
                },
                "lanes": [],
                "controls": [],
                "action_queue": [],
            }
        lane_rows = connection.execute(
            "SELECT * FROM operating_lanes WHERE audit_id = ?",
            (audit_id,),
        ).fetchall()
        control_clauses = ["audit_id = ?"]
        control_parameters: list[Any] = [audit_id]
        if lane:
            control_clauses.append("lane = ?")
            control_parameters.append(lane)
        if state:
            control_clauses.append("state = ?")
            control_parameters.append(state)
        control_rows = connection.execute(
            f"""
            SELECT * FROM control_findings
            WHERE {' AND '.join(control_clauses)}
            ORDER BY lane, control_id
            """,
            control_parameters,
        ).fetchall()
        action_clauses = ["audit_id = ?"]
        action_parameters: list[Any] = [audit_id]
        if lane:
            action_clauses.append("lane = ?")
            action_parameters.append(lane)
        if state:
            action_clauses.append("state = ?")
            action_parameters.append(state)
        action_rows = connection.execute(
            f"""
            SELECT * FROM fabric_actions
            WHERE {' AND '.join(action_clauses)}
            ORDER BY
                CASE priority
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                control_id
            """,
            action_parameters,
        ).fetchall()
        lane_rank = {name: index for index, name in enumerate(LANE_ORDER)}
        all_lanes = sorted(
            [
                {
                    "lane": row["lane"],
                    "assessment": row["assessment"],
                    "score": row["score"],
                    "coverage": row["coverage"],
                    "control_count": row["control_count"],
                    "critical_blockers": json_load(row["critical_blockers_json"]),
                    "claim_state": row["claim_state"],
                }
                for row in lane_rows
            ],
            key=lambda item: lane_rank.get(item["lane"], 99),
        )
        lanes = [item for item in all_lanes if lane is None or item["lane"] == lane]
        controls = [
            {
                "control_id": row["control_id"],
                "lane": row["lane"],
                "title": row["title"],
                "state": row["state"],
                "truth_label": row["truth_label"],
                "critical": bool(row["critical"]),
                "severity": row["severity"],
                "owner_role": row["owner_role"],
                "observed_at": row["observed_at"],
                "evidence": json_load(row["evidence_json"]),
                "metric": json_load(row["metric_json"]),
                "response": json_load(row["response_json"]),
            }
            for row in control_rows
        ]
        actions = [
            {
                "action_id": row["action_id"],
                "control_id": row["control_id"],
                "lane": row["lane"],
                "priority": row["priority"],
                "state": row["state"],
                "owner_role": row["owner_role"],
                "execution_mode": row["execution_mode"],
                "approval": row["approval"],
                "playbook": row["playbook"],
            }
            for row in action_rows
        ]
        all_control_rows = connection.execute(
            "SELECT state, COUNT(*) AS count FROM control_findings WHERE audit_id = ? GROUP BY state",
            (audit_id,),
        ).fetchall()
        truth_rows = connection.execute(
            "SELECT truth_label, COUNT(*) AS count FROM control_findings WHERE audit_id = ? GROUP BY truth_label",
            (audit_id,),
        ).fetchall()
        truth_counts = {row["truth_label"]: row["count"] for row in truth_rows}
        total_controls = sum(row["count"] for row in all_control_rows)
        total_actions = connection.execute(
            "SELECT COUNT(*) AS count FROM fabric_actions WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()["count"]
        assessment_counts: dict[str, int] = {}
        for item in all_lanes:
            assessment_counts[item["assessment"]] = assessment_counts.get(item["assessment"], 0) + 1
        return {
            "status": (
                "MEASURED"
                if total_controls and truth_counts.get("MEASURED") == total_controls
                else "PARTIAL"
                if total_controls
                else "UNAVAILABLE"
            ),
            "schema": "szl.operating-fabric/v1",
            "audit_id": audit_id,
            "filters": {"lane": lane, "state": state},
            "execution_policy": "DEFENSIVE_READ_ONLY; RESPONSES_PROPOSE_ONLY; APPROVAL_REQUIRED",
            "summary": {
                "lane_count": len(all_lanes),
                "control_count": total_controls,
                "action_count": total_actions,
                "state_counts": {row["state"]: row["count"] for row in all_control_rows},
                "truth_counts": truth_counts,
                "evaluation_truth": (
                    "MEASURED"
                    if total_controls and truth_counts.get("MEASURED") == total_controls
                    else "PARTIAL"
                    if total_controls
                    else "UNAVAILABLE"
                ),
                "assessment_counts": assessment_counts,
                "readiness_to_claim_fully_operational": (
                    "SUPPORTED"
                    if all_lanes
                    and all(item["claim_state"] == "SUPPORTED" for item in all_lanes)
                    else "BLOCKED"
                ),
            },
            "lanes": lanes,
            "controls": controls,
            "action_queue": actions,
        }
    finally:
        connection.close()


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SZL Estate OS</title>
  <style>
    :root {
      --paper: #f2eddf;
      --ink: #102b31;
      --rust: #bd3f28;
      --sea: #007b73;
      --line: rgba(16,43,49,.18);
      --muted: #657175;
      --shadow: 0 18px 55px rgba(16,43,49,.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; color: var(--ink); background:
      linear-gradient(90deg, transparent 24px, rgba(189,63,40,.08) 25px, transparent 26px),
      linear-gradient(var(--paper), #e9e3d4);
      font-family: Georgia, "Times New Roman", serif;
      min-height: 100vh;
    }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 42px 0 70px; }
    header { display: grid; grid-template-columns: 1fr auto; gap: 28px; align-items: end; border-bottom: 3px solid var(--ink); padding-bottom: 22px; }
    .eyebrow, .mono { font: 700 12px/1.5 Consolas, "Courier New", monospace; letter-spacing: .14em; text-transform: uppercase; }
    h1 { font-size: clamp(44px, 8vw, 104px); line-height: .82; letter-spacing: -.065em; margin: 9px 0 0; max-width: 760px; }
    .stamp { border: 2px solid var(--rust); color: var(--rust); padding: 12px 15px; transform: rotate(-2deg); text-align: center; }
    .lede { font-size: 21px; line-height: 1.42; max-width: 760px; margin: 24px 0 30px; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
    .card { background: rgba(255,255,255,.43); border: 1px solid var(--line); padding: 18px; box-shadow: var(--shadow); }
    .card b { display: block; font-size: 38px; line-height: 1; margin-top: 12px; }
    .wide { grid-column: span 2; }
    section { margin-top: 26px; }
    h2 { font-size: 28px; margin: 0 0 12px; }
    table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,.4); }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 12px 10px; vertical-align: top; }
    th { font: 700 11px/1.4 Consolas, monospace; letter-spacing: .1em; text-transform: uppercase; }
    td { font-size: 14px; }
    a { color: var(--sea); text-decoration-thickness: 1px; text-underline-offset: 3px; }
    .pill { display: inline-block; border: 1px solid currentColor; border-radius: 99px; padding: 3px 8px; font: 700 10px/1.2 Consolas, monospace; letter-spacing: .08em; }
    .LIVE, .MEASURED { color: var(--sea); }
    .BROKEN, .HIGH, .CRITICAL { color: var(--rust); }
    .MODELED, .UNAVAILABLE, .PARTIAL { color: #8a6500; }
    .source { display: flex; justify-content: space-between; gap: 20px; border-top: 1px solid var(--line); padding: 10px 0; }
    .empty { color: var(--muted); font-style: italic; }
    footer { margin-top: 28px; border-top: 1px solid var(--line); padding-top: 15px; color: var(--muted); }
    @media (max-width: 760px) {
      main { width: min(100% - 20px, 1180px); padding-top: 24px; }
      header { grid-template-columns: 1fr; }
      .stamp { justify-self: start; }
      .grid { grid-template-columns: 1fr 1fr; }
      .wide { grid-column: span 2; }
      .table-wrap { overflow-x: auto; }
      h1 { font-size: 58px; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <div><div class="eyebrow">Governed intelligence substrate</div><h1>Estate<br>Operating System</h1></div>
    <div id="stamp" class="stamp mono">Loading truth state</div>
  </header>
  <p class="lede">One measured view across repositories, Hub assets, domain routes, proposals, and receipt integrity. External mutations are governance-gated.</p>
  <div class="grid">
    <div class="card"><span class="mono">Assets</span><b id="assets">-</b></div>
    <div class="card"><span class="mono">Proposals</span><b id="proposals">-</b></div>
    <div class="card"><span class="mono">Live routes/spaces</span><b id="live">-</b></div>
    <div class="card"><span class="mono">Broken</span><b id="broken">-</b></div>
    <div class="card"><span class="mono">Operating lanes</span><b id="lanecount">-</b></div>
    <div class="card"><span class="mono">Full-operation claim</span><b id="claim" style="font-size:18px">-</b></div>
    <div class="card wide"><span class="mono">Latest audit</span><b id="audit" style="font-size:18px">-</b></div>
    <div class="card wide"><span class="mono">Receipt chain</span><b id="chain" style="font-size:18px">-</b></div>
  </div>
  <section><h2>Source truth</h2><div id="sources" class="card"></div></section>
  <section><h2>Seven-lane operating fabric</h2><div class="table-wrap"><table>
    <thead><tr><th>Lane</th><th>Assessment</th><th>Score</th><th>Coverage</th><th>Claim</th></tr></thead>
    <tbody id="lanes"></tbody>
  </table></div></section>
  <section><h2>Defensive action queue</h2><div class="table-wrap"><table>
    <thead><tr><th>Priority</th><th>Lane</th><th>Control</th><th>Mode</th><th>Playbook</th></tr></thead>
    <tbody id="fabric-actions"></tbody>
  </table></div></section>
  <section><h2>Governance queue</h2><div class="table-wrap"><table>
    <thead><tr><th>Risk</th><th>Fate</th><th>Asset</th><th>Why</th></tr></thead>
    <tbody id="queue"></tbody>
  </table></div></section>
  <section><h2>Estate atlas</h2><div class="table-wrap"><table>
    <thead><tr><th>Truth</th><th>Type</th><th>Asset</th><th>Operational state</th></tr></thead>
    <tbody id="atlas"></tbody>
  </table></div></section>
  <footer class="mono">Read-only control plane | Never mark green what was not directly observed</footer>
</main>
<script>
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[c]));
const pill = value => `<span class="pill ${esc(value)}">${esc(value)}</span>`;
Promise.all([
  fetch("/api/v1/status").then(r => r.json()),
  fetch("/api/v1/proposals?limit=25").then(r => r.json()),
  fetch("/api/v1/assets?limit=100").then(r => r.json()),
  fetch("/api/v1/operating-fabric").then(r => r.json())
]).then(([status, proposalData, assetData, fabric]) => {
  document.getElementById("stamp").textContent = status.status || "UNAVAILABLE";
  document.getElementById("stamp").classList.add(status.status || "UNAVAILABLE");
  document.getElementById("assets").textContent = status.asset_count ?? 0;
  document.getElementById("proposals").textContent = status.proposal_count ?? 0;
  document.getElementById("live").textContent = status.status_counts?.LIVE ?? 0;
  document.getElementById("broken").textContent = status.status_counts?.BROKEN ?? 0;
  document.getElementById("lanecount").textContent = fabric.summary?.lane_count ?? 0;
  document.getElementById("claim").textContent = fabric.summary?.readiness_to_claim_fully_operational || "BLOCKED";
  document.getElementById("audit").textContent = status.audit_id || "No audit";
  document.getElementById("chain").textContent = status.receipt_chain?.status || "UNAVAILABLE";
  const sources = status.source_reports || [];
  document.getElementById("sources").innerHTML = sources.length ? sources.map(source =>
    `<div class="source"><span><b>${esc(source.source)}</b><br><small>${esc(source.scope)} · ${source.count} assets · ${source.elapsed_ms} ms</small></span>${pill(source.status)}</div>`
  ).join("") : `<span class="empty">No source reports yet.</span>`;
  const lanes = fabric.lanes || [];
  document.getElementById("lanes").innerHTML = lanes.length ? lanes.map(item =>
    `<tr><td><b>${esc(item.lane)}</b></td><td>${pill(item.assessment)}</td><td>${item.score ?? "UNAVAILABLE"}</td><td>${Math.round((item.coverage || 0) * 100)}%</td><td>${pill(item.claim_state)}</td></tr>`
  ).join("") : `<tr><td colspan="5" class="empty">Run an audit to evaluate every operating lane.</td></tr>`;
  const fabricActions = fabric.action_queue || [];
  document.getElementById("fabric-actions").innerHTML = fabricActions.length ? fabricActions.slice(0, 25).map(item =>
    `<tr><td>${pill(item.priority)}</td><td>${esc(item.lane)}</td><td>${esc(item.control_id)}</td><td>${pill(item.execution_mode)}</td><td>${esc(item.playbook)}</td></tr>`
  ).join("") : `<tr><td colspan="5" class="empty">No defensive actions are currently proposed.</td></tr>`;
  const proposals = proposalData.items || [];
  document.getElementById("queue").innerHTML = proposals.length ? proposals.map(item =>
    `<tr><td>${pill(item.risk_level)}</td><td>${pill(item.proposed_fate)}</td><td>${item.asset_url ? `<a href="${esc(item.asset_url)}" target="_blank" rel="noreferrer">${esc(item.asset_name)}</a>` : esc(item.asset_name)}</td><td>${esc((item.rationale || [])[0])}</td></tr>`
  ).join("") : `<tr><td colspan="4" class="empty">No gated proposals in the latest audit.</td></tr>`;
  const assets = assetData.items || [];
  document.getElementById("atlas").innerHTML = assets.length ? assets.map(item =>
    `<tr><td>${pill(item.status_label)}</td><td>${esc(item.asset_type)}</td><td>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(item.name)}</a>` : esc(item.name)}</td><td>${esc(item.operational_status)}</td></tr>`
  ).join("") : `<tr><td colspan="4" class="empty">Run an audit to populate the estate atlas.</td></tr>`;
}).catch(error => {
  document.getElementById("stamp").textContent = "UNAVAILABLE";
  document.getElementById("sources").textContent = error.message;
});
</script>
</body>
</html>
"""


class EstateRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = f"SZLEstateOS/{APP_VERSION}"
    db_path: Path = DEFAULT_DB
    require_auth: bool = False
    control_token: str | None = None

    def log_message(self, format_string: str, *args: Any) -> None:
        sys.stderr.write(
            f"{utc_now()} request={self.command} path={self.path!r} "
            f"message={format_string % args}\n"
        )

    def security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
        )

    def authorized(self) -> bool:
        if not self.require_auth:
            return True
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.control_token}" if self.control_token else ""
        return bool(expected) and hmac.compare_digest(supplied, expected)

    def send_json(self, status: int, payload: Any) -> None:
        body = (pretty_json(payload) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/healthz":
            self.send_json(
                200,
                {
                    "ok": True,
                    "status": "LIVE",
                    "service": APP_NAME,
                    "version": APP_VERSION,
                    "time": utc_now(),
                },
            )
            return
        if path == "/readyz":
            try:
                status = load_status(self.db_path)
                ready = status.get("audit_id") is not None
                self.send_json(
                    200 if ready else 503,
                    {
                        "ok": ready,
                        "status": "READY" if ready else "UNAVAILABLE",
                        "database": "AVAILABLE" if ready else "UNAVAILABLE",
                        "latest_audit": status.get("audit_id"),
                        "full_operation_claim": (status.get("operating_fabric") or {}).get(
                            "readiness_to_claim_fully_operational", "BLOCKED"
                        ),
                    },
                )
            except sqlite3.Error as exc:
                self.send_json(
                    503,
                    {"ok": False, "status": "BROKEN", "error": sanitize_error(exc)},
                )
            return
        if not self.authorized():
            self.send_json(401, {"error": "UNAUTHORIZED"})
            return
        if path == "/":
            self.send_text(200, DASHBOARD_HTML, "text/html; charset=utf-8")
            return
        if path == "/api/v1/status":
            self.send_json(200, load_status(self.db_path))
            return
        if path == "/api/v1/assets":
            asset_type = (query.get("type") or [None])[0]
            status_label = (query.get("status") or [None])[0]
            limit = safe_int((query.get("limit") or ["250"])[0], 250)
            items = load_assets(
                self.db_path,
                asset_type=asset_type,
                status_label=status_label,
                limit=limit,
            )
            self.send_json(200, {"count": len(items), "items": items})
            return
        if path == "/api/v1/proposals":
            status = (query.get("status") or [None])[0]
            limit = safe_int((query.get("limit") or ["250"])[0], 250)
            items = load_proposals(self.db_path, status=status, limit=limit)
            self.send_json(200, {"count": len(items), "items": items})
            return
        if path == "/api/v1/operating-fabric":
            lane = (query.get("lane") or [None])[0]
            state = (query.get("state") or [None])[0]
            self.send_json(
                200,
                load_operating_fabric(self.db_path, lane=lane, state=state),
            )
            return
        if path == "/api/v1/receipts":
            limit = safe_int((query.get("limit") or ["100"])[0], 100)
            items = load_receipts(self.db_path, limit=limit)
            self.send_json(
                200,
                {
                    "count": len(items),
                    "chain": verify_receipt_chain(self.db_path),
                    "items": items,
                },
            )
            return
        if path == "/metrics":
            status = load_status(self.db_path)
            operating_fabric = load_operating_fabric(self.db_path)
            lines = [
                "# HELP szl_estate_assets Assets in the latest estate audit.",
                "# TYPE szl_estate_assets gauge",
                f"szl_estate_assets {status.get('asset_count', 0)}",
                "# HELP szl_estate_proposals Gated proposals in the latest estate audit.",
                "# TYPE szl_estate_proposals gauge",
                f"szl_estate_proposals {status.get('proposal_count', 0)}",
            ]
            for label, count in (status.get("status_counts") or {}).items():
                safe_label = str(label).replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'szl_estate_truth_state{{state="{safe_label}"}} {count}')
            for label, count in (operating_fabric.get("summary", {}).get("state_counts") or {}).items():
                safe_label = str(label).replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'szl_operating_controls{{state="{safe_label}"}} {count}')
            for lane in operating_fabric.get("lanes") or []:
                safe_lane = str(lane["lane"]).replace("\\", "\\\\").replace('"', '\\"')
                score = lane["score"] if lane["score"] is not None else -1
                lines.append(f'szl_operating_lane_score{{lane="{safe_lane}"}} {score}')
                lines.append(
                    f'szl_operating_lane_coverage{{lane="{safe_lane}"}} {lane["coverage"]}'
                )
            self.send_text(
                200,
                "\n".join(lines) + "\n",
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return
        self.send_json(404, {"error": "NOT_FOUND", "path": path})


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class EstateHTTPServer(http.server.ThreadingHTTPServer):
    """Threaded read-only server with a burst-capable accept queue."""

    allow_reuse_address = True
    block_on_close = True
    daemon_threads = True
    request_queue_size = DEFAULT_REQUEST_QUEUE_SIZE


def serve(db_path: Path, host: str, port: int, allow_remote: bool) -> None:
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    is_loopback = host in loopback_hosts
    if not is_loopback and not allow_remote:
        raise RuntimeError("Non-loopback binding requires --allow-remote")
    control_token = env_token("SZL_CONTROL_TOKEN")
    if not is_loopback and not control_token:
        raise RuntimeError(
            "Non-loopback binding requires SZL_CONTROL_TOKEN in the environment"
        )
    handler = type(
        "ConfiguredEstateRequestHandler",
        (EstateRequestHandler,),
        {
            "db_path": db_path,
            "require_auth": not is_loopback,
            "control_token": control_token,
        },
    )
    server = EstateHTTPServer((host, port), handler)
    print(
        pretty_json(
            {
                "status": "LIVE",
                "service": APP_NAME,
                "version": APP_VERSION,
                "listen": f"http://{host}:{port}",
                "database": str(db_path),
                "remote_auth_required": not is_loopback,
                "mutation_policy": "READ_ONLY",
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


def self_test() -> dict[str, Any]:
    checks: list[str] = []
    if EstateHTTPServer.request_queue_size < DEFAULT_WORKERS * 8:
        raise AssertionError("HTTP accept queue is below the burst-safety floor")
    checks.append("burst-capable HTTP accept queue")
    observed = utc_now()
    source_revision = "a" * 40
    with tempfile.TemporaryDirectory(prefix="szl-estate-os-") as temporary:
        root = Path(temporary)
        db_path = root / "estate.db"
        export_path = root / "audit.json"
        audit_id = f"audit-{uuid.uuid4().hex}"
        assets = [
            Asset(
                asset_id="github:repo:szl-holdings/calibration-kernel",
                asset_type="repo",
                source="github",
                name="szl-holdings/calibration-kernel",
                url="https://github.com/szl-holdings/calibration-kernel",
                status_label="OBSERVED",
                operational_status="ACTIVE",
                observed_at=observed,
                metadata={
                    "description": "Calibration kernel with governed receipts",
                    "license": "Apache-2.0",
                    "homepage": "https://example.test",
                    "topics": ["calibration", "kernel", "governance"],
                    "pushed_at": observed,
                    "branch_protection_enabled": True,
                    "web_commit_signoff_required": True,
                    "security_and_analysis": {
                        "advanced_security": "enabled",
                        "secret_scanning": "enabled",
                    },
                    "has_pages": True,
                    "default_branch_sha": source_revision,
                    "default_branch_commit_fact": {
                        "source_repository": (
                            "szl-holdings/calibration-kernel"
                        ),
                        "source_revision": source_revision,
                        "state": "VERIFIED_REACHABLE",
                    },
                },
            ),
            Asset(
                asset_id="huggingface:model:szlholdings/calibration-kernel",
                asset_type="model",
                source="huggingface",
                name="SZLHOLDINGS/calibration-kernel",
                url="https://huggingface.co/SZLHOLDINGS/calibration-kernel",
                status_label="OBSERVED",
                operational_status="PUBLISHED",
                observed_at=observed,
                metadata={
                    "last_modified": observed,
                    "tags": ["calibration", "governance"],
                    "card_present": True,
                    "card_data": {"license": "apache-2.0", "datasets": ["synthetic"]},
                    "provenance_docs": [
                        {
                            "file": "hf-deploy-manifest.json",
                            "schema": "szl.hf-deploy-manifest/v1",
                            "source_repository": "szl-holdings/calibration-kernel",
                            "source_revision": source_revision,
                            "binding_kind": "ARTIFACT_SOURCE",
                            "status": "OBSERVED",
                        }
                    ],
                },
            ),
            Asset(
                asset_id="domain:route:a11oy.net/verify",
                asset_type="route",
                source="domains",
                name="a11oy.net/verify",
                url="https://a11oy.net/verify",
                status_label="LIVE",
                operational_status="REAL",
                observed_at=observed,
                metadata={
                    "title": "Verification",
                    "content_length_observed": 5000,
                    "content_state": "REAL",
                    "https": True,
                    "security_headers": {
                        "strict-transport-security": True,
                        "content-security-policy": True,
                        "x-content-type-options": True,
                        "referrer-policy": True,
                    },
                    "security_header_values": {
                        "strict-transport-security": (
                            "max-age=31536000; includeSubDomains"
                        ),
                        "content-security-policy": (
                            "default-src 'self'; script-src 'self'; "
                            "object-src 'none'; frame-ancestors 'none'; "
                            "base-uri 'self'; form-action 'self'"
                        ),
                        "x-content-type-options": "nosniff",
                        "referrer-policy": "strict-origin-when-cross-origin",
                    },
                },
            ),
        ]
        alignment_counts = attach_cross_estate_alignment(
            assets, source_scope="AUTHENTICATED_COMPLETE"
        )
        assert alignment_counts["EXACT_HEAD"] == 1
        assert (
            assets[1].metadata["github_alignment"]["source_revision"]
            == source_revision
        )
        assert (
            assets[1].metadata["provenance_policy"]["artifact_provenance"]["state"]
            == "PASS"
        )
        checks.append("cross-estate exact-source alignment")
        assert strict_readme_source_binding(
            "Source: https://github.com/szl-holdings/calibration-kernel\n"
            f"Source revision: `{source_revision}`"
        ) == ("szl-holdings/calibration-kernel", source_revision)
        assert (
            strict_readme_source_binding(
                "Sources: https://github.com/szl-holdings/one and "
                "https://github.com/szl-holdings/two\n"
                f"Revision: {source_revision}"
            )
            is None
        )
        assert provenance_source(
            {
                "sourceRepository": (
                    "https://github.com/szl-holdings/calibration-kernel"
                ),
                "sourceCommit": source_revision,
            },
            "a11oy-metadata.json",
        ) == ("szl-holdings/calibration-kernel", source_revision)
        assert provenance_source(
            {
                "source": {
                    "repository": (
                        "https://github.com/szl-holdings/calibration-kernel"
                    ),
                    "mergedCommit": source_revision,
                }
            },
            "publication.json",
        ) == ("szl-holdings/calibration-kernel", source_revision)
        assert provenance_source(
            {
                "source_repository": "szl-holdings/calibration-kernel",
                "source_revision": source_revision,
            },
            "DATASET_PROVENANCE.json",
        ) == ("szl-holdings/calibration-kernel", source_revision)
        assert provenance_source(
            {
                "managed_by": "szl-holdings/calibration-kernel:deploy/hf",
                "source_revision": source_revision,
            },
            "publication-manifest.json",
        ) == ("szl-holdings/calibration-kernel", source_revision)
        checks.append("strict README source binding")
        source_reference_asset = Asset(
            asset_id="huggingface:space:szlholdings/calibration-reference",
            asset_type="space",
            source="huggingface",
            name="SZLHOLDINGS/calibration-reference",
            url="https://huggingface.co/spaces/SZLHOLDINGS/calibration-reference",
            status_label="LIVE",
            operational_status="RUNNING",
            observed_at=observed,
            metadata={
                "provenance_docs": [],
                "runtime_source": {
                    "status": "OBSERVED",
                    "domain": "calibration-reference.hf.space",
                    "source_repository": "szl-holdings/calibration-kernel",
                    "source_revision": source_revision,
                    "relation": "reference-only",
                    "alignment_state": "NOT_A_DIRECT_MIRROR",
                },
            },
        )
        reference_counts = attach_cross_estate_alignment(
            [assets[0], source_reference_asset],
            source_scope="AUTHENTICATED_COMPLETE",
        )
        assert reference_counts["SOURCE_REFERENCE_ONLY"] == 1
        checks.append("runtime source-reference boundary")
        scorecards, clusters, proposals = build_analysis(audit_id, assets)
        assert len(set(clusters.values())) == 1
        checks.append("duplicate clustering")
        assert all(name in scorecards[assets[0].asset_id].scores for name in SCORE_NAMES)
        checks.append("complete score contract")
        config = AuditConfig(domains=("example.test",))
        reports = [
            SourceReport(
                source="synthetic",
                status="MEASURED",
                scope="SELF_TEST",
                count=len(assets),
                observed_at=observed,
                elapsed_ms=1,
            )
        ]
        operating_fabric = evaluate_operating_fabric(
            audit_id,
            assets,
            reports,
            proposals,
            observed,
            receipt_chain=verify_receipt_chain(db_path),
        )
        assert len(operating_fabric["lanes"]) == 7
        assert all(
            action["execution_mode"] == "PROPOSE_ONLY"
            and action["approval"] == "REQUIRED"
            for action in operating_fabric["action_queue"]
        )
        proposal_gate = next(
            control
            for control in operating_fabric["controls"]
            if control["control_id"] == "governance.proposal_gate"
        )
        assert proposal_gate["state"] == "PASS"
        assert operating_fabric["summary"]["readiness_to_claim_fully_operational"] == "BLOCKED"
        checks.append("seven-lane defensive operating fabric")
        evidence_path = root / "operating-evidence.json"
        evidence_payload = evidence_template()
        evidence_now = parse_datetime(observed)
        assert evidence_now is not None
        for assertion in evidence_payload["assertions"]:
            assertion["observed_at"] = (evidence_now - dt.timedelta(minutes=5)).isoformat()
            assertion["expires_at"] = (evidence_now + dt.timedelta(days=1)).isoformat()
            assertion["reference"] = f"urn:szl:self-test:{assertion['control_id']}"
        write_json_atomic(evidence_path, evidence_payload)
        admitted_bundle = load_evidence_bundle(evidence_path)
        attested_fabric = evaluate_operating_fabric(
            audit_id,
            assets,
            reports,
            proposals,
            observed,
            receipt_chain=verify_receipt_chain(db_path),
            evidence_bundle=admitted_bundle,
        )
        people_controls = [
            control
            for control in attested_fabric["controls"]
            if control["lane"] == "people"
        ]
        assert people_controls and all(
            control["truth_label"] == "ATTESTED" for control in people_controls
        )
        assert attested_fabric["summary"]["readiness_to_claim_fully_operational"] == "BLOCKED"
        rejected_payload = evidence_template()
        rejected_payload["assertions"][0]["control_id"] = "cybersecurity.identity_mfa"
        rejected_path = root / "rejected-evidence.json"
        write_json_atomic(rejected_path, rejected_payload)
        try:
            load_evidence_bundle(rejected_path)
        except ValueError as exc:
            assert "not accepted" in str(exc)
        else:
            raise AssertionError("External evidence overrode a directly observed control")
        checks.append("bounded attested-evidence admission")
        receipt = persist_audit(
            db_path,
            audit_id=audit_id,
            started_at=observed,
            completed_at=observed,
            status="MEASURED",
            config=config,
            source_reports=reports,
            assets=assets,
            scorecards=scorecards,
            clusters=clusters,
            proposals=proposals,
            operating_fabric=operating_fabric,
        )
        assert receipt["receipt_hash"]
        checks.append("audit persistence")
        chain = verify_receipt_chain(db_path)
        assert chain["chain_valid"]
        checks.append("receipt chain")
        status = load_status(db_path)
        assert status["asset_count"] == len(assets)
        assert status["audit_id"] == audit_id
        checks.append("status projection")
        stored_fabric = load_operating_fabric(db_path)
        assert stored_fabric["summary"]["lane_count"] == 7
        assert len(stored_fabric["controls"]) == operating_fabric["summary"]["control_count"]
        checks.append("operating-fabric persistence")
        exported = {
            "status": status,
            "assets": load_assets(db_path),
            "proposals": load_proposals(db_path),
            "operating_fabric": stored_fabric,
        }
        write_json_atomic(export_path, exported)
        assert export_path.exists() and export_path.stat().st_size > 0
        checks.append("atomic JSON export")
        live_result = HttpResult(
            requested_url="https://example.test",
            final_url="https://example.test",
            status=200,
            headers={"content-type": "text/html"},
            body=b"<html><title>Real</title><body>Measured content that is operational.</body></html>",
            elapsed_ms=1,
        )
        assert classify_content(live_result, live_result.body.decode())[0] == "LIVE"
        checks.append("honesty labels")
        roadmap_result = dataclasses.replace(
            live_result,
            body=(
                b"<html><title>Evidence registry</title><body>"
                + b"Measured operational evidence. " * 80
                + b"A separate capability remains on the roadmap.</body></html>"
            ),
        )
        assert classify_content(roadmap_result, roadmap_result.body.decode())[0] == "LIVE"
        placeholder_result = dataclasses.replace(
            live_result,
            body=b"<html><title>Coming soon</title><body>Work in progress.</body></html>",
        )
        assert (
            classify_content(placeholder_result, placeholder_result.body.decode())[0]
            == "MODELED"
        )
        checks.append("placeholder precision")
        assert hf_truth_label(
            "space", {"runtime": {"stage": "RUNNING"}}
        ) == ("LIVE", "RUNNING")
        assert hf_truth_label(
            "space", {"runtime": {"stage": "BUILD_ERROR"}}
        ) == ("BROKEN", "BUILD_ERROR")
        assert hf_truth_label(
            "space", {"runtime": {"stage": "SLEEPING"}}
        ) == ("UNAVAILABLE", "SLEEPING")
        checks.append("Hugging Face runtime truth labels")
        try:
            normalize_domain("https://operator:secret@example.test")
        except ValueError as exc:
            assert "must not include credentials" in str(exc)
        else:
            raise AssertionError("credential-bearing domain URL was accepted")
        checks.append("secret-safe domain normalization")
    return {
        "status": "PASS",
        "checks": checks,
        "check_count": len(checks),
        "version": APP_VERSION,
    }


def add_db_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB,
        help=f"SQLite database path (default: {DEFAULT_DB})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(__file__).name,
        description="Governed, read-only SZL estate inventory and control plane",
    )
    parser.add_argument("--version", action="version", version=APP_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run a live, read-only estate audit",
    )
    add_db_argument(audit_parser)
    audit_parser.add_argument("--github-org", default=DEFAULT_GITHUB_ORG)
    audit_parser.add_argument("--hf-org", default=DEFAULT_HF_ORG)
    audit_parser.add_argument(
        "--hf-space",
        action="append",
        dest="hf_spaces",
        help="Explicit owner/name Space to observe; repeat for cross-owner Spaces",
    )
    audit_parser.add_argument(
        "--domain",
        action="append",
        dest="domains",
        help="Domain to probe; repeat for multiple domains",
    )
    audit_parser.add_argument(
        "--deep",
        action="store_true",
        help="Request privileged/deeper metadata where credentials permit",
    )
    audit_parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    audit_parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    audit_parser.add_argument("--max-pages", type=int, default=20)
    audit_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_EXPORT,
        help=f"Latest audit JSON path (default: {DEFAULT_EXPORT})",
    )
    audit_parser.add_argument(
        "--evidence",
        type=Path,
        help="Optional szl.operating-evidence/v1 JSON bundle for external-only controls",
    )

    status_parser = subparsers.add_parser("status", help="Show the latest audit status")
    add_db_argument(status_parser)

    export_parser = subparsers.add_parser(
        "export",
        help="Export the latest database projection",
    )
    add_db_argument(export_parser)
    export_parser.add_argument("--output", type=Path, default=DEFAULT_EXPORT)

    verify_parser = subparsers.add_parser(
        "verify-receipts",
        help="Verify the local receipt hash chain and signatures",
    )
    add_db_argument(verify_parser)

    operating_parser = subparsers.add_parser(
        "operating-report",
        help="Show the latest seven-lane defensive operating-fabric evaluation",
    )
    add_db_argument(operating_parser)
    operating_parser.add_argument("--lane", choices=LANE_ORDER)
    operating_parser.add_argument(
        "--state",
        choices=("PASS", "PARTIAL", "FAIL", "UNAVAILABLE"),
    )
    operating_parser.add_argument("--output", type=Path)

    template_parser = subparsers.add_parser(
        "evidence-template",
        help="Emit a template for external-only operating evidence",
    )
    template_parser.add_argument("--output", type=Path)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Serve the local dashboard and read-only API",
    )
    add_db_argument(serve_parser)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Permit non-loopback binding; requires SZL_CONTROL_TOKEN",
    )

    subparsers.add_parser("self-test", help="Run deterministic built-in checks")
    return parser


def command_export(db_path: Path, output_path: Path) -> dict[str, Any]:
    payload = {
        "status": load_status(db_path),
        "assets": load_assets(db_path, limit=1000),
        "proposals": load_proposals(db_path, limit=1000),
        "receipts": load_receipts(db_path, limit=1000),
        "operating_fabric": load_operating_fabric(db_path),
    }
    write_json_atomic(output_path, payload)
    return {
        "status": "EXPORTED",
        "output": str(output_path),
        "asset_count": len(payload["assets"]),
        "proposal_count": len(payload["proposals"]),
        "receipt_count": len(payload["receipts"]),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "self-test":
            print(pretty_json(self_test()))
            return 0
        if args.command == "evidence-template":
            payload = evidence_template()
            if args.output:
                write_json_atomic(args.output.resolve(), payload)
                print(pretty_json({"status": "WRITTEN", "output": str(args.output.resolve())}))
            else:
                print(pretty_json(payload))
            return 0
        db_path = args.db.resolve()
        if args.command == "audit":
            if args.timeout <= 0:
                raise ValueError("--timeout must be positive")
            if not 1 <= args.workers <= 32:
                raise ValueError("--workers must be between 1 and 32")
            if not 1 <= args.max_pages <= 100:
                raise ValueError("--max-pages must be between 1 and 100")
            config = AuditConfig(
                github_org=args.github_org,
                hf_org=args.hf_org,
                hf_spaces=normalize_hf_spaces(args.hf_spaces or []),
                domains=tuple(args.domains or DEFAULT_DOMAINS),
                deep=args.deep,
                timeout=args.timeout,
                workers=args.workers,
                max_pages=args.max_pages,
            )
            evidence_bundle = load_evidence_bundle(
                args.evidence.resolve() if args.evidence else None
            )
            payload = run_audit(
                config,
                db_path,
                args.output.resolve(),
                evidence_bundle=evidence_bundle,
            )
            summary = {
                "status": payload["meta"]["status"],
                "audit_id": payload["meta"]["audit_id"],
                "asset_count": payload["summary"]["asset_count"],
                "proposal_count": payload["summary"]["proposal_count"],
                "duplicate_cluster_count": payload["summary"][
                    "duplicate_cluster_count"
                ],
                "source_reports": payload["source_reports"],
                "receipt": payload["receipt"],
                "operating_fabric": payload["operating_fabric"]["summary"],
                "database": str(db_path),
                "output": str(args.output.resolve()),
            }
            print(pretty_json(summary))
            return 0 if payload["meta"]["status"] in {"MEASURED", "PARTIAL"} else 2
        if args.command == "status":
            print(pretty_json(load_status(db_path)))
            return 0
        if args.command == "export":
            print(pretty_json(command_export(db_path, args.output.resolve())))
            return 0
        if args.command == "verify-receipts":
            result = verify_receipt_chain(db_path)
            print(pretty_json(result))
            return 0 if result["chain_valid"] else 3
        if args.command == "operating-report":
            result = load_operating_fabric(db_path, lane=args.lane, state=args.state)
            if args.output:
                write_json_atomic(args.output.resolve(), result)
                print(
                    pretty_json(
                        {
                            "status": "WRITTEN",
                            "output": str(args.output.resolve()),
                            "summary": result["summary"],
                        }
                    )
                )
            else:
                print(pretty_json(result))
            return 0
        if args.command == "serve":
            serve(db_path, args.host, args.port, args.allow_remote)
            return 0
        raise RuntimeError(f"Unhandled command: {args.command}")
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(
            pretty_json(
                {
                    "status": "FAILED",
                    "error_type": type(exc).__name__,
                    "error": sanitize_error(exc),
                }
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
