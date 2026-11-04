"""Evidence-bound defensive and cross-lane operating fabric for Estate OS.

This module evaluates observed estate assets.  It never executes a response or
changes an external system: every suggested response is emitted as a governed,
proposal-only action.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


FABRIC_SCHEMA = "szl.operating-fabric/v1"
EVIDENCE_SCHEMA = "szl.operating-evidence/v1"
LANE_ORDER = (
    "cybersecurity",
    "product",
    "engineering",
    "data_ai",
    "operations",
    "people",
    "governance",
)
MAX_EVIDENCE_BYTES = 1_000_000
EXTERNAL_CONTROL_IDS = {
    "operations.restore_drill",
    "people.security_training",
    "people.incident_ownership",
}
STATE_SCORE = {"PASS": 100.0, "PARTIAL": 50.0, "FAIL": 0.0}
GITHUB_COMPLETE_SCOPES = {"AUTHENTICATED_COMPLETE", "ORGANIZATION_COMPLETE"}
WEB_SECURITY_HEADERS = (
    "content-security-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
)
HSTS_MIN_MAX_AGE_SECONDS = 31_536_000
APPROVED_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
CSP_REQUIRED_DIRECTIVES = {
    "base-uri",
    "default-src",
    "form-action",
    "frame-ancestors",
    "object-src",
}
CSP_UNSAFE_SOURCE_TOKENS = {
    "'unsafe-eval'",
    "'unsafe-inline'",
    "'wasm-unsafe-eval'",
    "blob:",
    "data:",
    "http:",
    "https:",
}

HF_EMBED_FRAME_ANCESTOR_HOST_TOKENS = {
    "https://huggingface.co",
    "https://*.huggingface.co",
    "https://*.hf.space",
}


def _parse_csp_directives(value: str) -> dict[str, list[str]] | None:
    directives: dict[str, list[str]] = {}
    for segment in value.split(";"):
        parts = segment.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name in directives or re.fullmatch(r"[a-z][a-z0-9-]*", name) is None:
            return None
        directives[name] = [token.lower() for token in parts[1:]]
    return directives


def _is_hf_embed_frame_ancestors(directives: dict[str, list[str]]) -> bool:
    """Product surfaces embedded on Hugging Face Spaces use an allow-list."""
    if set(directives) != {"frame-ancestors"}:
        return False
    sources = directives["frame-ancestors"]
    if "'self'" not in sources:
        return False
    hosts = {token for token in sources if token != "'self'"}
    return bool(hosts) and hosts <= HF_EMBED_FRAME_ANCESTOR_HOST_TOKENS



def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _metadata(item: Any) -> dict[str, Any]:
    value = _value(item, "metadata", {})
    return value if isinstance(value, dict) else {}


def _asset_id(item: Any) -> str:
    return str(_value(item, "asset_id", "") or "")


def _content_security_policy_state(
    value: Any, report_only: Any = None
) -> tuple[bool, str]:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        return False, "content-security-policy is missing or invalid"
    directives = _parse_csp_directives(value)
    if directives is None:
        return False, "content-security-policy contains duplicate or invalid directives"

    # HF-embed product profile (a-11-oy.com / a11oy Space): enforced CSP is
    # intentionally frame-ancestors-only so Hugging Face can embed the product.
    # Resource directives ship on Content-Security-Policy-Report-Only while the
    # product migrates; requiring fail-closed enforced CSP would reject the
    # published dual-header design. Proof domain a11oy.net keeps full enforced CSP.
    if _is_hf_embed_frame_ancestors(directives):
        if not isinstance(report_only, str) or not report_only.strip():
            return (
                False,
                "content-security-policy HF-embed profile requires report-only resource policy",
            )
        ro = _parse_csp_directives(report_only)
        if ro is None or "default-src" not in ro:
            return False, "content-security-policy report-only missing default-src"
        return (
            True,
            "content-security-policy HF-embed enforced frame-ancestors + report-only resource policy present",
        )

    missing = sorted(CSP_REQUIRED_DIRECTIVES - set(directives))
    if missing:
        return False, f"content-security-policy missing directives={','.join(missing)}"
    default_sources = directives["default-src"]
    if not default_sources or any(
        "*" in token or token in CSP_UNSAFE_SOURCE_TOKENS
        for token in default_sources
    ):
        return False, "content-security-policy default-src is not fail-closed"
    for directive in ("object-src", "frame-ancestors", "base-uri", "form-action"):
        sources = directives[directive]
        allowed = {"'none'"} if directive == "object-src" else {"'none'", "'self'"}
        if len(sources) != 1 or sources[0] not in allowed:
            return False, f"content-security-policy {directive} is not restrictive"
    for directive in ("script-src", "script-src-elem", "script-src-attr"):
        if directive not in directives:
            continue
        sources = directives[directive]
        if not sources or any(
            "*" in token or token in CSP_UNSAFE_SOURCE_TOKENS for token in sources
        ):
            return False, f"content-security-policy {directive} permits unsafe sources"
    if "script-src" not in directives and any(
        "*" in token or token in CSP_UNSAFE_SOURCE_TOKENS
        for token in default_sources
    ):
        return False, "content-security-policy permits unsafe script sources"
    return True, "content-security-policy is fail-closed"


def _strict_transport_security_state(value: Any) -> tuple[bool, str]:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        return False, "strict-transport-security is missing or invalid"
    directives = [part.strip().lower() for part in value.split(";") if part.strip()]
    max_age_values = [
        part.split("=", 1)[1]
        for part in directives
        if part.startswith("max-age=")
    ]
    if (
        len(max_age_values) != 1
        or re.fullmatch(r"[0-9]+", max_age_values[0]) is None
    ):
        return False, "strict-transport-security max-age policy is insufficient"
    # HTTP delta-seconds is decimal text. Compare its magnitude without an int
    # conversion, which can raise on an externally supplied long digit string.
    max_age = max_age_values[0].lstrip("0") or "0"
    minimum = str(HSTS_MIN_MAX_AGE_SECONDS)
    if (len(max_age), max_age) < (len(minimum), minimum):
        return False, "strict-transport-security max-age policy is insufficient"
    return True, "strict-transport-security max-age policy is satisfied"


def _content_type_options_state(value: Any) -> tuple[bool, str]:
    passed = isinstance(value, str) and value.strip().lower() == "nosniff"
    return passed, (
        "x-content-type-options is nosniff"
        if passed
        else "x-content-type-options must be exactly nosniff"
    )


def _referrer_policy_state(value: Any) -> tuple[bool, str]:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        return False, "referrer-policy is missing or invalid"
    policies = [part.strip().lower() for part in value.split(",") if part.strip()]
    passed = bool(policies) and all(
        policy in APPROVED_REFERRER_POLICIES for policy in policies
    )
    return passed, (
        "referrer-policy is in the non-leaking allowlist"
        if passed
        else "referrer-policy is not in the non-leaking allowlist"
    )


def assess_web_security_headers(values: Any) -> dict[str, dict[str, Any]] | None:
    """Semantically assess normalized raw header values; booleans never count."""

    if not isinstance(values, dict):
        return None
    validators = {
        "content-security-policy": _content_security_policy_state,
        "referrer-policy": _referrer_policy_state,
        "strict-transport-security": _strict_transport_security_state,
        "x-content-type-options": _content_type_options_state,
    }
    assessment: dict[str, dict[str, Any]] = {}
    for name, validator in validators.items():
        if name == "content-security-policy":
            passed, detail = _content_security_policy_state(
                values.get(name),
                report_only=values.get("content-security-policy-report-only"),
            )
        else:
            passed, detail = validator(values.get(name))
        assessment[name] = {"passed": passed, "detail": detail}
    return assessment


def _measured_branch_rules(item: Any) -> dict[str, Any] | None:
    rules = _metadata(item).get("default_branch_rules")
    if not isinstance(rules, dict) or rules.get("status") != "MEASURED":
        return None
    values = rules.get("types")
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        return None
    pull_request = rules.get("pull_request")
    if pull_request is not None and not isinstance(pull_request, dict):
        return None
    required_status_checks = rules.get("required_status_checks")
    if not isinstance(required_status_checks, list) or any(
        not isinstance(value, str) for value in required_status_checks
    ):
        return None
    return rules


def _measured_branch_rule_types(item: Any) -> set[str] | None:
    rules = _measured_branch_rules(item)
    if rules is None:
        return None
    return {value for value in rules["types"] if value}


def _branch_minimum_failures(item: Any) -> list[str] | None:
    rules = _measured_branch_rules(item)
    if rules is None:
        return None
    rule_types = {value for value in rules["types"] if value}
    pull_request = rules.get("pull_request")
    pull_request = pull_request if isinstance(pull_request, dict) else {}
    approvals = pull_request.get("required_approving_review_count")
    required_status_checks = [
        value for value in rules["required_status_checks"] if value.strip()
    ]
    requirements = {
        "non_fast_forward_rule": "non_fast_forward" in rule_types,
        "pull_request_rule": "pull_request" in rule_types,
        "required_status_checks_rule": "required_status_checks" in rule_types,
        "at_least_one_approval": (
            isinstance(approvals, int)
            and not isinstance(approvals, bool)
            and approvals >= 1
        ),
        "review_thread_resolution": (
            pull_request.get("required_review_thread_resolution") is True
        ),
        "nonempty_required_status_checks": bool(required_status_checks),
    }
    return sorted(name for name, passed in requirements.items() if not passed)


def _parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def load_evidence_bundle(path: Path | None) -> dict[str, Any] | None:
    """Load and validate optional operator evidence without treating it as measured."""

    if path is None:
        return None
    size = path.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"Evidence bundle exceeds {MAX_EVIDENCE_BYTES} bytes")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError(f"Evidence bundle schema must be {EVIDENCE_SCHEMA}")
    assertions = payload.get("assertions")
    if not isinstance(assertions, list):
        raise ValueError("Evidence bundle assertions must be a list")
    seen: set[str] = set()
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise ValueError("Each evidence assertion must be an object")
        control_id = assertion.get("control_id")
        if control_id not in EXTERNAL_CONTROL_IDS:
            raise ValueError(
                f"External evidence is not accepted for control {control_id!r}"
            )
        if control_id in seen:
            raise ValueError(f"Duplicate evidence assertion for {control_id}")
        seen.add(str(control_id))
        if assertion.get("state") not in {"PASS", "PARTIAL", "FAIL"}:
            raise ValueError(f"Invalid state for {control_id}")
        observed_at = _parse_time(assertion.get("observed_at"))
        expires_at = _parse_time(assertion.get("expires_at"))
        if observed_at is None:
            raise ValueError(
                f"observed_at must be an ISO-8601 timestamp for {control_id}"
            )
        if expires_at is None:
            raise ValueError(
                f"expires_at must be an ISO-8601 timestamp for {control_id}"
            )
        if expires_at <= observed_at:
            raise ValueError(
                f"expires_at must be later than observed_at for {control_id}"
            )
        if observed_at > dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5):
            raise ValueError(f"observed_at is in the future for {control_id}")
        for required in ("source", "reference", "owner"):
            if (
                not isinstance(assertion.get(required), str)
                or not assertion[required].strip()
            ):
                raise ValueError(f"{required} is required for {control_id}")
            if "replace-me" in assertion[required].lower():
                raise ValueError(
                    f"{required} still contains a placeholder for {control_id}"
                )
    return {**payload, "bundle_sha256": _digest(payload)}


def evidence_template() -> dict[str, Any]:
    observed_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return {
        "schema": EVIDENCE_SCHEMA,
        "assertions": [
            {
                "control_id": "operations.restore_drill",
                "state": "PASS",
                "observed_at": observed_at.isoformat(),
                "expires_at": (observed_at + dt.timedelta(days=90)).isoformat(),
                "source": "restore-test receipt",
                "reference": "urn:szl:restore-test:replace-me",
                "owner": "incident-commander",
            },
            {
                "control_id": "people.security_training",
                "state": "PASS",
                "observed_at": observed_at.isoformat(),
                "expires_at": (observed_at + dt.timedelta(days=365)).isoformat(),
                "source": "training-system export",
                "reference": "urn:szl:training:replace-me",
                "owner": "security-lead",
            },
            {
                "control_id": "people.incident_ownership",
                "state": "PASS",
                "observed_at": observed_at.isoformat(),
                "expires_at": (observed_at + dt.timedelta(days=30)).isoformat(),
                "source": "on-call roster receipt",
                "reference": "urn:szl:on-call:replace-me",
                "owner": "operations-lead",
            },
        ],
    }


def _control(
    control_id: str,
    lane: str,
    title: str,
    *,
    state: str,
    truth_label: str,
    critical: bool,
    severity: str,
    owner_role: str,
    observed_at: str,
    evidence: Iterable[str],
    metric: dict[str, Any] | None = None,
    playbook: str,
) -> dict[str, Any]:
    return {
        "control_id": control_id,
        "lane": lane,
        "title": title,
        "state": state,
        "truth_label": truth_label,
        "critical": critical,
        "severity": severity,
        "owner_role": owner_role,
        "observed_at": observed_at,
        "evidence": list(evidence),
        "metric": metric or {},
        "response": {
            "mode": "PROPOSE_ONLY",
            "approval": "REQUIRED",
            "playbook": playbook,
        },
    }


def _coverage_control(
    control_id: str,
    lane: str,
    title: str,
    *,
    passed: int,
    measured: int,
    total: int,
    scope_partial: bool,
    critical: bool,
    severity: str,
    owner_role: str,
    observed_at: str,
    unit: str,
    playbook: str,
    failed_asset_ids: Iterable[str] = (),
    unassessed_asset_ids: Iterable[str] = (),
    metric_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    failed_ids = sorted({str(asset_id) for asset_id in failed_asset_ids if asset_id})
    unassessed_ids = sorted(
        {str(asset_id) for asset_id in unassessed_asset_ids if asset_id}
    )
    if total == 0 or measured == 0:
        state = "UNAVAILABLE"
        truth_label = "UNAVAILABLE"
    elif passed == total and measured == total and not scope_partial:
        state = "PASS"
        truth_label = "MEASURED"
    elif passed == 0 and measured == total:
        state = "FAIL"
        truth_label = "MEASURED" if not scope_partial else "PARTIAL"
    else:
        state = "PARTIAL"
        truth_label = "PARTIAL"
    metric = {
        "passed": passed,
        "assessed": measured,
        "total": total,
        "scope_partial": scope_partial,
        "failed_asset_ids": failed_ids,
        "unassessed_asset_ids": unassessed_ids,
    }
    if metric_extra:
        metric.update(metric_extra)
    return _control(
        control_id,
        lane,
        title,
        state=state,
        truth_label=truth_label,
        critical=critical,
        severity=severity,
        owner_role=owner_role,
        observed_at=observed_at,
        evidence=[
            f"{passed}/{total} {unit} passed; {measured}/{total} were assessable"
        ],
        metric=metric,
        playbook=playbook,
    )


def _external_control(
    control_id: str,
    lane: str,
    title: str,
    *,
    critical: bool,
    severity: str,
    owner_role: str,
    observed_at: str,
    assertions: dict[str, dict[str, Any]],
    bundle_sha256: str | None,
    playbook: str,
) -> dict[str, Any]:
    assertion = assertions.get(control_id)
    if assertion is None:
        return _control(
            control_id,
            lane,
            title,
            state="UNAVAILABLE",
            truth_label="UNAVAILABLE",
            critical=critical,
            severity=severity,
            owner_role=owner_role,
            observed_at=observed_at,
            evidence=["No current external evidence assertion was supplied"],
            playbook=playbook,
        )
    expires_at = _parse_time(assertion.get("expires_at"))
    evaluation_time = _parse_time(observed_at) or dt.datetime.now(dt.timezone.utc)
    expired = expires_at is None or expires_at < evaluation_time
    state = "UNAVAILABLE" if expired else str(assertion["state"])
    evidence = [
        f"Operator-attested source={assertion['source']}; reference={assertion['reference']}",
        f"owner={assertion['owner']}; expires_at={assertion['expires_at']}",
    ]
    if bundle_sha256:
        evidence.append(f"bundle_sha256={bundle_sha256}")
    if expired:
        evidence.append("Assertion expired before this evaluation")
    return _control(
        control_id,
        lane,
        title,
        state=state,
        truth_label="UNAVAILABLE" if expired else "ATTESTED",
        critical=critical,
        severity=severity,
        owner_role=owner_role,
        observed_at=str(assertion.get("observed_at") or observed_at),
        evidence=evidence,
        playbook=playbook,
    )


def evaluate_operating_fabric(
    audit_id: str,
    assets: list[Any],
    source_reports: list[Any],
    proposals: list[dict[str, Any]],
    observed_at: str,
    *,
    receipt_chain: dict[str, Any] | None = None,
    evidence_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate all seven operating lanes from directly observed evidence."""

    reports = {_value(report, "source"): report for report in source_reports}
    github_report = reports.get("github")
    github_source_partial = (
        github_report is None or _value(github_report, "status") != "MEASURED"
    )
    github_repo_scope_partial = (
        github_source_partial
        or _value(github_report, "scope") not in GITHUB_COMPLETE_SCOPES
    )
    domain_report = reports.get("domains")
    hf_report = reports.get("huggingface")
    orgs = [
        a
        for a in assets
        if _value(a, "source") == "github" and _value(a, "asset_type") == "organization"
    ]
    repos = [
        a
        for a in assets
        if _value(a, "source") == "github"
        and _value(a, "asset_type") == "repo"
        and _value(a, "operational_status") == "ACTIVE"
    ]
    routes = [
        a
        for a in assets
        if _value(a, "source") == "domains" and _value(a, "asset_type") == "route"
    ]
    hf_assets = [
        a
        for a in assets
        if _value(a, "source") == "huggingface"
        and _value(a, "asset_type") in {"model", "dataset", "space"}
    ]
    controls: list[dict[str, Any]] = []

    mfa = _metadata(orgs[0]).get("two_factor_requirement_enabled") if orgs else None
    controls.append(
        _control(
            "cybersecurity.identity_mfa",
            "cybersecurity",
            "Organization MFA enforcement",
            state="PASS" if mfa is True else "FAIL" if mfa is False else "UNAVAILABLE",
            truth_label=("PARTIAL" if github_source_partial else "MEASURED")
            if isinstance(mfa, bool)
            else "UNAVAILABLE",
            critical=True,
            severity="CRITICAL",
            owner_role="security-lead",
            observed_at=observed_at,
            evidence=[f"GitHub organization two_factor_requirement_enabled={mfa!r}"],
            playbook="Enforce organization MFA and verify recovery ownership.",
        )
    )

    secret_measured = 0
    secret_passed = 0
    secret_failed_ids: list[str] = []
    secret_unassessed_ids: list[str] = []
    for repo in repos:
        asset_id = _asset_id(repo)
        security = _metadata(repo).get("security_and_analysis")
        security = security if isinstance(security, dict) else {}
        scanning = security.get("secret_scanning")
        protection = security.get("secret_scanning_push_protection")
        if scanning == "enabled" and protection == "enabled":
            secret_measured += 1
            secret_passed += 1
        elif scanning == "disabled" or protection == "disabled":
            secret_measured += 1
            secret_failed_ids.append(asset_id)
        else:
            secret_unassessed_ids.append(asset_id)
    controls.append(
        _coverage_control(
            "cybersecurity.secret_protection",
            "cybersecurity",
            "Secret scanning and push protection",
            passed=secret_passed,
            measured=secret_measured,
            total=len(repos),
            scope_partial=github_repo_scope_partial,
            critical=True,
            severity="CRITICAL",
            owner_role="security-engineering",
            observed_at=observed_at,
            unit="active repositories",
            playbook="Propose enabling secret scanning and push protection on uncovered repositories.",
            failed_asset_ids=secret_failed_ids,
            unassessed_asset_ids=secret_unassessed_ids,
        )
    )

    header_passed = 0
    header_measured = 0
    header_failed_ids: list[str] = []
    header_unassessed_ids: list[str] = []
    header_failures_by_asset_id: dict[str, dict[str, str]] = {}
    for route in routes:
        asset_id = _asset_id(route)
        assessment = assess_web_security_headers(
            _metadata(route).get("security_header_values")
        )
        if assessment is not None:
            header_measured += 1
            failures = {
                name: str(result["detail"])
                for name, result in assessment.items()
                if result.get("passed") is not True
            }
            if not failures:
                header_passed += 1
            else:
                header_failed_ids.append(asset_id)
                header_failures_by_asset_id[asset_id] = failures
        else:
            header_unassessed_ids.append(asset_id)
    controls.append(
        _coverage_control(
            "cybersecurity.web_hardening",
            "cybersecurity",
            "Public web security headers",
            passed=header_passed,
            measured=header_measured,
            total=len(routes),
            scope_partial=domain_report is None
            or _value(domain_report, "status") != "MEASURED",
            critical=False,
            severity="HIGH",
            owner_role="platform-engineering",
            observed_at=observed_at,
            unit="observed routes",
            playbook="Propose HSTS, CSP, referrer-policy, and nosniff remediation for uncovered routes.",
            failed_asset_ids=header_failed_ids,
            unassessed_asset_ids=header_unassessed_ids,
            metric_extra={
                "required_headers": list(WEB_SECURITY_HEADERS),
                "hsts_min_max_age_seconds": HSTS_MIN_MAX_AGE_SECONDS,
                "failed_header_requirements_by_asset_id": (
                    header_failures_by_asset_id
                ),
            },
        )
    )

    live_routes = [
        route
        for route in routes
        if _value(route, "status_label") == "LIVE"
        and _value(route, "operational_status") == "REAL"
    ]
    controls.append(
        _coverage_control(
            "product.live_surface",
            "product",
            "Customer surface operational reality",
            passed=len(live_routes),
            measured=len(routes),
            total=len(routes),
            scope_partial=domain_report is None
            or _value(domain_report, "status") != "MEASURED",
            critical=True,
            severity="HIGH",
            owner_role="product-lead",
            observed_at=observed_at,
            unit="public routes",
            playbook="Propose repair or explicit modeled labeling for non-live customer routes.",
        )
    )
    trust_routes = [
        route
        for route in live_routes
        if any(
            token in str(_value(route, "name", "")).lower()
            for token in ("verify", "receipt", "status", "trust")
        )
    ]
    controls.append(
        _control(
            "product.customer_trust_surface",
            "product",
            "Live customer trust surface",
            state="PASS" if trust_routes else "FAIL" if routes else "UNAVAILABLE",
            truth_label="MEASURED"
            if routes and _value(domain_report, "status") == "MEASURED"
            else "PARTIAL"
            if routes
            else "UNAVAILABLE",
            critical=False,
            severity="MEDIUM",
            owner_role="product-lead",
            observed_at=observed_at,
            evidence=[
                f"{len(trust_routes)} live trust/verify/receipt/status routes observed"
            ],
            playbook="Propose a measured customer trust route backed by current evidence.",
        )
    )

    branch_measured = 0
    branch_passed = 0
    branch_failed_ids: list[str] = []
    branch_unassessed_ids: list[str] = []
    branch_failures_by_asset_id: dict[str, list[str]] = {}
    for repo in repos:
        asset_id = _asset_id(repo)
        protected = _metadata(repo).get("branch_protection_enabled")
        minimum_failures = _branch_minimum_failures(repo)
        if protected is False:
            branch_measured += 1
            branch_failed_ids.append(asset_id)
            branch_failures_by_asset_id[asset_id] = ["branch_not_protected"]
        elif protected is True and minimum_failures is not None:
            branch_measured += 1
            if not minimum_failures:
                branch_passed += 1
            else:
                branch_failed_ids.append(asset_id)
                branch_failures_by_asset_id[asset_id] = minimum_failures
        else:
            branch_unassessed_ids.append(asset_id)
    controls.append(
        _coverage_control(
            "engineering.branch_protection",
            "engineering",
            "Applicable default-branch protection rules",
            passed=branch_passed,
            measured=branch_measured,
            total=len(repos),
            scope_partial=github_repo_scope_partial,
            critical=True,
            severity="CRITICAL",
            owner_role="engineering-lead",
            observed_at=observed_at,
            unit="active repositories",
            playbook="Propose protected-branch rules through normal repository governance.",
            failed_asset_ids=branch_failed_ids,
            unassessed_asset_ids=branch_unassessed_ids,
            metric_extra={
                "required_rule_types": [
                    "non_fast_forward",
                    "pull_request",
                    "required_status_checks",
                ],
                "minimum_required_approving_review_count": 1,
                "required_review_thread_resolution": True,
                "required_status_check_count_minimum": 1,
                "failed_requirements_by_asset_id": branch_failures_by_asset_id,
            },
        )
    )
    signoff_measured = 0
    signoff_passed = 0
    signoff_failed_ids: list[str] = []
    signoff_unassessed_ids: list[str] = []
    web_only_signoff_ids: list[str] = []
    for repo in repos:
        asset_id = _asset_id(repo)
        web_signoff = _metadata(repo).get("web_commit_signoff_required")
        rule_types = _measured_branch_rule_types(repo)
        signatures_required = (
            "required_signatures" in rule_types if rule_types is not None else None
        )
        if web_signoff is False or signatures_required is False:
            signoff_measured += 1
            signoff_failed_ids.append(asset_id)
            if web_signoff is True and signatures_required is False:
                web_only_signoff_ids.append(asset_id)
        elif web_signoff is True and signatures_required is True:
            signoff_measured += 1
            signoff_passed += 1
        else:
            signoff_unassessed_ids.append(asset_id)
    controls.append(
        _coverage_control(
            "engineering.change_signoff",
            "engineering",
            "Web signoff plus signed-commit enforcement",
            passed=signoff_passed,
            measured=signoff_measured,
            total=len(repos),
            scope_partial=github_repo_scope_partial,
            critical=False,
            severity="HIGH",
            owner_role="engineering-lead",
            observed_at=observed_at,
            unit="active repositories",
            playbook="Propose signed-commit rules while retaining web signoff; verify DCO separately where policy requires it.",
            failed_asset_ids=signoff_failed_ids,
            unassessed_asset_ids=signoff_unassessed_ids,
            metric_extra={
                "web_signoff_only_asset_ids": sorted(web_only_signoff_ids),
                "required_rule_type": "required_signatures",
            },
        )
    )

    provenance_passed = 0
    provenance_measured = 0
    provenance_failed_ids: list[str] = []
    provenance_unassessed_ids: list[str] = []
    artifact_provenance_state_counts: dict[str, int] = {}
    for asset in hf_assets:
        decision = _metadata(asset).get("provenance_policy")
        artifact_provenance = (
            decision.get("artifact_provenance")
            if isinstance(decision, dict)
            else None
        )
        state = (
            str(artifact_provenance.get("state") or "")
            if isinstance(artifact_provenance, dict)
            else ""
        )
        state = state if state in {"PASS", "FAIL", "UNAVAILABLE"} else "UNAVAILABLE"
        artifact_provenance_state_counts[state] = (
            artifact_provenance_state_counts.get(state, 0) + 1
        )
        asset_id = _asset_id(asset)
        if state == "PASS":
            provenance_passed += 1
            provenance_measured += 1
        elif state == "FAIL":
            provenance_measured += 1
            provenance_failed_ids.append(asset_id)
        else:
            provenance_unassessed_ids.append(asset_id)
    controls.append(
        _coverage_control(
            "data_ai.source_provenance",
            "data_ai",
            "Verified artifact source provenance",
            passed=provenance_passed,
            measured=provenance_measured,
            total=len(hf_assets),
            scope_partial=(
                hf_report is None
                or _value(hf_report, "status") != "MEASURED"
                or _value(hf_report, "scope") != "ORGANIZATION_COMPLETE"
                or github_repo_scope_partial
            ),
            critical=True,
            severity="HIGH",
            owner_role="data-ai-lead",
            observed_at=observed_at,
            unit="Hub artifact assets",
            playbook=(
                "Propose exact immutable source bindings and independently verify "
                "the declared Git commit evidence."
            ),
            failed_asset_ids=provenance_failed_ids,
            unassessed_asset_ids=provenance_unassessed_ids,
            metric_extra={
                "artifact_provenance_state_counts": dict(
                    sorted(artifact_provenance_state_counts.items())
                )
            },
        )
    )
    card_assets = [
        a for a in hf_assets if _value(a, "asset_type") in {"model", "dataset"}
    ]
    card_values = [_metadata(asset).get("card_present") for asset in card_assets]
    controls.append(
        _coverage_control(
            "data_ai.asset_cards",
            "data_ai",
            "Model and dataset card coverage",
            passed=sum(value is True for value in card_values),
            measured=sum(isinstance(value, bool) for value in card_values),
            total=len(card_assets),
            scope_partial=hf_report is None
            or _value(hf_report, "status") != "MEASURED",
            critical=False,
            severity="MEDIUM",
            owner_role="data-ai-lead",
            observed_at=observed_at,
            unit="models and datasets",
            playbook="Propose evidence-bound cards for uncovered models and datasets.",
        )
    )

    report_values = list(reports.values())
    measured_reports = sum(
        _value(report, "status") == "MEASURED" for report in report_values
    )
    controls.append(
        _coverage_control(
            "operations.source_availability",
            "operations",
            "Estate source availability",
            passed=measured_reports,
            measured=len(report_values),
            total=len(report_values),
            scope_partial=False,
            critical=True,
            severity="HIGH",
            owner_role="operations-lead",
            observed_at=observed_at,
            unit="inventory sources",
            playbook="Propose connector or source remediation for partial and unavailable inventories.",
        )
    )

    assertions = {
        str(assertion.get("control_id")): assertion
        for assertion in (evidence_bundle or {}).get("assertions", [])
        if isinstance(assertion, dict)
    }
    bundle_sha256 = (evidence_bundle or {}).get("bundle_sha256")
    controls.append(
        _external_control(
            "operations.restore_drill",
            "operations",
            "Current restore-drill evidence",
            critical=True,
            severity="CRITICAL",
            owner_role="incident-commander",
            observed_at=observed_at,
            assertions=assertions,
            bundle_sha256=bundle_sha256,
            playbook="Run a non-destructive restore test and attach its governed receipt.",
        )
    )
    controls.append(
        _external_control(
            "people.security_training",
            "people",
            "Current role-based security training",
            critical=False,
            severity="MEDIUM",
            owner_role="people-lead",
            observed_at=observed_at,
            assertions=assertions,
            bundle_sha256=bundle_sha256,
            playbook="Collect current role-based training evidence without employee secrets.",
        )
    )
    controls.append(
        _external_control(
            "people.incident_ownership",
            "people",
            "Current incident ownership and on-call coverage",
            critical=True,
            severity="CRITICAL",
            owner_role="operations-lead",
            observed_at=observed_at,
            assertions=assertions,
            bundle_sha256=bundle_sha256,
            playbook="Attach a current on-call ownership receipt and escalation boundary.",
        )
    )

    proposals_gated = all(
        proposal.get("execution_mode") == "MANUAL_GOVERNANCE_GATE"
        and proposal.get("status") == "PROPOSED"
        for proposal in proposals
    )
    controls.append(
        _control(
            "governance.proposal_gate",
            "governance",
            "External actions remain proposal-only",
            state="PASS" if proposals_gated else "FAIL",
            truth_label="MEASURED",
            critical=True,
            severity="CRITICAL",
            owner_role="governance-owner",
            observed_at=observed_at,
            evidence=[
                f"{len(proposals)} proposals inspected; all_gated={proposals_gated}"
            ],
            playbook="Stop execution and repair any proposal that bypasses the governance gate.",
        )
    )
    allowed_truth = {"OBSERVED", "ARCHIVED", "LIVE", "BROKEN", "UNAVAILABLE", "MODELED"}
    invalid_truth = sorted(
        {
            str(_value(asset, "status_label"))
            for asset in assets
            if _value(asset, "status_label") not in allowed_truth
        }
    )
    controls.append(
        _control(
            "governance.truth_boundary",
            "governance",
            "Truth-label contract",
            state="PASS"
            if assets and not invalid_truth
            else "FAIL"
            if invalid_truth
            else "UNAVAILABLE",
            truth_label="MEASURED" if assets else "UNAVAILABLE",
            critical=True,
            severity="CRITICAL",
            owner_role="governance-owner",
            observed_at=observed_at,
            evidence=[f"{len(assets)} assets checked; invalid_labels={invalid_truth}"],
            playbook="Fail closed on unknown truth labels and repair the source adapter.",
        )
    )
    chain = receipt_chain or {}
    chain_count = int(chain.get("receipt_count") or 0)
    controls.append(
        _control(
            "governance.receipt_integrity",
            "governance",
            "Pre-audit receipt-chain integrity",
            state="PASS"
            if chain_count and chain.get("chain_valid") is True
            else "FAIL"
            if chain_count
            else "UNAVAILABLE",
            truth_label="MEASURED" if chain_count else "UNAVAILABLE",
            critical=True,
            severity="CRITICAL",
            owner_role="governance-owner",
            observed_at=observed_at,
            evidence=[
                f"prior_receipts={chain_count}; chain_valid={chain.get('chain_valid')!r}"
            ],
            playbook="Fail closed, preserve the database, and investigate any receipt-chain break.",
        )
    )

    lanes: list[dict[str, Any]] = []
    for lane_name in LANE_ORDER:
        lane_controls = [
            control for control in controls if control["lane"] == lane_name
        ]
        assessed = [
            control for control in lane_controls if control["state"] != "UNAVAILABLE"
        ]
        score = (
            round(
                sum(STATE_SCORE[control["state"]] for control in assessed)
                / len(assessed),
                1,
            )
            if assessed
            else None
        )
        critical_blockers = [
            control["control_id"]
            for control in lane_controls
            if control["critical"]
            and (control["state"] != "PASS" or control["truth_label"] != "MEASURED")
        ]
        if not assessed:
            assessment = "UNAVAILABLE"
        elif any(
            control["critical"] and control["state"] == "FAIL"
            for control in lane_controls
        ):
            assessment = "RED"
        elif any(
            control["state"] != "PASS" or control["truth_label"] != "MEASURED"
            for control in lane_controls
        ):
            assessment = "AMBER"
        else:
            assessment = "GREEN"
        lanes.append(
            {
                "lane": lane_name,
                "assessment": assessment,
                "score": score,
                "coverage": round(len(assessed) / len(lane_controls), 4)
                if lane_controls
                else 0.0,
                "control_count": len(lane_controls),
                "critical_blockers": critical_blockers,
                "claim_state": "SUPPORTED" if assessment == "GREEN" else "BLOCKED",
            }
        )

    action_queue: list[dict[str, Any]] = []
    priority_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
    state_rank = {"FAIL": 1, "PARTIAL": 2, "UNAVAILABLE": 3, "PASS": 4}
    for control in controls:
        if control["state"] == "PASS" and control["truth_label"] == "MEASURED":
            continue
        material = f"{audit_id}\n{control['control_id']}\n{control['state']}"
        action_queue.append(
            {
                "action_id": f"fabric-action-{hashlib.sha256(material.encode()).hexdigest()[:20]}",
                "control_id": control["control_id"],
                "lane": control["lane"],
                "priority": control["severity"],
                "state": control["state"],
                "owner_role": control["owner_role"],
                "execution_mode": "PROPOSE_ONLY",
                "approval": "REQUIRED",
                "playbook": control["response"]["playbook"],
            }
        )
    action_queue.sort(
        key=lambda action: (
            priority_rank.get(action["priority"], 9),
            state_rank.get(action["state"], 9),
            action["control_id"],
        )
    )
    overall_claim = (
        "SUPPORTED"
        if lanes and all(lane["claim_state"] == "SUPPORTED" for lane in lanes)
        else "BLOCKED"
    )
    truth_counts = {
        truth: sum(control["truth_label"] == truth for control in controls)
        for truth in ("MEASURED", "PARTIAL", "ATTESTED", "UNAVAILABLE")
    }
    return {
        "schema": FABRIC_SCHEMA,
        "audit_id": audit_id,
        "evaluated_at": observed_at,
        "execution_policy": "DEFENSIVE_READ_ONLY; RESPONSES_PROPOSE_ONLY; APPROVAL_REQUIRED",
        "summary": {
            "lane_count": len(lanes),
            "control_count": len(controls),
            "action_count": len(action_queue),
            "state_counts": {
                state: sum(control["state"] == state for control in controls)
                for state in ("PASS", "PARTIAL", "FAIL", "UNAVAILABLE")
            },
            "truth_counts": truth_counts,
            "evaluation_truth": (
                "MEASURED"
                if controls and truth_counts["MEASURED"] == len(controls)
                else "PARTIAL"
                if controls
                else "UNAVAILABLE"
            ),
            "assessment_counts": {
                state: sum(lane["assessment"] == state for lane in lanes)
                for state in ("GREEN", "AMBER", "RED", "UNAVAILABLE")
            },
            "readiness_to_claim_fully_operational": overall_claim,
        },
        "lanes": lanes,
        "controls": controls,
        "action_queue": action_queue,
    }
