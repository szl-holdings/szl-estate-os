"""Evidence-bound defensive and cross-lane operating fabric for Estate OS.

This module evaluates observed estate assets.  It never executes a response or
changes an external system: every suggested response is emitted as a governed,
proposal-only action.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
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


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _metadata(item: Any) -> dict[str, Any]:
    value = _value(item, "metadata", {})
    return value if isinstance(value, dict) else {}


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
) -> dict[str, Any]:
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
        metric={"passed": passed, "assessed": measured, "total": total},
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
        or _value(github_report, "scope") != "ORGANIZATION_COMPLETE"
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
    for repo in repos:
        security = _metadata(repo).get("security_and_analysis")
        security = security if isinstance(security, dict) else {}
        scanning = security.get("secret_scanning")
        protection = security.get("secret_scanning_push_protection")
        if scanning is not None or protection is not None:
            secret_measured += 1
            if scanning == "enabled" and protection == "enabled":
                secret_passed += 1
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
        )
    )

    header_passed = 0
    header_measured = 0
    for route in routes:
        headers = _metadata(route).get("security_headers")
        if isinstance(headers, dict):
            header_measured += 1
            if all(
                headers.get(name) is True
                for name in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                )
            ):
                header_passed += 1
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
            playbook="Propose HSTS, CSP, and nosniff header remediation for uncovered routes.",
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

    protected_values = [
        _metadata(repo).get("branch_protection_enabled") for repo in repos
    ]
    controls.append(
        _coverage_control(
            "engineering.branch_protection",
            "engineering",
            "Default branch protection",
            passed=sum(value is True for value in protected_values),
            measured=sum(isinstance(value, bool) for value in protected_values),
            total=len(repos),
            scope_partial=github_repo_scope_partial,
            critical=True,
            severity="CRITICAL",
            owner_role="engineering-lead",
            observed_at=observed_at,
            unit="active repositories",
            playbook="Propose protected-branch rules through normal repository governance.",
        )
    )
    signoff_values = [
        _metadata(repo).get("web_commit_signoff_required") for repo in repos
    ]
    controls.append(
        _coverage_control(
            "engineering.change_signoff",
            "engineering",
            "Web commit signoff requirement",
            passed=sum(value is True for value in signoff_values),
            measured=sum(isinstance(value, bool) for value in signoff_values),
            total=len(repos),
            scope_partial=github_repo_scope_partial,
            critical=False,
            severity="HIGH",
            owner_role="engineering-lead",
            observed_at=observed_at,
            unit="active repositories",
            playbook="Propose signoff enforcement without weakening existing protected flows.",
        )
    )

    alignment_states = [
        str((_metadata(asset).get("github_alignment") or {}).get("status") or "")
        for asset in hf_assets
    ]
    exact_states = {"EXACT_HEAD", "EXACT_RUNTIME_HEAD"}
    controls.append(
        _coverage_control(
            "data_ai.source_provenance",
            "data_ai",
            "Exact source provenance",
            passed=sum(state in exact_states for state in alignment_states),
            measured=sum(
                bool(state)
                and state not in {"EVIDENCE_UNAVAILABLE", "SOURCE_HEAD_UNAVAILABLE"}
                for state in alignment_states
            ),
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
            unit="Hub runtime/artifact assets",
            playbook="Propose exact immutable source bindings and verify runtime revision equality.",
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
