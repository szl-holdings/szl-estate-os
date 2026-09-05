from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from verify_estate_readiness import (
    PRODUCTION_EVIDENCE_INDEX_SCHEMA,
    PRODUCTION_SIGNATURE_ALGORITHM,
    RSA_SHA256_DIGEST_INFO_PREFIX,
    canonical_audit_payload,
    canonical_deployment_receipt_payload,
    deployment_url_identity_state,
    signature_state,
    verify as verify_readiness,
    verify_rsa_signature,
)


RSA_N = int(
    "c85428138c4e6e830e0e5bce6e2d9b17fa0ff20fb0868102a0937629dbb97afd"
    "6ce48f1ee0ae903063bb6a59636e3004745f838f9006f7e0b0dce67b9ba244ef"
    "49677db0f6d9606b740833e2d57cc85cdb9cf895ae70e458c63f3c36a0d7ee05"
    "e865824d98dcce9a485cf8d30fcb1df61a5a81a3231de377d5d919bb4d726041"
    "4446ba3775c471b6f701236e6b0a5c28e7660e75d0ce78c13200d165c9ad4c95"
    "bbbc6b6725f3ae26b310c1a749e19493cd60718fbf7bd2f271bb259921638c19a"
    "df242d10315beea9dd0197a9e4bbb4ed1c69ae71ec2bb2ceebb30396952f54af8"
    "e1fc63e95212849b1d91b220c0033f521489f2dda4d7d8f626fb47a4b52b3b",
    16,
)
RSA_E = 65537
RSA_D = int(
    "13c38a95b3f988f0fca2dd2bd9d13022af1eedb6ec06083e6e526ee52175d53e"
    "ff9f42e48749892972e3565fbb456f7ab02fa7f5398576792f658e50ea55a730"
    "aa44dab7925f9fd115083a23b6114db9e904fa44ca2bf0ac290b4d52f4b73082"
    "c66258554c22db0296e7cb24a93cc0cddccf1b2d9d1bd775397d1bd534aed5bf"
    "37f795c99745e3aa66e100b40a522f9f7873b55be6ec3dbea79dc594a90fe00c"
    "b79fe9034a2462a7d8c71d7d564669de93659a1c62516eab6598bb6d8b48594a"
    "0dac3df4d9c4442f7848549a4d366bf6ae51e33e09eaff8822928fd1e9dabdad"
    "71d49d2cbf41410d89d0c965121a7b7be91d789f608e6e41de7c76d938745f1",
    16,
)

VERIFICATION_TIME = datetime(2026, 8, 1, 20, 0, tzinfo=timezone.utc)
PRIMARY_REPOSITORY_ASSET_ID = "github:repo:szl-holdings/a11oy"
PRIMARY_DEPLOYMENT_ASSET_ID = "domain:route:a-11-oy.com/"
PRIMARY_DEPLOYMENT_URL = "https://a-11-oy.com/"


def verify(
    value: dict[str, object],
    contract: dict[str, object],
    profile: str,
    *,
    evidence_root: Path | None = None,
) -> dict[str, object]:
    return verify_readiness(
        value,
        contract,
        profile,
        evidence_root=evidence_root,
        verification_time=VERIFICATION_TIME,
    )


def manifest(requirements: dict[str, object] | None = None) -> dict[str, object]:
    production_requirements: dict[str, object] = {
        "authenticated_inventory": True,
        "critical_huggingface_alignment": ["EXACT_RUNTIME_HEAD"],
        "independent_asymmetric_evidence": True,
        "credential_backed_deployment_witness": True,
        "browser_e2e_and_accessibility": True,
        "restore_and_failure_domain_drill": True,
        "zero_active_critical_gaps": True,
    }
    if requirements is not None:
        production_requirements.update(requirements)
    return {
        "schema": "szl.estate-critical-surface/v1",
        "status": "CONTROL_CONTRACT",
        "baseline": {
            "source_minimums": {
                "github": 1,
                "huggingface": 1,
                "domains": 1,
            },
            "required_source_status": "MEASURED",
            "prohibited_status_labels": ["BROKEN"],
            "required_security_headers": [
                "content-security-policy",
                "referrer-policy",
                "strict-transport-security",
                "x-content-type-options",
            ],
        },
        "canonical_identities": {
            "github_organization": "szl-holdings",
            "huggingface_organization": "SZLHOLDINGS",
            "huggingface_spaces": ["SZLHOLDINGS/a11oy"],
            "domains": ["a-11-oy.com", "a11oy.net"],
        },
        "critical_assets": [
            {
                "asset_id": "github:repo:szl-holdings/a11oy",
                "tier": 0,
                "role": "test source repository",
                "public": True,
            },
            {
                "asset_id": "domain:route:a-11-oy.com/",
                "tier": 0,
                "role": "test deployment route",
                "public": True,
                "required_status": "LIVE",
            },
            {
                "asset_id": "huggingface:space:szlholdings/a11oy",
                "tier": 0,
                "role": "test deployment Space",
                "public": True,
                "required_status": "LIVE",
            },
        ],
        "production_recovery_contract": {
            "required_scenarios": ["primary-store-loss"],
        },
        "production_deployment_sources": {
            "domain:route:a-11-oy.com/": "github:repo:szl-holdings/a11oy",
            "huggingface:space:szlholdings/a11oy": "github:repo:szl-holdings/a11oy",
        },
        "known_gaps": [],
        "production_requirements": production_requirements,
        "production_policies": {
            "max_audit_age_seconds": 7200,
            "max_deployment_age_seconds": 86400,
            "max_browser_age_seconds": 7200,
            "max_restore_age_seconds": 2592000,
            "max_rto_seconds": 900,
            "max_rpo_seconds": 300,
        },
        "production_trusted_keys": {
            "test-key": {
                "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
                "modulus_hex": format(RSA_N, "x"),
                "exponent": RSA_E,
            }
        },
        "deployment_provider_trusted_keys": {
            "test-provider-key": {
                "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
                "provider": "github-deployments",
                "modulus_hex": format(RSA_N, "x"),
                "exponent": RSA_E,
            }
        },
    }


def single_deployment_manifest(
    requirements: dict[str, object] | None = None,
) -> dict[str, object]:
    contract = manifest(requirements)
    critical_assets = contract["critical_assets"]
    assert isinstance(critical_assets, list)
    contract["critical_assets"] = [
        asset
        for asset in critical_assets
        if isinstance(asset, dict)
        and not str(asset.get("asset_id") or "").startswith("huggingface:space:")
    ]
    contract["production_deployment_sources"] = {
        "domain:route:a-11-oy.com/": "github:repo:szl-holdings/a11oy"
    }
    return contract


def audit() -> dict[str, object]:
    return {
        "schema": "szl.estate-audit/v1",
        "meta": {
            "audit_id": "audit-20260801-1",
            "status": "UNAVAILABLE",
            "started_at": "2026-08-01T18:50:00Z",
            "completed_at": "2026-08-01T19:00:00Z",
        },
        "assets": [],
        "source_reports": [
            {
                "source": "github",
                "status": "MEASURED",
                "scope": "AUTHENTICATED_COMPLETE",
                "count": 0,
                "observed_at": "2026-08-01T18:55:00Z",
            },
            {
                "source": "huggingface",
                "status": "MEASURED",
                "scope": "AUTHENTICATED_COMPLETE",
                "count": 0,
                "observed_at": "2026-08-01T18:55:00Z",
            },
            {
                "source": "domains",
                "status": "MEASURED",
                "scope": "PUBLIC_NETWORK",
                "count": 0,
                "observed_at": "2026-08-01T18:55:00Z",
            },
        ],
        "receipt": {"signature_status": "ASYMMETRIC_VERIFIED"},
    }


def sign_payload(payload: bytes) -> str:
    width = (RSA_N.bit_length() + 7) // 8
    digest_info = RSA_SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(payload).digest()
    encoded = (
        b"\x00\x01"
        + (b"\xff" * (width - len(digest_info) - 3))
        + b"\x00"
        + digest_info
    )
    signature = pow(int.from_bytes(encoded, "big"), RSA_D, RSA_N).to_bytes(
        width, "big"
    )
    return base64.b64encode(signature).decode("ascii")


def sign_deployment_receipt(receipt: dict[str, object]) -> None:
    receipt["provider_signature"] = {
        "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
        "key_id": "test-provider-key",
        "signature_base64": "",
    }
    receipt["provider_signature"]["signature_base64"] = sign_payload(
        canonical_deployment_receipt_payload(receipt)
    )


def deployment_witness(
    *,
    repository_asset_id: str = PRIMARY_REPOSITORY_ASSET_ID,
    deployment_asset_id: str = PRIMARY_DEPLOYMENT_ASSET_ID,
    deployment_url: str = PRIMARY_DEPLOYMENT_URL,
    revision: str = "b" * 40,
    artifact_sha256: str = "c" * 64,
    receipt_id: str = "deployment-receipt-20260801-1",
) -> dict[str, object]:
    deployed_at = "2026-08-01T17:55:00Z"
    environment = "production"
    owner = "szl-holdings"
    bindings = {
        "repository_asset_id": repository_asset_id,
        "deployment_asset_id": deployment_asset_id,
        "deployment_revision": revision,
        "deployed_artifact_sha256": artifact_sha256,
        "deployed_at": deployed_at,
        "environment": environment,
        "deployment_url": deployment_url,
        "owner": owner,
    }
    receipt = {
        "schema": "szl.deployment-receipt/v1",
        "status": "VERIFIED",
        **bindings,
        "receipt_id": receipt_id,
        "provider": "github-deployments",
    }
    sign_deployment_receipt(receipt)
    return {
        "schema": "szl.estate-deployment-witness/v1",
        "status": "VERIFIED",
        **bindings,
        "credential_scope": "DEPLOYMENT_READ_ONLY",
        "deployment_receipt": receipt,
    }


def browser_artifact(
    report_path: str,
    report_sha256: str,
    witness: dict[str, object] | None = None,
) -> dict[str, object]:
    promoted = witness or deployment_witness()
    receipt = promoted["deployment_receipt"]
    assert isinstance(receipt, dict)
    return {
        "schema": "szl.estate-browser-evidence/v1",
        "status": "VERIFIED",
        "deployment_asset_id": promoted["deployment_asset_id"],
        "tested_url": promoted["deployment_url"],
        "tested_at": "2026-08-01T18:00:00Z",
        "deployment_revision": promoted["deployment_revision"],
        "deployed_artifact_sha256": promoted["deployed_artifact_sha256"],
        "deployment_receipt_id": receipt["receipt_id"],
        "browsers": [
            {"name": "chromium", "form_factor": "desktop", "status": "PASS"},
            {"name": "webkit", "form_factor": "mobile", "status": "PASS"},
        ],
        "checks": {
            name: "PASS"
            for name in (
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
            )
        },
        "report_path": report_path,
        "report_sha256": report_sha256,
    }


def restore_artifact(
    report_path: str,
    report_sha256: str,
    witness: dict[str, object] | None = None,
) -> dict[str, object]:
    promoted = witness or deployment_witness()
    receipt = promoted["deployment_receipt"]
    assert isinstance(receipt, dict)
    return {
        "schema": "szl.estate-restore-drill/v2",
        "status": "VERIFIED",
        "backup_id": "backup-20260801-1",
        "backup_manifest_sha256": "d" * 64,
        "source_deployment_asset_id": promoted["deployment_asset_id"],
        "source_deployment_url": promoted["deployment_url"],
        "source_deployment_revision": promoted["deployment_revision"],
        "source_deployed_artifact_sha256": promoted["deployed_artifact_sha256"],
        "source_deployment_receipt_id": receipt["receipt_id"],
        "source_environment": promoted["environment"],
        "recovery_target": {
            "target_id": "recovery:isolated:a11oy-us-east-2",
            "environment": "recovery",
            "failure_domain": "us-east-2",
        },
        "recovery_point_id": "checkpoint-20260801-1",
        "recovery_point_at": "2026-08-01T17:55:00Z",
        "failure_started_at": "2026-08-01T18:00:00Z",
        "restore_started_at": "2026-08-01T18:01:00Z",
        "completed_at": "2026-08-01T18:05:00Z",
        "service_restored_at": "2026-08-01T18:05:00Z",
        "rto_seconds": 300,
        "rpo_seconds": 300,
        "checks": {
            "backup_integrity": "PASS",
            "restored_data_integrity": "PASS",
            "service_readiness": "PASS",
            "receipt_persistence": "PASS",
        },
        "dependency_loss_scenarios": [
            {"name": "primary-store-loss", "status": "PASS"}
        ],
        "findings": [],
        "corrective_actions": [],
        "restore_status": "PASS",
        "failure_domain_status": "PASS",
        "report_path": report_path,
        "report_sha256": report_sha256,
    }


def write_report(
    root: Path,
    name: str,
    witness: dict[str, object] | None = None,
) -> tuple[str, str]:
    if "browser" in name:
        wrapper = browser_artifact("", "", witness)
        schema = "szl.estate-browser-report/v1"
    elif "restore" in name:
        wrapper = restore_artifact("", "", witness)
        schema = "szl.estate-restore-report/v1"
    else:
        raise ValueError("test report name must identify browser or restore evidence")
    bindings = {
        key: value
        for key, value in wrapper.items()
        if key not in {"schema", "status", "report_path", "report_sha256"}
    }
    payload = json.dumps(
        {"schema": schema, "status": "PASS", **bindings},
        sort_keys=True,
    ).encode("utf-8")
    path = root / name
    path.write_bytes(payload)
    return path.name, hashlib.sha256(payload).hexdigest()


def write_artifact(root: Path, name: str, artifact: dict[str, object]) -> dict[str, str]:
    path = root / name
    payload = json.dumps(artifact, sort_keys=True).encode("utf-8")
    path.write_bytes(payload)
    return {
        "artifact_path": path.name,
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
    }


def add_evidence_reference(
    value: dict[str, object],
    requirement: str,
    target_asset_id: str,
    reference: dict[str, str],
) -> None:
    production_evidence = value.setdefault("production_evidence", {})
    assert isinstance(production_evidence, dict)
    index = production_evidence.setdefault(
        requirement,
        {"schema": PRODUCTION_EVIDENCE_INDEX_SCHEMA, "artifacts": {}},
    )
    assert isinstance(index, dict)
    artifacts = index["artifacts"]
    assert isinstance(artifacts, dict)
    artifacts[target_asset_id] = reference


def indexed_evidence(
    references: dict[str, dict[str, str]],
    target_asset_id: str = PRIMARY_DEPLOYMENT_ASSET_ID,
) -> dict[str, object]:
    return {
        requirement: {
            "schema": PRODUCTION_EVIDENCE_INDEX_SCHEMA,
            "artifacts": {target_asset_id: reference},
        }
        for requirement, reference in references.items()
    }


def add_audited_deployment(
    value: dict[str, object], witness: dict[str, object] | None = None
) -> None:
    promoted = witness or deployment_witness()
    repository_asset_id = str(promoted["repository_asset_id"])
    deployment_asset_id = str(promoted["deployment_asset_id"])
    deployment_url = str(promoted["deployment_url"])
    revision = str(promoted["deployment_revision"])
    receipt = promoted["deployment_receipt"]
    assert isinstance(receipt, dict)
    edge = {
        "schema": "szl.audit-deployment-edge/v1",
        **{
            field: receipt[field]
            for field in (
                "repository_asset_id",
                "deployment_asset_id",
                "deployment_revision",
                "deployed_artifact_sha256",
                "deployed_at",
                "environment",
                "deployment_url",
                "owner",
                "receipt_id",
            )
        },
    }
    source, asset_type = (
        ("domains", "route")
        if deployment_asset_id.startswith("domain:route:")
        else ("huggingface", "space")
    )
    deployment_metadata: dict[str, object] = {
        "final_url": deployment_url,
        "deployment": edge,
    }
    if source == "huggingface":
        source_repository = repository_asset_id.removeprefix("github:repo:")
        deployment_metadata.update(
            {
                "github_alignment": {
                    "status": "EXACT_RUNTIME_HEAD",
                    "source_repository": source_repository,
                    "source_revision": revision,
                    "github_default_revision": revision,
                },
                "runtime_build": {
                    "status": "OBSERVED",
                    "state": "OBSERVED",
                    "revision": revision,
                },
                "provenance_docs": [
                    {
                        "status": "OBSERVED",
                        "binding_kind": "ARTIFACT_SOURCE",
                        "source_repository": source_repository,
                        "source_revision": revision,
                    }
                ],
            }
        )
    assets = value.setdefault("assets", [])
    assert isinstance(assets, list)
    assets[:] = [
        asset
        for asset in assets
        if isinstance(asset, dict)
        and asset.get("asset_id") not in {repository_asset_id, deployment_asset_id}
    ]
    assets.extend(
        [
        {
            "asset_id": repository_asset_id,
            "asset_type": "repo",
            "source": "github",
            "status_label": "OBSERVED",
            "operational_status": "ACTIVE",
            "observed_at": "2026-08-01T18:56:00Z",
            "url": "https://github.com/"
            + repository_asset_id.removeprefix("github:repo:"),
            "metadata": {"default_branch_sha": revision},
        },
        {
            "asset_id": deployment_asset_id,
            "asset_type": asset_type,
            "source": source,
            "status_label": "LIVE",
            "operational_status": "REAL",
            "observed_at": "2026-08-01T18:56:00Z",
            "url": deployment_url,
            "metadata": deployment_metadata,
        },
        ]
    )
    meta = value["meta"]
    assert isinstance(meta, dict)
    meta["status"] = "MEASURED"
    reports = value["source_reports"]
    assert isinstance(reports, list)
    for report in reports:
        assert isinstance(report, dict)
        report["count"] = sum(
            1
            for asset in assets
            if isinstance(asset, dict) and asset.get("source") == report.get("source")
        )


def sign(value: dict[str, object], key_id: str = "test-key") -> None:
    receipt = value["receipt"]
    assert isinstance(receipt, dict)
    receipt["asymmetric_signature"] = {
        "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signature_base64": "",
    }
    payload = canonical_audit_payload(value)
    receipt["asymmetric_signature"]["signature_base64"] = sign_payload(payload)


def check(report: dict[str, object], check_id: str) -> dict[str, str]:
    checks = report["checks"]
    assert isinstance(checks, list)
    return next(item for item in checks if item["id"] == check_id)


class ReadinessTests(unittest.TestCase):
    def test_baseline_accepts_only_known_local_evidence(self) -> None:
        self.assertEqual(signature_state("HMAC_SHA256", "baseline"), "PASS")
        self.assertEqual(signature_state("UNSIGNED", "baseline"), "WARN")

    def test_baseline_rejects_missing_or_invented_states(self) -> None:
        for status in ("UNAVAILABLE", "SIGNED", "VERIFIED", "UNKNOWN"):
            with self.subTest(status=status):
                self.assertEqual(signature_state(status, "baseline"), "FAIL")

    def test_production_requires_exact_signature_state_and_valid_rsa(self) -> None:
        contract = manifest({"independent_asymmetric_evidence": True})
        for status in ("UNSIGNED", "HMAC_SHA256", "VERIFIED", "UNKNOWN", ""):
            with self.subTest(status=status):
                value = audit()
                receipt = value["receipt"]
                assert isinstance(receipt, dict)
                receipt["signature_status"] = status
                sign(value)
                report = verify(value, contract, "production")
                self.assertEqual(
                    check(report, "evidence.independent_signature")["state"], "FAIL"
                )
                self.assertEqual(
                    check(
                        report,
                        "production.requirement.independent_asymmetric_evidence",
                    )["state"],
                    "FAIL",
                )

        value = audit()
        sign(value)
        report = verify(value, contract, "production")
        self.assertEqual(
            check(report, "evidence.independent_signature")["state"], "PASS"
        )

    def test_rsa_rejects_signature_representative_outside_modulus(self) -> None:
        width = (RSA_N.bit_length() + 7) // 8
        signature = {
            "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
            "key_id": "test-key",
            "signature_base64": base64.b64encode(
                RSA_N.to_bytes(width, "big")
            ).decode("ascii"),
        }
        state, detail = verify_rsa_signature(
            b"payload", signature, manifest()["production_trusted_keys"]
        )
        self.assertEqual(state, "FAIL")
        self.assertIn("outside the trusted RSA modulus", detail)

    def test_audit_payload_contract_fails_closed(self) -> None:
        valid = verify(audit(), manifest(), "baseline")
        self.assertEqual(check(valid, "audit.payload_contract")["state"], "PASS")

        missing_schema = audit()
        missing_schema.pop("schema")
        duplicate_source = audit()
        duplicate_source["source_reports"].append(
            dict(duplicate_source["source_reports"][0])
        )
        missing_source = audit()
        missing_source["source_reports"].pop()
        invalid_interval = audit()
        invalid_interval["meta"]["started_at"] = "2026-08-01T19:01:00Z"
        invalid_count = audit()
        invalid_count["source_reports"][0]["count"] = True
        pre_start_source = audit()
        pre_start_source["source_reports"][0]["observed_at"] = (
            "2026-08-01T18:49:59Z"
        )
        inconsistent_status = audit()
        inconsistent_status["meta"]["status"] = "MEASURED"
        invalid_receipt = audit()
        invalid_receipt["receipt"] = []

        for value in (
            missing_schema,
            duplicate_source,
            missing_source,
            invalid_interval,
            invalid_count,
            pre_start_source,
            inconsistent_status,
            invalid_receipt,
        ):
            with self.subTest(value=value):
                report = verify(value, manifest(), "baseline")
                self.assertEqual(
                    check(report, "audit.payload_contract")["state"], "FAIL"
                )

    def test_manifest_requires_baseline_and_critical_surface_contract(self) -> None:
        valid = verify(audit(), manifest(), "baseline")
        self.assertEqual(
            check(valid, "manifest.baseline_contract")["state"], "PASS"
        )

        missing_baseline = manifest()
        missing_baseline.pop("baseline")
        empty_baseline = manifest()
        empty_baseline["baseline"] = {}
        missing_critical_assets = manifest()
        missing_critical_assets.pop("critical_assets")
        empty_critical_assets = manifest()
        empty_critical_assets["critical_assets"] = []
        incomplete_sources = manifest()
        incomplete_sources["baseline"]["source_minimums"].pop("domains")
        incomplete_headers = manifest()
        incomplete_headers["baseline"]["required_security_headers"] = []
        malformed_prohibited_statuses = manifest()
        malformed_prohibited_statuses["baseline"]["prohibited_status_labels"] = [
            {}
        ]
        malformed_headers = manifest()
        malformed_headers["baseline"]["required_security_headers"] = [{}]
        missing_recovery_contract = manifest()
        missing_recovery_contract.pop("production_recovery_contract")
        missing_deployment_sources = manifest()
        missing_deployment_sources.pop("production_deployment_sources")
        invalid_repository_path = manifest()
        invalid_repository_path["critical_assets"][0]["asset_id"] = (
            "github:repo:szl-holdings/a11oy/extra"
        )

        for contract in (
            missing_baseline,
            empty_baseline,
            missing_critical_assets,
            empty_critical_assets,
            incomplete_sources,
            incomplete_headers,
            malformed_prohibited_statuses,
            malformed_headers,
            missing_recovery_contract,
            missing_deployment_sources,
            invalid_repository_path,
        ):
            with self.subTest(contract=contract):
                report = verify(audit(), contract, "baseline")
                self.assertEqual(
                    check(report, "manifest.baseline_contract")["state"], "FAIL"
                )

    def test_deployment_url_identity_is_derived_from_asset_id(self) -> None:
        contract = manifest()
        canonical = contract["canonical_identities"]
        assert isinstance(canonical, dict)
        spaces = canonical["huggingface_spaces"]
        assert isinstance(spaces, list)
        spaces.append("betterwithage/anatomy")
        passing_urls = (
            (
                "domain:route:a-11-oy.com/",
                "https://a-11-oy.com/",
            ),
            (
                "huggingface:space:szlholdings/a11oy",
                "https://huggingface.co/spaces/SZLHOLDINGS/a11oy",
            ),
            (
                "huggingface:space:betterwithage/anatomy",
                "https://huggingface.co/spaces/betterwithage/anatomy",
            ),
            (
                "huggingface:space:szlholdings/a11oy",
                "https://szlholdings-a11oy.hf.space/",
            ),
        )
        for asset_id, url in passing_urls:
            with self.subTest(asset_id=asset_id, url=url):
                self.assertEqual(
                    deployment_url_identity_state(contract, asset_id, url)[0],
                    "PASS",
                )

        failing_urls = (
            ("domain:route:a-11-oy.com/", "https://evil.example/"),
            ("domain:route:a-11-oy.com/", "https://a-11-oy.com/unbound"),
            (
                "huggingface:space:szlholdings/a11oy",
                "https://huggingface.co/spaces/SZLHOLDINGS/other",
            ),
            (
                "huggingface:space:szlholdings/a11oy",
                "https://evil.example/",
            ),
        )
        for asset_id, url in failing_urls:
            with self.subTest(asset_id=asset_id, url=url):
                self.assertEqual(
                    deployment_url_identity_state(contract, asset_id, url)[0],
                    "FAIL",
                )

    def test_known_gap_register_fails_closed(self) -> None:
        valid = manifest()
        valid_report = verify(audit(), valid, "production")
        for check_id in (
            "gaps.contract",
            "gaps.critical",
            "production.requirement.zero_active_critical_gaps",
        ):
            self.assertEqual(check(valid_report, check_id)["state"], "PASS")

        missing = manifest()
        missing.pop("known_gaps")
        wrong_type = manifest()
        wrong_type["known_gaps"] = {}
        malformed_shape = manifest()
        malformed_shape["known_gaps"] = [{"id": "missing-fields"}]
        malformed_values = manifest()
        malformed_values["known_gaps"] = [
            {
                "id": "invalid-gap",
                "severity": "P4",
                "status": "UNKNOWN",
                "evidence": "",
            }
        ]
        duplicate_ids = manifest()
        duplicate_ids["known_gaps"] = [
            {
                "id": "duplicate-gap",
                "severity": "P2",
                "status": "ACTIVE",
                "evidence": "first",
            },
            {
                "id": "duplicate-gap",
                "severity": "P3",
                "status": "CLOSED",
                "evidence": "second",
            },
        ]

        for contract in (
            missing,
            wrong_type,
            malformed_shape,
            malformed_values,
            duplicate_ids,
        ):
            with self.subTest(contract=contract):
                report = verify(audit(), contract, "production")
                self.assertEqual(
                    check(report, "manifest.baseline_contract")["state"], "FAIL"
                )
                for check_id in (
                    "gaps.contract",
                    "gaps.critical",
                    "production.requirement.zero_active_critical_gaps",
                ):
                    self.assertEqual(check(report, check_id)["state"], "FAIL")

        active = manifest()
        active["known_gaps"] = [
            {
                "id": "active-critical-gap",
                "severity": "P1",
                "status": "ACTIVE",
                "evidence": "critical evidence is unavailable",
            }
        ]
        active_report = verify(audit(), active, "production")
        self.assertEqual(check(active_report, "gaps.contract")["state"], "PASS")
        self.assertEqual(check(active_report, "gaps.critical")["state"], "FAIL")
        self.assertEqual(
            check(
                active_report, "production.requirement.zero_active_critical_gaps"
            )["state"],
            "FAIL",
        )

        closed = manifest()
        closed["known_gaps"] = [
            {
                "id": "closed-critical-gap",
                "severity": "P0",
                "status": "CLOSED",
                "evidence": "closure evidence verified",
            }
        ]
        closed_report = verify(audit(), closed, "production")
        self.assertEqual(check(closed_report, "gaps.contract")["state"], "PASS")
        self.assertEqual(check(closed_report, "gaps.critical")["state"], "PASS")

    def test_production_rejects_asymmetric_label_without_signature(self) -> None:
        report = verify(
            audit(),
            manifest({"independent_asymmetric_evidence": True}),
            "production",
        )
        self.assertEqual(check(report, "evidence.independent_signature")["state"], "FAIL")

    def test_production_requires_measured_audit_status(self) -> None:
        value = audit()
        meta = value["meta"]
        assert isinstance(meta, dict)
        meta["status"] = "UNAVAILABLE"
        sign(value)
        report = verify(value, manifest(), "production")

        status_check = check(report, "production.audit_status")
        self.assertEqual(status_check["state"], "FAIL")
        self.assertIn("required=MEASURED", status_check["detail"])
        self.assertEqual(report["status"], "FAIL")

    def test_production_verifies_real_signature_and_rejects_tampering(self) -> None:
        value = audit()
        sign(value)
        contract = manifest({"independent_asymmetric_evidence": True})
        report = verify(value, contract, "production")
        self.assertEqual(check(report, "evidence.independent_signature")["state"], "PASS")
        value["assets"] = [{"asset_id": "tampered"}]
        tampered = verify(value, contract, "production")
        self.assertEqual(
            check(tampered, "evidence.independent_signature")["state"], "FAIL"
        )

    def test_production_rejects_unknown_signing_key(self) -> None:
        value = audit()
        sign(value, key_id="unknown-key")
        report = verify(
            value,
            manifest({"independent_asymmetric_evidence": True}),
            "production",
        )
        self.assertIn(
            "trusted key unavailable",
            check(report, "evidence.independent_signature")["detail"],
        )

    def test_production_requires_completeness_proven_scopes(self) -> None:
        value = audit()
        contract = manifest({"authenticated_inventory": True})
        report = verify(value, contract, "production")
        self.assertEqual(
            check(report, "production.requirement.authenticated_inventory")["state"],
            "PASS",
        )
        value["source_reports"][0]["scope"] = "AUTHENTICATED_VISIBILITY_UNKNOWN"
        failed = verify(value, contract, "production")
        self.assertEqual(check(failed, "scope.github")["state"], "FAIL")

    def test_production_enforces_signed_artifact_requirements(self) -> None:
        requirements = {
            "independent_asymmetric_evidence": True,
            "credential_backed_deployment_witness": True,
            "browser_e2e_and_accessibility": True,
            "restore_and_failure_domain_drill": True,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            witnesses = (
                deployment_witness(),
                deployment_witness(
                    deployment_asset_id="huggingface:space:szlholdings/a11oy",
                    deployment_url=(
                        "https://huggingface.co/spaces/SZLHOLDINGS/a11oy"
                    ),
                    receipt_id="deployment-receipt-20260801-2",
                ),
            )
            for index, witness in enumerate(witnesses, start=1):
                target_asset_id = str(witness["deployment_asset_id"])
                add_audited_deployment(value, witness)
                browser_report = write_report(
                    root, f"browser-report-{index}.json", witness
                )
                restore_report = write_report(
                    root, f"restore-report-{index}.json", witness
                )
                artifacts = {
                    "credential_backed_deployment_witness": witness,
                    "browser_e2e_and_accessibility": browser_artifact(
                        *browser_report, witness
                    ),
                    "restore_and_failure_domain_drill": restore_artifact(
                        *restore_report, witness
                    ),
                }
                for requirement, artifact in artifacts.items():
                    add_evidence_reference(
                        value,
                        requirement,
                        target_asset_id,
                        write_artifact(
                            root, f"{requirement}-{index}.json", artifact
                        ),
                    )
            sign(value)
            report = verify(
                value, manifest(requirements), "production", evidence_root=root
            )
        for requirement in requirements:
            self.assertEqual(
                check(report, f"production.requirement.{requirement}")["state"],
                "PASS",
            )

    def test_production_requires_evidence_for_every_critical_deployment(self) -> None:
        requirements = {
            "independent_asymmetric_evidence": True,
            "credential_backed_deployment_witness": True,
            "browser_e2e_and_accessibility": True,
            "restore_and_failure_domain_drill": True,
        }
        missing_target = "huggingface:space:szlholdings/a11oy"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            browser_report = write_report(root, "browser-report.json")
            restore_report = write_report(root, "restore-report.json")
            value = audit()
            add_audited_deployment(value)
            references = {
                "credential_backed_deployment_witness": write_artifact(
                    root, "deployment.json", deployment_witness()
                ),
                "browser_e2e_and_accessibility": write_artifact(
                    root,
                    "browser.json",
                    browser_artifact(*browser_report),
                ),
                "restore_and_failure_domain_drill": write_artifact(
                    root,
                    "restore.json",
                    restore_artifact(*restore_report),
                ),
            }
            value["production_evidence"] = indexed_evidence(references)
            sign(value)
            report = verify(
                value, manifest(requirements), "production", evidence_root=root
            )

        for requirement in references:
            requirement_check = check(
                report, f"production.requirement.{requirement}"
            )
            self.assertEqual(requirement_check["state"], "FAIL")
            self.assertIn("critical deployment coverage mismatch", requirement_check["detail"])
            self.assertIn(missing_target, requirement_check["detail"])

    def test_disabled_repository_cannot_supply_critical_deployment(self) -> None:
        requirement = "credential_backed_deployment_witness"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            assets = value["assets"]
            assert isinstance(assets, list)
            repository = next(
                asset
                for asset in assets
                if isinstance(asset, dict)
                and asset.get("asset_id") == PRIMARY_REPOSITORY_ASSET_ID
            )
            repository["operational_status"] = "DISABLED"
            value["production_evidence"] = indexed_evidence(
                {
                    requirement: write_artifact(
                        root, "deployment.json", deployment_witness()
                    )
                }
            )
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )

        repository_check = check(report, f"asset.{PRIMARY_REPOSITORY_ASSET_ID}")
        self.assertEqual(repository_check["state"], "FAIL")
        self.assertIn("operational_status=DISABLED", repository_check["detail"])
        self.assertIn(
            "not an active audited GitHub repository",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_github_required_status_cannot_override_operational_gate(self) -> None:
        contract = single_deployment_manifest()
        critical_assets = contract["critical_assets"]
        assert isinstance(critical_assets, list)
        repository_contract = next(
            asset
            for asset in critical_assets
            if isinstance(asset, dict)
            and asset.get("asset_id") == PRIMARY_REPOSITORY_ASSET_ID
        )
        repository_contract["required_status"] = "ARCHIVED"

        value = audit()
        add_audited_deployment(value)
        assets = value["assets"]
        assert isinstance(assets, list)
        repository = next(
            asset
            for asset in assets
            if isinstance(asset, dict)
            and asset.get("asset_id") == PRIMARY_REPOSITORY_ASSET_ID
        )
        repository["status_label"] = "ARCHIVED"
        repository["operational_status"] = "DISABLED"
        report = verify(value, contract, "baseline")

        self.assertEqual(
            check(report, "manifest.baseline_contract")["state"], "FAIL"
        )
        repository_check = check(report, f"asset.{PRIMARY_REPOSITORY_ASSET_ID}")
        self.assertEqual(repository_check["state"], "FAIL")
        self.assertIn("status=ARCHIVED", repository_check["detail"])
        self.assertIn("operational_status=DISABLED", repository_check["detail"])

    def test_critical_repository_requires_github_repo_record(self) -> None:
        value = audit()
        add_audited_deployment(value)
        assets = value["assets"]
        assert isinstance(assets, list)
        repository = next(
            asset
            for asset in assets
            if isinstance(asset, dict)
            and asset.get("asset_id") == PRIMARY_REPOSITORY_ASSET_ID
        )
        repository["source"] = "domains"
        repository["asset_type"] = "route"
        report = verify(value, single_deployment_manifest(), "baseline")

        repository_check = check(report, f"asset.{PRIMARY_REPOSITORY_ASSET_ID}")
        self.assertEqual(repository_check["state"], "FAIL")
        self.assertIn("source=domains", repository_check["detail"])
        self.assertIn("asset_type=route", repository_check["detail"])

    def test_space_witness_must_match_verified_runtime_source(self) -> None:
        requirement = "credential_backed_deployment_witness"
        target_asset_id = "huggingface:space:szlholdings/a11oy"
        witness = deployment_witness(
            repository_asset_id="github:repo:szl-holdings/killinchu",
            deployment_asset_id=target_asset_id,
            deployment_url="https://huggingface.co/spaces/SZLHOLDINGS/a11oy",
            receipt_id="deployment-receipt-20260801-space",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value, witness)
            assets = value["assets"]
            assert isinstance(assets, list)
            target = next(
                asset
                for asset in assets
                if isinstance(asset, dict)
                and asset.get("asset_id") == target_asset_id
            )
            metadata = target["metadata"]
            assert isinstance(metadata, dict)
            alignment_revision = "a" * 40
            alignment_repository = "szl-holdings/a11oy"
            metadata["github_alignment"] = {
                "status": "EXACT_RUNTIME_HEAD",
                "source_repository": alignment_repository,
                "source_revision": alignment_revision,
                "github_default_revision": alignment_revision,
            }
            metadata["runtime_build"] = {
                "status": "OBSERVED",
                "state": "OBSERVED",
                "revision": alignment_revision,
            }
            metadata["provenance_docs"] = [
                {
                    "status": "OBSERVED",
                    "binding_kind": "ARTIFACT_SOURCE",
                    "source_repository": alignment_repository,
                    "source_revision": alignment_revision,
                }
            ]
            assets.append(
                {
                    "asset_id": "github:repo:szl-holdings/a11oy",
                    "asset_type": "repo",
                    "source": "github",
                    "status_label": "OBSERVED",
                    "operational_status": "ACTIVE",
                    "observed_at": "2026-08-01T18:56:00Z",
                    "url": "https://github.com/szl-holdings/a11oy",
                    "metadata": {"default_branch_sha": alignment_revision},
                }
            )
            value["production_evidence"] = indexed_evidence(
                {
                    requirement: write_artifact(
                        root, "space-deployment.json", witness
                    )
                },
                target_asset_id,
            )
            sign(value)
            contract = manifest(
                {"independent_asymmetric_evidence": True, requirement: True}
            )
            critical_assets = contract["critical_assets"]
            assert isinstance(critical_assets, list)
            contract["critical_assets"] = [
                asset
                for asset in critical_assets
                if isinstance(asset, dict)
                and not str(asset.get("asset_id") or "").startswith("domain:route:")
            ]
            contract["critical_assets"].append(
                {
                    "asset_id": "github:repo:szl-holdings/killinchu",
                    "tier": 0,
                    "role": "alternate witnessed source repository",
                    "public": True,
                }
            )
            contract["production_deployment_sources"] = {
                target_asset_id: "github:repo:szl-holdings/killinchu"
            }
            report = verify(value, contract, "production", evidence_root=root)

        self.assertEqual(check(report, f"alignment.{target_asset_id}")["state"], "PASS")
        self.assertIn(
            "does not match its verified runtime source",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_production_rejects_tampered_artifact(self) -> None:
        requirement = "credential_backed_deployment_witness"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "deployment.json"
            payload = json.dumps(deployment_witness(), sort_keys=True).encode("utf-8")
            path.write_bytes(payload)
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                requirement: {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                }
            })
            sign(value)
            path.write_text("{}", encoding="utf-8")
            report = verify(
                value,
                single_deployment_manifest(
                    {
                        "independent_asymmetric_evidence": True,
                        requirement: True,
                    }
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "digest mismatch",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_production_binds_deployment_witness_to_audited_assets(self) -> None:
        requirement = "credential_backed_deployment_witness"
        contract = single_deployment_manifest(
            {"independent_asymmetric_evidence": True, requirement: True}
        )
        for mutation, expected in (
            (
                lambda witness: witness.__setitem__(
                    "deployment_asset_id", "domain:route:unrelated.example/"
                ),
                "does not match its evidence index",
            ),
            (
                lambda witness: witness.__setitem__(
                    "repository_asset_id", "github:repo:szl-holdings/other"
                ),
                "repository does not match target source binding",
            ),
            (
                lambda witness: witness.__setitem__("deployment_revision", "d" * 40),
                "does not match the audited repository head",
            ),
            (
                lambda witness: witness["deployment_receipt"].__setitem__(
                    "deployed_artifact_sha256", "d" * 64
                ),
                "receipt binding mismatch",
            ),
            (
                lambda witness: witness.__setitem__("deployment_revision", ""),
                "deployment revision is missing or invalid",
            ),
            (
                lambda witness: witness.__setitem__("deployment_revision", "e" * 41),
                "deployment revision is missing or invalid",
            ),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                witness = deployment_witness()
                mutation(witness)
                path = root / "deployment.json"
                payload = json.dumps(witness, sort_keys=True).encode("utf-8")
                path.write_bytes(payload)
                value = audit()
                add_audited_deployment(value)
                value["production_evidence"] = indexed_evidence({
                    requirement: {
                        "artifact_path": path.name,
                        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                })
                sign(value)
                report = verify(
                    value, contract, "production", evidence_root=root
                )
                self.assertIn(
                    expected,
                    check(report, f"production.requirement.{requirement}")["detail"],
                )

    def test_null_deployment_source_remains_unpromotable(self) -> None:
        requirement = "credential_backed_deployment_witness"
        contract = manifest(
            {"independent_asymmetric_evidence": True, requirement: True}
        )
        deployment_sources = contract["production_deployment_sources"]
        assert isinstance(deployment_sources, dict)
        deployment_sources[PRIMARY_DEPLOYMENT_ASSET_ID] = None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            witnesses = (
                deployment_witness(),
                deployment_witness(
                    deployment_asset_id="huggingface:space:szlholdings/a11oy",
                    deployment_url=(
                        "https://huggingface.co/spaces/SZLHOLDINGS/a11oy"
                    ),
                    receipt_id="deployment-receipt-20260801-null-source-space",
                ),
            )
            for index, witness in enumerate(witnesses, start=1):
                add_audited_deployment(value, witness)
                add_evidence_reference(
                    value,
                    requirement,
                    str(witness["deployment_asset_id"]),
                    write_artifact(
                        root, f"deployment-{index}.json", witness
                    ),
                )
            sign(value)
            report = verify(value, contract, "production", evidence_root=root)

        self.assertEqual(
            check(report, "manifest.baseline_contract")["state"], "PASS"
        )
        requirement_check = check(
            report, f"production.requirement.{requirement}"
        )
        self.assertEqual(requirement_check["state"], "FAIL")
        self.assertIn(
            "deployment target has no declared source repository",
            requirement_check["detail"],
        )

    def test_production_witness_must_target_manifest_critical_asset(self) -> None:
        requirement = "credential_backed_deployment_witness"
        contract = manifest({"independent_asymmetric_evidence": True, requirement: True})
        critical_assets = contract["critical_assets"]
        assert isinstance(critical_assets, list)
        domain_contract = critical_assets[1]
        assert isinstance(domain_contract, dict)
        domain_contract["asset_id"] = "domain:route:a11oy.net/"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                requirement: write_artifact(
                    root, "deployment.json", deployment_witness()
                )
            })
            sign(value)
            report = verify(value, contract, "production", evidence_root=root)

        self.assertIn(
            "critical deployment coverage mismatch",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_production_witness_rejects_audited_url_identity_mismatch(self) -> None:
        requirement = "credential_backed_deployment_witness"
        for deployment_url in (
            "https://evil.example/",
            "https://a-11-oy.com/unbound",
        ):
            with self.subTest(deployment_url=deployment_url), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                witness = deployment_witness()
                witness["deployment_url"] = deployment_url
                receipt = witness["deployment_receipt"]
                assert isinstance(receipt, dict)
                receipt["deployment_url"] = deployment_url
                sign_deployment_receipt(receipt)

                value = audit()
                add_audited_deployment(value)
                assets = value["assets"]
                assert isinstance(assets, list)
                deployment_asset = assets[1]
                assert isinstance(deployment_asset, dict)
                deployment_asset["url"] = deployment_url
                metadata = deployment_asset["metadata"]
                assert isinstance(metadata, dict)
                metadata["final_url"] = deployment_url
                edge = metadata["deployment"]
                assert isinstance(edge, dict)
                edge["deployment_url"] = deployment_url
                value["production_evidence"] = indexed_evidence({
                    requirement: write_artifact(
                        root, "deployment.json", witness
                    )
                })
                sign(value)
                report = verify(
                    value,
                    single_deployment_manifest(
                        {"independent_asymmetric_evidence": True, requirement: True}
                    ),
                    "production",
                    evidence_root=root,
                )

            self.assertIn(
                "does not match the domain route identity",
                check(report, f"production.requirement.{requirement}")["detail"],
            )

    def test_production_requires_audited_repository_deployment_edge(self) -> None:
        requirement = "credential_backed_deployment_witness"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            witness = deployment_witness()
            path = root / "deployment.json"
            payload = json.dumps(witness, sort_keys=True).encode("utf-8")
            path.write_bytes(payload)
            value = audit()
            add_audited_deployment(value)
            value["assets"][1]["metadata"].pop("deployment")
            value["production_evidence"] = indexed_evidence({
                requirement: {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                }
            })
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "repository-to-deployment edge",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_deployment_receipt_requires_provider_authentication(self) -> None:
        requirement = "credential_backed_deployment_witness"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            witness = deployment_witness()
            witness["deployment_receipt"]["provider"] = "untrusted-provider"
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                requirement: write_artifact(root, "deployment.json", witness)
            })
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "provider authentication failed",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_browser_report_digest_binds_loaded_report_bytes(self) -> None:
        requirement = "browser_e2e_and_accessibility"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path, report_sha256 = write_report(root, "browser-report.json")
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                "credential_backed_deployment_witness": write_artifact(
                    root, "deployment.json", deployment_witness()
                ),
                requirement: write_artifact(
                    root,
                    "browser.json",
                    browser_artifact(report_path, report_sha256),
                ),
            })
            sign(value)
            (root / report_path).write_bytes(b"tampered browser report")
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "report digest mismatch",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_restore_binds_promoted_deployment_and_policy_ceilings(self) -> None:
        requirement = "restore_and_failure_domain_drill"
        for mutation, expected in (
            (
                lambda artifact: artifact.__setitem__(
                    "source_deployment_revision", "f" * 40
                ),
                "does not bind the promoted deployment witness",
            ),
            (
                lambda artifact: artifact.update(
                    {
                        "service_restored_at": "2026-08-01T18:15:01Z",
                        "completed_at": "2026-08-01T18:15:01Z",
                        "rto_seconds": 901,
                    }
                ),
                "exceeds the production policy ceiling",
            ),
            (
                lambda artifact: artifact.__setitem__("rto_seconds", 1),
                "does not match the recorded restore interval",
            ),
            (
                lambda artifact: artifact.__setitem__("rpo_seconds", 1),
                "does not match the recorded recovery point",
            ),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact = restore_artifact(*write_report(root, "restore-report.json"))
                mutation(artifact)
                value = audit()
                add_audited_deployment(value)
                value["production_evidence"] = indexed_evidence({
                    "credential_backed_deployment_witness": write_artifact(
                        root, "deployment.json", deployment_witness()
                    ),
                    requirement: write_artifact(root, "restore.json", artifact),
                })
                sign(value)
                report = verify(
                    value,
                    single_deployment_manifest(
                        {"independent_asymmetric_evidence": True, requirement: True}
                    ),
                    "production",
                    evidence_root=root,
                )
            self.assertIn(
                expected,
                check(report, f"production.requirement.{requirement}")["detail"],
            )

    def test_evidence_timestamps_reject_stale_and_future_observations(self) -> None:
        requirement = "browser_e2e_and_accessibility"
        for tested_at, expected in (
            ("2026-08-01T16:30:00Z", "evidence is stale"),
            ("2026-08-01T19:00:01Z", "later than audit completion"),
        ):
            with self.subTest(tested_at=tested_at), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact = browser_artifact(*write_report(root, "browser-report.json"))
                artifact["tested_at"] = tested_at
                value = audit()
                add_audited_deployment(value)
                value["production_evidence"] = indexed_evidence({
                    "credential_backed_deployment_witness": write_artifact(
                        root, "deployment.json", deployment_witness()
                    ),
                    requirement: write_artifact(root, "browser.json", artifact),
                })
                sign(value)
                report = verify(
                    value,
                    single_deployment_manifest(
                        {"independent_asymmetric_evidence": True, requirement: True}
                    ),
                    "production",
                    evidence_root=root,
                )
            self.assertIn(
                expected,
                check(report, f"production.requirement.{requirement}")["detail"],
            )

    def test_production_requires_runtime_head_for_critical_spaces(self) -> None:
        asset_id = "huggingface:space:szlholdings/a11oy"
        value = audit()
        value["assets"] = [
            {
                "asset_id": "github:repo:szl-holdings/a11oy",
                "asset_type": "repo",
                "source": "github",
                "status_label": "OBSERVED",
                "operational_status": "ACTIVE",
                "metadata": {"default_branch_sha": "b" * 40},
            },
            {
                "asset_id": asset_id,
                "asset_type": "space",
                "source": "huggingface",
                "status_label": "LIVE",
                "metadata": {
                    "github_alignment": {
                        "status": "EXACT_HEAD",
                        "source_repository": "szl-holdings/a11oy",
                        "source_revision": "b" * 40,
                        "github_default_revision": "b" * 40,
                    },
                    "runtime_build": {
                        "status": "OBSERVED",
                        "state": "OBSERVED",
                        "revision": "b" * 40,
                    },
                    "provenance_docs": [
                        {
                            "status": "OBSERVED",
                            "binding_kind": "ARTIFACT_SOURCE",
                            "source_repository": "szl-holdings/a11oy",
                            "source_revision": "b" * 40,
                        }
                    ],
                },
            }
        ]
        contract = manifest(
            {"critical_huggingface_alignment": ["EXACT_RUNTIME_HEAD"]}
        )
        contract["critical_assets"] = [
            {"asset_id": asset_id, "public": True, "required_status": "LIVE"}
        ]
        failed = verify(value, contract, "production")
        self.assertEqual(check(failed, f"alignment.{asset_id}")["state"], "FAIL")
        value["assets"][1]["metadata"]["github_alignment"][
            "status"
        ] = "EXACT_RUNTIME_HEAD"
        passed = verify(value, contract, "production")
        self.assertEqual(
            check(
                passed, "production.requirement.critical_huggingface_alignment"
            )["state"],
            "PASS",
        )
        value["assets"][1]["metadata"]["provenance_docs"][0][
            "source_repository"
        ] = "szl-holdings/unrelated"
        wrong_source = verify(value, contract, "production")
        self.assertEqual(
            check(wrong_source, f"alignment.{asset_id}")["state"], "FAIL"
        )

    def test_production_rejects_runtime_source_outside_canonical_org(self) -> None:
        asset_id = "huggingface:space:szlholdings/a11oy"
        value = audit()
        value["assets"] = [
            {
                "asset_id": "github:repo:other-org/a11oy",
                "asset_type": "repo",
                "source": "github",
                "status_label": "OBSERVED",
                "operational_status": "ACTIVE",
                "metadata": {"default_branch_sha": "b" * 40},
            },
            {
                "asset_id": asset_id,
                "asset_type": "space",
                "source": "huggingface",
                "status_label": "LIVE",
                "metadata": {
                    "github_alignment": {
                        "status": "EXACT_RUNTIME_HEAD",
                        "source_repository": "other-org/a11oy",
                        "source_revision": "b" * 40,
                        "github_default_revision": "b" * 40,
                    },
                    "runtime_build": {
                        "status": "OBSERVED",
                        "state": "OBSERVED",
                        "revision": "b" * 40,
                    },
                    "provenance_docs": [
                        {
                            "status": "OBSERVED",
                            "binding_kind": "ARTIFACT_SOURCE",
                            "source_repository": "other-org/a11oy",
                            "source_revision": "b" * 40,
                        }
                    ],
                },
            },
        ]
        contract = manifest(
            {"critical_huggingface_alignment": ["EXACT_RUNTIME_HEAD"]}
        )
        contract["critical_assets"] = [
            {"asset_id": asset_id, "public": True, "required_status": "LIVE"}
        ]
        report = verify(value, contract, "production")
        self.assertIn(
            "outside the canonical organization",
            check(report, f"alignment.{asset_id}")["detail"],
        )

    def test_browser_evidence_rejects_stale_deployment_binding(self) -> None:
        requirement = "browser_e2e_and_accessibility"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            artifact = browser_artifact(*write_report(root, "browser-report.json"))
            artifact["deployment_revision"] = "f" * 40
            path = root / "browser.json"
            payload = json.dumps(artifact, sort_keys=True).encode("utf-8")
            path.write_bytes(payload)
            witness_path = root / "deployment.json"
            witness_payload = json.dumps(
                deployment_witness(), sort_keys=True
            ).encode("utf-8")
            witness_path.write_bytes(witness_payload)
            value["production_evidence"] = indexed_evidence({
                requirement: {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                },
                "credential_backed_deployment_witness": {
                    "artifact_path": witness_path.name,
                    "artifact_sha256": hashlib.sha256(witness_payload).hexdigest(),
                },
            })
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "does not bind the promoted deployment witness",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_production_rejects_shallow_browser_and_restore_assertions(self) -> None:
        shallow_artifacts = {
            "browser_e2e_and_accessibility": {
                "schema": "szl.estate-browser-evidence/v1",
                "status": "VERIFIED",
                "checks": {
                    "browser_e2e": "PASS",
                    "keyboard": "PASS",
                    "mobile": "PASS",
                    "accessibility": "PASS",
                },
            },
            "restore_and_failure_domain_drill": {
                "schema": "szl.estate-restore-drill/v2",
                "status": "VERIFIED",
                "restore_status": "PASS",
                "failure_domain_status": "PASS",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            references = {}
            for requirement, artifact in shallow_artifacts.items():
                path = root / f"{requirement}.json"
                payload = json.dumps(artifact, sort_keys=True).encode("utf-8")
                path.write_bytes(payload)
                references[requirement] = {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                }
            value["production_evidence"] = indexed_evidence(references)
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {requirement: True for requirement in shallow_artifacts}
                ),
                "production",
                evidence_root=root,
            )
        for requirement in shallow_artifacts:
            self.assertEqual(
                check(report, f"production.requirement.{requirement}")["state"],
                "FAIL",
            )

    def test_source_minimum_uses_actual_asset_inventory(self) -> None:
        value = audit()
        value["source_reports"] = [
            {"source": "github", "status": "MEASURED", "count": 2}
        ]
        value["assets"] = [
            {"asset_id": "github:one", "source": "github", "status_label": "OBSERVED"}
        ]
        contract = manifest()
        contract["baseline"] = {
            "source_minimums": {"github": 2},
            "required_source_status": "MEASURED",
        }
        failed = verify(value, contract, "baseline")
        self.assertEqual(check(failed, "source.github")["state"], "FAIL")
        value["assets"].append(
            {"asset_id": "github:two", "source": "github", "status_label": "OBSERVED"}
        )
        passed = verify(value, contract, "baseline")
        self.assertEqual(check(passed, "source.github")["state"], "PASS")

    def test_duplicate_asset_ids_fail_closed(self) -> None:
        value = audit()
        value["assets"] = [
            {"asset_id": "github:duplicate", "source": "github"},
            {"asset_id": "github:duplicate", "source": "github"},
        ]
        report = verify(value, manifest(), "baseline")
        self.assertEqual(check(report, "assets.unique_ids")["state"], "FAIL")
        self.assertIn("github:duplicate", check(report, "assets.unique_ids")["detail"])

    def test_unknown_enabled_requirement_fails_closed(self) -> None:
        report = verify(
            audit(), manifest({"future_requirement": True}), "production"
        )
        self.assertEqual(
            check(report, "production.requirement.future_requirement")["state"],
            "FAIL",
        )

    def test_production_requirements_contract_fails_closed(self) -> None:
        valid = manifest()
        passing = verify(audit(), valid, "production")
        self.assertEqual(
            check(passing, "production.requirements_contract")["state"], "PASS"
        )
        invalid_contracts = (
            None,
            [],
            {"authenticated_inventory": True},
            {
                **valid["production_requirements"],
                "restore_and_failure_domain_drill": False,
            },
            {
                **valid["production_requirements"],
                "authenticated_inventory": [False],
            },
            {
                **valid["production_requirements"],
                "critical_huggingface_alignment": True,
            },
        )
        for configured in invalid_contracts:
            with self.subTest(configured=configured):
                contract = manifest()
                contract["production_requirements"] = configured
                report = verify(audit(), contract, "production")
                self.assertEqual(
                    check(report, "production.requirements_contract")["state"],
                    "FAIL",
                )

    def test_production_audit_freshness_uses_verification_time(self) -> None:
        for completed_at, expected in (
            ("2020-08-01T19:00:00Z", "audit evidence is stale"),
            ("2026-08-01T20:00:01Z", "later than verification time"),
        ):
            with self.subTest(completed_at=completed_at):
                value = audit()
                value["meta"]["completed_at"] = completed_at
                report = verify(value, manifest(), "production")
                freshness = check(report, "production.audit_freshness")
                self.assertEqual(freshness["state"], "FAIL")
                self.assertIn(expected, freshness["detail"])

    def test_critical_asset_records_fail_closed_on_schema_and_status(self) -> None:
        asset_id = "github:repo:szl-holdings/a11oy"

        wrong_source = audit()
        add_audited_deployment(wrong_source)
        wrong_source["assets"][0]["source"] = "domains"
        report = verify(wrong_source, manifest(), "baseline")
        self.assertEqual(check(report, f"schema.asset.{asset_id}")["state"], "FAIL")

        explicit_port = audit()
        add_audited_deployment(explicit_port)
        explicit_port["assets"][0]["url"] = (
            "https://github.com:444/szl-holdings/a11oy"
        )
        report = verify(explicit_port, manifest(), "baseline")
        self.assertEqual(check(report, f"schema.asset.{asset_id}")["state"], "FAIL")

        nested_repository = audit()
        add_audited_deployment(nested_repository)
        nested_asset_id = "github:repo:szl-holdings/a11oy/extra"
        nested_repository["assets"][0]["asset_id"] = nested_asset_id
        nested_repository["assets"][0]["url"] = (
            "https://github.com/szl-holdings/a11oy/extra"
        )
        nested_contract = manifest()
        nested_contract["critical_assets"][0]["asset_id"] = nested_asset_id
        report = verify(nested_repository, nested_contract, "baseline")
        self.assertEqual(
            check(report, f"schema.asset.{nested_asset_id}")["state"], "FAIL"
        )

        for status in ("UNAVAILABLE", "PARTIAL", "UNKNOWN", "ARCHIVED"):
            with self.subTest(status=status):
                value = audit()
                add_audited_deployment(value)
                value["assets"][0]["status_label"] = status
                report = verify(value, manifest(), "baseline")
                self.assertEqual(check(report, f"asset.{asset_id}")["state"], "FAIL")

        observed = audit()
        add_audited_deployment(observed)
        report = verify(observed, manifest(), "baseline")
        self.assertEqual(check(report, f"schema.asset.{asset_id}")["state"], "PASS")
        self.assertEqual(check(report, f"asset.{asset_id}")["state"], "PASS")

    def test_production_requires_fresh_source_and_critical_asset_observations(self) -> None:
        stale_source = audit()
        stale_source["source_reports"][0]["observed_at"] = "2026-08-01T16:59:59Z"
        source_report = verify(stale_source, manifest(), "production")
        self.assertEqual(
            check(source_report, "freshness.source.github")["state"], "FAIL"
        )

        future_source = audit()
        future_source["source_reports"][0]["observed_at"] = "2026-08-01T19:00:01Z"
        source_report = verify(future_source, manifest(), "production")
        self.assertEqual(
            check(source_report, "freshness.source.github")["state"], "FAIL"
        )

        pre_start_source = audit()
        pre_start_source["source_reports"][0]["observed_at"] = (
            "2026-08-01T18:49:59Z"
        )
        source_report = verify(pre_start_source, manifest(), "production")
        source_freshness = check(source_report, "freshness.source.github")
        self.assertEqual(source_freshness["state"], "FAIL")
        self.assertIn("predates audit start", source_freshness["detail"])

        asset_id = "github:repo:szl-holdings/a11oy"
        stale_asset = audit()
        add_audited_deployment(stale_asset)
        stale_asset["assets"][0]["observed_at"] = "2026-08-01T16:59:59Z"
        asset_report = verify(stale_asset, manifest(), "production")
        self.assertEqual(
            check(asset_report, f"freshness.asset.{asset_id}")["state"], "FAIL"
        )

        pre_start_asset = audit()
        add_audited_deployment(pre_start_asset)
        pre_start_asset["assets"][0]["observed_at"] = "2026-08-01T18:49:59Z"
        baseline_asset_report = verify(pre_start_asset, manifest(), "baseline")
        self.assertEqual(
            check(
                baseline_asset_report, f"schema.asset.{asset_id}"
            )["state"],
            "FAIL",
        )
        asset_report = verify(pre_start_asset, manifest(), "production")
        asset_freshness = check(
            asset_report, f"freshness.asset.{asset_id}"
        )
        self.assertEqual(asset_freshness["state"], "FAIL")
        self.assertIn("predates audit start", asset_freshness["detail"])

    def test_typed_report_schema_and_outage_clock_fail_closed(self) -> None:
        requirement = "browser_e2e_and_accessibility"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path, _ = write_report(root, "browser-report.json")
            invalid_report = json.loads((root / report_path).read_text(encoding="utf-8"))
            invalid_report["schema"] = "szl.test-report/v1"
            report_bytes = json.dumps(invalid_report, sort_keys=True).encode("utf-8")
            (root / report_path).write_bytes(report_bytes)
            artifact = browser_artifact(
                report_path, hashlib.sha256(report_bytes).hexdigest()
            )
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                "credential_backed_deployment_witness": write_artifact(
                    root, "deployment.json", deployment_witness()
                ),
                requirement: write_artifact(root, "browser.json", artifact),
            })
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "report schema/status is invalid",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

        requirement = "restore_and_failure_domain_drill"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = restore_artifact(*write_report(root, "restore-report.json"))
            artifact.update(
                {
                    "failure_started_at": "2026-08-01T18:00:00Z",
                    "restore_started_at": "2026-08-01T18:14:00Z",
                    "service_restored_at": "2026-08-01T18:16:00Z",
                    "completed_at": "2026-08-01T18:16:00Z",
                    "rto_seconds": 960,
                    "rpo_seconds": 300,
                }
            )
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence({
                "credential_backed_deployment_witness": write_artifact(
                    root, "deployment.json", deployment_witness()
                ),
                requirement: write_artifact(root, "restore.json", artifact),
            })
            sign(value)
            report = verify(
                value,
                single_deployment_manifest(
                    {"independent_asymmetric_evidence": True, requirement: True}
                ),
                "production",
                evidence_root=root,
            )
        self.assertIn(
            "rto_seconds exceeds the production policy ceiling",
            check(report, f"production.requirement.{requirement}")["detail"],
        )

    def test_workflow_aggregates_independent_evidence_after_failures(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "estate-readiness.yml"
        ).read_text(encoding="utf-8")
        for step_id in (
            "deterministic",
            "live_audit",
            "baseline",
            "receipt_chain",
            "stress",
        ):
            self.assertIn(f"id: {step_id}", workflow)
        self.assertGreaterEqual(workflow.count("if: always()"), 6)
        self.assertGreaterEqual(workflow.count("continue-on-error: true"), 5)
        self.assertIn("Aggregate evidence outcomes", workflow)
        self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
        self.assertIn("egress-policy: block", workflow)
        self.assertIn("disable-telemetry: true", workflow)
        for endpoint in (
            "api.github.com:443",
            "huggingface.co:443",
            "*.hf.space:443",
            "a-11-oy.com:443",
            "a11oy.net:443",
        ):
            self.assertIn(endpoint, workflow)
        self.assertNotIn("ESTATE_HF_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
