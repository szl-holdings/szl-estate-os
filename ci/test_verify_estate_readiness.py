from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from verify_estate_readiness import (
    PRODUCTION_EVIDENCE_INDEX_SCHEMA,
    PRODUCTION_SIGNATURE_ALGORITHM,
    RSA_SHA256_DIGEST_INFO_PREFIX,
    canonical_audit_payload,
    canonical_deployment_receipt_payload,
    canonical_restore_artifact_payload,
    deployment_url_identity_state,
    signature_state,
    verify as verify_readiness,
)
from run_restore_drill import (
    file_attestation,
    run_restore_drill,
    validate_output_path,
    write_json_atomic,
)
from estate.evidence_contract import (
    RESTORE_MEASUREMENT_SCHEMA,
    validate_restore_measurement,
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
        "restore_provider_trusted_keys": {
            "test-restore-provider-key": {
                "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
                "provider": "estate-restore-ci",
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
    return contract


def audit() -> dict[str, object]:
    return {
        "meta": {
            "audit_id": "audit-20260801-1",
            "completed_at": "2026-08-01T19:00:00Z",
        },
        "assets": [],
        "source_reports": [
            {"source": "github", "scope": "AUTHENTICATED_COMPLETE"},
            {"source": "huggingface", "scope": "AUTHENTICATED_COMPLETE"},
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


def sign_restore_artifact(artifact: dict[str, object]) -> None:
    artifact["provider_signature"] = {
        "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
        "key_id": "test-restore-provider-key",
        "signature_base64": "",
    }
    artifact["provider_signature"]["signature_base64"] = sign_payload(
        canonical_restore_artifact_payload(artifact)
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


def restore_measurement() -> dict[str, object]:
    absent_sidecar = {
        "exists": False,
        "sha256": None,
        "size_bytes": None,
        "mtime_ns": None,
        "device_id": None,
        "file_id": None,
    }
    return {
        "schema": RESTORE_MEASUREMENT_SCHEMA,
        "status": "PASS",
        "run_id": "restore-test-20260801",
        "tool_sha256": "1" * 64,
        "recovery_point_at": "2026-08-01T17:59:00Z",
        "started_at": "2026-08-01T18:00:00Z",
        "completed_at": "2026-08-01T18:05:00Z",
        "rto_seconds": 300,
        "rpo_seconds": 60,
        "source": {
            "database_sha256_before": "2" * 64,
            "database_sha256_after": "2" * 64,
            "size_bytes_before": 4096,
            "size_bytes_after": 4096,
            "mtime_ns_before": 100,
            "mtime_ns_after": 100,
            "data_version_before": 1,
            "data_version_after": 1,
            "sidecars": {
                suffix: {
                    "before": dict(absent_sidecar),
                    "after": dict(absent_sidecar),
                }
                for suffix in ("-wal", "-shm", "-journal")
            },
            "query_only": True,
            "unchanged": True,
        },
        "backup": {
            "sha256": "3" * 64,
            "size_bytes": 4096,
            "created_at": "2026-08-01T17:59:59Z",
        },
        "restore_target": {
            "isolation": "EPHEMERAL_TEMP_DIRECTORY",
            "loopback_only": True,
            "production_writes": 0,
            "path_disclosed": False,
            "cleaned_up": True,
        },
        "validation": {
            "integrity_check": "ok",
            "foreign_key_violation_count": 0,
            "source_schema_sha256": "4" * 64,
            "restored_schema_sha256": "4" * 64,
            "source_content_sha256": "5" * 64,
            "restored_content_sha256": "5" * 64,
            "source_row_counts": {"receipts": 1},
            "restored_row_counts": {"receipts": 1},
            "receipt_chain_valid": True,
            "receipt_count": 1,
        },
        "failure_scenarios": {
            "corrupt_backup_rejected": True,
            "missing_backup_rejected": True,
        },
    }


def restore_artifact(
    measurement_path: str,
    measurement_sha256: str,
    witness: dict[str, object] | None = None,
) -> dict[str, object]:
    promoted = witness or deployment_witness()
    receipt = promoted["deployment_receipt"]
    assert isinstance(receipt, dict)
    artifact: dict[str, object] = {
        "schema": "szl.estate-restore-drill/v2",
        "status": "VERIFIED",
        "source_deployment_asset_id": promoted["deployment_asset_id"],
        "deployment_url": promoted["deployment_url"],
        "deployment_revision": promoted["deployment_revision"],
        "deployed_artifact_sha256": promoted["deployed_artifact_sha256"],
        "deployment_receipt_id": receipt["receipt_id"],
        "environment": "production",
        "measurement_path": measurement_path,
        "measurement_sha256": measurement_sha256,
        "dependency_loss_scenarios": [
            {"name": "primary-store-loss", "status": "PASS"}
        ],
        "corrective_actions": [{"id": "restore-drill-1", "status": "CLOSED"}],
        "failure_domain_status": "PASS",
        "provider": "estate-restore-ci",
    }
    sign_restore_artifact(artifact)
    return artifact


def write_report(root: Path, name: str) -> tuple[str, str]:
    payload = json.dumps(
        {"schema": "szl.test-report/v1", "name": name, "status": "PASS"},
        sort_keys=True,
    ).encode("utf-8")
    path = root / name
    path.write_bytes(payload)
    return path.name, hashlib.sha256(payload).hexdigest()


def write_restore_measurement(
    root: Path,
    name: str = "restore-measurement.json",
    measurement: dict[str, object] | None = None,
) -> tuple[str, str]:
    payload = json.dumps(
        measurement or restore_measurement(), sort_keys=True
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


def verified_space_provenance_policy(
    asset_id: str,
    repository: str,
    revision: str,
) -> dict[str, object]:
    return {
        "schema": "szl.provenance-policy-decision/v1",
        "target": {"asset_id": asset_id, "evidence_state": "OBSERVED"},
        "scope": {
            "state": "AUTHENTICATED_COMPLETE",
            "completeness": "COMPLETE",
        },
        "artifact_provenance": {
            "state": "PASS",
            "evidence_state": "VERIFIED_REACHABLE",
            "alignment_state": "EXACT_HEAD",
            "current": True,
            "source_repository": repository,
            "source_revision": revision,
            "head_revision": revision,
        },
        "runtime_currency": {
            "state": "PASS",
            "evidence_state": "OBSERVED_RUNTIME_REVISION",
            "currency_state": "CURRENT",
            "current": True,
            "source_repository": repository,
            "source_revision": revision,
            "head_revision": revision,
        },
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
                "provenance_policy": verified_space_provenance_policy(
                    deployment_asset_id,
                    source_repository,
                    revision,
                ),
            }
        )
    else:
        deployment_metadata.update(
            {
                "security_headers": {
                    "content-security-policy": True,
                    "referrer-policy": True,
                    "strict-transport-security": True,
                    "x-content-type-options": True,
                },
                "security_header_values": {
                    "content-security-policy": (
                        "default-src 'self'; script-src 'self'; object-src 'none'; "
                        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                    ),
                    "strict-transport-security": (
                        "max-age=31536000; includeSubDomains"
                    ),
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "strict-origin-when-cross-origin",
                },
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
    repository_metadata: dict[str, object] = {"default_branch_sha": revision}
    if source == "huggingface":
        repository_metadata["default_branch_commit_fact"] = {
            "source_repository": repository_asset_id.removeprefix("github:repo:"),
            "source_revision": revision,
            "state": "VERIFIED_REACHABLE",
        }
    assets.extend(
        [
        {
            "asset_id": repository_asset_id,
            "asset_type": "repo",
            "source": "github",
            "status_label": "OBSERVED",
            "operational_status": "ACTIVE",
            "url": "https://github.com/"
            + repository_asset_id.removeprefix("github:repo:"),
            "metadata": repository_metadata,
        },
        {
            "asset_id": deployment_asset_id,
            "asset_type": asset_type,
            "source": source,
            "status_label": "LIVE",
            "operational_status": "REAL" if source == "domains" else "RUNNING",
            "url": deployment_url,
            "metadata": deployment_metadata,
        },
        ]
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

        for contract in (
            missing_baseline,
            empty_baseline,
            missing_critical_assets,
            empty_critical_assets,
            incomplete_sources,
            incomplete_headers,
            malformed_prohibited_statuses,
            malformed_headers,
        ):
            with self.subTest(contract=contract):
                report = verify(audit(), contract, "baseline")
                self.assertEqual(
                    check(report, "manifest.baseline_contract")["state"], "FAIL"
                )

    def test_security_header_values_fail_closed_and_reject_weak_policies(self) -> None:
        value = audit()
        add_audited_deployment(value)
        contract = single_deployment_manifest()
        passing = verify(value, contract, "baseline")
        self.assertEqual(
            check(passing, f"headers.{PRIMARY_DEPLOYMENT_ASSET_ID}")["state"],
            "PASS",
        )

        invented_presence = json.loads(json.dumps(value))
        invented_target = next(
            asset
            for asset in invented_presence["assets"]
            if asset["asset_id"] == PRIMARY_DEPLOYMENT_ASSET_ID
        )
        invented_target["metadata"]["security_headers"][
            "content-security-policy"
        ] = "PRESENT"
        invented_report = verify(invented_presence, contract, "baseline")
        invented_check = check(
            invented_report, f"headers.{PRIMARY_DEPLOYMENT_ASSET_ID}"
        )
        self.assertEqual(invented_check["state"], "FAIL")
        self.assertIn("missing=content-security-policy", invented_check["detail"])

        mutations = (
            ("missing", None, "raw security header values are missing"),
            (
                "content-security-policy",
                (
                    "default-src *; script-src * 'unsafe-inline'; object-src 'none'; "
                    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
                ),
                "content-security-policy",
            ),
            (
                "strict-transport-security",
                "max-age=0",
                "max-age policy is insufficient",
            ),
            ("x-content-type-options", "sniff", "must be nosniff"),
            ("referrer-policy", "unsafe-url", "non-leaking allowlist"),
        )
        for header, weak_value, expected in mutations:
            with self.subTest(header=header):
                observed = json.loads(json.dumps(value))
                assets = observed["assets"]
                target = next(
                    asset
                    for asset in assets
                    if asset["asset_id"] == PRIMARY_DEPLOYMENT_ASSET_ID
                )
                metadata = target["metadata"]
                if header == "missing":
                    metadata.pop("security_header_values")
                else:
                    metadata["security_header_values"][header] = weak_value
                report = verify(observed, contract, "baseline")
                header_check = check(
                    report, f"headers.{PRIMARY_DEPLOYMENT_ASSET_ID}"
                )
                self.assertEqual(header_check["state"], "FAIL")
                self.assertIn(expected, header_check["detail"])

        for directive in ("script-src", "script-src-elem", "script-src-attr"):
            with self.subTest(unsafe_script_directive=directive):
                observed = json.loads(json.dumps(value))
                target = next(
                    asset
                    for asset in observed["assets"]
                    if asset["asset_id"] == PRIMARY_DEPLOYMENT_ASSET_ID
                )
                metadata = target["metadata"]
                safe_policy = metadata["security_header_values"][
                    "content-security-policy"
                ]
                metadata["security_header_values"][
                    "content-security-policy"
                ] = (
                    safe_policy.replace("script-src 'self'", "script-src *")
                    if directive == "script-src"
                    else f"{safe_policy}; {directive} *"
                )
                report = verify(observed, contract, "baseline")
                header_check = check(
                    report, f"headers.{PRIMARY_DEPLOYMENT_ASSET_ID}"
                )
                self.assertEqual(header_check["state"], "FAIL")
                self.assertIn(directive, header_check["detail"])

    def test_deployment_url_identity_is_derived_from_asset_id(self) -> None:
        contract = manifest()
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
                    root, f"browser-report-{index}.json"
                )
                restore_report = write_restore_measurement(
                    root, f"restore-measurement-{index}.json"
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
            restore_report = write_restore_measurement(root)
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

    def test_non_operational_target_cannot_supply_critical_deployment(self) -> None:
        requirement = "credential_backed_deployment_witness"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            assets = value["assets"]
            target = next(
                asset
                for asset in assets
                if asset["asset_id"] == PRIMARY_DEPLOYMENT_ASSET_ID
            )
            target["operational_status"] = "AVAILABLE"
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
        requirement_check = check(report, f"production.requirement.{requirement}")
        self.assertEqual(requirement_check["state"], "FAIL")
        self.assertIn("not an audited operational LIVE deployment", requirement_check["detail"])

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
            metadata["provenance_policy"] = verified_space_provenance_policy(
                target_asset_id,
                alignment_repository,
                alignment_revision,
            )
            assets.append(
                {
                    "asset_id": "github:repo:szl-holdings/a11oy",
                    "asset_type": "repo",
                    "source": "github",
                    "status_label": "OBSERVED",
                    "operational_status": "ACTIVE",
                    "metadata": {
                        "default_branch_sha": alignment_revision,
                        "default_branch_commit_fact": {
                            "source_repository": alignment_repository,
                            "source_revision": alignment_revision,
                            "state": "VERIFIED_REACHABLE",
                        },
                    },
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
            ("deployment_revision", "does not bind the promoted deployment witness"),
            ("rto_ceiling", "exceeds the production policy ceiling"),
            ("rto_mismatch", "RTO does not match its timestamps"),
            ("rpo_mismatch", "RPO does not match its timestamps"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                measurement = restore_measurement()
                if mutation == "rto_ceiling":
                    measurement.update(
                        {"completed_at": "2026-08-01T18:15:01Z", "rto_seconds": 901}
                    )
                elif mutation == "rto_mismatch":
                    measurement["rto_seconds"] = 1
                elif mutation == "rpo_mismatch":
                    measurement["rpo_seconds"] = 1
                artifact = restore_artifact(
                    *write_restore_measurement(root, measurement=measurement)
                )
                if mutation == "deployment_revision":
                    artifact["deployment_revision"] = "f" * 40
                    sign_restore_artifact(artifact)
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

    def test_restore_requires_typed_isolated_provider_signed_measurement(self) -> None:
        requirement = "restore_and_failure_domain_drill"
        contract = single_deployment_manifest(
            {"independent_asymmetric_evidence": True, requirement: True}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = restore_artifact(*write_restore_measurement(root))
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence(
                {
                    "credential_backed_deployment_witness": write_artifact(
                        root, "deployment.json", deployment_witness()
                    ),
                    requirement: write_artifact(root, "restore.json", artifact),
                }
            )
            sign(value)
            passing = verify(value, contract, "production", evidence_root=root)
            self.assertEqual(
                check(passing, f"production.requirement.{requirement}")["state"],
                "PASS",
            )

        for mutation, expected in (
            ("one_byte", "not valid UTF-8 JSON"),
            ("self_asserted", "restore provider authentication failed"),
            ("production_write", "not proven isolated and non-destructive"),
            ("backup_after_start", "backup values are invalid"),
            ("missing_sidecars", "source shape is invalid"),
            ("legacy_schema", "identity/status is invalid"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                measurement = restore_measurement()
                if mutation == "one_byte":
                    measurement_path = root / "restore-measurement.json"
                    measurement_path.write_bytes(b"x")
                    measurement_ref = (
                        measurement_path.name,
                        hashlib.sha256(b"x").hexdigest(),
                    )
                else:
                    if mutation == "production_write":
                        measurement["restore_target"]["production_writes"] = 1
                    elif mutation == "backup_after_start":
                        measurement["backup"]["created_at"] = "2026-08-01T18:00:01Z"
                    elif mutation == "missing_sidecars":
                        measurement["source"].pop("sidecars")
                    elif mutation == "legacy_schema":
                        measurement["schema"] = "szl.sqlite-restore-measurement/v1"
                    measurement_ref = write_restore_measurement(
                        root, measurement=measurement
                    )
                artifact = restore_artifact(*measurement_ref)
                if mutation == "self_asserted":
                    artifact["provider_signature"] = {}
                value = audit()
                add_audited_deployment(value)
                value["production_evidence"] = indexed_evidence(
                    {
                        "credential_backed_deployment_witness": write_artifact(
                            root, "deployment.json", deployment_witness()
                        ),
                        requirement: write_artifact(root, "restore.json", artifact),
                    }
                )
                sign(value)
                report = verify(value, contract, "production", evidence_root=root)
            requirement_check = check(
                report, f"production.requirement.{requirement}"
            )
            self.assertEqual(requirement_check["state"], "FAIL")
            self.assertIn(expected, requirement_check["detail"])

    def test_restore_runner_is_non_destructive_and_contract_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "estate.db"
            connection = sqlite3.connect(database)
            try:
                connection.executescript(
                    """
                    CREATE TABLE audit_runs (completed_at TEXT NOT NULL);
                    CREATE TABLE receipts (
                        sequence INTEGER PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL,
                        signature_status TEXT NOT NULL
                    );
                    """
                )
                recovery_point = datetime.now(timezone.utc) - timedelta(seconds=1)
                payload = "{}"
                payload_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                receipt_hash = hashlib.sha256(
                    f"GENESIS\n{payload_sha256}".encode("utf-8")
                ).hexdigest()
                connection.execute(
                    "INSERT INTO audit_runs VALUES (?)", (recovery_point.isoformat(),)
                )
                connection.execute(
                    "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        1,
                        payload,
                        payload_sha256,
                        "GENESIS",
                        receipt_hash,
                        "UNSIGNED",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            source_before = hashlib.sha256(database.read_bytes()).hexdigest()
            measurement = run_restore_drill(
                database,
                temporary_root=root,
                max_rto_seconds=60,
                max_rpo_seconds=60,
            )
            source_after = hashlib.sha256(database.read_bytes()).hexdigest()
        self.assertEqual(source_before, source_after)
        self.assertEqual(validate_restore_measurement(measurement)[0], "PASS")
        self.assertTrue(measurement["source"]["unchanged"])
        self.assertTrue(measurement["restore_target"]["cleaned_up"])
        self.assertEqual(measurement["restore_target"]["production_writes"], 0)

    def test_restore_sidecar_attestations_fail_closed(self) -> None:
        present = {
            "exists": True,
            "sha256": "6" * 64,
            "size_bytes": 32768,
            "mtime_ns": 123456789,
            "device_id": 1,
            "file_id": 2,
        }
        absent = {
            "exists": False,
            "sha256": None,
            "size_bytes": None,
            "mtime_ns": None,
            "device_id": None,
            "file_id": None,
        }

        missing_field = restore_measurement()
        missing_field["source"].pop("sidecars")
        self.assertEqual(validate_restore_measurement(missing_field)[0], "FAIL")

        missing_suffix = restore_measurement()
        missing_suffix["source"]["sidecars"].pop("-shm")
        self.assertEqual(validate_restore_measurement(missing_suffix)[0], "FAIL")

        for transition, before, after in (
            ("created", absent, present),
            ("deleted", present, absent),
        ):
            with self.subTest(transition=transition):
                measurement = restore_measurement()
                measurement["source"]["sidecars"]["-wal"] = {
                    "before": dict(before),
                    "after": dict(after),
                }
                state, detail = validate_restore_measurement(measurement)
                self.assertEqual(state, "FAIL")
                self.assertIn("did not preserve every SQLite sidecar", detail)

        for field, changed_value in (
            ("sha256", "7" * 64),
            ("size_bytes", 32769),
            ("mtime_ns", 123456790),
            ("device_id", 3),
            ("file_id", 4),
        ):
            with self.subTest(changed_identity_field=field):
                measurement = restore_measurement()
                after = dict(present)
                after[field] = changed_value
                measurement["source"]["sidecars"]["-shm"] = {
                    "before": dict(present),
                    "after": after,
                }
                state, detail = validate_restore_measurement(measurement)
                self.assertEqual(state, "FAIL")
                self.assertIn("did not preserve every SQLite sidecar", detail)

    def test_restore_runner_preserves_wal_backed_source_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "estate-wal.db"
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                    "wal",
                )
                connection.execute("PRAGMA wal_autocheckpoint = 0")
                connection.executescript(
                    """
                    CREATE TABLE audit_runs (completed_at TEXT NOT NULL);
                    CREATE TABLE receipts (
                        sequence INTEGER PRIMARY KEY,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        receipt_hash TEXT NOT NULL,
                        signature_status TEXT NOT NULL
                    );
                    """
                )
                recovery_point = datetime.now(timezone.utc) - timedelta(seconds=1)
                payload = "{}"
                payload_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                receipt_hash = hashlib.sha256(
                    f"GENESIS\n{payload_sha256}".encode("utf-8")
                ).hexdigest()
                connection.execute(
                    "INSERT INTO audit_runs VALUES (?)",
                    (recovery_point.isoformat(),),
                )
                connection.execute(
                    "INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        1,
                        payload,
                        payload_sha256,
                        "GENESIS",
                        receipt_hash,
                        "UNSIGNED",
                    ),
                )
                connection.commit()
                sidecars_before = {
                    suffix: file_attestation(Path(f"{database}{suffix}"))
                    for suffix in ("-wal", "-shm", "-journal")
                }

                measurement = run_restore_drill(
                    database,
                    temporary_root=root,
                    max_rto_seconds=60,
                    max_rpo_seconds=60,
                )
                sidecars_after = {
                    suffix: file_attestation(Path(f"{database}{suffix}"))
                    for suffix in ("-wal", "-shm", "-journal")
                }
            finally:
                connection.close()

        self.assertEqual(sidecars_before, sidecars_after)
        self.assertTrue(sidecars_before["-wal"]["exists"])
        self.assertTrue(sidecars_before["-shm"]["exists"])
        self.assertFalse(sidecars_before["-journal"]["exists"])
        self.assertEqual(validate_restore_measurement(measurement)[0], "PASS")
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertEqual(
                measurement["source"]["sidecars"][suffix],
                {
                    "before": sidecars_before[suffix],
                    "after": sidecars_after[suffix],
                },
            )

    def test_restore_output_rejects_source_and_sidecar_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "estate.db"
            original = b"immutable-source-database"
            database.write_bytes(original)

            safe_output = root / "evidence" / "restore-measurement.json"
            self.assertEqual(
                validate_output_path(database, safe_output),
                safe_output.resolve(),
            )

            collisions = (database,) + tuple(
                Path(f"{database}{suffix}")
                for suffix in ("-wal", "-shm", "-journal")
            )
            for collision in collisions:
                with self.subTest(collision=collision.name), self.assertRaisesRegex(
                    ValueError,
                    "must not alias the source database or SQLite sidecars",
                ):
                    validate_output_path(database, collision)

            with self.assertRaisesRegex(
                ValueError,
                "must not alias the source database or SQLite sidecars",
            ):
                write_json_atomic(
                    database,
                    {"status": "PASS"},
                    protected_database=database,
                )
            self.assertEqual(database.read_bytes(), original)

    def test_restore_output_rejects_filesystem_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "estate.db"
            database.write_bytes(b"immutable-source-database")
            hardlink = root / "hardlink-output.json"
            try:
                os.link(database, hardlink)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable on this filesystem: {exc}")
            with self.assertRaisesRegex(
                ValueError,
                "must not alias the source database or SQLite sidecars",
            ):
                validate_output_path(database, hardlink)

            symlink = root / "symlink-output.json"
            try:
                symlink.symlink_to(database)
            except OSError:
                return
            with self.assertRaisesRegex(
                ValueError,
                "must not alias the source database or SQLite sidecars",
            ):
                validate_output_path(database, symlink)

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

    def test_artifact_freshness_is_anchored_to_verification_time(self) -> None:
        requirement = "browser_e2e_and_accessibility"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            browser = browser_artifact(*write_report(root, "browser-report.json"))
            value = audit()
            add_audited_deployment(value)
            value["production_evidence"] = indexed_evidence(
                {
                    "credential_backed_deployment_witness": write_artifact(
                        root, "deployment.json", deployment_witness()
                    ),
                    requirement: write_artifact(root, "browser.json", browser),
                }
            )
            sign(value)
            contract = single_deployment_manifest(
                {"independent_asymmetric_evidence": True, requirement: True}
            )
            contract["production_policies"]["max_browser_age_seconds"] = 3600
            report = verify(
                value, contract, "production", evidence_root=root
            )
        requirement_check = check(report, f"production.requirement.{requirement}")
        self.assertEqual(requirement_check["state"], "FAIL")
        self.assertIn("browser evidence is stale", requirement_check["detail"])

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
                "metadata": {
                    "default_branch_sha": "b" * 40,
                    "default_branch_commit_fact": {
                        "source_repository": "szl-holdings/a11oy",
                        "source_revision": "b" * 40,
                        "state": "VERIFIED_REACHABLE",
                    },
                },
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
                    "provenance_policy": verified_space_provenance_policy(
                        asset_id,
                        "szl-holdings/a11oy",
                        "b" * 40,
                    ),
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

    def test_runtime_only_currency_cannot_satisfy_critical_space_alignment(
        self,
    ) -> None:
        asset_id = "huggingface:space:szlholdings/a11oy"
        value = audit()
        add_audited_deployment(
            value,
            deployment_witness(
                deployment_asset_id=asset_id,
                deployment_url=(
                    "https://huggingface.co/spaces/SZLHOLDINGS/a11oy"
                ),
                receipt_id="deployment-receipt-runtime-only",
            ),
        )
        target = next(
            asset
            for asset in value["assets"]
            if asset["asset_id"] == asset_id
        )
        metadata = target["metadata"]
        metadata["provenance_docs"] = []
        revision = metadata["runtime_build"]["revision"]
        metadata["provenance_policy"]["artifact_provenance"] = {
            "state": "UNAVAILABLE",
            "evidence_state": "RUNTIME_ONLY_NOT_ARTIFACT_PROVENANCE",
            "alignment_state": "NOT_DECLARED",
            "current": None,
            "source_repository": None,
            "source_revision": None,
            "head_revision": revision,
        }

        report = verify(value, manifest(), "production")
        alignment_check = check(report, f"alignment.{asset_id}")
        self.assertEqual(alignment_check["state"], "FAIL")
        self.assertIn(
            "artifact provenance does not verify the exact runtime source",
            alignment_check["detail"],
        )

    def test_unverified_commit_cannot_satisfy_critical_space_alignment(
        self,
    ) -> None:
        asset_id = "huggingface:space:szlholdings/a11oy"
        value = audit()
        add_audited_deployment(
            value,
            deployment_witness(
                deployment_asset_id=asset_id,
                deployment_url=(
                    "https://huggingface.co/spaces/SZLHOLDINGS/a11oy"
                ),
                receipt_id="deployment-receipt-unverified-commit",
            ),
        )
        repository = next(
            asset
            for asset in value["assets"]
            if asset["asset_id"] == PRIMARY_REPOSITORY_ASSET_ID
        )
        repository["metadata"]["default_branch_commit_fact"][
            "state"
        ] = "REACHABLE_UNVERIFIED"

        report = verify(value, manifest(), "production")
        alignment_check = check(report, f"alignment.{asset_id}")
        self.assertEqual(alignment_check["state"], "FAIL")
        self.assertIn(
            "source repository commit is not independently verified and reachable",
            alignment_check["detail"],
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
                "schema": "szl.estate-restore-drill/v1",
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


if __name__ == "__main__":
    unittest.main()
