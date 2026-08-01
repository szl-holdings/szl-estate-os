from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_estate_readiness import (
    PRODUCTION_SIGNATURE_ALGORITHM,
    RSA_SHA256_DIGEST_INFO_PREFIX,
    canonical_audit_payload,
    signature_state,
    verify,
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


def manifest(requirements: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "baseline": {"source_minimums": {}},
        "canonical_identities": {"github_organization": "szl-holdings"},
        "critical_assets": [],
        "known_gaps": [],
        "production_requirements": requirements or {},
        "production_trusted_keys": {
            "test-key": {
                "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
                "modulus_hex": format(RSA_N, "x"),
                "exponent": RSA_E,
            }
        },
    }


def audit() -> dict[str, object]:
    return {
        "assets": [],
        "source_reports": [
            {"source": "github", "scope": "AUTHENTICATED_COMPLETE"},
            {"source": "huggingface", "scope": "AUTHENTICATED_COMPLETE"},
        ],
        "receipt": {"signature_status": "ASYMMETRIC_VERIFIED"},
    }


def deployment_witness() -> dict[str, object]:
    repository_asset_id = "github:repo:szl-holdings/a11oy"
    deployment_asset_id = "domain:route:a-11-oy.com/"
    revision = "b" * 40
    artifact_sha256 = "c" * 64
    deployment_url = "https://a-11-oy.com/"
    environment = "production"
    owner = "szl-holdings"
    bindings = {
        "repository_asset_id": repository_asset_id,
        "deployment_asset_id": deployment_asset_id,
        "deployment_revision": revision,
        "deployed_artifact_sha256": artifact_sha256,
        "environment": environment,
        "deployment_url": deployment_url,
        "owner": owner,
    }
    return {
        "schema": "szl.estate-deployment-witness/v1",
        "status": "VERIFIED",
        **bindings,
        "credential_scope": "DEPLOYMENT_READ_ONLY",
        "deployment_receipt": {
            "schema": "szl.deployment-receipt/v1",
            "status": "VERIFIED",
            **bindings,
        },
    }


def add_audited_deployment(value: dict[str, object]) -> None:
    value["assets"] = [
        {
            "asset_id": "github:repo:szl-holdings/a11oy",
            "asset_type": "repo",
            "source": "github",
            "status_label": "OBSERVED",
            "url": "https://github.com/szl-holdings/a11oy",
            "metadata": {"default_branch_sha": "b" * 40},
        },
        {
            "asset_id": "domain:route:a-11-oy.com/",
            "asset_type": "route",
            "source": "domains",
            "status_label": "LIVE",
            "url": "https://a-11-oy.com/",
            "metadata": {"final_url": "https://a-11-oy.com/"},
        },
    ]


def sign(value: dict[str, object], key_id: str = "test-key") -> None:
    receipt = value["receipt"]
    assert isinstance(receipt, dict)
    receipt["asymmetric_signature"] = {
        "algorithm": PRODUCTION_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signature_base64": "",
    }
    payload = canonical_audit_payload(value)
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
    receipt["asymmetric_signature"]["signature_base64"] = base64.b64encode(
        signature
    ).decode("ascii")


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
        artifacts = {
            "credential_backed_deployment_witness": deployment_witness(),
            "browser_e2e_and_accessibility": {
                "schema": "szl.estate-browser-evidence/v1",
                "status": "VERIFIED",
                "deployment_asset_id": "domain:route:a-11-oy.com/",
                "tested_url": "https://a-11-oy.com/",
                "tested_at": "2026-08-01T18:00:00Z",
                "browsers": [
                    {"name": "chromium", "form_factor": "desktop", "status": "PASS"},
                    {"name": "webkit", "form_factor": "mobile", "status": "PASS"},
                ],
                "checks": {
                    "browser_e2e": "PASS",
                    "keyboard": "PASS",
                    "mobile": "PASS",
                    "accessibility": "PASS",
                    "console_errors": "PASS",
                    "network_errors": "PASS",
                    "screen_reader": "PASS",
                    "zoom_200": "PASS",
                    "contrast": "PASS",
                    "wcag_2_2_aa": "PASS",
                },
                "report_sha256": "d" * 64,
            },
            "restore_and_failure_domain_drill": {
                "schema": "szl.estate-restore-drill/v1",
                "status": "VERIFIED",
                "backup_id": "backup-20260801-1",
                "restored_target_asset_id": "domain:route:a-11-oy.com/",
                "started_at": "2026-08-01T18:00:00Z",
                "completed_at": "2026-08-01T18:05:00Z",
                "rto_seconds": 300,
                "rpo_seconds": 60,
                "dependency_loss_scenarios": [
                    {"name": "primary-store-loss", "status": "PASS"}
                ],
                "corrective_actions": [
                    {"id": "restore-drill-1", "status": "CLOSED"}
                ],
                "restore_status": "PASS",
                "failure_domain_status": "PASS",
                "report_sha256": "e" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = audit()
            add_audited_deployment(value)
            references = {}
            for requirement, artifact in artifacts.items():
                path = root / f"{requirement}.json"
                payload = json.dumps(artifact, sort_keys=True).encode("utf-8")
                path.write_bytes(payload)
                references[requirement] = {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                }
            value["production_evidence"] = references
            sign(value)
            report = verify(
                value, manifest(requirements), "production", evidence_root=root
            )
        for requirement in requirements:
            self.assertEqual(
                check(report, f"production.requirement.{requirement}")["state"],
                "PASS",
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
            value["production_evidence"] = {
                requirement: {
                    "artifact_path": path.name,
                    "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                }
            }
            sign(value)
            path.write_text("{}", encoding="utf-8")
            report = verify(
                value,
                manifest(
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
        contract = manifest({"independent_asymmetric_evidence": True, requirement: True})
        contract["canonical_identities"] = {
            "github_organization": "szl-holdings"
        }
        for mutation, expected in (
            (
                lambda witness: witness.__setitem__(
                    "deployment_asset_id", "domain:route:unrelated.example/"
                ),
                "not present in the audited inventory",
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
                value["production_evidence"] = {
                    requirement: {
                        "artifact_path": path.name,
                        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                }
                sign(value)
                report = verify(
                    value, contract, "production", evidence_root=root
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
                "asset_id": asset_id,
                "asset_type": "space",
                "source": "huggingface",
                "status_label": "LIVE",
                "metadata": {"github_alignment": {"status": "EXACT_HEAD"}},
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
        value["assets"][0]["metadata"]["github_alignment"][
            "status"
        ] = "EXACT_RUNTIME_HEAD"
        passed = verify(value, contract, "production")
        self.assertEqual(
            check(
                passed, "production.requirement.critical_huggingface_alignment"
            )["state"],
            "PASS",
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
            value["production_evidence"] = references
            sign(value)
            report = verify(
                value,
                manifest({requirement: True for requirement in shallow_artifacts}),
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

    def test_unknown_enabled_requirement_fails_closed(self) -> None:
        report = verify(
            audit(), manifest({"future_requirement": True}), "production"
        )
        self.assertEqual(
            check(report, "production.requirement.future_requirement")["state"],
            "FAIL",
        )

    def test_workflow_aggregates_independent_evidence_after_failures(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "estate-readiness.yml"
        ).read_text(encoding="utf-8")
        for step_id in ("baseline", "receipt_chain", "stress"):
            self.assertIn(f"id: {step_id}", workflow)
        self.assertGreaterEqual(workflow.count("if: always()"), 4)
        self.assertGreaterEqual(workflow.count("continue-on-error: true"), 3)
        self.assertIn("Aggregate evidence outcomes", workflow)


if __name__ == "__main__":
    unittest.main()
