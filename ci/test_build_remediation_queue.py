#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import unittest

from build_remediation_queue import ContractError, build_queue, sanitize_detail


DIGEST = "1" * 64
MANIFEST_DIGEST = "a" * 64


def readiness(*checks: tuple[str, str, str]) -> dict:
    records = [
        {"id": check_id, "state": state, "detail": detail}
        for check_id, state, detail in checks
    ]
    failures = sum(item["state"] == "FAIL" for item in records)
    warnings = sum(item["state"] in {"WARN", "UNAVAILABLE"} for item in records)
    return {
        "schema": "szl.estate-readiness-report/v1",
        "profile": "baseline",
        "status": "FAIL" if failures else "PASS",
        "audit_id": "audit-test",
        "failure_count": failures,
        "warning_count": warnings,
        "checks": records,
    }


def manifest() -> dict:
    return {
        "schema": "szl.estate-critical-surface/v1",
        "baseline": {
            "required_security_headers": [
                "content-security-policy",
                "referrer-policy",
                "strict-transport-security",
                "x-content-type-options",
            ]
        },
        "production_deployment_sources": {
            "domain:route:a11oy.net/": "github:repo:szl-holdings/a11oy-net",
            "huggingface:space:szlholdings/a11oy": "github:repo:szl-holdings/a11oy",
        },
    }


class RemediationQueueTests(unittest.TestCase):
    def test_provider_headers_keep_source_binding_and_missing_headers(self) -> None:
        queue = build_queue(
            readiness(
                (
                    "headers.domain:route:a11oy.net/",
                    "FAIL",
                    "missing=referrer-policy,content-security-policy",
                )
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        action = queue["actions"][0]
        self.assertEqual(queue["status"], "BLOCKED")
        self.assertEqual(action["control_plane"], "provider")
        self.assertEqual(action["action"], "APPLY_EDGE_RESPONSE_HEADERS")
        self.assertEqual(action["authority"], "EXTERNAL_ACTION_REQUIRED")
        self.assertEqual(action["source_repository"], "github:repo:szl-holdings/a11oy-net")
        self.assertEqual(
            action["required_headers"],
            ["content-security-policy", "referrer-policy"],
        )

    def test_inventory_and_evidence_findings_remain_distinct(self) -> None:
        queue = build_queue(
            readiness(
                ("source.github", "UNAVAILABLE", "authenticated inventory unavailable"),
                ("evidence.independent_signature", "WARN", "receipt_signature=UNSIGNED"),
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        by_check = {item["check_id"]: item for item in queue["actions"]}
        self.assertEqual(queue["status"], "ACTION_REQUIRED")
        self.assertEqual(by_check["source.github"]["control_plane"], "inventory")
        self.assertEqual(
            by_check["source.github"]["action"], "COLLECT_AUTHENTICATED_INVENTORY"
        )
        self.assertEqual(
            by_check["evidence.independent_signature"]["control_plane"], "evidence"
        )

    def test_public_baseline_private_asset_is_inventory_not_source_repair(self) -> None:
        queue = build_queue(
            readiness(
                (
                    "asset.github:repo:szl-holdings/szl-estate-os",
                    "UNAVAILABLE",
                    "Authenticated evidence is outside the public baseline",
                )
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        action = queue["actions"][0]
        self.assertEqual(action["control_plane"], "inventory")
        self.assertEqual(action["action"], "COLLECT_AUTHENTICATED_INVENTORY")
        self.assertEqual(action["authority"], "MEASURED_READBACK_REQUIRED")

    def test_inconsistent_counts_fail_closed(self) -> None:
        value = readiness(("one", "FAIL", "broken"))
        value["failure_count"] = 0
        with self.assertRaisesRegex(ContractError, "failure_count"):
            build_queue(
                value,
                manifest(),
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )

    def test_duplicate_check_ids_fail_closed(self) -> None:
        value = readiness(("duplicate", "WARN", "one"), ("duplicate", "WARN", "two"))
        with self.assertRaisesRegex(ContractError, "duplicate readiness check"):
            build_queue(
                value,
                manifest(),
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )

    def test_stable_ids_do_not_depend_on_transient_or_secret_detail(self) -> None:
        first = build_queue(
            readiness(("source.github", "WARN", "count=10 token=ghp_exampleexample")),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        second = build_queue(
            readiness(("source.github", "WARN", "count=11 token=ghp_anotherexample")),
            manifest(),
            readiness_sha256="2" * 64,
            manifest_sha256=MANIFEST_DIGEST,
        )
        self.assertEqual(first["actions"][0]["id"], second["actions"][0]["id"])
        self.assertNotEqual(first["readiness_sha256"], second["readiness_sha256"])

    def test_pass_only_report_compiles_to_clear_queue(self) -> None:
        queue = build_queue(
            readiness(("audit.payload_contract", "PASS", "verified")),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        self.assertEqual(queue["status"], "CLEAR")
        self.assertEqual(queue["summary"]["action_count"], 0)
        self.assertEqual(queue["actions"], [])

    def test_credentials_are_masked_from_detail(self) -> None:
        secrets = (
            "authorization=Basic dXNlcjpwYXNz "
            "client_secret=client-value "
            "sessionid=session-value "
            "https://user:password@example.test/path "
            '{\"private_key\":\"key-value\"}'
        )
        masked = sanitize_detail(secrets)
        for leaked in (
            "dXNlcjpwYXNz",
            "client-value",
            "session-value",
            "user",
            "password",
            "key-value",
        ):
            self.assertNotIn(leaked, masked)
        self.assertGreaterEqual(masked.count("[REDACTED]"), 5)

    def test_cookie_and_pem_private_key_are_fully_masked(self) -> None:
        detail = (
            "Cookie: session=abc; csrf=def\n"
            "-----BEGIN PRIVATE KEY-----\nsecret-body\n-----END PRIVATE KEY-----"
        )
        masked = sanitize_detail(detail)
        self.assertNotIn("abc", masked)
        self.assertNotIn("def", masked)
        self.assertNotIn("secret-body", masked)
        self.assertIn("Cookie=[REDACTED]", masked)
        self.assertIn("[REDACTED PRIVATE KEY]", masked)

    def test_cloud_credentials_and_database_uri_are_fully_masked(self) -> None:
        detail = (
            "AWS_SECRET_ACCESS_KEY=example-cloud-secret "
            "DATABASE_URL=postgresql://dbuser:dbpassword@db.example.test/app"
        )
        masked = sanitize_detail(detail)
        for leaked in ("example-cloud-secret", "dbuser", "dbpassword"):
            self.assertNotIn(leaked, masked)
        self.assertGreaterEqual(masked.count("[REDACTED]"), 2)

    def test_credential_cannot_escape_through_required_headers(self) -> None:
        with self.assertRaisesRegex(ContractError, "non-allowlisted"):
            build_queue(
                readiness(
                    (
                        "headers.domain:route:a11oy.net/",
                        "FAIL",
                        "missing=content-security-policy,hf_abcdefghijklmnopqrstuvwxyz",
                    )
                ),
                manifest(),
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )

    def test_invalid_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "readiness_sha256"):
            build_queue(
                readiness(),
                manifest(),
                readiness_sha256="not-a-digest",
                manifest_sha256=MANIFEST_DIGEST,
            )

    def test_readiness_status_must_match_findings(self) -> None:
        value = readiness(("one", "FAIL", "broken"))
        value["status"] = "PASS"
        with self.assertRaisesRegex(ContractError, "readiness status"):
            build_queue(
                value,
                manifest(),
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )

    def test_source_binding_is_null_when_manifest_has_no_mapping(self) -> None:
        contract = copy.deepcopy(manifest())
        queue = build_queue(
            readiness(
                (
                    "headers.domain:route:unknown.example/",
                    "FAIL",
                    "missing=content-security-policy",
                )
            ),
            contract,
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        self.assertIsNone(queue["actions"][0]["source_repository"])

    def test_rejected_manifest_mapping_still_produces_unbound_repair_queue(self) -> None:
        missing = manifest()
        missing.pop("production_deployment_sources")
        contracts = [missing]
        for mappings in (
            None,
            [],
            "not-an-object",
            {"domain:route:a11oy.net/": ["invalid-source"]},
            {"domain:route:a11oy.net/": "github:repo:untrusted/source"},
            {"domain:route:a11oy.net/": "hf_example_secret_value"},
            {"hf_example_secret_value": "github:repo:owner/repository"},
        ):
            contract = manifest()
            contract["production_deployment_sources"] = mappings
            contracts.append(contract)
        for index, contract in enumerate(contracts):
            with self.subTest(case=index):
                report = readiness(
                    (
                        "manifest.baseline_contract",
                        "FAIL",
                        "production deployment-source contract is missing or invalid",
                    ),
                    (
                        "headers.domain:route:a11oy.net/",
                        "FAIL",
                        "missing=content-security-policy",
                    ),
                )
                queue = build_queue(
                    report,
                    contract,
                    readiness_sha256=DIGEST,
                    manifest_sha256=MANIFEST_DIGEST,
                )
                by_check = {item["check_id"]: item for item in queue["actions"]}
                repair = by_check["manifest.baseline_contract"]
                self.assertEqual(repair["action"], "REPAIR_EVIDENCE_CONTRACT")
                self.assertEqual(repair["state"], "BLOCKED")
                self.assertEqual(repair["authority"], "EVIDENCE_CONTRACT_REQUIRED")
                provider = by_check["headers.domain:route:a11oy.net/"]
                self.assertIsNone(provider["source_repository"])
                self.assertEqual(provider["authority"], "EXTERNAL_ACTION_REQUIRED")
                self.assertEqual(queue["status"], "BLOCKED")
                self.assertNotIn("hf_example_secret_value", json.dumps(queue))
                self.assertEqual(
                    queue,
                    build_queue(
                        report,
                        contract,
                        readiness_sha256=DIGEST,
                        manifest_sha256=MANIFEST_DIGEST,
                    ),
                )

    def test_invalid_mapping_requires_a_failed_manifest_contract_finding(self) -> None:
        for mappings in (None, [], "not-an-object"):
            with self.subTest(mappings=mappings), self.assertRaises(ContractError):
                contract = manifest()
                contract["production_deployment_sources"] = mappings
                build_queue(
                    readiness(("manifest.baseline_contract", "PASS", "verified")),
                    contract,
                    readiness_sha256=DIGEST,
                    manifest_sha256=MANIFEST_DIGEST,
                )

    def test_schema_and_freshness_targets_remain_evidence_work(self) -> None:
        queue = build_queue(
            readiness(
                ("schema.asset.domain:route:a11oy.net/", "FAIL", "invalid payload"),
                (
                    "schema.asset.github:repo:szl-holdings/a11oy",
                    "FAIL",
                    "invalid observation",
                ),
                (
                    "freshness.asset.huggingface:space:szlholdings/a11oy",
                    "WARN",
                    "observation is stale",
                ),
                (
                    "freshness.asset.github:repo:szl-holdings/a11oy",
                    "WARN",
                    "observation is stale",
                ),
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        by_check = {item["check_id"]: item for item in queue["actions"]}
        self.assertEqual(
            by_check["schema.asset.domain:route:a11oy.net/"]["action"],
            "REPAIR_EVIDENCE_CONTRACT",
        )
        self.assertEqual(
            by_check["freshness.asset.huggingface:space:szlholdings/a11oy"]["action"],
            "REFRESH_OR_COMPLETE_EVIDENCE",
        )
        self.assertEqual(
            by_check["schema.asset.github:repo:szl-holdings/a11oy"]["action"],
            "REPAIR_EVIDENCE_CONTRACT",
        )
        self.assertEqual(
            by_check["freshness.asset.github:repo:szl-holdings/a11oy"]["action"],
            "REFRESH_OR_COMPLETE_EVIDENCE",
        )

    def test_production_requirement_planes_are_specific(self) -> None:
        queue = build_queue(
            readiness(
                (
                    "production.requirement.authenticated_inventory",
                    "FAIL",
                    "missing inventory",
                ),
                (
                    "production.requirement.critical_huggingface_alignment",
                    "FAIL",
                    "runtime head mismatch",
                ),
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        by_check = {item["check_id"]: item for item in queue["actions"]}
        self.assertEqual(
            by_check["production.requirement.authenticated_inventory"]["control_plane"],
            "inventory",
        )
        self.assertEqual(
            by_check["production.requirement.critical_huggingface_alignment"]["control_plane"],
            "provider",
        )

    def test_prohibited_assets_expand_to_their_operational_control_planes(self) -> None:
        queue = build_queue(
            readiness(
                (
                    "assets.prohibited_status",
                    "FAIL",
                    (
                        "domain:route:a11oy.net/, "
                        "github:repo:szl-holdings/non-critical, "
                        "huggingface:model:szlholdings/non-critical"
                    ),
                )
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        by_target = {item["target"]: item for item in queue["actions"]}
        self.assertEqual(queue["summary"]["action_count"], 3)
        self.assertEqual(queue["summary"]["blocked_count"], 3)
        self.assertEqual(
            set(by_target),
            {
                "domain:route:a11oy.net/",
                "github:repo:szl-holdings/non-critical",
                "huggingface:model:szlholdings/non-critical",
            },
        )
        self.assertEqual(
            by_target["domain:route:a11oy.net/"]["control_plane"], "provider"
        )
        self.assertEqual(
            by_target["domain:route:a11oy.net/"]["action"],
            "RECONCILE_PROVIDER_TARGET",
        )
        self.assertEqual(
            by_target["domain:route:a11oy.net/"]["source_repository"],
            "github:repo:szl-holdings/a11oy-net",
        )
        self.assertEqual(
            by_target["github:repo:szl-holdings/non-critical"]["control_plane"],
            "source",
        )
        self.assertEqual(
            by_target["github:repo:szl-holdings/non-critical"]["source_repository"],
            "github:repo:szl-holdings/non-critical",
        )
        self.assertEqual(
            by_target["huggingface:model:szlholdings/non-critical"]["control_plane"],
            "provider",
        )

    def test_manifest_shape_checks_route_to_contract_repair(self) -> None:
        queue = build_queue(
            readiness(
                (
                    "production.requirements_contract",
                    "FAIL",
                    "shape_valid=False missing=['authenticated_inventory']",
                ),
                ("gaps.contract", "FAIL", "known_gaps must be a list"),
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        by_check = {item["check_id"]: item for item in queue["actions"]}
        for check_id in ("production.requirements_contract", "gaps.contract"):
            with self.subTest(check_id=check_id):
                self.assertEqual(by_check[check_id]["control_plane"], "evidence")
                self.assertEqual(
                    by_check[check_id]["action"], "REPAIR_EVIDENCE_CONTRACT"
                )
                self.assertEqual(
                    by_check[check_id]["authority"], "EVIDENCE_CONTRACT_REQUIRED"
                )

    def test_prohibited_asset_targets_reject_malformed_or_credential_like_input(self) -> None:
        invalid_details = (
            "",
            "domain:route:a11oy.net/, ",
            "domain:route:a11oy.net/, domain:route:a11oy.net/",
            "github:repo:szl-holdings/example token=ghp_exampleexample",
            "github:repo:szl-holdings/hf_exampleexample",
        )
        for detail in invalid_details:
            with self.subTest(detail=detail), self.assertRaises(ContractError):
                build_queue(
                    readiness(("assets.prohibited_status", "FAIL", detail)),
                    manifest(),
                    readiness_sha256=DIGEST,
                    manifest_sha256=MANIFEST_DIGEST,
                )

    def test_manifest_digest_is_part_of_queue_provenance(self) -> None:
        first = build_queue(
            readiness(
                (
                    "headers.domain:route:a11oy.net/",
                    "FAIL",
                    "missing=content-security-policy",
                )
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256=MANIFEST_DIGEST,
        )
        second = build_queue(
            readiness(
                (
                    "headers.domain:route:a11oy.net/",
                    "FAIL",
                    "missing=content-security-policy",
                )
            ),
            manifest(),
            readiness_sha256=DIGEST,
            manifest_sha256="b" * 64,
        )
        self.assertNotEqual(first["manifest_sha256"], second["manifest_sha256"])

    def test_unsafe_identifiers_fail_closed(self) -> None:
        value = readiness(("safe.check", "WARN", "detail"))
        value["audit_id"] = "audit id with spaces"
        with self.assertRaisesRegex(ContractError, "audit_id"):
            build_queue(
                value,
                manifest(),
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )

        contract = manifest()
        contract["production_deployment_sources"]["domain:route:unsafe/"] = (
            "github:repo:owner/repo?access_token=do-not-copy"
        )
        with self.assertRaisesRegex(ContractError, "deployment source"):
            build_queue(
                readiness(("safe.check", "WARN", "detail")),
                contract,
                readiness_sha256=DIGEST,
                manifest_sha256=MANIFEST_DIGEST,
            )


if __name__ == "__main__":
    unittest.main()
