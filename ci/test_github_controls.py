from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from SZL_ONE_OF_ONE_ESTATE_OS import (  # noqa: E402
    AuditConfig,
    GITHUB_COMPLETE_SCOPE,
    GITHUB_PARTIAL_SCOPE,
    HttpResult,
    collect_github,
    normalize_default_branch_rules,
    probe_domain_route,
    reconcile_github_inventory_scope,
)
from operating_fabric import evaluate_operating_fabric  # noqa: E402


OBSERVED_AT = "2026-08-01T20:57:59+00:00"


def repository_asset(
    index: int,
    *,
    operational_status: str = "ACTIVE",
    secret_scanning: str | None = "enabled",
    push_protection: str | None = "enabled",
    branch_protected: bool | None = True,
    rules_status: str = "MEASURED",
    rule_types: list[str] | None = None,
    required_approvals: int | None = 1,
    review_thread_resolution: bool | None = True,
    required_status_checks: list[str] | None = None,
    web_signoff: bool | None = True,
) -> dict[str, Any]:
    security = {}
    if secret_scanning is not None:
        security["secret_scanning"] = secret_scanning
    if push_protection is not None:
        security["secret_scanning_push_protection"] = push_protection
    return {
        "asset_id": f"github:repo:szl-holdings/repo-{index:02d}",
        "asset_type": "repo",
        "source": "github",
        "operational_status": operational_status,
        "status_label": "ARCHIVED" if operational_status == "ARCHIVED" else "OBSERVED",
        "metadata": {
            "security_and_analysis": security,
            "branch_protection_enabled": branch_protected,
            "default_branch_rules": {
                "status": rules_status,
                "types": rule_types
                if rule_types is not None
                else [
                    "non_fast_forward",
                    "pull_request",
                    "required_signatures",
                    "required_status_checks",
                ],
                "sources": ["Organization:szl-holdings:1"],
                "pull_request": {
                    **(
                        {"required_approving_review_count": required_approvals}
                        if required_approvals is not None
                        else {}
                    ),
                    **(
                        {
                            "required_review_thread_resolution": (
                                review_thread_resolution
                            )
                        }
                        if review_thread_resolution is not None
                        else {}
                    ),
                },
                "required_status_checks": (
                    ["self-test"]
                    if required_status_checks is None
                    else required_status_checks
                ),
            },
            "web_commit_signoff_required": web_signoff,
        },
    }


def github_report(scope: str, status: str = "MEASURED") -> dict[str, Any]:
    return {
        "source": "github",
        "status": status,
        "scope": scope,
        "count": 0,
    }


def domain_report(status: str = "MEASURED") -> dict[str, Any]:
    return {
        "source": "domains",
        "status": status,
        "scope": "PUBLIC_ONLY",
        "count": 1,
    }


def domain_route_asset(
    index: int,
    *,
    header_values: dict[str, str] | None,
    semantic_headers: dict[str, bool] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "security_headers": semantic_headers
        or {
            "content-security-policy": True,
            "referrer-policy": True,
            "strict-transport-security": True,
            "x-content-type-options": True,
        }
    }
    if header_values is not None:
        metadata["security_header_values"] = header_values
    return {
        "asset_id": f"domain:route:example-{index}.test/",
        "asset_type": "route",
        "source": "domains",
        "name": f"example-{index}.test/",
        "operational_status": "REAL",
        "status_label": "LIVE",
        "metadata": metadata,
    }


def controls_by_id(
    assets: list[dict[str, Any]],
    report: dict[str, Any],
    *additional_reports: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    fabric = evaluate_operating_fabric(
        "audit-test",
        assets,
        [report, *additional_reports],
        [],
        OBSERVED_AT,
    )
    return {control["control_id"]: control for control in fabric["controls"]}


class GitHubInventoryScopeTests(unittest.TestCase):
    @patch("SZL_ONE_OF_ONE_ESTATE_OS.env_token", return_value="test-token")
    @patch("SZL_ONE_OF_ONE_ESTATE_OS.get_json")
    def test_collector_reconciles_all_repositories_and_preserves_archives(
        self, get_json: Any, _env_token: Any
    ) -> None:
        response = SimpleNamespace(headers={})
        repositories = [
            {
                "full_name": "szl-holdings/active",
                "html_url": "https://github.com/szl-holdings/active",
                "private": False,
                "archived": False,
                "disabled": False,
                "default_branch": "main",
            },
            {
                "full_name": "szl-holdings/archive",
                "html_url": "https://github.com/szl-holdings/archive",
                "private": True,
                "archived": True,
                "disabled": False,
                "default_branch": "main",
            },
        ]
        get_json.side_effect = [
            (
                {
                    "login": "szl-holdings",
                    "html_url": "https://github.com/szl-holdings",
                    "public_repos": 1,
                    "total_private_repos": 1,
                },
                response,
            ),
            (repositories, response),
            (repositories, response),
        ]

        assets, report = collect_github(AuditConfig(deep=False))

        self.assertEqual(report.scope, GITHUB_COMPLETE_SCOPE)
        self.assertEqual(report.status, "MEASURED")
        self.assertEqual(report.metadata["observed_repository_count"], 2)
        self.assertEqual(report.metadata["observed_public_repository_count"], 1)
        self.assertEqual(report.metadata["observed_private_repository_count"], 1)
        self.assertTrue(report.metadata["visibility_composition_reconciled"])
        self.assertTrue(report.metadata["inventory_stable"])
        self.assertEqual(report.metadata["active_repository_count"], 1)
        self.assertEqual(report.metadata["archived_repository_count"], 1)
        self.assertEqual(len(assets), 3)

    @patch("SZL_ONE_OF_ONE_ESTATE_OS.env_token", return_value="test-token")
    @patch("SZL_ONE_OF_ONE_ESTATE_OS.get_json")
    def test_collector_fails_closed_when_archived_repo_becomes_active(
        self, get_json: Any, _env_token: Any
    ) -> None:
        response = SimpleNamespace(headers={})
        archived = {
            "full_name": "szl-holdings/race",
            "html_url": "https://github.com/szl-holdings/race",
            "private": False,
            "archived": True,
            "disabled": False,
            "fork": False,
            "default_branch": "main",
        }
        active = {**archived, "archived": False}
        get_json.side_effect = [
            (
                {
                    "login": "szl-holdings",
                    "html_url": "https://github.com/szl-holdings",
                    "public_repos": 1,
                    "total_private_repos": 0,
                },
                response,
            ),
            ([archived], response),
            ([active], response),
        ]

        assets, report = collect_github(AuditConfig(deep=False))

        repository = next(asset for asset in assets if asset.asset_type == "repo")
        self.assertEqual(report.scope, GITHUB_PARTIAL_SCOPE)
        self.assertEqual(report.status, "PARTIAL")
        self.assertFalse(report.metadata["inventory_stable"])
        self.assertFalse(report.metadata["inventory_reconciled"])
        self.assertEqual(repository.operational_status, "ARCHIVED")
        self.assertIn(
            "Authenticated repository inventory changed between verification snapshots",
            report.warnings,
        )

    @patch("SZL_ONE_OF_ONE_ESTATE_OS.env_token", return_value="test-token")
    @patch("SZL_ONE_OF_ONE_ESTATE_OS.get_json")
    def test_collector_fails_closed_on_control_defining_repo_mutations(
        self, get_json: Any, _env_token: Any
    ) -> None:
        response = SimpleNamespace(headers={})

        def repository() -> dict[str, Any]:
            return {
                "full_name": "szl-holdings/governed",
                "html_url": "https://github.com/szl-holdings/governed",
                "private": False,
                "archived": False,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
                "web_commit_signoff_required": True,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }

        for mutation in ("default_branch", "web_commit_signoff", "secret_scanning"):
            with self.subTest(mutation=mutation):
                first = repository()
                second = repository()
                if mutation == "default_branch":
                    second["default_branch"] = "release"
                elif mutation == "web_commit_signoff":
                    second["web_commit_signoff_required"] = False
                else:
                    second["security_and_analysis"] = {
                        "secret_scanning": {"status": "disabled"},
                        "secret_scanning_push_protection": {"status": "enabled"},
                    }
                get_json.side_effect = [
                    (
                        {
                            "login": "szl-holdings",
                            "html_url": "https://github.com/szl-holdings",
                            "public_repos": 1,
                            "total_private_repos": 0,
                        },
                        response,
                    ),
                    ([first], response),
                    ([second], response),
                ]

                _, report = collect_github(AuditConfig(deep=False))

                self.assertEqual(report.scope, GITHUB_PARTIAL_SCOPE)
                self.assertEqual(report.status, "PARTIAL")
                self.assertFalse(report.metadata["inventory_stable"])
                self.assertFalse(report.metadata["inventory_reconciled"])

    def test_exact_authenticated_inventory_is_complete(self) -> None:
        scope, evidence = reconcile_github_inventory_scope(
            token_present=True,
            public_repositories=58,
            private_repositories=4,
            observed_repositories=62,
            unique_repositories=62,
            observed_public_repositories=58,
            observed_private_repositories=4,
            invalid_visibility_repositories=0,
            pagination_complete=True,
            inventory_stable=True,
            error_count=0,
        )
        self.assertEqual(scope, GITHUB_COMPLETE_SCOPE)
        self.assertTrue(evidence["inventory_reconciled"])
        self.assertEqual(evidence["expected_repository_count"], 62)

    def test_count_mismatch_remains_partial(self) -> None:
        scope, evidence = reconcile_github_inventory_scope(
            token_present=True,
            public_repositories=58,
            private_repositories=4,
            observed_repositories=61,
            unique_repositories=61,
            observed_public_repositories=57,
            observed_private_repositories=4,
            invalid_visibility_repositories=0,
            pagination_complete=True,
            inventory_stable=True,
            error_count=0,
        )
        self.assertEqual(scope, GITHUB_PARTIAL_SCOPE)
        self.assertFalse(evidence["inventory_reconciled"])

    def test_visibility_composition_mismatch_remains_partial(self) -> None:
        scope, evidence = reconcile_github_inventory_scope(
            token_present=True,
            public_repositories=58,
            private_repositories=4,
            observed_repositories=62,
            unique_repositories=62,
            observed_public_repositories=62,
            observed_private_repositories=0,
            invalid_visibility_repositories=0,
            pagination_complete=True,
            inventory_stable=True,
            error_count=0,
        )
        self.assertEqual(scope, GITHUB_PARTIAL_SCOPE)
        self.assertFalse(evidence["inventory_reconciled"])
        self.assertFalse(evidence["visibility_composition_reconciled"])

    def test_inventory_race_or_invalid_visibility_remains_partial(self) -> None:
        for inventory_stable, invalid_visibility in ((False, 0), (True, 1)):
            with self.subTest(
                inventory_stable=inventory_stable,
                invalid_visibility=invalid_visibility,
            ):
                scope, evidence = reconcile_github_inventory_scope(
                    token_present=True,
                    public_repositories=58,
                    private_repositories=4,
                    observed_repositories=62,
                    unique_repositories=62,
                    observed_public_repositories=(
                        58 if invalid_visibility == 0 else 57
                    ),
                    observed_private_repositories=4,
                    invalid_visibility_repositories=invalid_visibility,
                    pagination_complete=True,
                    inventory_stable=inventory_stable,
                    error_count=0,
                )
                self.assertEqual(scope, GITHUB_PARTIAL_SCOPE)
                self.assertFalse(evidence["inventory_reconciled"])

    def test_any_collection_error_remains_partial(self) -> None:
        scope, evidence = reconcile_github_inventory_scope(
            token_present=True,
            public_repositories=58,
            private_repositories=4,
            observed_repositories=62,
            unique_repositories=62,
            observed_public_repositories=58,
            observed_private_repositories=4,
            invalid_visibility_repositories=0,
            pagination_complete=True,
            inventory_stable=True,
            error_count=1,
        )
        self.assertEqual(scope, GITHUB_PARTIAL_SCOPE)
        self.assertFalse(evidence["inventory_reconciled"])

    def test_applicable_branch_rules_are_normalized(self) -> None:
        normalized = normalize_default_branch_rules(
            [
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 1,
                        "required_review_thread_resolution": True,
                    },
                    "ruleset_source_type": "Organization",
                    "ruleset_source": "szl-holdings",
                    "ruleset_id": 7,
                },
                {"type": "required_signatures"},
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{"context": "self-test"}]
                    },
                },
            ]
        )
        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(
            normalized["types"],
            ["pull_request", "required_signatures", "required_status_checks"],
        )
        self.assertEqual(normalized["required_status_checks"], ["self-test"])
        self.assertEqual(
            normalized["pull_request"]["required_approving_review_count"], 1
        )


class WebHeaderTruthTests(unittest.TestCase):
    safe_values = {
        "content-security-policy": (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        ),
        "referrer-policy": "strict-origin-when-cross-origin",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-content-type-options": "nosniff",
    }

    @patch("SZL_ONE_OF_ONE_ESTATE_OS.fetch")
    def test_probe_preserves_raw_values_and_emits_semantic_verdicts(
        self, fetch: Any
    ) -> None:
        observed_values = {
            **self.safe_values,
            "strict-transport-security": (
                "  max-age=31536000; includeSubDomains\t"
            ),
        }
        fetch.return_value = HttpResult(
            requested_url="https://example.test/",
            final_url="https://example.test/",
            status=200,
            headers={"content-type": "text/html", **observed_values},
            body=b"<html><title>Operational</title><body>measured</body></html>",
            elapsed_ms=1,
        )

        asset = probe_domain_route("https://example.test", "example.test", "/", 1)

        raw = asset.metadata["security_header_values"]
        self.assertEqual(
            raw["strict-transport-security"],
            "max-age=31536000; includeSubDomains",
        )
        self.assertEqual(
            raw["content-security-policy"],
            self.safe_values["content-security-policy"],
        )
        self.assertTrue(all(asset.metadata["security_headers"].values()))

    def test_safe_values_pass_and_weak_values_fail(self) -> None:
        safe = domain_route_asset(1, header_values=self.safe_values)
        safe_controls = controls_by_id(
            [safe], github_report(GITHUB_COMPLETE_SCOPE), domain_report()
        )
        self.assertEqual(safe_controls["cybersecurity.web_hardening"]["state"], "PASS")

        weak = domain_route_asset(
            2,
            header_values={
                "content-security-policy": (
                    "default-src * 'unsafe-inline' 'unsafe-eval'"
                ),
                "referrer-policy": "unsafe-url",
                "strict-transport-security": "max-age=0",
                "x-content-type-options": "sniff",
            },
        )
        weak_controls = controls_by_id(
            [weak], github_report(GITHUB_COMPLETE_SCOPE), domain_report()
        )
        control = weak_controls["cybersecurity.web_hardening"]
        self.assertEqual(control["state"], "FAIL")
        self.assertEqual(control["metric"]["failed_asset_ids"], [weak["asset_id"]])
        failures = control["metric"]["failed_header_requirements_by_asset_id"]
        self.assertEqual(set(failures[weak["asset_id"]]), set(self.safe_values))

    def test_presence_booleans_without_raw_values_cannot_pass(self) -> None:
        legacy_presence_only = domain_route_asset(3, header_values=None)
        controls = controls_by_id(
            [legacy_presence_only],
            github_report(GITHUB_COMPLETE_SCOPE),
            domain_report(),
        )
        control = controls["cybersecurity.web_hardening"]
        self.assertEqual(control["state"], "UNAVAILABLE")
        self.assertEqual(
            control["metric"]["unassessed_asset_ids"],
            [legacy_presence_only["asset_id"]],
        )


class GitHubControlTruthTests(unittest.TestCase):
    def test_all_55_active_repositories_are_observed_and_archives_are_excluded(self) -> None:
        active = [repository_asset(index) for index in range(55)]
        archived = [
            repository_asset(
                100 + index,
                operational_status="ARCHIVED",
                secret_scanning="disabled",
                push_protection="disabled",
                branch_protected=False,
                rule_types=[],
                web_signoff=False,
            )
            for index in range(7)
        ]
        controls = controls_by_id(
            [*active, *archived], github_report(GITHUB_COMPLETE_SCOPE)
        )
        for control_id in (
            "cybersecurity.secret_protection",
            "engineering.branch_protection",
            "engineering.change_signoff",
        ):
            control = controls[control_id]
            self.assertEqual(control["state"], "PASS")
            self.assertEqual(control["truth_label"], "MEASURED")
            self.assertEqual(control["metric"]["total"], 55)
            self.assertEqual(control["metric"]["assessed"], 55)
            self.assertEqual(control["metric"]["failed_asset_ids"], [])
            self.assertEqual(control["metric"]["unassessed_asset_ids"], [])

    def test_weak_branch_rules_and_zero_approval_cannot_turn_green(self) -> None:
        weak_repositories = [
            repository_asset(200, rule_types=["required_signatures"]),
            repository_asset(201, required_approvals=0),
            repository_asset(202, review_thread_resolution=False),
            repository_asset(203, required_status_checks=[]),
        ]
        controls = controls_by_id(
            weak_repositories, github_report(GITHUB_COMPLETE_SCOPE)
        )
        branch = controls["engineering.branch_protection"]
        self.assertEqual(branch["state"], "FAIL")
        self.assertEqual(
            branch["metric"]["failed_asset_ids"],
            sorted(repo["asset_id"] for repo in weak_repositories),
        )
        failures = branch["metric"]["failed_requirements_by_asset_id"]
        self.assertIn("pull_request_rule", failures[weak_repositories[0]["asset_id"]])
        self.assertIn("at_least_one_approval", failures[weak_repositories[1]["asset_id"]])
        self.assertIn(
            "review_thread_resolution", failures[weak_repositories[2]["asset_id"]]
        )
        self.assertIn(
            "nonempty_required_status_checks",
            failures[weak_repositories[3]["asset_id"]],
        )

    def test_partial_scope_and_web_only_signoff_cannot_turn_green(self) -> None:
        complete_rules = repository_asset(1)
        partial_controls = controls_by_id(
            [complete_rules],
            github_report(GITHUB_PARTIAL_SCOPE, status="PARTIAL"),
        )
        for control_id in (
            "cybersecurity.secret_protection",
            "engineering.branch_protection",
            "engineering.change_signoff",
        ):
            self.assertEqual(partial_controls[control_id]["state"], "PARTIAL")
            self.assertEqual(partial_controls[control_id]["truth_label"], "PARTIAL")

        web_only = repository_asset(
            2,
            rule_types=["non_fast_forward", "pull_request"],
            web_signoff=True,
        )
        complete_controls = controls_by_id(
            [web_only], github_report(GITHUB_COMPLETE_SCOPE)
        )
        signoff = complete_controls["engineering.change_signoff"]
        self.assertEqual(signoff["state"], "FAIL")
        self.assertEqual(signoff["truth_label"], "MEASURED")
        self.assertEqual(signoff["metric"]["failed_asset_ids"], [web_only["asset_id"]])
        self.assertEqual(
            signoff["metric"]["web_signoff_only_asset_ids"],
            [web_only["asset_id"]],
        )

    def test_failed_and_unassessed_assets_are_exact(self) -> None:
        failed = repository_asset(
            3,
            secret_scanning="disabled",
            push_protection="enabled",
        )
        unassessed = repository_asset(
            4,
            secret_scanning=None,
            push_protection=None,
        )
        controls = controls_by_id(
            [failed, unassessed], github_report(GITHUB_COMPLETE_SCOPE)
        )
        secret = controls["cybersecurity.secret_protection"]
        self.assertEqual(secret["metric"]["failed_asset_ids"], [failed["asset_id"]])
        self.assertEqual(
            secret["metric"]["unassessed_asset_ids"], [unassessed["asset_id"]]
        )
        self.assertNotEqual(secret["state"], "PASS")


if __name__ == "__main__":
    unittest.main()
