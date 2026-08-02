from __future__ import annotations

import os
import unittest
import sys
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from SZL_ONE_OF_ONE_ESTATE_OS import (
    AuditConfig,
    Asset,
    HttpResult,
    attach_cross_estate_alignment,
    collect_github,
    github_commit_fact_from_payload,
)
from estate.provenance_policy import POLICY_SCHEMA, classify_provenance
from operating_fabric import evaluate_operating_fabric


HISTORICAL_REVISION = "1" * 40
HEAD_REVISION = "2" * 40
OTHER_REVISION = "3" * 40
REPOSITORY = "szl-holdings/szl-forge"
OBSERVED_AT = "2026-08-01T12:00:00Z"


def artifact_document(
    revision: str, repository: str = REPOSITORY
) -> dict[str, object]:
    return {
        "status": "OBSERVED",
        "binding_kind": "ARTIFACT_SOURCE",
        "source_repository": repository,
        "source_revision": revision,
    }


def unavailable_artifact_document() -> dict[str, object]:
    return {
        "status": "UNAVAILABLE",
        "binding_kind": "ARTIFACT_SOURCE",
    }


def commit_fact(
    revision: str, state: str = "VERIFIED_REACHABLE", repository: str = REPOSITORY
) -> dict[str, object]:
    return {
        "source_repository": repository,
        "source_revision": revision,
        "state": state,
    }


def source_head(
    revision: str = HEAD_REVISION, repository: str = REPOSITORY
) -> dict[str, object]:
    return {
        "status": "OBSERVED",
        "source_repository": repository,
        "source_revision": revision,
    }


def runtime(
    revision: str = HEAD_REVISION, repository: str = REPOSITORY
) -> dict[str, object]:
    return {
        "status": "OBSERVED",
        "source_repository": repository,
        "source_revision": revision,
    }


def github_repository(
    revision: str = HEAD_REVISION,
    verified_commit_fact: dict[str, object] | None = None,
) -> Asset:
    metadata: dict[str, object] = {"default_branch_sha": revision}
    if verified_commit_fact is not None:
        metadata["default_branch_commit_fact"] = verified_commit_fact
    return Asset(
        asset_id=f"github:repo:{REPOSITORY}",
        asset_type="repo",
        source="github",
        name=REPOSITORY,
        url=f"https://github.com/{REPOSITORY}",
        status_label="OBSERVED",
        operational_status="ACTIVE",
        observed_at=OBSERVED_AT,
        metadata=metadata,
    )


def hub_asset(
    *,
    name: str,
    asset_type: str = "model",
    documents: list[dict[str, object]] | None = None,
    runtime_revision: str | None = None,
) -> Asset:
    metadata: dict[str, object] = {"provenance_docs": documents or []}
    if runtime_revision is not None:
        metadata["runtime_build"] = {
            "status": "OBSERVED",
            "state": "OBSERVED",
            "revision": runtime_revision,
            "domain": f"{name}.hf.space",
        }
    return Asset(
        asset_id=f"huggingface:{asset_type}:szlholdings/{name}",
        asset_type=asset_type,
        source="huggingface",
        name=f"SZLHOLDINGS/{name}",
        url=f"https://huggingface.co/SZLHOLDINGS/{name}",
        status_label="OBSERVED",
        operational_status="RUNNING" if asset_type == "space" else "PUBLISHED",
        observed_at=OBSERVED_AT,
        metadata=metadata,
    )


def attach_and_source_provenance_control(assets: list[Asset]) -> dict[str, object]:
    attach_cross_estate_alignment(
        assets, source_scope="AUTHENTICATED_COMPLETE"
    )
    reports = [
        {
            "source": "github",
            "status": "MEASURED",
            "scope": "AUTHENTICATED_COMPLETE",
            "count": 1,
            "observed_at": OBSERVED_AT,
            "elapsed_ms": 1,
        },
        {
            "source": "huggingface",
            "status": "MEASURED",
            "scope": "ORGANIZATION_COMPLETE",
            "count": len(assets) - 1,
            "observed_at": OBSERVED_AT,
            "elapsed_ms": 1,
        },
    ]
    fabric = evaluate_operating_fabric(
        "audit-provenance-policy",
        assets,
        reports,
        [],
        OBSERVED_AT,
    )
    return next(
        control
        for control in fabric["controls"]
        if control["control_id"] == "data_ai.source_provenance"
    )


class ProvenancePolicyTests(unittest.TestCase):
    def test_deep_collector_fetches_exact_head_once_and_rejects_invalid_head(
        self,
    ) -> None:
        calls: list[str] = []
        repository_payload = {
            "full_name": REPOSITORY,
            "name": "szl-forge",
            "private": False,
            "visibility": "public",
            "archived": False,
            "disabled": False,
            "fork": False,
            "default_branch": "main",
            "html_url": f"https://github.com/{REPOSITORY}",
        }

        def fake_get_json(url: str, **_: object) -> tuple[object, HttpResult]:
            calls.append(url)
            result = HttpResult(
                requested_url=url,
                final_url=url,
                status=200,
                headers={},
                body=b"{}",
                elapsed_ms=1,
            )
            if url.endswith("/orgs/szl-holdings"):
                return {
                    "login": "szl-holdings",
                    "public_repos": 1,
                    "total_private_repos": 0,
                }, result
            if "/orgs/szl-holdings/repos?" in url:
                return [repository_payload], result
            if url.endswith("/rules/branches/main"):
                return [], result
            if url.endswith("/branches/main"):
                return {
                    "protected": True,
                    "commit": {"sha": HEAD_REVISION},
                }, result
            if url.endswith(f"/git/commits/{HEAD_REVISION}"):
                return {
                    "sha": HEAD_REVISION,
                    "verification": {
                        "verified": True,
                        "reason": "valid",
                        "verified_at": OBSERVED_AT,
                    },
                }, result
            if url.endswith("/community/profile"):
                return {"health_percentage": 100, "files": {}}, result
            raise AssertionError(f"Unexpected URL: {url}")

        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch(
            "SZL_ONE_OF_ONE_ESTATE_OS.get_json", side_effect=fake_get_json
        ):
            assets, report = collect_github(
                AuditConfig(deep=True, workers=1, max_pages=2)
            )

        repository = next(asset for asset in assets if asset.asset_type == "repo")
        commit_calls = [url for url in calls if "/git/commits/" in url]
        self.assertEqual(commit_calls, [
            f"https://api.github.com/repos/{REPOSITORY}/git/commits/{HEAD_REVISION}"
        ])
        self.assertEqual(report.status, "MEASURED")
        self.assertEqual(
            repository.metadata["deep_status"], "MEASURED", repository.metadata
        )
        self.assertEqual(
            repository.metadata["default_branch_commit_fact"]["state"],
            "VERIFIED_REACHABLE",
        )

        calls.clear()

        def invalid_head_get_json(
            url: str, **kwargs: object
        ) -> tuple[object, HttpResult]:
            if url.endswith("/branches/main") and not url.endswith(
                "/rules/branches/main"
            ):
                calls.append(url)
                return {
                    "protected": True,
                    "commit": {"sha": "not-an-exact-sha"},
                }, HttpResult(
                    requested_url=url,
                    final_url=url,
                    status=200,
                    headers={},
                    body=b"{}",
                    elapsed_ms=1,
                )
            return fake_get_json(url, **kwargs)

        with mock.patch.dict(os.environ, {"GH_TOKEN": "test-token"}), mock.patch(
            "SZL_ONE_OF_ONE_ESTATE_OS.get_json",
            side_effect=invalid_head_get_json,
        ):
            invalid_assets, _ = collect_github(
                AuditConfig(deep=True, workers=1, max_pages=2)
            )

        invalid_repository = next(
            asset for asset in invalid_assets if asset.asset_type == "repo"
        )
        self.assertEqual([url for url in calls if "/git/commits/" in url], [])
        self.assertEqual(invalid_repository.metadata["deep_status"], "PARTIAL")
        self.assertIn(
            "commit_verification: DEFAULT_BRANCH_SHA_INVALID",
            invalid_repository.metadata["deep_errors"],
        )

    def test_exact_payload_verification_is_required_for_promotable_fact(self) -> None:
        verified_payload = {
            "sha": HEAD_REVISION,
            "verification": {
                "verified": True,
                "reason": "valid",
                "verified_at": OBSERVED_AT,
            },
        }
        verified = github_commit_fact_from_payload(
            REPOSITORY, HEAD_REVISION, verified_payload
        )
        mismatched = github_commit_fact_from_payload(
            REPOSITORY,
            HEAD_REVISION,
            {**verified_payload, "sha": OTHER_REVISION},
        )
        malformed = github_commit_fact_from_payload(
            REPOSITORY, HEAD_REVISION, {"sha": HEAD_REVISION}
        )

        self.assertEqual(verified["state"], "VERIFIED_REACHABLE")
        self.assertEqual(mismatched["state"], "UNAVAILABLE")
        self.assertEqual(malformed["state"], "UNAVAILABLE")

    def test_non_exact_sha_fails_before_commit_evidence(self) -> None:
        short_revision = "a" * 39
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/short-revision",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[artifact_document(short_revision)],
            commit_facts=[commit_fact(short_revision)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(provenance["evidence_state"], "INVALID_REVISION")

    def test_invented_exact_sha_fails_without_reachability(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/invented",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[artifact_document(HISTORICAL_REVISION)],
            commit_facts=[commit_fact(HISTORICAL_REVISION, "UNREACHABLE")],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(provenance["evidence_state"], "SOURCE_COMMIT_UNREACHABLE")
        self.assertEqual(provenance["alignment_state"], "UNVERIFIED_SOURCE")

    def test_reachable_but_unverified_sha_cannot_pass(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/unverified",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[artifact_document(HISTORICAL_REVISION)],
            commit_facts=[
                commit_fact(HISTORICAL_REVISION, "REACHABLE_UNVERIFIED")
            ],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(provenance["evidence_state"], "SOURCE_COMMIT_UNVERIFIED")

    def test_verified_reachable_historical_sha_passes_but_is_not_current(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/released-model",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[artifact_document(HISTORICAL_REVISION)],
            commit_facts=[commit_fact(HISTORICAL_REVISION)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "PASS")
        self.assertEqual(provenance["evidence_state"], "VERIFIED_REACHABLE")
        self.assertEqual(provenance["alignment_state"], "PINNED_NON_HEAD")
        self.assertIs(provenance["current"], False)
        self.assertEqual(decision["scope"]["completeness"], "PARTIAL")

    def test_runtime_only_head_match_is_currency_not_artifact_provenance(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:space:szlholdings/runtime-only",
            source_scope="AUTHENTICATED_VISIBILITY_UNKNOWN",
            source_head=source_head(),
            runtime_evidence=runtime(),
        )

        provenance = decision["artifact_provenance"]
        currency = decision["runtime_currency"]
        self.assertEqual(provenance["state"], "UNAVAILABLE")
        self.assertEqual(
            provenance["evidence_state"], "RUNTIME_ONLY_NOT_ARTIFACT_PROVENANCE"
        )
        self.assertEqual(currency["state"], "PASS")
        self.assertEqual(currency["currency_state"], "CURRENT")
        self.assertIs(currency["current"], True)

    def test_current_artifact_and_runtime_head_pass_independent_states(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:space:szlholdings/current",
            source_scope="AUTHENTICATED_COMPLETE",
            artifact_documents=[artifact_document(HEAD_REVISION)],
            commit_facts=[commit_fact(HEAD_REVISION)],
            source_head=source_head(),
            runtime_evidence=runtime(),
        )

        self.assertEqual(decision["schema"], POLICY_SCHEMA)
        provenance = decision["artifact_provenance"]
        currency = decision["runtime_currency"]
        self.assertEqual(provenance["state"], "PASS")
        self.assertEqual(provenance["alignment_state"], "EXACT_HEAD")
        self.assertIs(provenance["current"], True)
        self.assertEqual(currency["state"], "PASS")
        self.assertEqual(currency["currency_state"], "CURRENT")
        self.assertEqual(decision["scope"]["completeness"], "COMPLETE")

    def test_missing_private_target_preserves_public_only_scope(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/private-model",
            source_scope="PUBLIC_ONLY",
            target_evidence_state="PRIVATE_UNAVAILABLE",
        )

        self.assertEqual(decision["target"]["evidence_state"], "PRIVATE_UNAVAILABLE")
        self.assertEqual(decision["scope"], {"state": "PUBLIC_ONLY", "completeness": "PARTIAL"})
        self.assertEqual(decision["artifact_provenance"]["state"], "UNAVAILABLE")
        self.assertEqual(
            decision["artifact_provenance"]["evidence_state"],
            "PRIVATE_SCOPE_UNAVAILABLE",
        )
        self.assertEqual(decision["runtime_currency"]["state"], "UNAVAILABLE")

    def test_unknown_target_evidence_remains_unavailable(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:space:szlholdings/unknown",
            source_scope="AUTHENTICATED_VISIBILITY_UNKNOWN",
            target_evidence_state="UNKNOWN",
        )

        self.assertEqual(
            decision["scope"],
            {
                "state": "AUTHENTICATED_VISIBILITY_UNKNOWN",
                "completeness": "PARTIAL",
            },
        )
        self.assertEqual(
            decision["artifact_provenance"]["evidence_state"],
            "TARGET_EVIDENCE_UNKNOWN",
        )

    def test_conflicting_documents_fail_provenance_without_masking_currency(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:space:szlholdings/conflict",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[
                artifact_document(HEAD_REVISION),
                artifact_document(OTHER_REVISION),
            ],
            commit_facts=[
                commit_fact(HEAD_REVISION),
                commit_fact(OTHER_REVISION),
            ],
            source_head=source_head(),
            runtime_evidence=runtime(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(provenance["alignment_state"], "CONFLICT")
        self.assertEqual(
            provenance["evidence_state"], "CONFLICTING_ARTIFACT_SOURCE_DOCUMENTS"
        )
        self.assertEqual(decision["runtime_currency"]["currency_state"], "CURRENT")

    def test_exact_sha_without_commit_fact_cannot_pass(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:dataset:szlholdings/no-fact",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[artifact_document(HEAD_REVISION)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "UNAVAILABLE")
        self.assertEqual(
            provenance["evidence_state"], "SOURCE_COMMIT_EVIDENCE_MISSING"
        )
        self.assertNotEqual(provenance["alignment_state"], "EXACT_HEAD")

    def test_mixed_observed_and_unavailable_evidence_cannot_pass(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/partial-evidence",
            source_scope="AUTHENTICATED_COMPLETE",
            artifact_documents=[
                artifact_document(HEAD_REVISION),
                unavailable_artifact_document(),
            ],
            commit_facts=[commit_fact(HEAD_REVISION)],
            source_head=source_head(),
            runtime_evidence=runtime(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "UNAVAILABLE")
        self.assertEqual(
            provenance["evidence_state"], "ARTIFACT_SOURCE_EVIDENCE_PARTIAL"
        )
        self.assertEqual(provenance["alignment_state"], "UNAVAILABLE")
        self.assertIsNone(provenance["current"])
        self.assertEqual(provenance["source_repository"], REPOSITORY)
        self.assertEqual(provenance["source_revision"], HEAD_REVISION)
        self.assertEqual(decision["runtime_currency"]["state"], "PASS")
        self.assertEqual(decision["runtime_currency"]["currency_state"], "CURRENT")

    def test_all_unavailable_artifact_evidence_remains_unavailable(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:dataset:szlholdings/unavailable-evidence",
            source_scope="PUBLIC_ONLY",
            artifact_documents=[unavailable_artifact_document()],
            commit_facts=[commit_fact(HEAD_REVISION)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "UNAVAILABLE")
        self.assertEqual(
            provenance["evidence_state"], "ARTIFACT_SOURCE_EVIDENCE_UNAVAILABLE"
        )
        self.assertEqual(provenance["alignment_state"], "UNAVAILABLE")
        self.assertIsNone(provenance["source_repository"])
        self.assertIsNone(provenance["source_revision"])

    def test_invalid_observed_claim_still_fails_when_evidence_is_mixed(self) -> None:
        invalid_revision = "a" * 39
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/invalid-mixed-evidence",
            source_scope="AUTHENTICATED_COMPLETE",
            artifact_documents=[
                artifact_document(invalid_revision),
                unavailable_artifact_document(),
            ],
            commit_facts=[commit_fact(invalid_revision)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(provenance["evidence_state"], "INVALID_REVISION")
        self.assertEqual(provenance["alignment_state"], "INVALID_REVISION")

    def test_unknown_relevant_document_cannot_be_masked_by_valid_claim(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/unknown-document",
            source_scope="AUTHENTICATED_COMPLETE",
            artifact_documents=[
                artifact_document(HEAD_REVISION),
                {
                    "status": "PENDING",
                    "binding_kind": "ARTIFACT_SOURCE",
                },
            ],
            commit_facts=[commit_fact(HEAD_REVISION)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "UNAVAILABLE")
        self.assertEqual(
            provenance["evidence_state"], "ARTIFACT_SOURCE_EVIDENCE_PARTIAL"
        )

    def test_malformed_observed_document_cannot_be_masked_by_valid_claim(self) -> None:
        decision = classify_provenance(
            target_id="huggingface:model:szlholdings/malformed-document",
            source_scope="AUTHENTICATED_COMPLETE",
            artifact_documents=[
                artifact_document(HEAD_REVISION),
                {
                    "status": "OBSERVED",
                    "binding_kind": "ARTIFACT_SOURCE",
                },
            ],
            commit_facts=[commit_fact(HEAD_REVISION)],
            source_head=source_head(),
        )

        provenance = decision["artifact_provenance"]
        self.assertEqual(provenance["state"], "FAIL")
        self.assertEqual(
            provenance["evidence_state"], "INVALID_ARTIFACT_SOURCE_DOCUMENT"
        )

    def test_runtime_only_current_never_passes_artifact_control(self) -> None:
        repository = github_repository()
        space = hub_asset(
            name="runtime-only",
            asset_type="space",
            runtime_revision=HEAD_REVISION,
        )

        control = attach_and_source_provenance_control([repository, space])
        policy = space.metadata["provenance_policy"]

        self.assertEqual(
            space.metadata["github_alignment"]["status"], "EXACT_RUNTIME_HEAD"
        )
        self.assertEqual(policy["artifact_provenance"]["state"], "UNAVAILABLE")
        self.assertEqual(policy["runtime_currency"]["state"], "PASS")
        self.assertEqual(policy["runtime_currency"]["currency_state"], "CURRENT")
        self.assertEqual(control["state"], "UNAVAILABLE")
        self.assertEqual(control["metric"]["passed"], 0)

    def test_verified_observed_artifact_passes_end_to_end(self) -> None:
        fact = github_commit_fact_from_payload(
            REPOSITORY,
            HEAD_REVISION,
            {
                "sha": HEAD_REVISION,
                "verification": {
                    "verified": True,
                    "reason": "valid",
                    "verified_at": OBSERVED_AT,
                },
            },
        )
        repository = github_repository(verified_commit_fact=fact)
        model = hub_asset(
            name="verified-artifact",
            documents=[artifact_document(HEAD_REVISION)],
        )

        control = attach_and_source_provenance_control([repository, model])
        policy = model.metadata["provenance_policy"]["artifact_provenance"]

        self.assertEqual(model.metadata["github_alignment"]["status"], "EXACT_HEAD")
        self.assertEqual(policy["state"], "PASS")
        self.assertEqual(policy["alignment_state"], "EXACT_HEAD")
        self.assertEqual(control["state"], "PASS")
        self.assertEqual(control["metric"]["passed"], 1)

    def test_unverified_head_fails_artifact_control(self) -> None:
        fact = github_commit_fact_from_payload(
            REPOSITORY,
            HEAD_REVISION,
            {
                "sha": HEAD_REVISION,
                "verification": {
                    "verified": False,
                    "reason": "unsigned",
                    "verified_at": None,
                },
            },
        )
        repository = github_repository(verified_commit_fact=fact)
        model = hub_asset(
            name="unverified-artifact",
            documents=[artifact_document(HEAD_REVISION)],
        )

        control = attach_and_source_provenance_control([repository, model])
        policy = model.metadata["provenance_policy"]["artifact_provenance"]

        self.assertEqual(fact["state"], "REACHABLE_UNVERIFIED")
        self.assertEqual(policy["state"], "FAIL")
        self.assertEqual(policy["evidence_state"], "SOURCE_COMMIT_UNVERIFIED")
        self.assertEqual(control["state"], "FAIL")
        self.assertEqual(control["metric"]["passed"], 0)

    def test_historical_pin_without_exact_commit_fact_stays_unavailable(self) -> None:
        head_fact = commit_fact(HEAD_REVISION)
        repository = github_repository(verified_commit_fact=head_fact)
        model = hub_asset(
            name="historical-pin",
            documents=[artifact_document(HISTORICAL_REVISION)],
        )

        control = attach_and_source_provenance_control([repository, model])
        policy = model.metadata["provenance_policy"]["artifact_provenance"]

        self.assertEqual(policy["state"], "UNAVAILABLE")
        self.assertEqual(
            policy["evidence_state"], "SOURCE_COMMIT_EVIDENCE_MISSING"
        )
        self.assertEqual(control["state"], "UNAVAILABLE")

    def test_mixed_unavailable_artifact_evidence_stays_unavailable_end_to_end(
        self,
    ) -> None:
        repository = github_repository(
            verified_commit_fact=commit_fact(HEAD_REVISION)
        )
        dataset = hub_asset(
            name="mixed-evidence",
            asset_type="dataset",
            documents=[
                artifact_document(HEAD_REVISION),
                unavailable_artifact_document(),
            ],
        )

        control = attach_and_source_provenance_control([repository, dataset])
        policy = dataset.metadata["provenance_policy"]["artifact_provenance"]

        self.assertEqual(policy["state"], "UNAVAILABLE")
        self.assertEqual(
            policy["evidence_state"], "ARTIFACT_SOURCE_EVIDENCE_PARTIAL"
        )
        self.assertEqual(control["state"], "UNAVAILABLE")
        self.assertEqual(
            control["metric"]["artifact_provenance_state_counts"],
            {"UNAVAILABLE": 1},
        )


if __name__ == "__main__":
    unittest.main()
