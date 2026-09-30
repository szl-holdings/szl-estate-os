"""Offline Phase 1 traceability checks; no estate, runtime or release audit."""
from collections import Counter
from copy import deepcopy
from datetime import date, datetime
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "estate_reports" / "thread_audit.md"
MATRIX = ROOT / "estate_reports" / "thread_requirements.json"
BASE = "eb060db015b2165ca777520e04dcd9c9c06ac9f4"
EXPECTED_IDS = {
    *(f"OBS-{i:03}" for i in range(1, 4)),
    *(f"HIST-{i:03}" for i in range(1, 6)),
    *(f"CON-{i:03}" for i in range(1, 14)),
    *(f"FUT-{i:03}" for i in range(1, 22)),
}
CATEGORIES = {
    "observed_fact": "OBSERVED_AS_OF",
    "unverified_historical_claim": "HISTORICAL_UNVERIFIED",
    "constraint": "REQUIRED",
    "desired_future_state": "NOT_RUN",
}
PRIVATE_IDS = re.compile(
    r"(?:libfile_|file_)[0-9a-f]{24,}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,})\b|"
    r"(?i:authorization\s*:\s*bearer|x-amz-signature=|access_token=)"
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def validate(document, markdown):
    """Closed report contract plus evidence-bound invariants and paired prose."""
    require(set(document) == {
        "schema_version", "audited_at_utc", "scope", "canonical_repository",
        "stack", "readiness", "coverage_policy", "source_policy", "sources",
        "summary", "requirements",
    }, "document fields")
    require(document["schema_version"] == "szl.thread-requirements/v1", "schema")
    require(document["scope"] == "PHASE1_PROJECT_THREAD_INTENT_ONLY", "scope")
    require(document["canonical_repository"] == "szl-holdings/szl-estate-os", "canonical repository")
    audited_at = datetime.fromisoformat(document["audited_at_utc"].replace("Z", "+00:00"))
    require(audited_at.utcoffset().total_seconds() == 0, "audit UTC")
    require(document["stack"] == {
        "branch": "codex/estate-thread-audit-phase1", "base_branch": "codex/estate-audit-phase0",
        "base_commit": BASE, "base_pr": 51, "base_target": "main",
        "merge_authority": "PR_QUEUE_OWNER", "draft_required": True,
    }, "stack/base drift")
    require(BASE in markdown and "codex/estate-audit-phase0" in markdown, "prose stack")
    require(document["readiness"] == {
        "phase1_artifact_status": "DOCUMENTED_SCOPE_ONLY",
        "phase0_setup": "OBSERVED_AS_OF_2026-09-30T07:33:23Z",
        "estate_ready": False, "full_scope": "NOT_RUN", "deployment": "NOT_RUN",
        "scientific_validity": "NOT_ESTABLISHED",
    }, "readiness promotion")
    require(isinstance(document["sources"], list), "sources type")
    sources = {}
    for source in document["sources"]:
        require(set(source) == {"id", "kind", "artifact", "date", "date_precision", "commit", "sha256", "coverage"}, "source fields")
        require(source["id"] not in sources, "duplicate source")
        require(source["date_precision"] in {"DAY", "SECOND"}, "source precision")
        if source["date_precision"] == "DAY":
            observed = date.fromisoformat(source["date"])
            require(observed <= audited_at.date(), "future source date")
        else:
            observed = datetime.fromisoformat(source["date"].replace("Z", "+00:00"))
            require(observed.utcoffset().total_seconds() == 0 and observed <= audited_at, "future/non-UTC source")
        require(source["commit"] is None or re.fullmatch(r"[0-9a-f]{40}", source["commit"]), "commit format")
        require(source["sha256"] is None or re.fullmatch(r"[0-9a-f]{64}", source["sha256"]), "digest format")
        require(all(isinstance(source[k], str) and source[k].strip() for k in ("id", "kind", "artifact", "coverage")), "empty source provenance")
        sources[source["id"]] = source

    records = document["requirements"]
    require(isinstance(records, list), "requirements type")
    ids = [row["id"] for row in records]
    require(len(ids) == len(set(ids)) and set(ids) == EXPECTED_IDS, "missing/duplicate/extra ask")
    require(ids == sorted(ids), "deterministic order")
    prose_ids = re.findall(r"^\| ((?:OBS|HIST|CON|FUT)-\d{3}) \|", markdown, re.MULTILINE)
    require(prose_ids == ids, "Markdown/JSON matrix mismatch")
    prose_rows = {line.split("|")[1].strip(): [part.strip() for part in line.split("|")[1:-1]]
                  for line in markdown.splitlines()
                  if re.match(r"^\| (?:OBS|HIST|CON|FUT)-\d{3} \|", line)}
    require(not re.search(r"\bestate_ready\s*=\s*true\b", markdown, re.IGNORECASE), "unsupported prose estate readiness")
    for row in records:
        require(set(row) == {
            "id", "category", "title", "statement", "source_ids", "coverage",
            "acceptance_criterion", "owner", "blockers", "next_action",
            "implementation_status", "claim_basis", "claim_maturity",
            "unmet_acceptance_tests", "details",
        }, "row fields")
        category = row["category"]
        require(category in CATEGORIES, "category")
        require(category == {"OBS": "observed_fact", "HIST": "unverified_historical_claim", "CON": "constraint", "FUT": "desired_future_state"}[row["id"].split("-")[0]], "evidence-category promotion")
        require(row["implementation_status"] == CATEGORIES[category] or
                (row["id"] == "CON-010" and row["implementation_status"] == "EXCLUDED_SCOPE"), "unsupported completion/access state")
        require(row["source_ids"] and len(row["source_ids"]) == len(set(row["source_ids"])) and set(row["source_ids"]) <= sources.keys(), "source reference")
        require(row["claim_basis"] in {"FACT", "INFERENCE", "PROPOSAL"}, "basis axis")
        require(row["claim_maturity"] in {"SHIPPING", "DEMONSTRATED", "INTERNALLY_TESTED", "ROADMAP"}, "maturity axis")
        require(row["claim_maturity"] == ("INTERNALLY_TESTED" if row["id"] == "OBS-001" else "ROADMAP"), "unsupported maturity")
        expected_basis = "FACT" if category in {"constraint", "observed_fact"} else ("INFERENCE" if category == "unverified_historical_claim" else "PROPOSAL")
        require(row["claim_basis"] == expected_basis, "basis/category drift")
        require(all(isinstance(row[k], str) and row[k].strip() for k in ("title", "statement", "coverage", "acceptance_criterion", "next_action")), "missing criterion/coverage/next action")
        require(set(row["owner"]) == {"role", "assignment"} and row["owner"]["role"].strip() and row["owner"]["assignment"] == "ROLE_ONLY_PERSON_UNASSIGNED", "invented/missing owner")
        require(isinstance(row["blockers"], list) and all(isinstance(x, str) and x.strip() for x in row["blockers"]), "blockers")
        require(isinstance(row["unmet_acceptance_tests"], list) and all(isinstance(x, str) and x.strip() for x in row["unmet_acceptance_tests"]), "unmet checks")
        require(category != "desired_future_state" or (row["blockers"] and row["unmet_acceptance_tests"]), "future checks hidden")
        require(isinstance(row["details"], dict), "typed details")
        unmet = "; ".join(row["unmet_acceptance_tests"]) or row["coverage"]
        blocker = "; ".join(row["blockers"]) or "No separate blocker for recording this requirement; named person unassigned."
        expected_cells = [row["id"], category + " / " + row["implementation_status"], row["title"],
                          unmet, row["owner"]["role"] + "; " + blocker, row["next_action"]]
        expected_cells = [value.replace("|", "/").replace("\n", " ") for value in expected_cells]
        require(prose_rows[row["id"]] == expected_cells, "prose row status/coverage/owner drift")

    require(document["summary"] == {
        "requirements": len(records), "categories": dict(Counter(row["category"] for row in records)),
        "all_estate_completion": "NOT_ESTABLISHED",
        "future_acceptance_checks": sum(len(row["unmet_acceptance_tests"]) for row in records),
    }, "summary reconciliation")
    require(f"**{len(records)} rows**" in markdown and f"**{document['summary']['future_acceptance_checks']} unmet acceptance checks**" in markdown, "prose summary")
    rows = {row["id"]: row for row in records}
    backend = rows["OBS-002"]["details"]
    require(backend["content_inspections"] + backend["unread_paths"] == backend["tracked_paths"] == 32748, "backend coverage arithmetic")
    hf = rows["OBS-003"]["details"]
    require(sum(hf[k] for k in ("models", "datasets", "spaces", "kernels")) == hf["total"] == 120 and hf["collections"] is None, "HF scope arithmetic")
    require(sum(hf[k] for k in ("cards_inspected", "other_contracts_inspected", "inventory_only", "unavailable")) == hf["listed_paths"] == 7346, "HF file coverage arithmetic")
    require(rows["HIST-001"]["details"]["independently_verified"] is False and rows["HIST-002"]["details"]["freshness"] == "HISTORICAL_UNVERIFIED", "historical gate promotion")
    require(rows["HIST-003"]["details"]["current_state"] == "UNKNOWN" and rows["HIST-003"]["details"]["time_precision"] == "DAY", "queue precision/currentness")
    require(rows["HIST-005"]["details"]["source_executed"] is False and rows["HIST-005"]["details"]["compiled_attachment_loaded"] is False and rows["HIST-005"]["details"]["embedded_claims"] == "HISTORICAL_UNVERIFIED", "attachment execution or claims promotion")
    require(rows["HIST-005"]["details"]["attachment_review"] == "PENDING_INDEPENDENT_REVIEW", "unsupported attachment review completion")
    require(rows["HIST-005"]["details"]["conflicts_reported"] == ["DEFAULT_FIX_EVAL_WRITE_AND_COMPILE", "GH_ERROR_TO_EMPTY_LIST", "STALE_UNPINNED_MERGE_CLOSE_PLAN", "MISSING_HOLD_CHECK", "OLD_EMBEDDED_CLAIMS"], "legacy conflict suppressed")
    require(all(sources[key]["commit"] is None for key in ("backend-snapshot", "hf-snapshot")), "invented external origin commit")
    require(rows["CON-002"]["details"] == {"python_minimum": "3.11", "package_path": "tools/szl_estate", "typed_evidence_state": True, "output_formats": ["JSON", "CSV", "MARKDOWN_REPORT"], "deterministic_output": "SAME_INPUTS_AND_REFERENCE_TIME", "provenance_headings": 7}, "foundation contract omission")
    require(rows["CON-003"]["details"]["requested_dependencies"] == ["requests", "httpx", "pydantic", "rich", "huggingface_hub", "beautifulsoup4", "playwright", "pytest"], "requested dependency omission")
    require(rows["CON-004"]["details"] == {"comments_variants": ["int", "list", "totalCount"], "page_shapes": ["list", "object"], "error_implies_success": False}, "parser contract omission")
    require(rows["CON-007"]["details"]["pr_states"] == ["MERGE_NOW_GREEN", "WAIT_CHECKS", "FIX_CHECKS", "CONFLICT_REBASE", "DOCS_ONLY", "DRAFT_PRESERVE", "HOLD_PRESERVE", "NEEDS_OWNER_DECISION"], "PR doctrine")
    require("AUTO_CLOSE" in rows["CON-007"]["details"]["prohibited"], "automatic closing prohibition omitted")
    require(rows["CON-009"]["details"] == {"human_only": True, "gates": ["BIOSAFETY", "CLINICAL", "CUSTOM_LICENSE", "SECURITY_RELEASE"]}, "human gate bypass")
    require(rows["FUT-009"]["details"] == {"supersedes": "EARLIER_HOLOGRAPHIC_DIRECTION", "accent_count": 1, "themes": ["light", "dark"], "spacing_unit_px": 4}, "design precedence")
    require(rows["FUT-010"]["details"]["viewport_widths_px"] == [375, 390, 768, 1280, 1920] and rows["FUT-010"]["details"]["target_size_px"] == 44, "mobile target drift")
    require(rows["FUT-011"]["details"] == {"score_targets": [90, 100, 100], "metric_names": None, "measured_scores": None}, "invented Lighthouse result/profile")
    require(rows["FUT-012"]["details"] == {"target_month": "2026-11", "exact_date": None}, "invented demo date")
    require(rows["FUT-013"]["details"]["novelty"] == "NOT_ESTABLISHED" and rows["FUT-013"]["details"]["experiments_status"] == "PROPOSED_NOT_RUN", "research promotion")
    require(not PRIVATE_IDS.search(json.dumps(document) + markdown), "private identifier/secret leakage")

    # Bind the recorded setup numbers, authority and source identity to the stored
    # reviewed receipt, never to an assertion supplied in the thread matrix.
    setup_source = sources["phase0-setup"]
    require(setup_source["kind"] == "TEST_AND_ACCESS_RECEIPT" and setup_source["commit"] == BASE, "setup evidence type/revision")
    raw = (ROOT / setup_source["artifact"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == setup_source["sha256"], "setup source bytes mismatch")
    receipt = json.loads(raw)
    payload = receipt["payload"]
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    require(digest == receipt["sha256"], "receipt integrity")
    require(payload["setup_ready"] is True and payload["estate_ready"] is False and payload["replay_grants_live_readiness"] is False, "receipt proof scope")
    require(setup_source["date"] == payload["checked_at_utc"] == rows["OBS-001"]["details"]["checked_at"], "setup observation mismatch")
    for key, receipt_key in (("cases", "cases"), ("definitions", "executed_definitions"), ("failures", "failures"), ("errors", "errors"), ("skips", "skips")):
        require(rows["OBS-001"]["details"][key] == payload["tests"][receipt_key], "unsupported test count")
    require(payload["tests"]["executed_definitions"] == payload["tests"]["expected_definitions"], "unexecuted definitions")
    require(len(payload["checks"]) == 5 and all(x["status"] == "PASS" for x in payload["checks"]), "incomplete setup checks")
    require({x["scope"] for x in payload["access_matrix"]} == {"github:user", "github:org:szl-holdings", "github:membership:szl-holdings", "hf:whoami:SZLHOLDINGS"}, "incomplete narrow access")
    require(all(x["status"] == "PASS" and x["http_status"] == 200 for x in payload["access_matrix"]), "unproved narrow access")


class ThreadRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(MATRIX.read_text(encoding="utf-8"))
        self.markdown = REPORT.read_text(encoding="utf-8")

    def row(self, identifier):
        return next(r for r in self.document["requirements"] if r["id"] == identifier)

    def rejects(self, message):
        with self.assertRaisesRegex(ValueError, message):
            validate(self.document, self.markdown)

    def test_actual_artifacts_and_receipt_are_consistent(self):
        validate(self.document, self.markdown)

    def test_missing_project_ask_rejected(self):
        self.document["requirements"].pop()
        self.rejects("missing/duplicate/extra")

    def test_duplicate_requirement_rejected(self):
        self.document["requirements"].append(deepcopy(self.document["requirements"][0]))
        self.rejects("missing/duplicate/extra")

    def test_markdown_matrix_omission_rejected(self):
        self.markdown = self.markdown.replace("| FUT-006 |", "| OMITTED |")
        self.rejects("matrix mismatch")

    def test_markdown_cannot_promote_unmeasured_space_lane(self):
        self.markdown = self.markdown.replace("| desired_future_state / NOT_RUN | HF Spaces |", "| desired_future_state / VERIFIED | HF Spaces |")
        self.rejects("prose row status/coverage")

    def test_markdown_cannot_invent_setup_count(self):
        row = next(line for line in self.markdown.splitlines() if line.startswith("| OBS-001 |"))
        self.markdown = self.markdown.replace(row, row.replace("333 cases", "334 cases"))
        self.rejects("prose row status/coverage")

    def test_appended_estate_ready_claim_rejected(self):
        self.markdown += "\nThe estate_ready=true claim is unsupported.\n"
        self.rejects("unsupported prose estate readiness")

    def test_absent_source_reference_rejected(self):
        self.row("FUT-005")["source_ids"] = ["unprovided-receipt"]
        self.rejects("source reference")

    def test_future_observation_rejected(self):
        self.document["sources"][0]["date"] = "2099-01-01"
        self.rejects("future source")

    def test_full_estate_promotion_rejected(self):
        self.document["readiness"]["estate_ready"] = True
        self.rejects("readiness promotion")

    def test_unmeasured_lane_cannot_claim_verified(self):
        self.row("FUT-004")["implementation_status"] = "VERIFIED"
        self.rejects("unsupported completion")

    def test_unattempted_lane_cannot_claim_denied_access(self):
        self.row("FUT-005")["implementation_status"] = "INACCESSIBLE"
        self.rejects("unsupported completion")

    def test_historical_lane_cannot_claim_shipping(self):
        self.row("HIST-002")["claim_maturity"] = "SHIPPING"
        self.rejects("unsupported maturity")

    def test_claim_basis_is_separate_from_maturity(self):
        self.row("CON-006")["claim_basis"] = "INTERNALLY_TESTED"
        self.rejects("basis axis")

    def test_future_acceptance_cannot_be_hidden(self):
        self.row("FUT-019")["unmet_acceptance_tests"] = []
        self.rejects("future checks hidden")

    def test_unprovided_person_cannot_be_invented(self):
        self.row("FUT-001")["owner"]["assignment"] = "PERSON_ASSIGNED"
        self.rejects("owner")

    def test_unsupported_test_count_rejected(self):
        self.row("OBS-001")["details"]["cases"] = 334
        self.rejects("unsupported test count")

    def test_receipt_cannot_be_replaced_by_prose(self):
        next(s for s in self.document["sources"] if s["id"] == "phase0-setup")["kind"] = "AUTHORIZED_ENGINEERING_MESSAGE"
        self.rejects("setup evidence type")

    def test_receipt_digest_tampering_rejected(self):
        next(s for s in self.document["sources"] if s["id"] == "phase0-setup")["sha256"] = "0" * 64
        self.rejects("source bytes mismatch")

    def test_backend_partial_coverage_reconciles(self):
        self.row("OBS-002")["details"]["unread_paths"] -= 1
        self.rejects("backend coverage arithmetic")

    def test_hf_collections_cannot_be_assumed_complete(self):
        self.row("OBS-003")["details"]["collections"] = 0
        self.rejects("HF scope arithmetic")

    def test_consuming_commit_is_not_external_origin(self):
        next(s for s in self.document["sources"] if s["id"] == "backend-snapshot")["commit"] = BASE
        self.rejects("external origin")

    def test_deterministic_output_requirement_cannot_be_dropped(self):
        self.row("CON-002")["details"]["output_formats"].remove("CSV")
        self.rejects("foundation contract")

    def test_requested_dependency_cannot_be_omitted(self):
        self.row("CON-003")["details"]["requested_dependencies"].remove("playwright")
        self.rejects("dependency omission")

    def test_comment_count_variant_cannot_be_omitted(self):
        self.row("CON-004")["details"]["comments_variants"].remove("totalCount")
        self.rejects("parser contract")

    def test_queue_historical_time_is_not_current(self):
        self.row("HIST-003")["details"]["current_state"] = "CURRENT"
        self.rejects("queue precision")

    def test_pr_classifier_doctrine_preserved(self):
        self.row("CON-007")["details"]["pr_states"].remove("HOLD_PRESERVE")
        self.rejects("PR doctrine")

    def test_automatic_closing_prohibition_cannot_be_omitted(self):
        self.row("CON-007")["details"]["prohibited"].remove("AUTO_CLOSE")
        self.rejects("automatic closing")

    def test_attachment_claims_cannot_be_promoted(self):
        self.row("HIST-005")["details"]["embedded_claims"] = "VERIFIED"
        self.rejects("attachment execution or claims promotion")

    def test_reported_attachment_cannot_become_observed_fact(self):
        self.row("HIST-005")["category"] = "observed_fact"
        self.rejects("evidence-category promotion")

    def test_source_attachment_execution_cannot_be_asserted(self):
        self.row("HIST-005")["details"]["source_executed"] = True
        self.rejects("attachment execution or claims promotion")

    def test_opaque_compiled_loading_cannot_be_asserted(self):
        self.row("HIST-005")["details"]["compiled_attachment_loaded"] = True
        self.rejects("attachment execution or claims promotion")

    def test_unreceipted_attachment_review_cannot_be_completed(self):
        self.row("HIST-005")["details"]["attachment_review"] = "COMPLETED"
        self.rejects("unsupported attachment review completion")

    def test_error_to_empty_inventory_conflict_cannot_be_suppressed(self):
        self.row("HIST-005")["details"]["conflicts_reported"].remove("GH_ERROR_TO_EMPTY_LIST")
        self.rejects("legacy conflict suppressed")

    def test_human_gate_cannot_be_disabled(self):
        self.row("CON-009")["details"]["human_only"] = False
        self.rejects("human gate bypass")

    def test_holographic_direction_cannot_supersede_latest(self):
        self.row("FUT-009")["details"]["supersedes"] = "LATEST_RESTRAINED_DIRECTION"
        self.rejects("design precedence")

    def test_required_viewport_cannot_be_dropped(self):
        self.row("FUT-010")["details"]["viewport_widths_px"].remove(390)
        self.rejects("mobile target")

    def test_lighthouse_result_cannot_be_invented(self):
        self.row("FUT-011")["details"]["measured_scores"] = [90, 100, 100]
        self.rejects("invented Lighthouse")

    def test_exact_demo_date_cannot_be_invented(self):
        self.row("FUT-012")["details"]["exact_date"] = "2026-11-15"
        self.rejects("invented demo date")

    def test_research_proposal_cannot_claim_success(self):
        self.row("FUT-013")["details"]["experiments_status"] = "PASSED"
        self.rejects("research promotion")

    def test_private_provider_identifier_rejected(self):
        self.markdown += "\n" + "libfile_" + "a" * 32
        self.rejects("private identifier")

    def test_private_conversation_identifier_rejected(self):
        self.markdown += "\n" + "11111111-2222-3333-4444-555555555555"
        self.rejects("private identifier")

    def test_credential_rejected(self):
        self.markdown += "\n" + "hf_" + "a" * 32
        self.rejects("private identifier")


if __name__ == "__main__":
    unittest.main()
