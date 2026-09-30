"""Synthetic contract tests only; fixtures are not publishable evidence."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import steward_public as public

REVISION = "1" * 40  # TEST ONLY, not a verified source revision.
CLOCK = dt.datetime(2026, 9, 30, 3, 0, tzinfo=dt.timezone.utc)


def synthetic_status() -> dict:
    """Shape of load_steward_status, without inventing production provenance."""
    return {
        "schema_version": "szl.frontier-steward.status/v1",
        "mutation_policy": "PROPOSAL_ONLY",
        "runtime": {"private_diagnostic": "NEVER_PUBLISH_TEST_SECRET"},
        "latest_plan": {
            "state": "RECORDED", "recorded": True, "evidence_current": True,
            "evidence_fresh": True, "is_latest_recorded_plan": True,
            "path": "C:\\private-test-only\\plan.json", "plan_status": "PROPOSED",
            "plan_id": "steward-plan-" + "a" * 24,
            "proposal_digest": "sha256:" + "b" * 64,
            "artifact_sha256": "c" * 64, "receipt_id": "receipt-" + "d" * 32,
            "receipt_hash": "e" * 64, "signature_status": "UNSIGNED",
            "validation": {"valid": True, "status": "PASS", "errors": [],
                           "plan_id": "steward-plan-" + "a" * 24,
                           "proposal_digest": "sha256:" + "b" * 64},
            "audit_receipt_binding": {"valid": True, "state": "BOUND"},
            "receipt_chain": {
                "chain_valid": True, "status": "CHAIN_VALID_UNSIGNED", "receipt_count": 2,
                "unsigned_count": 2, "verified_signature_count": 0,
                "latest_hash": "f" * 64, "errors": [],
            },
            "model": {
                "adapter": "deterministic", "runtime": "NO_MODEL_CALL", "invoked": False,
                "production_allowed": False, "run_status": "NOT_INVOKED",
                "secret_isolation_state": "NO_MODEL_CALL", "identity_state": "UNAVAILABLE",
            },
            "policy": {
                "decision": "ALLOW_PROPOSAL", "violations": [], "denial_is_absorbing": True,
                "post_model_validation": "PASS", "error": None, "validation_errors": [],
            },
            "evidence_snapshot": {
                "audit_id": "audit-" + "0" * 32, "audit_status": "MEASURED",
                "audit_completed_at": "2026-09-30T02:30:00Z", "audit_receipt_hash": "2" * 64,
                "receipt_chain_valid": True, "receipt_chain_state": "CHAIN_VALID_UNSIGNED",
                "audit_receipt_binding_valid": True, "audit_receipt_binding_state": "BOUND",
                "eligible_for_planning": True, "planning_blockers": [],
                "audit_time_state": "CURRENT", "fresh_for_planning": True,
                "complete_file_audit_claimed": False,
                "source_reports": [
                    {"source": source, "status": "MEASURED", "scope": scope}
                    for source, scope in public.SOURCE_SCOPES.items()
                ],
                "asset_count": 100, "private_names": ["private-test-only-repo"],
            },
            "proposals": [{
                "title": "Synthetic contract test proposal",
                "objective": "Inspect public evidence scope for this test only.",
                "hypothesis": "Explicit scope checks reject incomplete observations.",
                "tests": ["Reject stale observations"],
                "success_metrics": ["All negative test fixtures rejected"],
                "stop_conditions": ["Scope is unknown"],
                "target": "private-test-only-do-not-publish",
                "steps": ["Inspect read-only evidence"],
                "denied_effects": ["No safety bypass or private credential access"],
            }],
        },
    }


def projection() -> dict:
    return public.build_public_projection(synthetic_status(), producer_revision=REVISION, now=CLOCK)


class PublicProjectionTests(unittest.TestCase):
    def assert_invalid(self, payload, code=None):
        result = public.validate_public_projection(payload, expected_source_revision=REVISION, now=CLOCK)
        self.assertFalse(result["valid"])
        self.assertEqual(result["state"], "INVALID")
        self.assertIsNone(result["projection"])
        if code:
            self.assertIn(code, result["errors"])

    def test_minimal_allowlist_and_unsigned_boundary(self):
        status = synthetic_status()
        before = copy.deepcopy(status)
        data = public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)
        self.assertEqual(status, before)
        self.assertEqual(data["state"], "CURRENT")
        self.assertFalse(data["production_ready"])
        self.assertFalse(data["integrity"]["independent_witness"])
        self.assertEqual(data["freshness"]["valid_until"], "2026-09-30T04:30:00Z")
        serialized = json.dumps(data)
        for denied in ("NEVER_PUBLISH_TEST_SECRET", "private-test-only", "C:\\", "asset_count", "steps", "target", "denied_effects"):
            self.assertNotIn(denied, serialized)
        self.assertTrue(public.validate_public_projection(data, expected_source_revision=REVISION, now=CLOCK)["valid"])

    def test_scope_precedes_private_text_and_stable_errors(self):
        for scope in ("AUTHENTICATED_COMPLETE", "AUTHENTICATED_VISIBILITY_UNKNOWN", "PARTIAL", None, "PUBLIC_ONLY_PRIVATE"):
            status = synthetic_status()
            status["latest_plan"]["evidence_snapshot"]["source_reports"][0]["scope"] = scope
            status["latest_plan"]["proposals"][0]["objective"] = "NEVER_PUBLISH_TEST_SECRET"
            with self.assertRaisesRegex(public.PublicProjectionError, "^NONPUBLIC_SOURCE_SCOPE$"):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_missing_unknown_duplicate_and_partial_sources(self):
        for mutation in ("missing", "unknown", "duplicate", "partial", "extra"):
            status = synthetic_status()
            sources = status["latest_plan"]["evidence_snapshot"]["source_reports"]
            if mutation == "missing":
                sources.pop()
            elif mutation == "unknown":
                sources[0]["source"] = "private-test-source"
            elif mutation == "duplicate":
                sources[1] = dict(sources[0])
            elif mutation == "partial":
                sources[0]["status"] = "PARTIAL"
            else:
                sources[0]["private_url"] = "C:\\private-test-only"
            with self.assertRaises(public.PublicProjectionError):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_each_proof_flag_is_required_exactly(self):
        for field in ("recorded", "evidence_current", "evidence_fresh", "is_latest_recorded_plan"):
            for value in (False, None, 1, "true"):
                status = synthetic_status()
                status["latest_plan"][field] = value
                with self.assertRaises(public.PublicProjectionError):
                    public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)
        for field, value in (("state", "UNRECORDED"), ("plan_status", "DENIED"), ("signature_status", "VERIFIED")):
            status = synthetic_status()
            status["latest_plan"][field] = value
            with self.assertRaises(public.PublicProjectionError):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_validation_policy_binding_and_chain_are_required(self):
        mutations = (
            ("validation", "valid", False), ("validation", "errors", ["private-error"]),
            ("policy", "decision", "DENY"), ("policy", "post_model_validation", "FAIL"),
            ("audit_receipt_binding", "valid", False), ("audit_receipt_binding", "state", "MISSING"),
            ("receipt_chain", "chain_valid", False), ("receipt_chain", "status", "VERIFIED"),
            ("receipt_chain", "receipt_count", True), ("receipt_chain", "unsigned_count", 0),
            ("receipt_chain", "verified_signature_count", False), ("receipt_chain", "errors", ["private-error"]),
            ("evidence_snapshot", "audit_receipt_binding_valid", False),
            ("evidence_snapshot", "planning_blockers", ["PARTIAL"]),
        )
        for parent, field, value in mutations:
            status = synthetic_status()
            status["latest_plan"][parent][field] = value
            with self.assertRaises(public.PublicProjectionError):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_live_and_local_agent_providers_not_publicly_admitted(self):
        for key, value in (("adapter", "responses"), ("adapter", "codex-cli"), ("invoked", True),
                           ("invoked", 0), ("production_allowed", True), ("runtime", "LOCAL_DEVELOPMENT_AGENT"),
                           ("requested_model", "forged-model"), ("resolved_model", "forged-model"),
                           ("response_sha256", "0" * 64), ("identity_state", "PROVIDER_REPORTED_UNPINNED")):
            status = synthetic_status()
            status["latest_plan"]["model"][key] = value
            with self.assertRaises(public.PublicProjectionError):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_plan_id_and_digest_must_match_retained_validation(self):
        for field, value in (("plan_id", "steward-plan-" + "b" * 24), ("proposal_digest", "sha256:" + "c" * 64)):
            status = synthetic_status()
            status["latest_plan"][field] = value
            with self.assertRaisesRegex(public.PublicProjectionError, "PLAN_VALIDATION_FAILED"):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_stale_builder_and_reader_remove_proposals_without_renewal(self):
        stale_clock = CLOCK + dt.timedelta(hours=3)
        stale = public.build_public_projection(synthetic_status(), producer_revision=REVISION, now=stale_clock)
        self.assertEqual(stale["state"], "STALE")
        self.assertEqual(stale["proposals"], [])
        self.assertEqual(stale["freshness"]["valid_until"], "2026-09-30T04:30:00Z")
        current = projection()
        before = copy.deepcopy(current)
        result = public.validate_public_projection(current, expected_source_revision=REVISION, now=stale_clock)
        self.assertTrue(result["valid"])
        self.assertEqual(result["state"], "STALE")
        self.assertEqual(result["projection"]["proposals"], [])
        self.assertEqual(current, before)
        # Exactly two hours remains valid; one microsecond later does not.
        expires = "2026-09-30T04:30:00Z"
        self.assertEqual(public.validate_public_projection(current, now=expires)["state"], "CURRENT")
        self.assertEqual(public.validate_public_projection(current, now="2026-09-30T04:30:00.000001Z")["state"], "STALE")

    def test_future_naive_invalid_and_inconsistent_time_rejected(self):
        for bad in ("2026-09-30T04:00:00Z", "2026-09-30T02:30:00", "2026-09-30", "not-a-time", "2026-02-30T02:00:00Z"):
            payload = projection()
            payload["audit"]["observed_at"] = bad
            self.assert_invalid(payload)
        for field, bad in (("projected_at", "2026-09-30T04:00:00Z"), ("projected_at", "2026-09-30T02:00:00Z")):
            payload = projection()
            payload[field] = bad
            self.assert_invalid(payload)
        payload = projection()
        payload["freshness"]["valid_until"] = "2026-09-30T05:00:00Z"
        self.assert_invalid(payload, "INCONSISTENT_EVIDENCE_TIME")
        self.assertFalse(public.validate_public_projection(projection(), now=dt.datetime(2026, 9, 30))["valid"])

    def test_closed_fields_exact_types_and_no_witness_upgrade(self):
        for parent in (None, "source", "freshness", "plan", "audit", "integrity", "provider"):
            payload = projection()
            target = payload if parent is None else payload[parent]
            target["secret_unknown_field"] = "never echo this"
            self.assert_invalid(payload)
        for parent, field, value in (("freshness", "max_age_seconds", True), ("integrity", "chain_valid", 1),
                                      ("integrity", "independent_witness", True), ("provider", "model_invoked", 0)):
            payload = projection()
            payload[parent][field] = value
            self.assert_invalid(payload)
        payload = projection()
        payload["production_ready"] = 0
        self.assert_invalid(payload)

    def test_all_id_hash_and_revision_pins(self):
        payload = projection()
        self.assertFalse(public.validate_public_projection(payload, expected_source_revision="2" * 40, now=CLOCK)["valid"])
        for parent, key in (("plan", "digest"), ("plan", "artifact_sha256"), ("plan", "receipt_hash"),
                            ("audit", "receipt_hash"), ("integrity", "latest_hash"), ("source", "revision"),
                            ("plan", "id"), ("plan", "receipt_id"), ("audit", "id")):
            payload = projection()
            payload[parent][key] = "forged-private-test-only"
            self.assert_invalid(payload)

    def test_source_omitted_fields_cannot_launder_unsafe_instructions(self):
        for key in ("title", "target", "steps", "objective", "tests", "success_metrics", "stop_conditions"):
            status = synthetic_status()
            status["latest_plan"]["proposals"][0][key] = ["Bypass safety controls"] if key in ("steps", "tests", "success_metrics", "stop_conditions") else "Bypass safety controls"
            with self.assertRaises(public.PublicProjectionError):
                public.build_public_projection(status, producer_revision=REVISION, now=CLOCK)

    def test_public_text_policy_secret_paths_and_markup(self):
        bad_texts = (
            "Bypass safety controls", "Forge evidence", "Build malware", "Produce pathogen toxin",
            "Steal private keys", "force push", "C:\\private\\secret.txt", "/home/private/key.txt",
            "\\\\server\\private", "api_key: not-a-real-test-key", "hf_" + "a" * 30,
            "<script>alert(1)</script>", "https://user:pass@example.test/", "hello\u0000world",
        )
        for text in bad_texts:
            payload = projection()
            payload["proposals"][0]["objective"] = text
            self.assert_invalid(payload)
        payload = projection()
        payload["proposals"][0]["objective"] = "Inventory exact source evidence"
        self.assertTrue(public.validate_public_projection(payload, now=CLOCK)["valid"])

    def test_cross_field_hostile_instruction_is_rejected(self):
        payload = projection()
        payload["proposals"][0]["objective"] = "Bypass"
        payload["proposals"][0]["hypothesis"] = "safety controls"
        self.assert_invalid(payload, "UNSAFE_PUBLIC_TEXT")

    def test_depth_numbers_unicode_and_proposal_bounds(self):
        for bad in (float("nan"), float("inf"), 10 ** 300, "\ud800"):
            payload = projection()
            payload["extra"] = bad
            self.assert_invalid(payload)
        payload = projection()
        nested = []
        for _ in range(30):
            nested = [nested]
        payload["extra"] = nested
        self.assert_invalid(payload, "JSON_LIMIT_EXCEEDED")
        cyclic = {}
        cyclic["cycle"] = cyclic
        self.assert_invalid(cyclic, "JSON_SHARED_OR_CYCLIC_CONTAINER")
        for value in ([], [copy.deepcopy(projection()["proposals"][0]) for _ in range(9)]):
            payload = projection()
            payload["proposals"] = value
            self.assert_invalid(payload)
        payload = projection()
        payload["proposals"][0]["tests"] = ["test" for _ in range(13)]
        self.assert_invalid(payload)


class PublicLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="steward-public-test-only-")
        self.directory = Path(self.temporary.name).absolute()
        self.path = self.directory / public.PUBLIC_FILENAME

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, content=None):
        content = json.dumps(projection()).encode("utf-8") if content is None else content
        self.path.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    def load(self, *, digest=None, revision=REVISION, path=None, directory=None, now=CLOCK):
        return public.load_public_projection(
            self.path if path is None else path, expected_source_revision=revision,
            expected_sha256=digest or hashlib.sha256(self.path.read_bytes()).hexdigest(),
            allowed_directory=self.directory if directory is None else directory, now=now,
        )

    def test_actual_byte_hash_pin_copy_and_no_write(self):
        digest = self.write()
        before = (self.path.read_bytes(), self.path.stat().st_mtime_ns, sorted(item.name for item in self.directory.iterdir()))
        result = self.load(digest=digest)
        self.assertTrue(result["valid"])
        self.assertEqual(result["state"], "CURRENT")
        self.assertEqual(before, (self.path.read_bytes(), self.path.stat().st_mtime_ns, sorted(item.name for item in self.directory.iterdir())))
        self.assertEqual(self.load(digest="0" * 64)["errors"], ["PUBLIC_ARTIFACT_HASH_MISMATCH"])
        self.assertEqual(self.load(revision="2" * 40)["errors"], ["SOURCE_REVISION_MISMATCH"])
        # Equivalent JSON with different retained bytes is still a changed artifact.
        self.path.write_bytes(json.dumps(projection(), indent=2).encode("utf-8"))
        self.assertEqual(self.load(digest=digest)["errors"], ["PUBLIC_ARTIFACT_HASH_MISMATCH"])

    def test_duplicate_nonfinite_overflow_deep_invalid_utf8(self):
        cases = (
            b'{"schema_version":1,"schema_version":2}', b'{"n":NaN}', b'{"n":Infinity}',
            b'{"n":1e999}', b'{"n":9999999999999999999999999999999999}',
            ("[" * 100 + "0" + "]" * 100).encode(), b'\xff',
        )
        for content in cases:
            digest = self.write(content)
            result = self.load(digest=digest)
            self.assertFalse(result["valid"])
            self.assertEqual(result["state"], "INVALID")
            self.assertIsNone(result["projection"])

    def test_oversize_missing_and_path_restrictions(self):
        self.write(b" " * (public.MAX_BYTES + 1))
        self.assertFalse(self.load()["valid"])
        result = self.load(digest="0" * 64, path=self.directory / "private-test-only.json")
        self.assertEqual(result["errors"], ["PUBLIC_PATH_NOT_ALLOWED"])
        self.assertNotIn("private-test-only", json.dumps(result))
        self.assertFalse(self.load(path=Path(public.PUBLIC_FILENAME))["valid"])
        self.assertFalse(self.load(directory=self.directory.parent)["valid"])
        self.path.unlink()
        result = self.load(digest="0" * 64)
        self.assertEqual(result["state"], "UNAVAILABLE")
        self.assertEqual(result["errors"], ["PUBLIC_ARTIFACT_UNAVAILABLE"])

    def test_link_rejection_and_directory_reparse_guard(self):
        digest = self.write()
        real = self.directory / "real.json"
        self.path.rename(real)
        try:
            self.path.symlink_to(real)
        except OSError:
            # Windows without symlink privilege still exercises reparse rejection.
            self.path.write_bytes(real.read_bytes())
        else:
            self.assertEqual(self.load(digest=digest)["errors"], ["PUBLIC_PATH_LINK_FORBIDDEN"])
            self.path.unlink()
            self.path.write_bytes(real.read_bytes())
        original = Path.lstat

        def reparse(path):
            info = original(path)
            if path == self.directory:
                fake = mock.Mock(wraps=info)
                fake.st_mode = info.st_mode
                fake.st_file_attributes = 0x400
                return fake
            return info

        with mock.patch.object(Path, "lstat", reparse):
            self.assertEqual(self.load(digest=digest)["errors"], ["PUBLIC_PATH_LINK_FORBIDDEN"])

    def test_stale_artifact_never_returns_current_proposals(self):
        self.write()
        result = self.load(now=CLOCK + dt.timedelta(hours=3))
        self.assertTrue(result["valid"])
        self.assertEqual(result["state"], "STALE")
        self.assertEqual(result["projection"]["proposals"], [])
        self.assertFalse(result["projection"]["production_ready"])

    def test_reader_import_is_standalone_and_has_no_side_effects(self):
        # Loading just the packaged reader cannot import provider code, make
        # requests, start processes, connect databases, or write evidence.
        spec = importlib.util.spec_from_file_location("isolated_public_reader_test", ROOT / "steward_public.py")
        module = importlib.util.module_from_spec(spec)
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network")), \
             mock.patch("sqlite3.connect", side_effect=AssertionError("database")), \
             mock.patch("subprocess.run", side_effect=AssertionError("execution")), \
             mock.patch("pathlib.Path.write_bytes", side_effect=AssertionError("write")), \
             mock.patch("os.environ.get", side_effect=AssertionError("secret read")):
            spec.loader.exec_module(module)
            result = module.validate_public_projection(projection(), now=CLOCK)
            self.assertTrue(result["valid"])
        self.assertNotIn("frontier_steward", module.__dict__)


class ActualReadbackContractTests(unittest.TestCase):
    def test_actual_loader_output_is_accepted_without_private_fields(self):
        import SZL_ONE_OF_ONE_ESTATE_OS as estate
        with tempfile.TemporaryDirectory(prefix="steward-public-actual-contract-test-only-") as temporary:
            directory = Path(temporary)
            database = directory / "test.db"
            plan = directory / "plan.json"
            now = dt.datetime.now(dt.timezone.utc)
            observed = now.isoformat()
            reports = [{"source": source, "status": "MEASURED", "scope": scope}
                       for source, scope in public.SOURCE_SCOPES.items()]
            connection = estate.connect_db(database)
            audit_id = "audit-" + "a" * 32
            receipt = estate.append_receipt(connection, audit_id=audit_id, kind="ESTATE_AUDIT", payload={
                "audit_id": audit_id, "status": "MEASURED", "completed_at": observed,
                "asset_count": 0, "proposal_count": 0, "scope": {}, "sources": reports,
            })
            connection.execute(
                "INSERT INTO audit_runs (audit_id,started_at,completed_at,status,scope_json,source_reports_json,asset_count,proposal_count,receipt_hash,app_version) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (audit_id, observed, observed, "MEASURED", "{}", json.dumps(reports), 0, 0, receipt["receipt_hash"], estate.APP_VERSION),
            )
            connection.commit()
            connection.close()
            with mock.patch.dict(os.environ, {"SZL_RECEIPT_SIGNING_KEY": ""}):
                written = estate.command_steward_plan(database, mission="Inspect safe public evidence", provider="deterministic",
                                                       model=None, timeout=10, output_path=plan)
                status = estate.load_steward_status(plan, database)
            self.assertTrue(written["readback"]["current_recorded_projection"])
            projected = public.build_public_projection(status, producer_revision=REVISION)
            self.assertEqual(len(projected["proposals"]), 3)
            self.assertNotIn(str(directory), json.dumps(projected))
            self.assertFalse(projected["production_ready"])
            self.assertTrue(public.validate_public_projection(projected, expected_source_revision=REVISION)["valid"])


if __name__ == "__main__":
    unittest.main()
