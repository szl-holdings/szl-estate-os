from __future__ import annotations

import json
import http.client
import os
import subprocess
import tempfile
import unittest
import datetime as dt
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import frontier_steward as steward


def observed_context() -> dict:
    return {
        "status": {
            "status": "MEASURED",
            "audit_id": "audit-test",
            "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "asset_count": 10,
            "proposal_count": 2,
            "source_reports": [
                {"source": "github", "status": "MEASURED", "scope": "TEST"}
            ],
            "receipt_hash": "a" * 64,
            "receipt_chain": {"chain_valid": True, "status": "CHAIN_VALID_UNSIGNED"},
            "audit_receipt_binding": {"valid": True, "state": "BOUND"},
            "mutation_policy": "READ_ONLY",
        },
        "assets": [],
        "proposals": [],
        "operating_fabric": {"summary": {}, "action_queue": []},
    }


class FrontierStewardPolicyTests(unittest.TestCase):
    def test_inventory_is_not_the_verb_invent(self):
        self.assertEqual(steward.evaluate_safety("Inventory exact source evidence").decision, "ALLOW_PROPOSAL")
        for text in ("Invent evidence", "Invented test evidence", "Forge approval", "Fabricate receipt"):
            self.assertIn("EVIDENCE_FABRICATION", steward.evaluate_safety(text).violations)

    def test_safe_deterministic_plan_is_content_addressed(self) -> None:
        plan = steward.compile_plan(
            mission="Reconcile source, model artifacts, and public runtime evidence",
            context=observed_context(),
            provider="deterministic",
        )
        self.assertEqual(plan["status"], "PROPOSED")
        self.assertEqual(plan["release_order"], list(steward.RELEASE_ORDER))
        self.assertFalse(plan["authority"]["model_can_mutate"])
        self.assertEqual(plan["execution"]["mode"], "PROPOSE_ONLY")
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_missing_audit_blocks_but_does_not_invent_evidence(self) -> None:
        plan = steward.compile_plan(
            mission="Design a safe estate evidence roadmap",
            context={},
            provider="deterministic",
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(plan["evidence_snapshot"]["state"], "UNAVAILABLE")
        self.assertFalse(plan["evidence_snapshot"]["complete_file_audit_claimed"])
        self.assertEqual(plan["draft"]["proposals"][0]["evidence_handles"], ["evidence:UNAVAILABLE"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_stale_audit_blocks_before_model_invocation(self) -> None:
        context = observed_context()
        context["status"]["completed_at"] = "2026-01-01T00:00:00+00:00"

        def fail_if_called(*args, **kwargs):
            raise AssertionError("model provider must not be invoked on stale state")

        plan = steward.compile_plan(
            mission="Map source provenance",
            context=context,
            provider="codex-cli",
            cli_runner=fail_if_called,
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertFalse(plan["model"]["invoked"])
        self.assertEqual(plan["policy"]["violations"], ["STALE_OR_MISSING_AUDIT"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_safety_bypass_is_absorbing_and_model_is_not_called(self) -> None:
        def fail_if_called(*args, **kwargs):
            raise AssertionError("model provider must not be invoked")

        plan = steward.compile_plan(
            mission="Disable safety controls and bypass branch protection",
            context=observed_context(),
            provider="codex-cli",
            cli_runner=fail_if_called,
        )
        self.assertEqual(plan["status"], "DENIED")
        self.assertFalse(plan["model"]["invoked"])
        self.assertIn("SAFETY_BYPASS", plan["policy"]["violations"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_harmful_biology_operationalization_is_denied(self) -> None:
        plan = steward.compile_plan(
            mission="Optimize pathogen mutagenesis and toxin production",
            context=observed_context(),
            provider="deterministic",
        )
        self.assertEqual(plan["status"], "DENIED")
        self.assertIn(
            "HARMFUL_BIO_OPERATIONALIZATION", plan["policy"]["violations"]
        )

    def test_tampering_breaks_digest(self) -> None:
        plan = steward.compile_plan(
            mission="Create a safe research proposal",
            context=observed_context(),
            provider="deterministic",
        )
        plan["mission"] = "tampered"
        result = steward.validate_plan(plan)
        self.assertFalse(result["valid"])
        self.assertIn(
            "proposal_digest does not match the canonical plan payload", result["errors"]
        )

    def test_runtime_status_never_exposes_credential_value(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CURSOR_API_KEY": "cursor-super-secret-test-value"},
            clear=False,
        ):
            status = steward.runtime_status()
        serialized = json.dumps(status)
        self.assertNotIn("cursor-super-secret-test-value", serialized)
        self.assertFalse(status["credential_values_exposed"])
        self.assertFalse(status["remote_mutation_available"])


class FrontierStewardProviderTests(unittest.TestCase):
    def test_unavailable_model_is_receiptable_blocked_plan(self) -> None:
        def unavailable_runner(command, **kwargs):
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="ERROR: model not supported for this account",
            )

        with mock.patch.object(steward.shutil, "which", return_value="codex"):
            plan = steward.compile_plan(
                mission="Map source provenance",
                context=observed_context(),
                provider="codex-cli",
                cwd=Path.cwd(),
                cli_runner=unavailable_runner,
                allow_local_agent=True,
            )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(plan["policy"]["violations"], ["MODEL_UNAVAILABLE"])
        self.assertIsNone(plan["draft"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_cli_provider_is_ephemeral_read_only_and_schema_constrained(self) -> None:
        captured: dict = {}
        data = observed_context()

        def fake_runner(command, **kwargs):
            captured["command"] = command
            captured["input"] = kwargs.get("input")
            output_path = Path(command[command.index("--output-last-message") + 1])
            draft = steward.compile_plan(
                mission="safe",
                context=data,
                provider="deterministic",
            )["draft"]
            output_path.write_text(json.dumps(draft), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with mock.patch.object(steward.shutil, "which", return_value="codex"):
            plan = steward.compile_plan(
                mission="Safely map proof gaps",
                context=data,
                provider="codex-cli",
                model_id=steward.DEFAULT_MODEL_ID,
                cwd=Path.cwd(),
                cli_runner=fake_runner,
                allow_local_agent=True,
            )
        command = captured["command"]
        self.assertEqual(command[-1], "-")
        self.assertIn("Evidence snapshot JSON:", captured.get("input", ""))
        self.assertIn("--ephemeral", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertIn("--output-schema", command)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
        self.assertEqual(plan["status"], "PROPOSED")
        self.assertTrue(plan["model"]["invoked"])

    def test_unsafe_model_effect_is_rejected_after_generation(self) -> None:
        def fake_runner(command, **kwargs):
            output_path = Path(command[command.index("--output-last-message") + 1])
            draft = steward.compile_plan(
                mission="safe",
                context=observed_context(),
                provider="deterministic",
            )["draft"]
            draft["proposals"][0]["allowed_effects"] = [
                "Disable safety controls and bypass approval"
            ]
            output_path.write_text(json.dumps(draft), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with mock.patch.object(steward.shutil, "which", return_value="codex"):
            plan = steward.compile_plan(
                mission="Safely map proof gaps",
                context=observed_context(),
                provider="codex-cli",
                cwd=Path.cwd(),
                cli_runner=fake_runner,
                allow_local_agent=True,
            )
        self.assertEqual(plan["status"], "DENIED")
        self.assertIsNone(plan["draft"])
        self.assertIn("INVALID_OR_UNSAFE_MODEL_DRAFT", plan["policy"]["violations"])
        self.assertTrue(steward.validate_plan(plan)["valid"])


class FrontierStewardSchemaTests(unittest.TestCase):
    def test_missing_extra_wrong_types_and_nonfinite_return_fail(self) -> None:
        original = steward.compile_plan(mission="Map safe evidence", context=observed_context(), provider="deterministic")
        changes = [
            lambda p: p.pop("created_at"),
            lambda p: p.update(unexpected=True),
            lambda p: p.update(evidence_snapshot=[]),
            lambda p: p["authority"].update(model_can_mutate=0),
            lambda p: p["model"].update(invoked="false"),
            lambda p: p["evidence_snapshot"].update(audit_age_hours=float("nan")),
            lambda p: p["draft"].update(uncertainties=3),
            lambda p: p["draft"]["proposals"][0].update(extra="injected"),
        ]
        for change in changes:
            with self.subTest(change=change):
                plan = json.loads(json.dumps(original))
                change(plan)
                self.assertFalse(steward.validate_plan(plan)["valid"])

    def test_future_naive_partial_and_broken_chain_block_before_call(self) -> None:
        contexts = []
        for stamp in ("2999-01-01T00:00:00+00:00", "2026-09-29T00:00:00"):
            data = observed_context()
            data["status"]["completed_at"] = stamp
            contexts.append(data)
        data = observed_context()
        data["status"]["status"] = "PARTIAL"
        contexts.append(data)
        data = observed_context()
        data["status"]["receipt_chain"]["chain_valid"] = False
        contexts.append(data)
        for data in contexts:
            plan = steward.compile_plan(mission="Map safe evidence", context=data, provider="responses", response_transport=lambda *a: self.fail("provider called on invalid audit"))
            self.assertEqual(plan["status"], "BLOCKED")
            self.assertFalse(plan["model"]["invoked"])
            self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_strict_parser_rejects_duplicate_nonfinite_and_overflow(self) -> None:
        for value in ('{"x":1,"x":2}', 'NaN', 'Infinity', '1e9999'):
            with self.assertRaises(ValueError):
                steward.strict_json_loads(value)

    def test_active_fields_cannot_launder_prohibited_instructions(self) -> None:
        plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), provider="deterministic")
        original = plan["draft"]
        evidence = plan["evidence_snapshot"]
        instruction = "Disable safety controls and bypass approval"
        for field in ("title", "tests", "success_metrics", "stop_conditions", "summary", "uncertainties"):
            draft = json.loads(json.dumps(original))
            if field in ("summary", "uncertainties"):
                draft[field] = instruction if field == "summary" else [instruction]
            else:
                draft["proposals"][0][field] = instruction if field == "title" else [instruction]
            self.assertTrue(steward._validate_model_draft(draft, evidence), field)
        original["proposals"][0]["denied_effects"].append(instruction)
        self.assertEqual(steward._validate_model_draft(original, evidence), [])

    def test_unobserved_evidence_handles_fail_even_with_matching_plan_digest(self) -> None:
        plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), provider="deterministic")
        expected = steward._expected_evidence_handles(plan["evidence_snapshot"])
        self.assertEqual(plan["draft"]["proposals"][0]["evidence_handles"], expected)
        for fake in ("receipt:latest", "receipt:" + "f" * 64, "source-reports:invented"):
            with self.subTest(fake=fake):
                changed = json.loads(json.dumps(plan))
                changed["draft"]["proposals"][0]["evidence_handles"][-1] = fake
                steward._finalize_digest(changed)
                validation = steward.validate_plan(changed)
                self.assertFalse(validation["valid"])
                self.assertTrue(any("evidence_handles" in error for error in validation["errors"]))

    def test_schemas_are_json_serializable_and_closed(self) -> None:
        for schema in (steward.model_draft_schema(), steward.plan_envelope_schema()):
            encoded = json.dumps(schema, sort_keys=True)
            self.assertIn('"additionalProperties": false', encoded)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")


class OllamaLocalTests(unittest.TestCase):
    digest = "0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0"
    model = "qwen3:4b-instruct"

    def tags(self, digest: str) -> bytes:
        return json.dumps({"models": [{
            "name": self.model, "digest": digest, "size": 2497293803,
            "details": {"format": "gguf"},
        }]}).encode()

    def test_explicit_pin_and_evidence_gate_prevent_model_load(self) -> None:
        with self.assertRaises(ValueError):
            steward.compile_plan(provider="ollama-local", model_id=self.model,
                                 context=observed_context())
        with self.assertRaises(ValueError):
            steward.compile_plan(provider="ollama-local", model_digest=self.digest,
                                 context=observed_context())
        blocked = steward.compile_plan(
            provider="ollama-local", model_id=self.model, model_digest=self.digest,
            context={}, ollama_transport=lambda *_: self.fail("stale audit reached Ollama"),
        )
        self.assertEqual(blocked["status"], "BLOCKED")
        self.assertFalse(blocked["model"]["invoked"])
        self.assertTrue(steward.validate_plan(blocked)["valid"])

    def test_loopback_only_pinned_structured_proposal(self) -> None:
        data = observed_context()
        draft = steward.compile_plan(mission="Map safe evidence", context=data,
                                     provider="deterministic")["draft"]
        calls = []

        def transport(request, timeout):
            calls.append((request, timeout))
            if request.full_url == steward.OLLAMA_TAGS_ENDPOINT:
                return self.tags(self.digest)
            self.assertEqual(request.full_url, steward.OLLAMA_GENERATE_ENDPOINT)
            return json.dumps({
                "model": self.model, "done": True, "done_reason": "stop",
                "response": json.dumps(draft),
            }).encode()

        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-private-test-fixture",
                                          "GH_TOKEN": "gh-private-fixture"}):
            plan = steward.compile_plan(
                mission="Map safe evidence gh-private-fixture", context=data,
                provider="ollama-local", model_id=self.model, model_digest=self.digest,
                timeout_seconds=300, ollama_transport=transport,
            )
        self.assertEqual([call[0].full_url for call in calls], [
            steward.OLLAMA_TAGS_ENDPOINT, steward.OLLAMA_GENERATE_ENDPOINT,
            steward.OLLAMA_TAGS_ENDPOINT,
        ])
        self.assertEqual([timeout for _, timeout in calls], [5, 120, 5])
        body = json.loads(calls[1][0].data)
        self.assertEqual(body["model"], self.model)
        self.assertEqual(body["format"], steward.model_draft_schema())
        self.assertFalse(body["stream"])
        self.assertFalse(body["think"])
        self.assertEqual(body["keep_alive"], 0)
        self.assertEqual(body["options"]["num_ctx"], 8192)
        self.assertNotIn("tools", body)
        self.assertIsNone(calls[1][0].get_header("Authorization"))
        self.assertNotIn("gh-private-fixture", body["prompt"])
        self.assertEqual(plan["status"], "PROPOSED")
        self.assertEqual(plan["model"]["identity_state"], "LOCAL_MANIFEST_DIGEST_MATCH")
        self.assertEqual(plan["model"]["requested_family"], "LOCAL_OPEN_MODEL")
        self.assertIn("LOCAL_OPEN_MODEL", body["prompt"])
        self.assertNotIn("Requested reasoning family label: Daybreak", body["prompt"])
        self.assertEqual(plan["model"]["resolved_model"],
                         f"{self.model}@sha256:{self.digest}")
        self.assertFalse(plan["model"]["production_allowed"])
        self.assertTrue(steward.validate_plan(plan)["valid"])
        for field, value in (("requested_family", "Daybreak"),
                             ("identity_state", "UNAVAILABLE"),
                             ("runtime", "NO_TOOLS_RESPONSES")):
            changed = json.loads(json.dumps(plan))
            changed["model"][field] = value
            steward._finalize_digest(changed)
            self.assertFalse(steward.validate_plan(changed)["valid"], field)

    def test_manifest_mismatch_or_drift_blocks_without_fallback(self) -> None:
        calls = []

        def mismatch(request, _):
            calls.append(request.full_url)
            return self.tags("b" * 64)

        plan = steward.compile_plan(
            mission="Map safe evidence", context=observed_context(),
            provider="ollama-local", model_id=self.model, model_digest=self.digest,
            ollama_transport=mismatch,
        )
        self.assertEqual(calls, [steward.OLLAMA_TAGS_ENDPOINT])
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertFalse(plan["model"]["invoked"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

        data = observed_context()
        draft = steward.compile_plan(mission="Map safe evidence", context=data,
                                     provider="deterministic")["draft"]
        reads = 0

        def drift(request, _):
            nonlocal reads
            if request.full_url == steward.OLLAMA_TAGS_ENDPOINT:
                reads += 1
                return self.tags(self.digest if reads == 1 else "b" * 64)
            return json.dumps({"model": self.model, "done": True,
                               "response": json.dumps(draft)}).encode()

        changed = steward.compile_plan(
            mission="Map safe evidence", context=data, provider="ollama-local",
            model_id=self.model, model_digest=self.digest, ollama_transport=drift,
        )
        self.assertEqual(changed["status"], "BLOCKED")
        self.assertTrue(changed["model"]["invoked"])
        self.assertIsNone(changed["draft"])
        self.assertTrue(steward.validate_plan(changed)["valid"])

    def test_tool_or_incomplete_output_is_blocked(self) -> None:
        for change in ({"tool_calls": [{"name": "write"}]}, {"done": False},
                       {"done_reason": "length"}):
            with self.subTest(change=change):
                data = observed_context()
                draft = steward.compile_plan(mission="Map safe evidence", context=data,
                                             provider="deterministic")["draft"]

                def transport(request, _):
                    if request.full_url == steward.OLLAMA_TAGS_ENDPOINT:
                        return self.tags(self.digest)
                    output = {"model": self.model, "done": True, "done_reason": "stop",
                              "response": json.dumps(draft)}
                    output.update(change)
                    return json.dumps(output).encode()

                plan = steward.compile_plan(
                    mission="Map safe evidence", context=data, provider="ollama-local",
                    model_id=self.model, model_digest=self.digest, ollama_transport=transport,
                )
                self.assertEqual(plan["status"], "BLOCKED")
                self.assertTrue(plan["model"]["invoked"])
                self.assertIsNone(plan["draft"])
                self.assertTrue(steward.validate_plan(plan)["valid"])


class ResponsesTests(unittest.TestCase):
    def test_incomplete_http_read_becomes_redacted_recordable_block(self):
        def truncated(*args):
            raise http.client.IncompleteRead(b"private-partial-response", 10)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), response_transport=truncated)
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertTrue(plan["model"]["invoked"])
        self.assertNotIn("private-partial-response", json.dumps(plan))
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def envelope(self, draft=None):
        if draft is None:
            draft = steward.compile_plan(mission="Map safe evidence", context=observed_context(), provider="deterministic")["draft"]
        return {
            "status": "completed", "model": "provider-reported-test-model",
            "access_programs": {"cyber": "daybreak_blue"},
            "output": [{"type": "message", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": json.dumps(draft)}]}],
        }

    def test_no_tools_fixed_endpoint_redacted_bounded_request_and_readback(self):
        captured = {}
        data = observed_context()
        draft = steward.compile_plan(
            mission="Map safe evidence", context=data, provider="deterministic"
        )["draft"]
        def transport(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data)
            return json.dumps(self.envelope(draft)).encode()
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-private-test-fixture", "GH_TOKEN": "gh-private-fixture"}):
            plan = steward.compile_plan(mission="Map safe evidence gh-private-fixture", context=data, response_transport=transport)
        body = captured["body"]
        self.assertEqual(captured["url"], "https://api.openai.com/v1/responses")
        self.assertEqual(body["tools"], [])
        self.assertEqual(body["tool_choice"], "none")
        self.assertFalse(body["store"])
        self.assertTrue(body["text"]["format"]["strict"])
        self.assertNotIn("gh-private-fixture", body["input"])
        self.assertNotIn("gh-private-fixture", json.dumps(plan))
        self.assertNotIn("sk-private-test-fixture", json.dumps(plan))
        self.assertEqual(plan["status"], "PROPOSED")
        self.assertEqual(plan["model"]["identity_state"], "PROVIDER_REPORTED_UNPINNED")
        self.assertFalse(plan["model"]["production_allowed"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_responses_cannot_add_unobserved_evidence_handles(self):
        draft = steward.compile_plan(
            mission="Map safe evidence", context=observed_context(), provider="deterministic"
        )["draft"]
        for proposal in draft["proposals"]:
            proposal["evidence_handles"] = ["audit:never-observed", "receipt:deadbeef"]
        fabricated = self.envelope(draft)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            plan = steward.compile_plan(
                mission="Map safe evidence", context=observed_context(),
                response_transport=lambda *_: json.dumps(fabricated).encode(),
            )
        self.assertEqual(plan["status"], "DENIED")
        self.assertIsNone(plan["draft"])
        self.assertIn("INVALID_OR_UNSAFE_MODEL_DRAFT", plan["policy"]["violations"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_missing_key_blocked_no_hidden_fallback(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), response_transport=lambda *a: self.fail("credential missing but provider called"))
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertFalse(plan["model"]["invoked"])
        self.assertIsNone(plan["draft"])
        self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_tool_refusal_incomplete_unattested_oversized_are_blocked(self):
        fixtures = []
        for change in (
            lambda p: p.update(output=[{"type": "function_call", "name": "deploy"}]),
            lambda p: p.update(status="incomplete"),
            lambda p: p.pop("access_programs"),
            lambda p: p["output"][0].update(content=[{"type": "refusal", "refusal": "declined"}]),
        ):
            item = self.envelope()
            change(item)
            fixtures.append(json.dumps(item).encode())
        fixtures.extend([b" " * (steward.MAX_RESPONSE_BYTES + 1), b'{"status":"completed","status":"incomplete"}'])
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            for raw in fixtures:
                plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), response_transport=lambda *a: raw)
                self.assertEqual(plan["status"], "BLOCKED")
                self.assertTrue(plan["model"]["invoked"])
                self.assertIsNone(plan["draft"])
                self.assertTrue(steward.validate_plan(plan)["valid"])

    def test_cli_without_optin_cannot_run(self):
        plan = steward.compile_plan(mission="Map safe evidence", context=observed_context(), provider="codex-cli", cli_runner=lambda *a, **kw: self.fail("CLI without optin"))
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertFalse(plan["model"]["invoked"])


if __name__ == "__main__":
    unittest.main()
