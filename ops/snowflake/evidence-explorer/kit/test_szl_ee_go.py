"""Reconstructed offline runner regression tests; synthetic accounts only.

These tests do not claim to reproduce the withheld historical runner suite or
qualify live Snowflake deployment. Run with python -I -B test_szl_ee_go.py.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock as mock
import types
import builtins

sys.path.insert(0, str(Path(__file__).resolve().parent))
import szl_ee_go as go

ACCOUNT = "SYNTHETIC_ACCOUNT"


class RunnerContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.kit, self.bundle = self.root / "kit", self.root / "bundle"
        self.kit.mkdir()
        self.bundle.mkdir()
        for name in go.KIT_REQUIRED:
            (self.kit / name).write_text("# synthetic pinned kit fixture\n")
        for name in go.BUNDLE_EXECUTED:
            (self.bundle / name).write_text("# synthetic pinned bundle fixture\n")
        self.sums = self.kit / go.KIT_SUMS_FILE
        self.sums.write_text("".join(go.sha256_file_or_none(str(p)) + "  " + p.name + "\n"
                                     for p in sorted(self.kit.iterdir())))
        self.manifest = self.bundle / "MANIFEST.json"
        self.manifest.write_text(json.dumps({"files": [
            {"path": p.name, "sha256": go.sha256_file_or_none(str(p))}
            for p in sorted(self.bundle.iterdir())]}))
        self.approval = self.root / "approval.txt"
        self.approval.write_text("SYNTHETIC TEST ONLY, account " + ACCOUNT + "\n")
        self.args = ["--kit", str(self.kit), "--bundle", str(self.bundle),
                     "--approval", str(self.approval), "--out", str(self.root / "runs"),
                     "--kit-sums-sha256", go.sha256_file_or_none(str(self.sums)),
                     "--manifest-sha256", go.sha256_file_or_none(str(self.manifest))]

    def pins(self):
        return go.check_pins(str(self.kit), str(self.bundle),
                             go.sha256_file_or_none(str(self.sums)),
                             go.sha256_file_or_none(str(self.manifest)))

    def invoke(self, extra=(), env=None, runner=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = go.main(self.args + list(extra), env={} if env is None else env,
                           connector=mock.Mock(), runner=runner or mock.Mock())
        return code, json.loads(output.getvalue())

    def test_unknown_argument_refused(self):
        with self.assertRaises(go.Refused):
            go.parse_args(self.args + ["--token", "synthetic-secret"])

    def test_deadline_bounds(self):
        for value in ("0", "59", "10801", "nan", "1.5"):
            with self.subTest(value=value), self.assertRaises(go.Refused):
                go.parse_args(self.args + ["--max-seconds", value])

    def test_malformed_approval_refused(self):
        self.approval.write_text("SYNTHETIC TEST ONLY\naccount X\n")
        code, result = self.invoke()
        self.assertEqual(code, go.EXIT_REFUSED)
        self.assertIn("approval", result["refusal"])

    def test_run_directories_are_unique(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
        _, first = self.invoke(["--dry-run-only"], runner=runner)
        _, second = self.invoke(["--dry-run-only"], runner=runner)
        self.assertNotEqual(first["out_dir"], second["out_dir"])
        self.assertNotEqual(first["run_id"], second["run_id"])

    def test_offline_flow_never_probes_imports_or_resolves_credentials(self):
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"synthetic plan", b""))
        with mock.patch.object(go, "probe_snowpark", side_effect=AssertionError("probe forbidden")), \
             mock.patch.object(go, "resolve_credentials", side_effect=AssertionError("credentials forbidden")), \
             mock.patch.object(go, "direct_sql", side_effect=AssertionError("SQL forbidden")):
            code, result = self.invoke(["--dry-run-only"],
                env={"SNOWFLAKE_PASSWORD": "synthetic-secret", "SZL_SF_SETUP_CONNECTION_NAME": "fake"},
                runner=runner)
        self.assertEqual(code, go.EXIT_PARTIAL)
        self.assertEqual(result["overall"], "INCOMPLETE")
        self.assertFalse(result["deployed_step_started"])
        self.assertTrue(result["chain_valid"])
        self.assertEqual(runner.call_count, 1)
        args, kwargs = runner.call_args
        self.assertIn("--dry-run", args[0])
        self.assertNotIn("--execute", args[0])
        self.assertFalse(any("synthetic-secret" == v for v in kwargs["env"].values()))
        self.assertFalse(Path(kwargs["env"]["SNOWFLAKE_HOME"]).exists())

    def test_offline_child_failure_is_failure(self):
        code, result = self.invoke(["--dry-run-only"], runner=mock.Mock(
            return_value=subprocess.CompletedProcess([], 1, b"", b"synthetic failure")))
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertEqual(result["overall"], "FAIL")

    def test_offline_timeout_is_failure(self):
        code, result = self.invoke(["--dry-run-only"], runner=mock.Mock(
            side_effect=subprocess.TimeoutExpired("synthetic", 1)))
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertFalse(result["deployed_step_started"])

    def test_missing_prerequisite_blocks_before_credentials(self):
        with mock.patch.object(go, "probe_snowpark", return_value=(False, "unavailable")), \
             mock.patch.object(go, "resolve_credentials", side_effect=AssertionError("unexpected credential access")):
            code, result = self.invoke()
        self.assertEqual(code, go.EXIT_BLOCKED)
        self.assertFalse(result["deployed_step_started"])

    def test_missing_credential_blocks_before_sql(self):
        with mock.patch.object(go, "probe_snowpark", return_value=(True, "")), \
             mock.patch.object(go, "direct_sql", side_effect=AssertionError("unexpected SQL")):
            code, _ = self.invoke()
        self.assertEqual(code, go.EXIT_BLOCKED)

    def test_changed_kit_refuses_before_child(self):
        (self.kit / "sf_deploy_pilot.py").write_text("# changed\n")
        child = mock.Mock(side_effect=AssertionError("unexpected child"))
        code, _ = self.invoke(["--dry-run-only"], runner=child)
        self.assertEqual(code, go.EXIT_REFUSED)
        child.assert_not_called()

    def test_changed_bundle_refuses(self):
        (self.bundle / go.BUNDLE_EXECUTED[0]).write_text("# changed\n")
        with self.assertRaises(go.Refused):
            self.pins()

    def test_missing_kit_file_refuses(self):
        (self.kit / go.KIT_REQUIRED[0]).unlink()
        with self.assertRaises(go.Refused):
            self.pins()

    def test_duplicate_and_escaping_manifest_entries_refuse(self):
        original = json.loads(self.manifest.read_text())
        for entry in (original["files"][0], {"path": "../escape.py", "sha256": "0" * 64}):
            doc = copy.deepcopy(original)
            doc["files"].append(entry)
            self.manifest.write_text(json.dumps(doc))
            with self.subTest(entry=entry), self.assertRaises(go.Refused):
                self.pins()

    def test_pin_recheck_detects_change_after_initial_validation(self):
        pins, _ = self.pins()
        path = self.kit / "sf_deploy_pilot.py"
        path.write_text("# tampered after initial validation\n")
        self.assertEqual(go.recheck_pins(pins, [str(path)]), [path.name])

    def test_profile_modes_cannot_be_mixed(self):
        with self.assertRaises(go.Refused):
            go.resolve_credentials({"SNOWFLAKE_DEPLOY_USER": "fake", "SZL_SF_SETUP_CONNECTION_NAME": "fake"}, self.tmp.name)

    def test_profile_names_must_be_distinct_and_complete(self):
        for env in ({"SZL_SF_SETUP_CONNECTION_NAME": "same"},
                    {"SZL_SF_SETUP_CONNECTION_NAME": "same", "SZL_SF_RUNTIME_CONNECTION_NAME": "same"}):
            with self.subTest(env=env), self.assertRaises(go.Refused):
                go.resolve_credentials(env, self.tmp.name)

    def test_legacy_credentials_refused(self):
        with self.assertRaises(go.Refused):
            go.resolve_credentials({"SNOWFLAKE_USER": "synthetic"}, self.tmp.name)

    def test_child_environment_scrubs_credentials_and_profiles(self):
        base = {"PATH": "/bin", "API_TOKEN": "fake-token", "SNOWFLAKE_PASSWORD": "fake-password",
                "SZL_SF_SETUP_CONNECTION_NAME": "owner-profile", "SNOWFLAKE_DEFAULT_CONNECTION_NAME": "owner"}
        env = go.child_env(base, {"SZL_SF_CONNECTION_NAME": "synthetic-runtime"})
        self.assertEqual(env["PATH"], "/bin")
        self.assertEqual(env["SZL_SF_CONNECTION_NAME"], "synthetic-runtime")
        for name in base.keys() - {"PATH"}:
            self.assertNotIn(name, env)

    def test_account_role_and_privilege_checks(self):
        row = {"a": ACCOUNT, "o": "SYNTH", "n": "TEST", "u": "FAKE_USER",
               "r": go.RUNTIME_ROLE, "ar": json.dumps([go.RUNTIME_ROLE, go.OPERATOR_ROLE])}
        self.assertEqual(go.check_identity(row, ACCOUNT, go.RUNTIME_ROLE, go.RUNTIME_MUST_NOT, go.RUNTIME_MUST_HAVE)[0], [])
        for changes in ({"a": "OTHER"}, {"r": "SYSADMIN"}, {"ar": "unreadable"},
                        {"ar": json.dumps([go.RUNTIME_ROLE])},
                        {"ar": json.dumps([go.RUNTIME_ROLE, go.OPERATOR_ROLE, "ACCOUNTADMIN"])}):
            with self.subTest(changes=changes):
                self.assertTrue(go.check_identity(dict(row, **changes), ACCOUNT, go.RUNTIME_ROLE,
                                                 go.RUNTIME_MUST_NOT, go.RUNTIME_MUST_HAVE)[0])

    def test_inventory_exact_names_and_warehouse_state(self):
        inv = {"inv_databases": [{"name": "SZL_EE_DB_BACKUP"}],
               "inv_warehouses": [{"name": go.WAREHOUSE, "state": "SUSPENDED", "auto_resume": False,
                                    "owner": "ACCOUNTADMIN", "resource_monitor": go.MONITOR}],
               "inv_monitors": [{"name": go.MONITOR}]}
        self.assertFalse(go.classify_inventory(inv)["existing_pilot_objects"])
        self.assertFalse(go.classify_inventory(inv)["warehouse_problems"])
        inv["inv_databases"].append({"name": "szl_ee_db"})
        self.assertTrue(go.classify_inventory(inv)["existing_pilot_objects"])
        for key, value in (("state", "STARTED"), ("auto_resume", True), ("owner", "SYSADMIN"),
                           ("resource_monitor", "OTHER")):
            changed = copy.deepcopy(inv)
            changed["inv_warehouses"][0][key] = value
            self.assertTrue(go.classify_inventory(changed)["warehouse_problems"])

    def test_itest_exit_zero_without_results_is_incomplete(self):
        self.assertEqual(go.parse_itests(0, "OK")["overall"], "NOT_RUN_OR_PARTIAL")

    def test_itest_all_eleven_required_for_pass(self):
        lines = [name + " (__main__.Synthetic) ... ok" for name in go.EXPECTED_ITESTS]
        self.assertEqual(go.parse_itests(0, "\n".join(lines))["overall"], "PASS")
        self.assertEqual(go.parse_itests(0, "\n".join(lines[:-1]))["overall"], "NOT_RUN_OR_PARTIAL")

    def test_itest_failures_outrank_skips(self):
        lines = [name + " (__main__.Synthetic) ... skipped 'not configured'" for name in go.EXPECTED_ITESTS]
        lines[0] = go.EXPECTED_ITESTS[0] + " (__main__.Synthetic) ... FAIL"
        self.assertEqual(go.parse_itests(3, "\n".join(lines))["overall"], "FAIL")

    def test_receipt_tamper_and_secret_scrubbing(self):
        rec = go.Receipt(str(self.root / "receipt"), ["synthetic-secret"], go.new_run_id())
        rec.add("one", "PASS", stdout="synthetic-secret")
        rec.add("two", "PASS")
        self.assertTrue(go.verify_chain(rec.path))
        self.assertNotIn("synthetic-secret", "".join(p.read_text() for p in Path(rec.logs).iterdir()))
        path = Path(rec.path)
        path.write_text(path.read_text().replace('"step":"one"', '"step":"tampered"'))
        self.assertFalse(go.verify_chain(rec.path))

    def test_deadline_caps_child_and_stops_expired_work(self):
        now = [0]
        clock = go._Clock(lambda: now[0], 60)
        now[0] = 55
        self.assertEqual(clock.step_timeout(100), 5)
        now[0] = 60
        with self.assertRaises(go.DeadlineExceeded):
            clock.step_timeout()

    def shutdown(self, uncertain=False, suspend_error=None, forward_code=None):
        rec = go.Receipt(str(self.root / "shutdown-receipt"), [], go.new_run_id())
        state = {"connector": mock.Mock(), "prof": {"setup": {}, "runtime": {}},
                 "pins": {}, "kit": str(self.kit), "cenv_runtime": {}, "uncertain": uncertain}
        inv = {"warehouse_state": "SUSPENDED", "complete": True, "errors": {},
               "existing_pilot_objects": []}

        def verifier(*args, **kwargs):
            (Path(rec.out_dir) / "shutdown.json").write_text(json.dumps({"checks": [
                {"id": name, "status": "PASS", "detail": "synthetic readback"}
                for name in ("W1", "W2", "T1")]}))
            return 0, "", ""

        with mock.patch.object(go, "direct_sql", side_effect=suspend_error,
                               return_value=([], [], "synthetic-query-id")), \
             mock.patch.object(go, "take_inventory", return_value=inv), \
             mock.patch.object(go, "recheck_pins", return_value=[]), \
             mock.patch.object(go, "run_py", side_effect=verifier):
            verdict = go._shutdown({"--kit": str(self.kit)}, state, mock.Mock(), rec,
                                   go.time.monotonic, rec.run_id, forward_code if forward_code is not None
                                   else (go.EXIT_UNCERTAIN if uncertain else go.EXIT_OK))
        billable = json.loads((Path(rec.out_dir) / "potentially_billable.json").read_text())
        return verdict, billable

    def test_known_completed_shutdown_can_be_verified(self):
        verdict, billable = self.shutdown()
        self.assertEqual(verdict, (True, False))
        self.assertFalse(billable["resources"][0]["potentially_billing_now"])

    def test_uncertain_forward_operation_prevents_verified_shutdown(self):
        verdict, billable = self.shutdown(uncertain=True)
        self.assertEqual(verdict, (False, False))
        self.assertFalse(billable["shutdown_verified"])
        self.assertTrue(billable["resources"][0]["potentially_billing_now"])

    def test_timed_out_suspend_prevents_verified_shutdown(self):
        verdict, billable = self.shutdown(suspend_error=go.StepTimeout("synthetic timeout"))
        self.assertEqual(verdict, (False, False))
        self.assertTrue(billable["uncertain_outcome"])

    def test_uncertain_exit_cannot_be_cleared_by_missing_state_flag(self):
        verdict, billable = self.shutdown(forward_code=go.EXIT_UNCERTAIN)
        self.assertFalse(verdict[0])
        self.assertTrue(billable["uncertain_outcome"])
        self.assertTrue(billable["resources"][0]["potentially_billing_now"])

    def test_delayed_resume_cannot_be_cleared_by_earlier_readback(self):
        release, finished = threading.Event(), threading.Event()

        def late_resume():
            release.wait(5)
            finished.set()

        try:
            with self.assertRaises(go.StepTimeout):
                go.bounded(late_resume, 0.01)
            self.assertFalse(finished.is_set())
            verdict, billable = self.shutdown(uncertain=True)
            self.assertFalse(verdict[0])
            self.assertTrue(billable["resources"][0]["unresolved_operation"])
            release.set()
            self.assertTrue(finished.wait(1))
        finally:
            release.set()
            finished.wait(1)


    def simulate_run(self, **config):
        """Run the real orchestrator with synthetic process and SQL boundaries.

        Child commands are recorded, never launched. SQL is represented by fixed
        readbacks; no connector import, account lookup or network call occurs.
        """
        observed = {"children": [], "direct": [], "timeouts": [], "deploy_intent": None}
        inventory = go.classify_inventory({
            "inv_warehouses": [{"name": go.WAREHOUSE, "state": "SUSPENDED", "auto_resume": False,
                                "owner": "ACCOUNTADMIN", "resource_monitor": go.MONITOR}],
            "inv_monitors": [{"name": go.MONITOR}]})
        inventory.update(complete=True, errors={})
        inventory.update(config.get("inventory", {}))
        successful = "\n".join(name + " (__main__.Synthetic) ... ok" for name in go.EXPECTED_ITESTS)

        def child(argv, **kwargs):
            script = argv[3]
            observed["children"].append((list(argv), dict(kwargs["env"])))
            observed["timeouts"].append(kwargs["timeout"])
            stdout, stderr, code = b"", b"", 0
            if script == "sf_verify_account_readonly.py":
                code = config.get("verify_code", 0)
            elif script == "sf_deploy_pilot.py" and "--dry-run" in argv:
                if config.get("after_dryrun"):
                    config["after_dryrun"]()
            elif script == "sf_deploy_pilot.py" and "--execute" in argv:
                out = Path(argv[argv.index("--out") + 1])
                entries = [json.loads(line) for line in (out.parent / "live_run_receipt.jsonl").read_text().splitlines()]
                observed["deploy_intent"] = entries[-1]
                if config.get("deploy_error"):
                    raise config["deploy_error"]
                evidence = config.get("deploy_evidence", {"post_checks": [{"check": "synthetic", "status": "PASS"}]})
                if evidence is not None:
                    out.write_text(json.dumps(evidence))
                code = config.get("deploy_code", 0)
            elif script == "test_integration_snowflake.py":
                code = config.get("itest_code", 0)
                stdout = config.get("itest_output", successful).encode()
                if config.get("after_itests"):
                    config["after_itests"]()
            elif script == "sf_shutdown_verify.py":
                out = Path(argv[argv.index("--out") + 1])
                out.write_text(json.dumps({"checks": [{"id": k, "status": config.get("shutdown_core", "PASS")}
                                                       for k in ("W1", "W2", "T1")]}))
                code = config.get("shutdown_code", 0)
            else:
                self.fail("unexpected synthetic child command: " + script)
            return subprocess.CompletedProcess(argv, code, stdout, stderr)

        def direct(connector, profile, key, run_id, timeout):
            observed["direct"].append((profile, key, run_id, timeout))
            if key == "identity":
                setup = profile["connection_name"] == "synthetic_setup"
                row = {"a": ACCOUNT, "o": "SYNTH", "n": "TEST", "u": "SETUP_USER" if setup else "RUNTIME_USER",
                       "r": go.SETUP_ROLE if setup else go.RUNTIME_ROLE,
                       "ar": [go.SETUP_ROLE] if setup else [go.RUNTIME_ROLE, go.OPERATOR_ROLE]}
                row.update(config.get("setup_identity" if setup else "runtime_identity", {}))
                return [], [row], "synthetic-identity"
            if key == "resume" and config.get("resume_error"):
                raise config["resume_error"]
            self.assertIn(key, ("resume", "suspend"))
            return [], [], "synthetic-control"

        def readback(connector, profile, *args, **kwargs):
            value = copy.deepcopy(inventory)
            if any(key == "suspend" for _, key, _, _ in observed["direct"]):
                value["warehouse_state"] = config.get(
                    "runtime_state" if profile["connection_name"] == "synthetic_runtime" else "setup_state", "SUSPENDED")
            return value

        probe = mock.Mock(return_value=config.get("probe", (True, "")), side_effect=config.get("probe_error"))
        with mock.patch.object(go, "probe_snowpark", probe), \
             mock.patch.object(go, "direct_sql", side_effect=direct), \
             mock.patch.object(go, "take_inventory", side_effect=readback):
            code, summary = self.invoke(env={"SZL_SF_SETUP_CONNECTION_NAME": "synthetic_setup",
                                            "SZL_SF_RUNTIME_CONNECTION_NAME": "synthetic_runtime"}, runner=child)
        observed["probe"] = probe
        return code, summary, observed

    def artifact(self, summary, name):
        path = Path(summary["out_dir"]) / name
        self.assertTrue(path.is_file(), "required evidence missing: " + name)
        return json.loads(path.read_text())

    def test_complete_synthetic_state_machine_retains_evidence_and_identity_separation(self):
        code, summary, seen = self.simulate_run()
        self.assertEqual(code, go.EXIT_OK)
        self.assertTrue(summary["deployed_step_started"])
        self.assertTrue(summary["shutdown_verified"])
        self.assertTrue(summary["chain_valid"])
        self.assertEqual(seen["deploy_intent"]["step"], "deploy")
        self.assertEqual(seen["deploy_intent"]["status"], "STARTED")
        self.assertTrue(self.artifact(summary, "inventory_pre.json")["complete"])
        self.assertTrue(self.artifact(summary, "potentially_billable.json")["shutdown_verified"])
        self.assertEqual(self.artifact(summary, "itests.json")["counts"], {"PASS": 11, "FAIL": 0, "NOT_RUN": 0})
        for argv, env in seen["children"]:
            runtime = argv[3] in ("test_integration_snowflake.py", "sf_shutdown_verify.py")
            self.assertEqual(env["SZL_SF_CONNECTION_NAME"], "synthetic_runtime" if runtime else "synthetic_setup")
        controls = [(p["connection_name"], k) for p, k, _, _ in seen["direct"] if k != "identity"]
        self.assertEqual(controls, [("synthetic_runtime", "resume"), ("synthetic_runtime", "suspend")])
        self.assertGreater(seen["direct"][-1][3], 1)

    def test_failed_shutdown_cannot_report_success(self):
        code, summary, _ = self.simulate_run(shutdown_core="FAIL")
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertFalse(summary["shutdown_verified"])

    def test_partial_shutdown_downgrades_success(self):
        code, summary, _ = self.simulate_run(shutdown_code=2)
        self.assertEqual(code, go.EXIT_PARTIAL)
        self.assertEqual(summary["overall"], "INCOMPLETE")

    def test_unknown_shutdown_core_cannot_be_verified(self):
        code, summary, _ = self.simulate_run(shutdown_core="UNKNOWN")
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertFalse(summary["shutdown_verified"])

    def test_both_warehouse_readbacks_must_allow_shutdown(self):
        for key in ("setup_state", "runtime_state"):
            with self.subTest(key=key):
                code, summary, _ = self.simulate_run(**{key: "STARTED"})
                self.assertEqual(code, go.EXIT_FAIL)
                self.assertFalse(summary["shutdown_verified"])

    def test_missing_and_failed_integration_results_never_report_success(self):
        for output, expected in (("OK", go.EXIT_PARTIAL),
                                  (go.EXPECTED_ITESTS[0] + " (__main__.Synthetic) ... FAIL", go.EXIT_FAIL)):
            with self.subTest(expected=expected):
                code, _, _ = self.simulate_run(itest_output=output)
                self.assertEqual(code, expected)

    def test_verify_failures_stop_before_identity_or_deploy(self):
        for value, expected in ((1, go.EXIT_FAIL), (4, go.EXIT_BLOCKED)):
            with self.subTest(value=value):
                code, summary, seen = self.simulate_run(verify_code=value)
                self.assertEqual(code, expected)
                self.assertFalse(summary["deployed_step_started"])
                self.assertEqual(seen["direct"], [])

    def test_identity_pair_requires_distinct_users_and_one_account(self):
        for changes in ({"u": "SETUP_USER"}, {"a": "OTHER_LOCATOR"}):
            with self.subTest(changes=changes):
                # ORG-ACCOUNT approval allows both locators individually; the
                # pair check must still reject inconsistent account locators.
                self.approval.write_text("SYNTHETIC TEST ONLY, account SYNTH-TEST\n")
                code, summary, _ = self.simulate_run(runtime_identity=changes)
                self.assertEqual(code, go.EXIT_REFUSED)
                self.assertFalse(summary["deployed_step_started"])

    def test_inventory_refusals_stop_before_deploy(self):
        for change in ({"complete": False, "errors": {"inv_roles": "synthetic"}},
                       {"existing_pilot_objects": [{"type": "database", "name": go.DATABASE}]},
                       {"monitor_exact_count": 0}, {"warehouse_problems": ["owner mismatch"]}):
            with self.subTest(change=change):
                code, summary, _ = self.simulate_run(inventory=change)
                self.assertEqual(code, go.EXIT_REFUSED)
                self.assertFalse(summary["deployed_step_started"])

    def test_deploy_timeout_is_uncertain_and_never_retried(self):
        code, summary, seen = self.simulate_run(deploy_error=subprocess.TimeoutExpired("synthetic", 1))
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertEqual(sum("--execute" in argv for argv, _ in seen["children"]), 1)
        self.assertFalse(summary["shutdown_verified"])
        self.assertTrue(self.artifact(summary, "potentially_billable.json")["uncertain_outcome"])

    def test_failed_resume_stops_integration_and_retains_uncertainty(self):
        code, summary, seen = self.simulate_run(resume_error=go.StepTimeout("synthetic"))
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertFalse(any(argv[3] == "test_integration_snowflake.py" for argv, _ in seen["children"]))
        self.assertFalse(summary["shutdown_verified"])

    def test_deploy_without_evidence_is_uncertain(self):
        code, summary, _ = self.simulate_run(deploy_evidence=None)
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertFalse(summary["shutdown_verified"])

    def test_deploy_requires_successful_post_checks(self):
        for evidence in ({"post_checks": []}, {"post_checks": [{"check": "synthetic", "status": "FAIL"}]}):
            with self.subTest(evidence=evidence):
                code, _, seen = self.simulate_run(deploy_evidence=evidence)
                self.assertEqual(code, go.EXIT_FAIL)
                self.assertFalse(any(k == "resume" for _, k, _, _ in seen["direct"]))

    def test_deploy_refusal_after_changes_is_uncertain(self):
        code, summary, _ = self.simulate_run(deploy_code=3, deploy_evidence={"changes_begun": True})
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertFalse(summary["shutdown_verified"])

    def test_partial_deploy_failure_never_continues(self):
        code, _, seen = self.simulate_run(deploy_code=5, deploy_evidence={"executed": ["synthetic"]})
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertFalse(any(k == "resume" for _, k, _, _ in seen["direct"]))

    def test_unexpected_deploy_exit_is_uncertain(self):
        code, summary, _ = self.simulate_run(deploy_code=9)
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertTrue(self.artifact(summary, "potentially_billable.json")["uncertain_outcome"])

    def test_unexpected_deploy_exception_is_recorded_and_shut_down(self):
        try:
            code, summary, _ = self.simulate_run(deploy_error=RuntimeError("synthetic failure"))
        except RuntimeError:
            self.fail("runner exception escaped instead of returning a recorded uncertain outcome")
        self.assertEqual(code, go.EXIT_UNCERTAIN)
        self.assertIn(["runner_exception", "UNKNOWN"], summary["steps"])
        self.assertIn(["suspend", "PASS"], summary["steps"])

    def test_changed_deploy_pin_is_refused_before_deploy_intent(self):
        code, summary, seen = self.simulate_run(after_dryrun=lambda: (self.kit / "sf_deploy_pilot.py").write_text("changed"))
        self.assertEqual(code, go.EXIT_REFUSED)
        self.assertFalse(summary["deployed_step_started"])
        self.assertIsNone(seen["deploy_intent"])

    def test_changed_shutdown_pin_never_executes_verifier(self):
        code, summary, seen = self.simulate_run(after_itests=lambda: (self.kit / "sf_shutdown_verify.py").write_text("changed"))
        self.assertEqual(code, go.EXIT_FAIL)
        self.assertFalse(summary["shutdown_verified"])
        self.assertFalse(any(argv[3] == "sf_shutdown_verify.py" for argv, _ in seen["children"]))

    def test_timed_out_prerequisite_blocks_before_children(self):
        code, summary, seen = self.simulate_run(probe_error=subprocess.TimeoutExpired("synthetic", 1))
        self.assertEqual(code, go.EXIT_BLOCKED)
        self.assertFalse(summary["deployed_step_started"])
        self.assertEqual(seen["children"], [])

    def test_changed_child_pin_records_refusal_without_launch(self):
        pins, _ = self.pins()
        path = self.kit / "sf_verify_account_readonly.py"
        path.write_text("changed")
        rec = go.Receipt(str(self.root / "child"), [], go.new_run_id())
        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
        with self.assertRaises(go.Refused):
            go._child(rec, "verify", path.name, [], str(self.kit), {}, runner, 1, {"pins": pins}, [str(path)])
        runner.assert_not_called()

    def test_receipts_bind_run_id_and_keep_stdout_bytes(self):
        rec = go.Receipt(str(self.root / "receipt-binding"), [], go.new_run_id())
        entry = rec.add("fixture", "PASS", stdout="synthetic stdout")
        self.assertEqual(entry.get("run_id"), rec.run_id)
        path = Path(rec.logs) / "00_fixture.stdout"
        self.assertTrue(path.is_file())
        self.assertEqual(go.sha256_file_or_none(str(path)), entry["stdout_sha256"])

    def test_run_id_uses_each_entropy_value(self):
        with mock.patch.object(go._secrets, "token_hex", side_effect=["1234abcd", "5678efab"]):
            first, second = go.new_run_id(), go.new_run_id()
        self.assertTrue(first.endswith("-1234abcd"))
        self.assertTrue(second.endswith("-5678efab"))

    def test_existing_run_directory_is_refused_without_overwriting_receipt(self):
        fixed = "20261101T120000Z-1234abcd"
        with mock.patch.object(go, "new_run_id", return_value=fixed):
            code, first = self.invoke(["--dry-run-only"], runner=mock.Mock(
                return_value=subprocess.CompletedProcess([], 0, b"", b"")))
            before = Path(first["receipt"]).read_bytes()
            child = mock.Mock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
            code, _ = self.invoke(["--dry-run-only"], runner=child)
        self.assertEqual(code, go.EXIT_REFUSED)
        child.assert_not_called()
        self.assertEqual(Path(first["receipt"]).read_bytes(), before)

    def test_direct_control_is_bounded_tagged_and_uses_operator_role(self):
        connector = mock.Mock()
        cursor = connector.connect.return_value.cursor.return_value
        cursor.description = []
        cursor.sfqid = "synthetic-query"
        with mock.patch.object(go, "bounded", side_effect=lambda fn, timeout: fn()) as bounded:
            go.direct_sql(connector, {"connection_name": "synthetic_runtime"}, "suspend", "synthetic-run", timeout=7)
        self.assertEqual(bounded.call_count, 1)
        self.assertEqual(bounded.call_args.args[1], 7)
        self.assertEqual(cursor.execute.call_args_list, [
            mock.call("USE SECONDARY ROLES SZL_EE_OPERATOR"), mock.call("ALTER WAREHOUSE SZL_EE_WH SUSPEND")])
        params = connector.connect.call_args.kwargs["session_parameters"]
        self.assertEqual(params["QUERY_TAG"], "szl_ee_go:synthetic-run:suspend")
        connector.connect.return_value.close.assert_called_once()

    def test_digest_file_pins_are_independently_required(self):
        for function, directory in ((go.load_kit_sums, self.kit), (go.load_manifest_pins, self.bundle)):
            with self.subTest(directory=directory), self.assertRaises(go.Refused):
                function(str(directory), "0" * 64)

    def expect_pin_refusal(self):
        try:
            self.pins()
        except go.Refused:
            return
        except Exception as exc:
            self.fail("pin validation crashed instead of refusing: " + type(exc).__name__)
        self.fail("invalid pin set accepted")

    def test_unlisted_kit_script_is_refused(self):
        (self.kit / "sf_unlisted.py").write_text("synthetic")
        self.expect_pin_refusal()

    def test_listed_missing_nonrequired_script_is_refused(self):
        with self.sums.open("a") as file:
            file.write("0" * 64 + "  sf_missing.py\n")
        self.expect_pin_refusal()

    def test_required_script_cannot_be_removed_from_both_pins_and_disk(self):
        name = go.KIT_REQUIRED[0]
        (self.kit / name).unlink()
        self.sums.write_text("\n".join(line for line in self.sums.read_text().splitlines() if not line.endswith("  " + name)) + "\n")
        self.expect_pin_refusal()

    def test_executed_bundle_file_must_be_listed(self):
        doc = json.loads(self.manifest.read_text())
        doc["files"] = doc["files"][1:]
        self.manifest.write_text(json.dumps(doc))
        self.expect_pin_refusal()

    def test_kit_sums_reject_parent_escape(self):
        with self.sums.open("a") as file:
            file.write("0" * 64 + "  ../outside.py\n")
        with self.assertRaises(go.Refused):
            go.load_kit_sums(str(self.kit), go.sha256_file_or_none(str(self.sums)))

    def synthetic_key_env(self):
        # PEM-shaped text only. These are not generated or usable credentials.
        pem = lambda body: "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
        return {"SNOWFLAKE_ACCOUNT": ACCOUNT, "SNOWFLAKE_DEPLOY_USER": "SYNTH_SETUP",
                "SNOWFLAKE_RUNTIME_USER": "SYNTH_RUNTIME", "SNOWFLAKE_DEPLOY_PRIVATE_KEY": pem("A" * 256),
                "SNOWFLAKE_RUNTIME_PRIVATE_KEY": pem("B" * 256)}

    def test_mode_a_separates_profiles_users_and_keys(self):
        env = self.synthetic_key_env()
        profiles = go.materialize(env, self.tmp.name)
        import tomllib
        config = tomllib.loads((self.root / "connections.toml").read_text())
        self.assertEqual(config[go.SETUP_PROFILE]["role"], "SZL_EE_SETUP")
        self.assertEqual(config[go.RUNTIME_PROFILE]["role"], "SZL_EE_INGEST")
        self.assertNotEqual(profiles["setup"]["private_key_file"], profiles["runtime"]["private_key_file"])
        for override in ({"SNOWFLAKE_RUNTIME_USER": "synth_setup"},
                         {"SNOWFLAKE_RUNTIME_PRIVATE_KEY": env["SNOWFLAKE_DEPLOY_PRIVATE_KEY"]}):
            with self.subTest(override=list(override)), self.assertRaises(go.Refused):
                go.materialize(dict(env, **override), self.tmp.name)

    def test_complete_credential_modes_cannot_be_mixed(self):
        env = self.synthetic_key_env()
        env.update(SZL_SF_SETUP_CONNECTION_NAME="synthetic_setup", SZL_SF_RUNTIME_CONNECTION_NAME="synthetic_runtime")
        with self.assertRaises(go.Refused):
            go.resolve_credentials(env, self.tmp.name)

    def test_pem_encryption_diagnostic_and_plain_body(self):
        with self.assertRaisesRegex(go.Refused, "encrypted private keys are not supported"):
            go.normalize_pem("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + "A" * 256 + "\n-----END ENCRYPTED PRIVATE KEY-----")
        body = "A" * 100 + "ENCRYPTED" + "B" * 100
        try:
            value = go.normalize_pem("-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----")
        except go.Refused:
            self.fail("an unencrypted PEM body was mistaken for an encrypted header")
        self.assertIn("ENCRYPTED", value)

    def test_connector_home_is_set_before_import(self):
        opts, flags, _ = go.parse_args(self.args)
        rec = go.Receipt(str(self.root / "import-receipt"), [], go.new_run_id())
        state = {"connector": None, "deployed": False}
        package = types.ModuleType("snowflake")
        package.connector = types.ModuleType("snowflake.connector")
        original_import = builtins.__import__
        observed = []

        def importing(name, *args, **kwargs):
            if name == "snowflake.connector":
                observed.append(go.os.environ.get("SNOWFLAKE_HOME"))
                return package
            return original_import(name, *args, **kwargs)

        with mock.patch.dict(go.os.environ, {}, clear=True), \
             mock.patch.object(builtins, "__import__", side_effect=importing), \
             mock.patch.object(go, "probe_snowpark", return_value=(True, "")), \
             mock.patch.object(go, "_forward", return_value=go.EXIT_BLOCKED):
            go._prereq_and_forward(opts, flags, {}, mock.Mock(), rec, self.tmp.name, state, ACCOUNT,
                                   "synthetic", go._Clock(go.time.monotonic, 60), rec.run_id)
        self.assertEqual(observed, [self.tmp.name])


if __name__ == "__main__":
    unittest.main()
