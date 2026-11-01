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

    def shutdown(self, uncertain=False, suspend_error=None):
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
                                   go.time.monotonic, rec.run_id, go.EXIT_UNCERTAIN if uncertain else go.EXIT_OK)
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


if __name__ == "__main__":
    unittest.main()
