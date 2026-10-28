"""Offline regression tests for ops/recovery. No network, no SSH, no GitHub writes: GitHub is a fake transport."""
import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
import unittest.mock as mock

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
os.environ["SZL_RECOVERY_DIR"] = tempfile.mkdtemp(prefix="szlrec-test-")
os.environ.pop("SZL_VM_KNOWN_HOSTS", None)
import szl_session_recovery as rec  # noqa: E402
import szl_vm_check  # noqa: E402

SHA = "a" * 40
OWNER = "/repos/szl-holdings/x"
PR = OWNER + "/pulls/1"
CR = OWNER + "/commits/" + SHA + "/check-runs"
ST = OWNER + "/commits/" + SHA + "/statuses"
PR_OPEN = {"state": "open", "merged_at": None, "draft": False, "mergeable_state": "clean",
           "head": {"sha": SHA}, "base": {"ref": "main"}, "title": "t"}
W9_RUN = {"id": 39879628870, "run_attempt": 1, "status": "completed", "conclusion": "failure",
          "head_sha": "7ad9b9aeedfff3c725ab245d00ed809b6372a726", "name": "frontier"}
RUN = "/repos/szl-holdings/szl-forge/actions/runs/39879628870"


def runs_pages(n, fail_at=None):
    allr = [{"name": f"c{i}", "status": "completed", "conclusion": "failure" if i == fail_at else "success"} for i in range(n)]
    def f(method, path, body):
        page = int(re.search(r"[?&]page=(\d+)", path).group(1))
        return 200, {"total_count": len(allr), "check_runs": allr[(page - 1) * 100:page * 100]}
    return f


class Fake:
    def __init__(self, routes):
        self.routes, self.calls = routes, []
    def __call__(self, method, path, body=None, tok=None):
        self.calls.append((method, path))
        for pref, resp in self.routes:
            if path.startswith(pref):
                return resp(method, path, body) if callable(resp) else resp
        return 404, {"message": "no route"}
    def wrote(self, verb):
        return any(m == verb for m, _ in self.calls)


class SelfTest(unittest.TestCase):
    def test_selftest_passes_with_all_mutants_killed(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rec.cmd_selftest(None)
        self.assertEqual(rc, 0, buf.getvalue()[-3000:])
        self.assertIn("mutants killed 10/10", buf.getvalue())


@mock.patch.object(rec.time, "sleep", lambda s: None)
class Integration(unittest.TestCase):
    def snap(self, routes):
        with mock.patch.object(rec, "gh", Fake(routes)):
            return rec.pr_snapshot("x", 1, None)

    def test_101st_check_failure_detected(self):
        s = self.snap([(PR, (200, PR_OPEN)), (CR, runs_pages(101, fail_at=100)), (ST, (200, []))])
        self.assertTrue(s["checks_complete"]); self.assertFalse(s["checks_green"]); self.assertEqual(s["n_check_runs"], 101)

    def test_150_checks_paginated_green(self):
        s = self.snap([(PR, (200, PR_OPEN)), (CR, runs_pages(150)), (ST, (200, []))])
        self.assertTrue(s["checks_green"]); self.assertEqual(s["n_check_runs"], 150)

    def test_403_check_runs_unknown_and_merge_refused(self):
        fake = Fake([(PR, (200, PR_OPEN)), (CR, (403, {})), (ST, (200, []))])
        with mock.patch.object(rec, "gh", fake):
            ok, msg = rec._step_merge_if_green("x", 1, True, None)
        self.assertFalse(ok); self.assertFalse(fake.wrote("PUT")); self.assertIn("HTTP_403", msg)

    def test_403_statuses_unknown(self):
        self.assertFalse(self.snap([(PR, (200, PR_OPEN)), (CR, runs_pages(3)), (ST, (403, {}))])["checks_complete"])

    def test_head_change_during_read_unknown(self):
        seq = {"n": 0}
        def moving(m, p, b):
            seq["n"] += 1
            d = dict(PR_OPEN); d["head"] = {"sha": SHA if seq["n"] == 1 else "b" * 40}
            return 200, d
        self.assertFalse(self.snap([(PR, moving), (CR, runs_pages(3)), (ST, (200, []))])["checks_complete"])

    def test_unstable_refused_even_when_green(self):
        fake = Fake([(PR, (200, dict(PR_OPEN, mergeable_state="unstable"))), (CR, runs_pages(3)), (ST, (200, []))])
        with mock.patch.object(rec, "gh", fake):
            ok, msg = rec._step_merge_if_green("x", 1, True, None)
        self.assertFalse(ok); self.assertFalse(fake.wrote("PUT")); self.assertIn("only 'clean'", msg)

    def test_clean_merge_requires_readback(self):
        state = {"merged": False}
        def pr_after(m, p, b):
            d = dict(PR_OPEN)
            if state["merged"]:
                d.update(merged_at="2026-10-28T00:00:00Z", merge_commit_sha="m" * 40)
            return 200, d
        def put(m, p, b):
            state["merged"] = True
            return 200, {"merged": True, "sha": "m" * 40}
        with mock.patch.object(rec, "gh", Fake([(PR + "/merge", put), (PR, pr_after), (CR, runs_pages(3)), (ST, (200, []))])):
            ok, msg = rec._step_merge_if_green("x", 1, True, None)
        self.assertTrue(ok); self.assertTrue(msg.startswith("SUCCEEDED_WITH_READBACK"))
        with mock.patch.object(rec, "gh", Fake([(PR + "/merge", (200, {"merged": True, "sha": "m" * 40})), (PR, (200, PR_OPEN)),
                                                (CR, runs_pages(3)), (ST, (200, []))])):
            ok, msg = rec._step_merge_if_green("x", 1, True, None)
        self.assertFalse(ok); self.assertTrue(msg.startswith("UNCERTAIN"))

    def w9(self):
        return next(i for i in rec.ITEMS if i["id"] == "W9")["steps"][0][1:]

    def test_w9_refuses_changed_attempt_without_post(self):
        fake = Fake([(RUN, (200, dict(W9_RUN, run_attempt=2)))])
        with mock.patch.object(rec, "gh", fake):
            ok, msg = rec._step_rerun_pinned(*self.w9(), True, None)
        self.assertFalse(ok); self.assertIn("ATTEMPT_CHANGED", msg); self.assertFalse(fake.wrote("POST"))

    def test_w9_accepted_pending_only_after_readback(self):
        st = {"a": 1}
        def run(m, p, b):
            if m == "POST":
                st["a"] = 2
                return 201, {}
            return 200, dict(W9_RUN, run_attempt=st["a"])
        with mock.patch.object(rec, "gh", Fake([(RUN, run)])):
            ok, msg = rec._step_rerun_pinned(*self.w9(), True, None)
        self.assertTrue(ok); self.assertTrue(msg.startswith("ACCEPTED_PENDING"))

    def test_unpinned_items_refused(self):
        self.assertIn("UNPINNED", rec._step_rerun_pinned("szl-router", "W6", 109, None, True, None)[1])
        self.assertIn("UNPINNED", rec._step_vm_stage_readiness("W8", False, None)[1])

    def test_offline_queue_makes_zero_network_calls(self):
        def no_network(*a, **k):
            raise AssertionError("network call in offline mode")
        with mock.patch.object(rec, "gh", no_network), contextlib.redirect_stdout(io.StringIO()):
            _m, _a, _g, _v, rows = rec.compute_queue(with_remote=False)
        self.assertEqual(next(r for r in rows if r["id"] == "O11")["state"], "UNKNOWN")

    def test_host_trust_refuses_missing_or_short_fingerprint(self):
        with mock.patch.dict(rec.VM, {"expected_fp": ""}):
            self.assertIn("VM_FP_UNKNOWN", rec.host_trust()[1])
        self.assertFalse(rec.exact_fp_match("SHA256:short", "")[0])


class VmCheckCli(unittest.TestCase):
    def test_local_mode_needs_no_network(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(szl_vm_check.main(["--local"]), 0)

    def test_missing_arguments_is_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            szl_vm_check.main(["--host", "203.0.113.5"])
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
