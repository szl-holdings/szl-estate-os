"""Tests for szl_readiness_runner.py 0.2.0. Uses a stub checker; never runs the real payload. Linux only."""
import hashlib, importlib, json, os, signal, subprocess, sys, tempfile, time, unittest

RUNNER = os.environ.get("RUNNER_MODULE", "szl_readiness_runner")
R = importlib.import_module(RUNNER)
RUNNER_FILE = os.path.abspath(R.__file__)

STUB = r"""
import argparse, hashlib, json, os, subprocess, sys, time
ap = argparse.ArgumentParser(); [ap.add_argument(x) for x in ("--root","--manifest","--data-pins","--data-root","--out")]
a, rest = ap.parse_known_args(); here = os.path.dirname(os.path.abspath(__file__))
mode = open(os.path.join(here, "MODE")).read().strip()
open(os.path.join(here, "ARGV.json"), "w").write(json.dumps(sys.argv[1:]))
if mode == "sleep": time.sleep(30)
if mode == "grandchild":
    g = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    open(os.path.join(here, "GRANDCHILD"), "w").write(str(g.pid)); time.sleep(60)
os.makedirs(a.out, exist_ok=True)
prev = None
for i in range(2):
    body = json.dumps({"i": i, "prev_receipt_sha256": prev}).encode()
    open(os.path.join(a.out, "r%d.json" % i), "wb").write(body); prev = hashlib.sha256(body).hexdigest()
if mode == "badchain": prev = "0" * 64
open(os.path.join(a.out, "chain.json"), "w").write(json.dumps({"head": prev}))
ok = mode in ("pass", "liar_exit", "badchain")
gates = {"g1": {"pass": True}, "g2": {"pass": ok}}
v = {"verdict": "OPERATIONAL" if ok else "NOT_OPERATIONAL", "failed_gates": [] if ok else ["g2"], "gates": gates}
if mode == "liar_gates": v["verdict"] = "OPERATIONAL"; v["failed_gates"] = []
if mode == "noverdict": sys.exit(0)
p = os.path.join(a.out, "readiness_verdict.json"); open(p, "w").write(json.dumps(v))
sha = hashlib.sha256(open(p, "rb").read()).hexdigest()
if mode == "badsha": sha = "f" * 64
print(json.dumps({"verdict": v["verdict"], "sha256": sha}))
code = 0 if v["verdict"] == "OPERATIONAL" else 1
if mode == "liar_exit": code = 1
sys.exit(code)
"""


def good_probe(_):
    return {"disk_free_gb": 100.0, "ram_avail_gb": 50.0, "gpu": ["stub"], "gpu_compute_apps": []}


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie still answers kill(0); check its state
        return open("/proc/%d/stat" % pid).read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); d = self.td.name
        self.bundle = os.path.join(d, "bundle"); os.makedirs(self.bundle)
        open(os.path.join(self.bundle, "szl_vm_master_payload.py"), "w").write("# payload stub\n")
        open(os.path.join(self.bundle, "szl_vm_readiness.py"), "w").write(STUB)
        self.write_sums()
        self.root = os.path.join(d, "run"); os.makedirs(self.root)
        self.data = os.path.join(d, "data"); os.makedirs(self.data)
        self.m = os.path.join(d, "M.json"); open(self.m, "w").write("{}")
        self.p = os.path.join(d, "P.json"); open(self.p, "w").write("{}")
        self.ev = os.path.join(d, "evidence")
        self.pins = {n: R.sha_file(os.path.join(self.bundle, n)) for n in R.PINS}

    def write_sums(self, extra=None):
        names = ["szl_vm_master_payload.py", "szl_vm_readiness.py"] + list(extra or [])
        with open(os.path.join(self.bundle, "SHA256SUMS"), "w") as f:
            for n in names:
                f.write("%s  %s\n" % (R.sha_file(os.path.join(self.bundle, n)), n))

    def tearDown(self):
        self.td.cleanup()

    def mode(self, m):
        open(os.path.join(self.bundle, "MODE"), "w").write(m)

    def argv(self, extra=()):
        return ["--bundle", self.bundle, "--root", self.root, "--data-root", self.data, "--manifest", self.m,
                "--data-pins", self.p, "--evidence-base", self.ev, "--timeout", "5"] + list(extra)

    def run_(self, extra=(), pins=None, probe=good_probe):
        return R.main(self.argv(extra), pins=pins or self.pins, probe=probe)

    def hist(self):
        return os.path.join(self.ev, "history.jsonl")

    def last(self):
        return json.loads(open(self.hist()).read().splitlines()[-1])

    def spawn(self, extra=(), env=None):
        """Run the runner as a real process (pins + probe patched through a tiny bootstrap)."""
        boot = ("import sys, json; sys.path.insert(0, %r); import %s as R; "
                "sys.exit(R.main(json.loads(sys.argv[1]), pins=json.loads(sys.argv[2]), "
                "probe=lambda _: {'disk_free_gb': 100.0, 'ram_avail_gb': 50.0, 'gpu': [], 'gpu_compute_apps': []}))"
                % (os.path.dirname(RUNNER_FILE), RUNNER))
        e = dict(os.environ); e.update(env or {})
        return subprocess.Popen([sys.executable, "-c", boot, json.dumps(self.argv(extra)), json.dumps(self.pins)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)

    # ---- 0.1.0 behaviour kept
    def test_pass_verified(self):
        self.mode("pass"); self.assertEqual(self.run_(), 0)
        cap = json.load(open(os.path.join(self.last()["run_dir"], "capture.json")))
        self.assertEqual(cap["checker_exit"], 0); self.assertIn("checker.stdout", cap["files_sha256"])

    def test_not_operational(self):
        self.mode("fail"); self.assertEqual(self.run_(), 1)

    def test_real_pins_refuse_stub(self):
        self.mode("pass"); self.assertEqual(R.main(self.argv(), probe=good_probe), 2)

    def test_tampered_payload(self):
        self.mode("pass"); open(os.path.join(self.bundle, "szl_vm_master_payload.py"), "a").write("x")
        self.write_sums(); self.assertEqual(self.run_(), 2)

    def test_missing_manifest(self):
        self.mode("pass"); os.remove(self.m); self.assertEqual(self.run_(), 2)

    def test_missing_pins(self):
        self.mode("pass"); os.remove(self.p); self.assertEqual(self.run_(), 2)

    def test_missing_root(self):
        self.mode("pass"); os.rmdir(self.root); self.assertEqual(self.run_(), 2)

    def test_disk_floor(self):
        self.mode("pass"); self.assertEqual(self.run_(probe=lambda _: dict(good_probe(_), disk_free_gb=1.0)), 2)

    def test_disk_unknown(self):
        self.mode("pass"); self.assertEqual(self.run_(probe=lambda _: dict(good_probe(_), disk_free_gb=None)), 2)

    def test_ram_unknown(self):
        self.mode("pass"); self.assertEqual(self.run_(probe=lambda _: dict(good_probe(_), ram_avail_gb=None)), 2)

    def test_stop_latch(self):
        self.mode("pass"); os.makedirs(self.ev); open(os.path.join(self.ev, "STOP"), "w").close()
        self.assertEqual(self.run_(), 2)

    def test_stale_lock_kept(self):
        self.mode("pass"); os.makedirs(self.ev); open(os.path.join(self.ev, ".lock"), "w").write("old")
        self.assertEqual(self.run_(), 2); self.assertTrue(os.path.exists(os.path.join(self.ev, ".lock")))

    def test_timeout_recorded(self):  # 0.1.0 used --timeout 1; 0.2.0 refuses that (no checker deadline left)
        self.mode("sleep"); self.assertEqual(self.run_(["--timeout", "3"]), 2)
        self.assertIsNotNone(self.last()["run_dir"])

    def test_timeout_too_small_refused(self):
        self.mode("pass"); self.assertEqual(self.run_(["--timeout", "1"]), 2)
        self.assertIsNone(self.last()["run_dir"]); self.assertIn("too small", self.last()["blockers"][-1])

    def test_exit_verdict_mismatch(self):
        self.mode("liar_exit"); self.assertEqual(self.run_(), 3)

    def test_gates_verdict_mismatch(self):
        self.mode("liar_gates"); self.assertEqual(self.run_(), 3)

    def test_printed_sha_mismatch(self):
        self.mode("badsha"); self.assertEqual(self.run_(), 3)

    def test_no_verdict(self):
        self.mode("noverdict"); self.assertEqual(self.run_(), 3)

    def test_bad_chain(self):
        self.mode("badchain"); self.assertEqual(self.run_(), 3)

    def test_history_chained(self):
        self.mode("pass"); self.run_(); self.run_()
        lines = open(self.hist(), "rb").read().splitlines()
        self.assertEqual(json.loads(lines[1])["prev_line_sha256"], hashlib.sha256(lines[0]).hexdigest())

    def test_fresh_run_dirs_same_second(self):
        self.mode("pass"); self.assertEqual(self.run_(), 0); a = self.last()["run_dir"]
        self.assertEqual(self.run_(), 0); self.assertNotEqual(a, self.last()["run_dir"])

    # ---- 0.2.0
    def test_missing_data_root(self):
        self.mode("pass"); os.rmdir(self.data); self.assertEqual(self.run_(), 2)

    def test_empty_root_arg_blocked(self):  # systemd ${SZL_ROOT} empty -> one empty argument
        self.mode("pass"); self.assertEqual(R.main(self.argv() + ["--root", ""], pins=self.pins, probe=good_probe), 2)

    def test_sha256sums_missing(self):
        self.mode("pass"); os.remove(os.path.join(self.bundle, "SHA256SUMS")); self.assertEqual(self.run_(), 2)

    def test_sha256sums_mismatch_other_file(self):
        self.mode("pass"); open(os.path.join(self.bundle, "szl-readiness.service"), "w").write("a")
        self.write_sums(["szl-readiness.service"])
        open(os.path.join(self.bundle, "szl-readiness.service"), "w").write("b")
        self.assertEqual(self.run_(), 2)

    def test_checker_gets_deadline_and_floors(self):
        self.mode("pass"); self.assertEqual(self.run_(["--timeout", "100", "--min-disk-gb", "7", "--min-ram-gb", "3"]), 0)
        av = json.load(open(os.path.join(self.bundle, "ARGV.json")))
        val = lambda k: av[av.index(k) + 1]
        self.assertLess(float(val("--deadline-s")), 100); self.assertEqual(val("--min-disk-gb"), "7.0")
        self.assertEqual(val("--min-ram-gb"), "3.0"); self.assertEqual(val("--disk-path"), os.path.abspath(self.ev))
        self.assertEqual(val("--data-root"), os.path.abspath(self.data))

    def test_history_tamper_refused_no_append(self):
        self.mode("pass"); self.run_(); self.run_()
        lines = open(self.hist(), "rb").read().splitlines()
        rec = json.loads(lines[0]); rec["status"] = "OPERATIONAL_VERIFIED_EDITED"
        open(self.hist(), "wb").write(json.dumps(rec, sort_keys=True).encode() + b"\n" + lines[1] + b"\n")
        before = open(self.hist(), "rb").read()
        self.assertEqual(self.run_(), 3); self.assertEqual(open(self.hist(), "rb").read(), before)

    def test_history_torn_line_refused(self):
        self.mode("pass"); self.run_()
        open(self.hist(), "ab").write(b'{"status": "half')
        self.assertEqual(self.run_(), 3)

    def test_history_truncation_of_first_line_detected(self):
        self.mode("pass"); self.run_(); self.run_(); self.run_()
        lines = open(self.hist(), "rb").read().splitlines(keepends=True)
        open(self.hist(), "wb").write(b"".join(lines[1:]))
        self.assertEqual(self.run_(), 3)

    def test_concurrent_appends_stay_linear(self):
        self.mode("pass"); os.makedirs(self.ev); open(os.path.join(self.ev, "STOP"), "w").close()
        ps = [self.spawn(env={"SZL_READINESS_TEST_APPEND_DELAY": "0.3"}) for _ in range(6)]
        codes = [p.wait(timeout=60) for p in ps]
        self.assertEqual(codes, [2] * 6)
        ok, _prev, n, err = R.verify_history(self.hist())
        self.assertTrue(ok, err); self.assertEqual(n, 6)

    def test_sigterm_releases_lock_and_kills_group(self):
        self.mode("grandchild")
        p = self.spawn(["--timeout", "120"])
        gpath = os.path.join(self.bundle, "GRANDCHILD")
        for _ in range(200):
            if os.path.exists(gpath) and open(gpath).read().strip():
                break
            time.sleep(0.05)
        gpid = int(open(gpath).read())
        p.send_signal(signal.SIGTERM); code = p.wait(timeout=30)
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(self.ev, ".lock")))
        time.sleep(0.3); self.assertFalse(alive(gpid))
        self.assertIn("signal", json.load(open(os.path.join(self.last()["run_dir"], "capture.json")))["blockers"][-1])

    def test_timeout_kills_grandchild(self):
        self.mode("grandchild"); self.assertEqual(self.run_(["--timeout", "2"]), 2)
        gpid = int(open(os.path.join(self.bundle, "GRANDCHILD")).read())
        time.sleep(0.3); self.assertFalse(alive(gpid))
        self.assertFalse(os.path.exists(os.path.join(self.ev, ".lock")))


if __name__ == "__main__":
    unittest.main(verbosity=1)
