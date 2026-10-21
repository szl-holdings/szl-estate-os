"""Tests for szl_readiness_runner.py. Uses a stub checker; never runs the real payload."""
import hashlib, importlib, json, os, sys, tempfile, unittest

RUNNER = os.environ.get("RUNNER_MODULE", "szl_readiness_runner")
R = importlib.import_module(RUNNER)

STUB = r'''
import argparse, hashlib, json, os, sys, time
ap = argparse.ArgumentParser(); [ap.add_argument(x) for x in ("--root","--manifest","--data-pins","--out")]
a = ap.parse_args(); mode = open(os.path.join(os.path.dirname(__file__), "MODE")).read().strip()
if mode == "sleep": time.sleep(30)
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
'''


def good_probe(_):
    return {"disk_free_gb": 100.0, "ram_avail_gib": 50.0, "gpu": ["stub"], "gpu_compute_apps": []}


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); d = self.td.name
        self.bundle = os.path.join(d, "bundle"); os.makedirs(self.bundle)
        open(os.path.join(self.bundle, "szl_vm_master_payload.py"), "w").write("# payload stub\n")
        open(os.path.join(self.bundle, "szl_vm_readiness.py"), "w").write(STUB)
        self.root = os.path.join(d, "run"); os.makedirs(self.root)
        self.m = os.path.join(d, "M.json"); open(self.m, "w").write("{}")
        self.p = os.path.join(d, "P.json"); open(self.p, "w").write("{}")
        self.ev = os.path.join(d, "evidence")
        self.pins = {n: R.sha_file(os.path.join(self.bundle, n)) for n in R.PINS}

    def tearDown(self):
        self.td.cleanup()

    def mode(self, m):
        open(os.path.join(self.bundle, "MODE"), "w").write(m)

    def run_(self, extra=(), pins=None, probe=good_probe):
        argv = ["--bundle", self.bundle, "--root", self.root, "--manifest", self.m, "--data-pins", self.p,
                "--evidence-base", self.ev, "--timeout", "5"] + list(extra)
        return R.main(argv, pins=pins or self.pins, probe=probe)

    def last(self):
        return json.loads(open(os.path.join(self.ev, "history.jsonl")).read().splitlines()[-1])

    def test_pass_verified(self):
        self.mode("pass"); self.assertEqual(self.run_(), 0)
        cap = json.load(open(os.path.join(self.last()["run_dir"], "capture.json")))
        self.assertEqual(cap["checker_exit"], 0); self.assertIn("checker.stdout", cap["files_sha256"])

    def test_not_operational(self):
        self.mode("fail"); self.assertEqual(self.run_(), 1)

    def test_real_pins_refuse_stub(self):
        self.mode("pass"); self.assertEqual(R.main(["--bundle", self.bundle, "--root", self.root, "--manifest", self.m,
                                                   "--data-pins", self.p, "--evidence-base", self.ev], probe=good_probe), 2)

    def test_tampered_payload(self):
        self.mode("pass"); open(os.path.join(self.bundle, "szl_vm_master_payload.py"), "a").write("x")
        self.assertEqual(self.run_(), 2)

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
        self.mode("pass"); self.assertEqual(self.run_(probe=lambda _: dict(good_probe(_), ram_avail_gib=None)), 2)

    def test_stop_latch(self):
        self.mode("pass"); os.makedirs(self.ev); open(os.path.join(self.ev, "STOP"), "w").close()
        self.assertEqual(self.run_(), 2)

    def test_stale_lock_kept(self):
        self.mode("pass"); os.makedirs(self.ev); open(os.path.join(self.ev, ".lock"), "w").write("old")
        self.assertEqual(self.run_(), 2); self.assertTrue(os.path.exists(os.path.join(self.ev, ".lock")))

    def test_timeout_recorded(self):
        self.mode("sleep"); self.assertEqual(self.run_(["--timeout", "1"]), 2)
        self.assertIsNotNone(self.last()["run_dir"])

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
        lines = open(os.path.join(self.ev, "history.jsonl"), "rb").read().splitlines()
        self.assertEqual(json.loads(lines[1])["prev_line_sha256"], hashlib.sha256(lines[0]).hexdigest())

    def test_fresh_run_dirs_same_second(self):
        self.mode("pass"); self.assertEqual(self.run_(), 0); a = self.last()["run_dir"]
        self.assertEqual(self.run_(), 0); self.assertNotEqual(a, self.last()["run_dir"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
