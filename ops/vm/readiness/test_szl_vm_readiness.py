"""Tests for szl_vm_readiness.py 0.2.0 (independent gates). Stub payload; never runs the real payload. Linux only."""
import hashlib, importlib, json, os, sys, tempfile, time, unittest

C = importlib.import_module(os.environ.get("CHECKER_MODULE", "szl_vm_readiness"))

STUB_PAYLOAD = r"""
import hashlib, json, os, sys, time
args = sys.argv[1:]; cmd = args[0]; here = os.path.dirname(os.path.abspath(__file__))
cfg = json.load(open(os.path.join(here, "PCFG.json")))
def receipt(kind, body):
    d = args[args.index("--out") + 1]; os.makedirs(d, exist_ok=True); ch = os.path.join(d, "chain.json")
    prev = json.load(open(ch))["head"] if os.path.exists(ch) else None
    b = json.dumps({"kind": kind, "prev_receipt_sha256": prev, "body": body}, sort_keys=True).encode()
    h = hashlib.sha256(b).hexdigest(); p = os.path.join(d, "%s_%s.json" % (kind, h[:12])); open(p, "wb").write(b)
    open(ch, "w").write(json.dumps({"head": h})); return p
if cfg.get("slow") == cmd: time.sleep(60)
if cmd == "selftest": print(json.dumps({"result": "PASS"})); sys.exit(0)
if cmd == "preflight":
    p = receipt("preflight", {"argv": args}); print(json.dumps({"status": "OK", "blockers": [], "receipt": p})); sys.exit(0)
if cmd == "inventory": receipt(cmd, {}); print(json.dumps({"counts": {"x": 1}})); sys.exit(0)
if cmd == "training": receipt(cmd, {}); print(json.dumps({"optimizer_step_evidence": "trainer_state global_step"})); sys.exit(0)
if cmd == "failures": receipt(cmd, {}); print(json.dumps({"files": 1})); sys.exit(0)
if cmd == "resume-gate":
    p = receipt("resume_gate", {"decision": "ADMIT", "checkpoint": cfg["ckpt"]})
    print(json.dumps({"decision": "ADMIT", "failed": [], "receipt": p})); sys.exit(0)
if cmd == "leakage":
    n = cfg.get("overlap", 0); body = {"train_rows": 3, "eval_rows": 2, "eval_rows_also_in_train": n,
                                       "eval_rows_near_dup_of_train": cfg.get("near", 0)}
    p = receipt("leakage", body); print(json.dumps(dict(body, receipt=p))); sys.exit(0 if n == 0 else 1)
sys.exit(2)
"""


def sha(b):
    return hashlib.sha256(b).hexdigest()


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(); d = self.td.name
        self.d = d
        self.root = os.path.join(d, "run"); self.ck = os.path.join(self.root, "checkpoint-2"); os.makedirs(self.ck)
        self.files = {"trainer_state.json": b'{"global_step": 2}', "optimizer.pt": b"opt", "scheduler.pt": b"sch",
                      "model.safetensors": b"weights"}
        for n, b in self.files.items():
            open(os.path.join(self.ck, n), "wb").write(b)
        self.man = {"checkpoint-2": {n: sha(b) for n, b in self.files.items()}}
        self.data = os.path.join(d, "data"); os.makedirs(self.data)
        open(os.path.join(self.data, "train.jsonl"), "wb").write(b'{"q":"a"}\n{"q":"b"}\n{"q":"c"}\n')
        open(os.path.join(self.data, "heldout.jsonl"), "wb").write(b'{"q":"x"}\n{"q":"y"}\n')
        self.pins = {"files": {"train.jsonl": C.sha256_file(os.path.join(self.data, "train.jsonl"))},
                     "eval_files": {"heldout.jsonl": C.sha256_file(os.path.join(self.data, "heldout.jsonl"))},
                     "row_overlap": 0, "near_dup_overlap": 0, "rights": "synthetic", "deadline_utc": "2026-11-01T00:00:00Z"}
        self.far = time.time() + 600

    def tearDown(self):
        self.td.cleanup()

    # ---- pure gates
    def test_manifest_all_good(self):
        g = C.manifest_gates(self.root, "checkpoint-2", self.man, self.far)
        self.assertTrue(all(ok for ok, _ in g.values()), g)

    def test_manifest_partial_listing_fails_coverage(self):
        man = {"checkpoint-2": {"trainer_state.json": self.man["checkpoint-2"]["trainer_state.json"]}}
        g = C.manifest_gates(self.root, "checkpoint-2", man, self.far)
        self.assertFalse(g["manifest_covers_checkpoint"][0]); self.assertTrue(g["manifest_hashes_independent"][0])

    def test_manifest_hash_mismatch(self):
        open(os.path.join(self.ck, "optimizer.pt"), "ab").write(b"!")
        self.assertFalse(C.manifest_gates(self.root, "checkpoint-2", self.man, self.far)["manifest_hashes_independent"][0])

    def test_manifest_dotdot_and_absolute_refused(self):
        outside = os.path.join(self.d, "secret.bin"); open(outside, "wb").write(b"s")
        for bad in ("../../secret.bin", outside, "./optimizer.pt", "a//b"):
            man = {"checkpoint-2": dict(self.man["checkpoint-2"], **{bad: sha(b"s")})}
            self.assertFalse(C.manifest_gates(self.root, "checkpoint-2", man, self.far)["manifest_paths_safe"][0], bad)

    def test_manifest_symlink_escape_refused(self):
        outside = os.path.join(self.d, "secret.bin"); open(outside, "wb").write(b"s")
        os.symlink(outside, os.path.join(self.ck, "link.bin"))
        man = {"checkpoint-2": dict(self.man["checkpoint-2"], **{"link.bin": sha(b"s")})}
        self.assertFalse(C.manifest_gates(self.root, "checkpoint-2", man, self.far)["manifest_paths_safe"][0])

    def test_manifest_unknown_checkpoint(self):
        g = C.manifest_gates(self.root, None, self.man, self.far)
        self.assertFalse(any(ok for ok, _ in g.values()))
        g = C.manifest_gates(self.root, "../run/checkpoint-2", self.man, self.far)
        self.assertFalse(any(ok for ok, _ in g.values()))

    def test_manifest_budget_exhausted(self):
        g = C.manifest_gates(self.root, "checkpoint-2", self.man, time.time() - 1)
        self.assertFalse(g["manifest_hashes_independent"][0]); self.assertIn("TIMEOUT", g["manifest_hashes_independent"][1])

    def test_data_gate_good(self):
        ok, d, tr, ev = C.data_gate(self.data, self.pins, self.far); self.assertTrue(ok, d)
        self.assertEqual(len(tr), 1); self.assertEqual(len(ev), 1)

    def test_data_gate_format_only_pins_refused(self):  # the 0.1.0 gap: 64-hex strings that match nothing
        pins = dict(self.pins, files={"train.jsonl": "a" * 64}, eval_files={"heldout.jsonl": "b" * 64})
        self.assertFalse(C.data_gate(self.data, pins, self.far)[0])

    def test_data_gate_byte_change_refused(self):
        open(os.path.join(self.data, "train.jsonl"), "ab").write(b'{"q":"d"}\n')
        self.assertFalse(C.data_gate(self.data, self.pins, self.far)[0])

    def test_data_gate_missing_and_unsafe(self):
        for files in ({"nope.jsonl": "a" * 64}, {"../run/checkpoint-2/optimizer.pt": sha(b"opt")}, {"/etc/hostname": "a" * 64}):
            self.assertFalse(C.data_gate(self.data, dict(self.pins, files=files), self.far)[0], files)

    def test_data_gate_needs_eval(self):
        self.assertFalse(C.data_gate(self.data, {k: v for k, v in self.pins.items() if k != "eval_files"}, self.far)[0])

    # ---- end to end with a stub payload
    def e2e(self, cfg, pins=None, man=None, extra=()):
        b = os.path.join(self.d, "bundle"); os.makedirs(b, exist_ok=True)
        open(os.path.join(b, "szl_vm_master_payload.py"), "w").write(STUB_PAYLOAD)
        json.dump(dict({"ckpt": "checkpoint-2"}, **cfg), open(os.path.join(b, "PCFG.json"), "w"))
        mp = os.path.join(self.d, "M.json"); json.dump(man or self.man, open(mp, "w"))
        pp = os.path.join(self.d, "P.json"); json.dump(pins or self.pins, open(pp, "w"))
        out = os.path.join(self.d, "out")
        old = C.HERE; C.HERE = b
        try:
            rc = C.main(["--root", self.root, "--manifest", mp, "--data-pins", pp, "--data-root", self.data, "--out", out,
                         "--min-disk-gb", "7", "--min-ram-gb", "3", "--disk-path", self.d] + list(extra),
                        expect_sha=C.sha256_file(os.path.join(b, "szl_vm_master_payload.py")))
        finally:
            C.HERE = old
        return rc, json.load(open(os.path.join(out, "readiness_verdict.json"))), out

    def test_e2e_operational(self):
        rc, v, _ = self.e2e({}); self.assertEqual(rc, 0, v["failed_gates"]); self.assertEqual(v["verdict"], "OPERATIONAL")
        self.assertEqual(v["checker"], "szl-vm-readiness/0.2.0")

    def test_e2e_unpinned_payload_never_runs(self):
        b = os.path.join(self.d, "bundle"); os.makedirs(b, exist_ok=True)
        open(os.path.join(b, "szl_vm_master_payload.py"), "w").write(STUB_PAYLOAD)
        old = C.HERE; C.HERE = b
        try:
            out = os.path.join(self.d, "o2")
            rc = C.main(["--root", self.root, "--manifest", "M", "--data-pins", "P", "--data-root", self.data, "--out", out])
        finally:
            C.HERE = old
        v = json.load(open(os.path.join(out, "readiness_verdict.json")))
        self.assertEqual(rc, 1); self.assertEqual(list(v["gates"]), ["payload_hash"])

    def test_e2e_floors_forwarded_to_preflight(self):
        rc, v, out = self.e2e({})
        pre = [json.load(open(os.path.join(out, f))) for f in os.listdir(out) if f.startswith("preflight_")][0]
        av = pre["body"]["argv"]
        self.assertEqual(av[av.index("--min-disk-gb") + 1], "7.0"); self.assertEqual(av[av.index("--min-ram-gb") + 1], "3.0")
        self.assertEqual(av[av.index("--disk-path") + 1], self.d)

    def test_e2e_pins_lie_about_overlap(self):
        rc, v, _ = self.e2e({"overlap": 1}); self.assertEqual(rc, 1)
        self.assertIn("heldout_overlap_measured", v["failed_gates"])

    def test_e2e_pins_claim_mismatch(self):
        rc, v, _ = self.e2e({}, pins=dict(self.pins, row_overlap=None)); self.assertEqual(rc, 1)
        self.assertEqual(v["failed_gates"], ["heldout_overlap_measured"])

    def test_e2e_near_dup_measured(self):
        rc, v, _ = self.e2e({"near": 2}); self.assertIn("heldout_overlap_measured", v["failed_gates"])

    def test_e2e_tampered_data_fails_even_if_payload_admits(self):
        open(os.path.join(self.data, "heldout.jsonl"), "ab").write(b'{"q":"z"}\n')
        rc, v, _ = self.e2e({}); self.assertEqual(rc, 1)
        self.assertTrue(v["gates"]["resume_gate"]["pass"])
        self.assertIn("dataset_bytes_match_pins", v["failed_gates"])

    def test_e2e_call_timeout_writes_verdict(self):
        rc, v, _ = self.e2e({"slow": "training"}, extra=["--call-timeout", "2"]); self.assertEqual(rc, 1)
        self.assertEqual(v["gates"]["training_progress_evidence"]["detail"], "TIMEOUT")

    def test_e2e_deadline_exhausted_fails_closed(self):
        rc, v, _ = self.e2e({"slow": "selftest"}, extra=["--deadline-s", "3", "--call-timeout", "60"])
        self.assertEqual(rc, 1); self.assertEqual(v["gates"]["selftest"]["detail"], "TIMEOUT")
        self.assertEqual(v["gates"]["preflight"]["detail"], "TIMEOUT")

    def test_e2e_checkpoint_outside_root(self):
        rc, v, _ = self.e2e({"ckpt": "../run/checkpoint-2"}); self.assertIn("manifest_paths_safe", v["failed_gates"])

    def test_no_expect_sha_cli_flag(self):
        with self.assertRaises(SystemExit):
            C.main(["--root", "r", "--manifest", "m", "--data-pins", "p", "--data-root", "d", "--expect-sha", "0" * 64])


if __name__ == "__main__":
    unittest.main(verbosity=1)
