"""Regression tests for szl_coordinator.py (stdlib unittest, subprocess-driven).

Run:  python -I -B test_szl_coordinator.py
Env:  SZL_COORD_UNDER_TEST=<path>  test a different copy (used by the mutant harness)
      SZL_COORD_LEGACY=<path>      optional real 2.0.0 script; without it a built-in synthetic
                                   2.0.0-shaped receipt is used, so the legacy test never skips
      SZL_OPENSSL=<path>           openssl 3.x for the independent Ed25519 cross-check
2.3.0: ownership_reconciliation is BLOCKED (exit 2) unless a valid lane lease is
configured. Tests whose intent is "a clean run is PREPARED / exit 0" therefore
configure a real lease via szl_lane_lease.py loaded from beside the script under test
(the same file the coordinator loads). Inherited SZL_LEASE* variables are stripped.
Scratch folders are created under ./_scratch with os.makedirs (no tempfile: on the
Windows sandbox, 0o700 temp dirs lock out the process).
"""
import base64
import concurrent.futures as cf
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = Path(os.environ.get("SZL_COORD_UNDER_TEST", HERE / "szl_coordinator.py")).resolve()
LEGACY = os.environ.get("SZL_COORD_LEGACY")
SCRATCH = HERE / "_scratch"
GIT = shutil.which("git")
LEASE_PATH = SCRIPT.parent / "szl_lane_lease.py"
LEASE_REPO = "szl-holdings/szl-forge"
LEASE_SHA = "0123456789abcdef0123456789abcdef01234567"
LEASE_CLAIMANT = "sess-coord-test"
LEASE_REQUIRED = ("SZL_LEASES_DIR", "SZL_LEASE_REPO", "SZL_LEASE_PATHS", "SZL_LEASE_CLAIMANT")
OPENSSL = os.environ.get("SZL_OPENSSL") or shutil.which("openssl")


def fresh(tag):
    d = SCRATCH / f"{tag}_{uuid.uuid4().hex[:8]}"
    os.makedirs(d)
    return d


def run(root, *args, env=None, script=SCRIPT):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SZL_LEASE")}
    e.pop("PYTHONSAFEPATH", None)
    e["SZL_WORK_ROOT"] = str(root)
    e.update(env or {})
    p = subprocess.run([sys.executable, "-I", "-B", str(script), *args], cwd=str(root),
                       env=e, capture_output=True, text=True, timeout=120)
    return p


def out_dir(root):
    return Path(root) / "szl_execution_receipts"


def receipts(root):
    return sorted(out_dir(root).glob("receipt_*.json"))


def latest(root):
    head = json.loads((out_dir(root) / "HEAD.json").read_text(encoding="utf-8"))
    return json.loads((out_dir(root) / head["receipt"]).read_text(encoding="utf-8"))


def steps(doc, name):
    return [r for r in doc["receipts"] if r["step"] == name]


def git(root, *a):
    return subprocess.run([GIT, *a], cwd=str(root), capture_output=True, text=True, check=True)


def load_lease():
    spec = importlib.util.spec_from_file_location("lease_fixture", LEASE_PATH)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def lease_env(tag, base_branch="main", base_sha=LEASE_SHA, supply_sha=True):
    """Acquire a real, valid lease in a fresh leases dir; return the coordinator env."""
    d = fresh(tag + "_leases")
    r = load_lease().acquire(str(d), "coord-test", LEASE_CLAIMANT, LEASE_REPO, base_branch,
                             base_sha, ["src/"], timedelta(hours=1), "coordinator test fixture",
                             datetime.now(timezone.utc))
    assert r["result"] == "ACQUIRED", r
    env = {"SZL_LEASES_DIR": str(d), "SZL_LEASE_REPO": LEASE_REPO,
           "SZL_LEASE_PATHS": "src/a.py", "SZL_LEASE_CLAIMANT": LEASE_CLAIMANT}
    if supply_sha:
        env["SZL_LEASE_BASE_SHA"] = base_sha
    return env


def ownership(doc):
    s = steps(doc, "ownership_reconciliation")
    assert len(s) == 1, s
    return s[0]


def load_module():
    spec = importlib.util.spec_from_file_location("coord_under_test", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m          # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(m)
    return m


class Run(unittest.TestCase):
    def test_non_repo_prepared_once(self):
        r = fresh("nonrepo")
        p = run(r, env=lease_env("nonrepo"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        d = latest(r)
        self.assertEqual(d["terminal_state"], "PREPARED")
        self.assertEqual(ownership(d)["status"], "PASS", ownership(d)["evidence"])
        self.assertEqual(len(steps(d, "repo_root")), 1)
        self.assertEqual(steps(d, "repo_root")[0]["status"], "HOLD")
        self.assertFalse(steps(d, "git_status"))
        self.assertEqual(run(r, "verify").returncode, 0)

    def test_no_duplicate_steps(self):
        r = fresh("dups")
        run(r)
        names = [x["step"] for x in latest(r)["receipts"]]
        self.assertEqual(len(names), len(set(names)), names)

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_repo_root_with_commit_passes(self):
        r = fresh("repo")
        git(r, "init", "-q")
        git(r, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "commit", "-q", "--allow-empty", "-m", "init")
        branch = git(r, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
        head = git(r, "rev-parse", "HEAD").stdout.strip()
        # base sha NOT supplied: the coordinator must read it from git (F11)
        p = run(r, env=lease_env("repo", base_branch=branch, base_sha=head, supply_sha=False))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        d = latest(r)
        for s in ("repo_root", "git_status", "git_head"):
            self.assertEqual(steps(d, s)[0]["status"], "PASS", s)
        self.assertEqual(ownership(d)["status"], "PASS", ownership(d)["evidence"])
        self.assertEqual(json.loads(ownership(d)["evidence"])["base_sha_source"], "GIT")

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_empty_repo_head_fail_is_blocked(self):
        r = fresh("emptyrepo")
        git(r, "init", "-q")
        p = run(r)
        self.assertEqual(p.returncode, 2, p.stdout)
        d = latest(r)
        self.assertEqual(d["terminal_state"], "BLOCKED")
        self.assertEqual(steps(d, "git_head")[0]["status"], "FAIL")
        self.assertEqual(steps(d, "git_head")[0]["exit_code"], 128)
        self.assertIn("git_head", d["blocking_steps"])

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_subdirectory_is_not_repo_root(self):
        r = fresh("subrepo")
        git(r, "init", "-q")
        sub = r / "inner"
        os.makedirs(sub)
        p = run(sub, env=lease_env("subrepo"))
        d = latest(sub)
        rr = steps(d, "repo_root")
        self.assertEqual(len(rr), 1)
        self.assertEqual(rr[0]["status"], "HOLD")
        self.assertFalse(steps(d, "git_status"), "git probes must not run off-root")
        self.assertEqual(p.returncode, 0, p.stdout + json.dumps(ownership(d)))

    def test_prepare_mode_is_held_and_runs_nothing(self):
        r = fresh("prepare")
        p = run(r, "--mode", "prepare")
        self.assertEqual(p.returncode, 3, p.stdout)
        d = latest(r)
        self.assertEqual(d["terminal_state"], "HELD")
        self.assertEqual([x["step"] for x in d["receipts"]], ["mode_gate"])

    def test_missing_git_is_blocked(self):
        r = fresh("nogit")
        # Hide git with an empty PATH dir. The interpreter's own dir is NOT safe on Linux
        # (/usr/bin holds both python3 and git); keep it only on Windows when git is absent there.
        pydir = str(Path(sys.executable).parent)
        path = pydir if (os.name == "nt" and not shutil.which("git", path=pydir)) else str(fresh("emptypath"))
        self.assertIsNone(shutil.which("git", path=path), "precondition: git must be hidden")
        p = run(r, env={"PATH": path})
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        d = latest(r)
        self.assertEqual(steps(d, "repo_root")[0]["status"], "BLOCKED")
        self.assertEqual(steps(d, "capability_git")[0]["status"], "TOOL_NOT_AVAILABLE")


class Ownership(unittest.TestCase):
    """2.2.0 lease gate: everything short of a PASS verdict is BLOCKED, exit 2."""

    def assert_blocked(self, r, p, code):
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        d = latest(r)
        s = ownership(d)
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn(code, s["evidence"])
        self.assertEqual(d["terminal_state"], "BLOCKED")
        self.assertIn("ownership_reconciliation", d["blocking_steps"])
        self.assertNotIn("ownership_reconciliation", d["open_steps"])
        self.assertEqual(run(r, "verify").returncode, 0)      # receipt still written and sealed

    def test_unconfigured_lease_is_blocked_exit_2(self):
        r = fresh("unconf")
        self.assert_blocked(r, run(r), "LEASE_NOT_CONFIGURED")

    def test_blank_lease_values_are_unconfigured(self):
        r = fresh("blank")
        env = {k: "  " for k in LEASE_REQUIRED + ("SZL_LEASE_BASE_SHA",)}
        self.assert_blocked(r, run(r, env=env), "LEASE_NOT_CONFIGURED")

    def test_partial_lease_config_is_blocked(self):
        full = lease_env("partial")
        for k in LEASE_REQUIRED:
            with self.subTest(missing=k):
                r = fresh("partial_" + k.lower())
                env = {a: b for a, b in full.items() if a != k}
                p = run(r, env=env)
                self.assert_blocked(r, p, "LEASE_CONFIG_INCOMPLETE")
                self.assertIn(k, ownership(latest(r))["evidence"])
        r = fresh("partial_only_sha")
        self.assert_blocked(r, run(r, env={"SZL_LEASE_BASE_SHA": LEASE_SHA}), "LEASE_CONFIG_INCOMPLETE")

    def test_non_pass_verdict_is_blocked(self):
        env = lease_env("verdict")
        r = fresh("verdict_claimant")
        self.assert_blocked(r, run(r, env=dict(env, SZL_LEASE_CLAIMANT="sess-someone-else")),
                            "NO_COVERING_LEASE")
        r = fresh("verdict_stale")
        self.assert_blocked(r, run(r, env=dict(env, SZL_LEASE_BASE_SHA="f" * 40)), "STALE_BASE")

    def test_no_base_sha_outside_a_repo_is_blocked(self):
        r = fresh("nobase")
        env = lease_env("nobase", supply_sha=False)
        self.assert_blocked(r, run(r, env=env), "BASE_UNREADABLE")


class Redaction(unittest.TestCase):
    def test_receipt_has_no_home_or_interpreter_path(self):
        r = fresh("redact")
        run(r)
        raw = (out_dir(r) / json.loads((out_dir(r) / "HEAD.json").read_text())["receipt"]).read_text()
        doc = json.loads(raw)
        flat = json.dumps(doc).lower().replace("\\\\", "/")
        for needle in (str(Path.home()), sys.executable, str(r)):
            self.assertNotIn(needle.lower().replace("\\", "/"), flat, needle)
        self.assertIn("<PYTHON>", raw)

    def test_redact_is_separator_and_case_insensitive(self):
        m = load_module()
        c = m.Coordinator(fresh("unit"))
        home = str(Path.home())
        for v in (home, home.replace("\\", "/"), home.upper(), home.lower()):
            self.assertNotIn(v.lower().replace("\\", "/"),
                             c.redact(v + "/x").lower().replace("\\", "/"), v)

    def test_generic_pass_redacts_foreign_home(self):
        # Paths under a home that is NOT Path.home() are only caught by the generic pass.
        m = load_module()
        c = m.Coordinator(fresh("unit2"))
        for v in ("/home/someone-else/proj/x", "C:\\Users\\SomeoneElse\\proj\\x", "/Users/other/x"):
            out = c.redact(v)
            self.assertTrue(out.startswith("<HOME>"), (v, out))
            self.assertFalse(m.redaction_leaks({"v": out}), (v, out))

    def test_guard_catches_foreign_home_path(self):
        m = load_module()
        self.assertTrue(m.redaction_leaks({"a": [{"b": r"C:\Users\someone\secret"}]}))
        self.assertTrue(m.redaction_leaks({"a": "/home/someone/x"}))
        self.assertFalse(m.redaction_leaks({"a": "<HOME>/x <WORK_ROOT>"}))


class Chain(unittest.TestCase):
    def test_concurrent_runs_all_kept_and_chained(self):
        r = fresh("conc")
        env = lease_env("conc")
        with cf.ThreadPoolExecutor(6) as ex:
            codes = list(ex.map(lambda _: run(r, env=env).returncode, range(6)))
        self.assertTrue(all(c == 0 for c in codes), codes)
        self.assertEqual(len(receipts(r)), 6)
        v = run(r, "verify")
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertEqual(json.loads(v.stdout)["chain_length"], 6)

    def test_head_hash_matches_bytes_and_lf_only(self):
        r = fresh("bytes")
        run(r)
        head = json.loads((out_dir(r) / "HEAD.json").read_text())
        raw = (out_dir(r) / head["receipt"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), head["sha256"])
        self.assertNotIn(b"\r\n", raw)

    def _three(self, tag):
        r = fresh(tag)
        for _ in range(3):
            run(r)
        return r

    def test_tampered_receipt_detected(self):
        r = self._three("tamper")
        f = receipts(r)[1]
        f.write_bytes(f.read_bytes().replace(b'"PENDING"', b'"PASS"', 1))
        self.assertEqual(run(r, "verify").returncode, 1)

    def test_evidence_rewrite_detected_even_with_matching_file_hash(self):
        r = fresh("evid")
        run(r)
        head_p = out_dir(r) / "HEAD.json"
        head = json.loads(head_p.read_text())
        f = out_dir(r) / head["receipt"]
        doc = json.loads(f.read_text())
        doc["receipts"][0]["evidence"] = "forged"
        data = (json.dumps(doc, indent=2) + "\n").encode()
        f.write_bytes(data)
        head["sha256"] = hashlib.sha256(data).hexdigest()
        head_p.write_text(json.dumps(head))
        v = run(r, "verify")
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("evidence hash mismatch", v.stdout)

    def test_deleted_middle_receipt_detected(self):
        r = self._three("delete")
        os.remove(receipts(r)[1])
        self.assertEqual(run(r, "verify").returncode, 1)

    def test_orphan_receipt_detected(self):
        r = self._three("orphan")
        shutil.copyfile(receipts(r)[0], out_dir(r) / "receipt_19990101T000000000000Z_1_abcdef.json")
        v = run(r, "verify")
        self.assertEqual(v.returncode, 1)
        self.assertIn("orphan", v.stdout)

    def test_verify_empty_dir_fails(self):
        r = fresh("empty")
        self.assertEqual(run(r, "verify").returncode, 1)

    def _write_legacy(self, r):
        """Real 2.0.0 script if given, else a synthetic 2.0.0-shaped receipt (no subprocess)."""
        if LEGACY:
            run(r, script=Path(LEGACY))
            return
        os.makedirs(out_dir(r))
        doc = {"payload_version": "2.0.0", "mode": "READ_ONLY", "terminal_state": "PREPARED",
               "receipts": [{"step": "payload_identity", "status": "PASS"}], "mutations": []}
        with open(out_dir(r) / "receipt_20261020T000000Z.json", "x", encoding="utf-8") as f:
            f.write(json.dumps(doc, indent=2))

    def test_legacy_receipt_is_adopted_and_sealed(self):
        r = fresh("legacy")
        self._write_legacy(r)
        self.assertEqual(len(receipts(r)), 1)
        run(r)
        v = json.loads(run(r, "verify").stdout)
        self.assertTrue(v["verified"], v)
        self.assertEqual(v["adopted_unchained"], 1)
        run(r)  # a second chained run must not re-adopt it
        self.assertEqual(latest(r)["adopted_unchained"], [])
        self.assertEqual(json.loads(run(r, "verify").stdout)["adopted_unchained"], 1)
        legacy = [f for f in receipts(r) if json.loads(f.read_text()).get("payload_version") == "2.0.0"][0]
        legacy.write_text(legacy.read_text().replace("PREPARED", "DEPLOYED"))
        self.assertEqual(run(r, "verify").returncode, 1)

    def test_held_lock_is_not_stolen(self):
        r = fresh("lock")
        os.makedirs(out_dir(r))
        lock = out_dir(r) / ".chain.lock"
        lock.write_text("pid=other")
        p = run(r, env={"SZL_LOCK_WAIT_S": "0.5"})
        self.assertEqual(p.returncode, 6, p.stdout)
        self.assertEqual(receipts(r), [])
        self.assertTrue(lock.exists())


def write_key(d, seed=None):
    seed = seed or os.urandom(32)
    k = Path(d) / f"k_{uuid.uuid4().hex[:6]}.key"
    k.write_text(seed.hex() + "\n")
    return k, seed


def write_pub(d, pub):
    p = Path(d) / f"p_{uuid.uuid4().hex[:6]}.pub"
    p.write_text(pub.hex() + "\n")
    return p


RFC8032 = [  # (seed, public, message, signature), RFC 8032 section 7.1 tests 1 and 2
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


class Signing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_module()

    def test_rfc8032_vectors(self):
        for sk, pk, msg, sig in RFC8032:
            seed, mg = bytes.fromhex(sk), bytes.fromhex(msg)
            self.assertEqual(self.m.ed25519_public(seed).hex(), pk)
            self.assertEqual(self.m.ed25519_sign(seed, mg).hex(), sig)
            self.assertTrue(self.m.ed25519_verify(bytes.fromhex(pk), mg, bytes.fromhex(sig)))
            bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 1
            self.assertFalse(self.m.ed25519_verify(bytes.fromhex(pk), mg, bytes(bad)))

    def test_malleable_signature_rejected(self):
        sk, pk, msg, sig = RFC8032[1]
        raw = bytes.fromhex(sig)
        s = int.from_bytes(raw[32:], "little") + self.m._Q   # same point equation, non-canonical s
        forged = raw[:32] + s.to_bytes(32, "little")
        self.assertFalse(self.m.ed25519_verify(bytes.fromhex(pk), bytes.fromhex(msg), forged))

    @unittest.skipUnless(OPENSSL, "openssl not found (set SZL_OPENSSL)")
    def test_openssl_cross_check(self):
        d = fresh("ossl")
        seed = os.urandom(32)
        msg = self.m.dsse_pae(self.m.PAYLOAD_TYPE, b'{"receipt": "x"}\n')
        (d / "k.der").write_bytes(bytes.fromhex("302e020100300506032b657004220420") + seed)
        (d / "m.bin").write_bytes(msg)
        subprocess.run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey",
                        str(d / "k.der"), "-in", str(d / "m.bin"), "-out", str(d / "s.bin")], check=True)
        subprocess.run([OPENSSL, "pkey", "-inform", "DER", "-in", str(d / "k.der"), "-pubout",
                        "-outform", "DER", "-out", str(d / "p.der")], check=True)
        self.assertEqual((d / "s.bin").read_bytes(), self.m.ed25519_sign(seed, msg))
        self.assertEqual((d / "p.der").read_bytes()[-32:], self.m.ed25519_public(seed))

    def _signed(self, tag, runs=2):
        r = fresh(tag)
        k, seed = write_key(r)
        self._lease = lease_env(tag)   # 2.3.0: a PREPARED run needs a valid lane lease
        for _ in range(runs):
            p = run(r, "--signing-key", str(k), env=self._lease)
            self.assertEqual(p.returncode, 0, p.stdout)
        pub = write_pub(r, self.m.ed25519_public(seed))
        return r, k, seed, pub

    def test_signed_chain_verifies(self):
        r, k, seed, pub = self._signed("sign")
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertEqual(json.loads(v.stdout)["signature"], "VALID")

    def test_wrong_pubkey_fails(self):
        r, k, seed, pub = self._signed("wrongpub", 1)
        other = write_pub(r, self.m.ed25519_public(os.urandom(32)))
        self.assertEqual(run(r, "verify", "--pubkey", str(other)).returncode, 1)

    def _env(self, r):
        return out_dir(r) / "HEAD.dsse.json"

    def test_validly_signed_wrong_type_refused(self):
        r, k, seed, pub = self._signed("ptype", 1)
        env = json.loads(self._env(r).read_text())
        body = (out_dir(r) / "HEAD.json").read_bytes()
        sig = self.m.ed25519_sign(seed, self.m.dsse_pae("application/other", body))
        env["payloadType"] = "application/other"
        env["signatures"][0]["sig"] = base64.b64encode(sig).decode()
        self._env(r).write_text(json.dumps(env))
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 1); self.assertIn("payloadType", v.stdout)

    def test_bit_flipped_signature_refused(self):
        # type, keyid and payload all correct: only the Ed25519 check can catch this
        r, k, seed, pub = self._signed("bitflip", 1)
        env = json.loads(self._env(r).read_text())
        sig = bytearray(base64.b64decode(env["signatures"][0]["sig"])); sig[5] ^= 0x01
        env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
        self._env(r).write_text(json.dumps(env))
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 1); self.assertIn("signature invalid", v.stdout)

    def test_keyid_must_bind_to_pubkey(self):
        r, k, seed, pub = self._signed("keyid", 1)
        env = json.loads(self._env(r).read_text())
        env["signatures"][0]["keyid"] = "0" * 64
        self._env(r).write_text(json.dumps(env))
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 1); self.assertIn("keyid", v.stdout)

    def test_stale_envelope_detected(self):
        r, k, seed, pub = self._signed("stale", 1)
        old = self._env(r).read_bytes()
        run(r, "--signing-key", str(k), env=self._lease)
        self._env(r).write_bytes(old)          # validly signed, but over the previous HEAD
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 1); self.assertIn("stale", v.stdout)

    def test_missing_envelope_fails_when_pubkey_given(self):
        r = fresh("noenv")
        run(r)
        pub = write_pub(r, self.m.ed25519_public(os.urandom(32)))
        self.assertEqual(run(r, "verify", "--pubkey", str(pub)).returncode, 1)

    def test_unsigned_run_on_signed_chain_refused(self):
        r, k, seed, pub = self._signed("downgrade", 1)
        before = receipts(r)
        p = run(r, env=self._lease)   # lease present: only the signing check may refuse
        self.assertEqual(p.returncode, 5, p.stdout)
        self.assertEqual(receipts(r), before)

    def test_blocked_run_keeps_signed_chain_verifiable(self):
        # 2.3.0 interaction: a run refused by the ownership gate (exit 2) still writes a
        # chained receipt; the signed chain must stay verifiable with the same key.
        r, k, seed, pub = self._signed("blocked", 1)
        p = run(r, "--signing-key", str(k))          # no lease -> BLOCKED
        self.assertEqual(p.returncode, 2, p.stdout)
        self.assertEqual(ownership(latest(r))["status"], "BLOCKED")
        v = run(r, "verify", "--pubkey", str(pub))
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertEqual(json.loads(v.stdout)["signature"], "VALID")

    def test_bad_key_refused_before_any_write(self):
        r = fresh("badkey")
        k = r / "bad.key"; k.write_text("not-hex")
        p = run(r, "--signing-key", str(k))
        self.assertEqual(p.returncode, 5, p.stdout)
        self.assertFalse(out_dir(r).exists() and receipts(r))

    def test_keygen_never_overwrites(self):
        r = fresh("keygen")
        p1 = run(r, "keygen", "--out", str(r / "keys"))
        self.assertEqual(p1.returncode, 0, p1.stdout)
        first = (r / "keys" / "szl_coordinator_ed25519.key").read_text()
        p2 = run(r, "keygen", "--out", str(r / "keys"))
        self.assertEqual(p2.returncode, 5)
        self.assertEqual((r / "keys" / "szl_coordinator_ed25519.key").read_text(), first)
        pub = json.loads(p1.stdout)["public_key_hex"]
        seed = bytes.fromhex(first.strip())
        self.assertEqual(self.m.ed25519_public(seed).hex(), pub)


if __name__ == "__main__":
    os.makedirs(SCRATCH, exist_ok=True)
    unittest.main(verbosity=1)
