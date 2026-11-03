"""Tests for szl_lane_lease.py (stdlib unittest).

Run:  python -I -B test_szl_lane_lease.py
Env:  SZL_LEASE_UNDER_TEST=<path>  test a different copy (used by mutate_szl_lane_lease.py)
      SZL_COORD_PATCHED=<path>     optional patched szl_coordinator.py for integration tests
After the run, the suite fails unless every reason code in REASONS was asserted
at least once (reason-code coverage is checked, not assumed).
Scratch folders are made under ./_scratch_lease with os.makedirs (no tempfile).
1.1.0 adds GitBase (F11: base sha read from git) and AcquireLock (F12: acquire.lock,
including thread and process races that must yield at most one lease / one PASS).
"""
import concurrent.futures as cf
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = Path(os.environ.get("SZL_LEASE_UNDER_TEST", HERE / "szl_lane_lease.py")).resolve()
PATCHED = os.environ.get("SZL_COORD_PATCHED")
SCRATCH = HERE / "_scratch_lease"
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
REPO = "szl-holdings/szl-forge"
COVERED = set()
GIT = shutil.which("git")


def load():
    spec = importlib.util.spec_from_file_location("lease_under_test", MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


m = load()


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh(tag):
    d = SCRATCH / f"{tag}_{uuid.uuid4().hex[:8]}"
    os.makedirs(d)
    return d


def lease_doc(**kw):
    d = {"schema": "szl.lane-lease/v1", "lane": "lane-a", "owner_session": "sess-A",
         "repo": REPO, "base_branch": "main", "base_sha": SHA, "paths": ["src/"],
         "acquired_utc": ts(NOW - timedelta(hours=1)),
         "expires_utc": ts(NOW + timedelta(hours=3)), "purpose": "unit test"}
    d.update(kw)
    return d


def put(d, doc, name=None):
    raw = doc if isinstance(doc, bytes) else (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()
    name = name or f"lease_20261021T110000Z_t_{secrets.token_hex(4)}.json"
    (Path(d) / name).write_bytes(raw)
    return name, hashlib.sha256(raw).hexdigest()


def put_release(d, lease_name, lease_sha, by="sess-A", when=None, **kw):
    doc = {"schema": "szl.lane-lease-release/v1", "lease_file": lease_name,
           "lease_sha256": lease_sha, "released_by": by,
           "released_utc": ts(when or NOW - timedelta(minutes=10)), "reason": "done"}
    doc.update(kw)
    name = f"release_20261021T115000Z_{lease_sha[:12]}_{secrets.token_hex(4)}.json"
    return put(d, doc, name)


def chk(d, paths=("src/a.py",), claimant="sess-A", base=SHA, repo=REPO, now=NOW):
    return m.check(str(d), repo, list(paths), claimant, base, now)


class Base(unittest.TestCase):
    def ok(self, v):
        self.assertEqual(v["verdict"], "PASS", v["reasons"])
        self.assertEqual(v["reason_codes"], [])
        self.assertIsNotNone(v["lease"])

    def blocked(self, v, *codes):
        self.assertEqual(v["verdict"], "BLOCKED", v)
        for c in codes:
            self.assertIn(c, v["reason_codes"], v["reasons"])
            COVERED.add(c)


class Verdicts(Base):
    def test_pass_dir_prefix_and_file(self):
        d = fresh("pass")
        put(d, lease_doc(paths=["src/", "README.md"]))
        self.ok(chk(d, ["src/a.py", "src/deep/", "README.md"]))
        self.ok(chk(d, ["src/"]))

    def test_missing_dir(self):
        self.blocked(chk(SCRATCH / "does_not_exist_xyz"), "LEASES_DIR_UNREADABLE")

    def test_empty_dir_no_lease(self):
        self.blocked(chk(fresh("empty")), "NO_COVERING_LEASE")

    def test_partial_coverage_blocked(self):
        d = fresh("partial")
        put(d, lease_doc(paths=["src/"]))
        self.blocked(chk(d, ["src/a.py", "docs/x.md"]), "NO_COVERING_LEASE")

    def test_expired_blocked_including_boundary(self):
        d = fresh("exp")
        put(d, lease_doc(expires_utc=ts(NOW - timedelta(seconds=1))))
        self.blocked(chk(d), "NO_COVERING_LEASE", "LEASE_EXPIRED")
        d2 = fresh("expb")
        put(d2, lease_doc(expires_utc=ts(NOW)))
        self.blocked(chk(d2), "LEASE_EXPIRED")

    def test_released_blocked(self):
        d = fresh("rel")
        n, s = put(d, lease_doc())
        put_release(d, n, s)
        self.blocked(chk(d), "NO_COVERING_LEASE", "LEASE_RELEASED")

    def test_other_owner_blocked(self):
        d = fresh("owner")
        put(d, lease_doc(owner_session="sess-B"))
        v = chk(d, claimant="sess-A")
        self.blocked(v, "NO_COVERING_LEASE", "OVERLAP")
        self.assertIsNone(v["lease"])

    def test_owner_compare_is_exact(self):
        d = fresh("ownercase")
        put(d, lease_doc(owner_session="SESS-A"))
        self.blocked(chk(d, claimant="sess-A"), "NO_COVERING_LEASE")

    def test_stale_base(self):
        d = fresh("stale")
        put(d, lease_doc())
        self.blocked(chk(d, base=SHA2), "STALE_BASE")

    def test_overlap_other_owner_file_inside_dir(self):
        d = fresh("ovl")
        put(d, lease_doc())
        put(d, lease_doc(owner_session="sess-B", lane="lane-b", paths=["src/a.py"]))
        self.blocked(chk(d), "OVERLAP")

    def test_overlap_reverse_direction(self):
        d = fresh("ovlrev")
        put(d, lease_doc(paths=["src/"]))
        put(d, lease_doc(owner_session="sess-B", paths=["src/deep/x.py"]))
        self.blocked(chk(d, ["src/"]), "OVERLAP")
        d2 = fresh("ovlrev2")
        put(d2, lease_doc(paths=["src/x.py"]))
        put(d2, lease_doc(owner_session="sess-B", paths=["src/"]))
        self.blocked(chk(d2, ["src/x.py"]), "OVERLAP")

    def test_overlap_case_insensitive(self):
        d = fresh("ovlcase")
        put(d, lease_doc(paths=["Src/"]))
        self.ok(chk(d, ["src/A.py"]))
        put(d, lease_doc(owner_session="sess-B", paths=["SRC/a.PY"]))
        self.blocked(chk(d, ["src/A.py"]), "OVERLAP")

    def test_repo_compare_case_insensitive(self):
        d = fresh("repocase")
        put(d, lease_doc(repo="SZL-Holdings/SZL-Forge"))
        self.ok(chk(d))

    def test_no_overlap_across_repos_or_siblings(self):
        d = fresh("disjoint")
        put(d, lease_doc(paths=["src/"]))
        put(d, lease_doc(owner_session="sess-B", repo="szl-holdings/other", paths=["src/"]))
        put(d, lease_doc(owner_session="sess-C", paths=["srcx/", "sr", "src-2/a.py"]))
        self.ok(chk(d, ["src/a.py"]))

    def test_expired_or_released_other_lease_does_not_overlap(self):
        d = fresh("deadovl")
        put(d, lease_doc())
        put(d, lease_doc(owner_session="sess-B", expires_utc=ts(NOW - timedelta(minutes=1))))
        n, s = put(d, lease_doc(owner_session="sess-C", lane="lane-c"))
        put_release(d, n, s, by="sess-C")
        self.ok(chk(d))

    def test_file_lease_is_not_a_prefix(self):
        d = fresh("noprefix")
        put(d, lease_doc(paths=["src/a"]))
        self.blocked(chk(d, ["src/ab.py"]), "NO_COVERING_LEASE")
        self.blocked(chk(d, ["src/a/x.py"]), "NO_COVERING_LEASE")
        self.ok(chk(d, ["src/a"]))
        self.ok(chk(d, ["SRC/A"]))

    def test_ambiguous(self):
        d = fresh("amb")
        put(d, lease_doc(paths=["src/"]))
        put(d, lease_doc(paths=["src/a.py"], lane="lane-z"))
        self.blocked(chk(d), "AMBIGUOUS_LEASE")

    def test_ttl(self):
        d = fresh("ttl")
        a = NOW - timedelta(hours=1)
        put(d, lease_doc(acquired_utc=ts(a), expires_utc=ts(a + timedelta(hours=24, seconds=1))))
        self.blocked(chk(d), "TTL_EXCEEDED")
        d2 = fresh("ttl24")
        put(d2, lease_doc(acquired_utc=ts(a), expires_utc=ts(a + timedelta(hours=24))))
        self.ok(chk(d2))

    def test_future_dated(self):
        d = fresh("future")
        put(d, lease_doc(acquired_utc=ts(NOW + timedelta(minutes=6))))
        self.blocked(chk(d), "FUTURE_DATED")
        d2 = fresh("skew")
        put(d2, lease_doc(acquired_utc=ts(NOW + timedelta(minutes=4))))
        self.ok(chk(d2))

    def test_short_or_upper_sha_lease_is_malformed(self):
        for bad in ("0123456", SHA.upper(), SHA[:39], SHA + "8"):
            d = fresh("sha")
            put(d, lease_doc(base_sha=bad))
            self.blocked(chk(d, base=bad if len(bad) == 40 and bad.islower() else SHA), "MALFORMED_LEASE")

    def test_bad_request(self):
        d = fresh("badreq")
        put(d, lease_doc())
        cases = [dict(base="0123456"), dict(base=SHA.upper()), dict(repo="noslash"),
                 dict(paths=[]), dict(paths=["../x"]), dict(paths=["/abs"]),
                 dict(paths=["a\\b"]), dict(paths=["src/a.py", "SRC/A.PY"]), dict(claimant=""),
                 dict(now=NOW.replace(tzinfo=None)), dict(base=None), dict(base="")]
        for kw in cases:
            with self.subTest(kw=kw):
                self.blocked(chk(d, **kw), "BAD_REQUEST")
        self.blocked(m.check(str(d), REPO, "src/a.py", "sess-A", SHA, NOW), "BAD_REQUEST")


class FailClosed(Base):
    def _malformed(self, raw_or_doc, code="MALFORMED_LEASE", name=None):
        d = fresh("mal")
        put(d, lease_doc())                                  # a valid lease is present
        put(d, raw_or_doc, name)
        self.blocked(chk(d), code)

    def test_malformed_variants_block_everything(self):
        good = lease_doc(repo="szl-holdings/unrelated", owner_session="sess-Z")
        raw_good = (json.dumps(good, indent=2) + "\n").encode()
        variants = {
            "bad_json": b"{not json\n",
            "array": b"[]\n",
            "crlf": raw_good.replace(b"\n", b"\r\n"),
            "bom": b"\xef\xbb\xbf" + raw_good,
            "not_utf8": raw_good.replace(b"unit test", b"unit \xff test"),
            "dup_key": raw_good.replace(b'"lane": "lane-a",', b'"lane": "lane-a", "lane": "x",'),
            "nan": raw_good.replace(b'"purpose": "unit test"', b'"purpose": NaN'),
            "too_big": b'{"x": "' + b"a" * (70 * 1024) + b'"}\n',
        }
        for k, raw in variants.items():
            with self.subTest(k=k):
                self._malformed(raw)
        docs = {
            "unknown_key": dict(good, extra=1),
            "missing_key": {k: v for k, v in good.items() if k != "purpose"},
            "schema": dict(good, schema="szl.lane-lease/v2"),
            "empty_paths": dict(good, paths=[]),
            "paths_not_list": dict(good, paths="src/"),
            "dotdot": dict(good, paths=["src/../x"]),
            "dot": dict(good, paths=["./src/"]),
            "abs": dict(good, paths=["/src/"]),
            "backslash": dict(good, paths=["src\\a"]),
            "double_slash": dict(good, paths=["src//a"]),
            "trailing_dot": dict(good, paths=["src./"]),
            "tilde": dict(good, paths=["PROGRA~1/"]),
            "device": dict(good, paths=["nul.txt"]),
            "dup_path": dict(good, paths=["a/", "A/"]),
            "bad_ts": dict(good, acquired_utc="2026-10-21 11:00:00"),
            "bad_ts2": dict(good, acquired_utc="2026-02-30T00:00:00Z"),
            "exp_before": dict(good, expires_utc=good["acquired_utc"]),
            "bad_repo": dict(good, repo="szl-holdings"),
            "bad_lane": dict(good, lane="Lane A"),
            "bad_branch": dict(good, base_branch="ma..in"),
            "empty_purpose": dict(good, purpose=""),
            "path_purpose": dict(good, purpose="see C:\\Users\\x"),
            "int_owner": dict(good, owner_session=5),
        }
        for k, doc in docs.items():
            with self.subTest(k=k):
                self._malformed(doc)

    def test_unrecognized_entries(self):
        d = fresh("unrec")
        put(d, lease_doc())
        (d / "notes.txt").write_text("x")
        self.blocked(chk(d), "UNRECOGNIZED_ENTRY")
        d2 = fresh("unrecdir")
        put(d2, lease_doc())
        os.makedirs(d2 / "lease_20261021T110000Z_t_0000abcd.json")
        self.blocked(chk(d2), "UNRECOGNIZED_ENTRY")

    def test_unreadable_file(self):
        d = fresh("unread")
        put(d, lease_doc())
        put(d, lease_doc(lane="lane-b", repo="szl-holdings/other"), "lease_20261021T110000Z_t_deadbeef.json")
        real_open = open

        def fake_open(p, *a, **k):
            if str(p).endswith("deadbeef.json"):
                raise PermissionError(13, "denied")
            return real_open(p, *a, **k)
        m.open = fake_open
        try:
            v = chk(d)
        finally:
            del m.open
        self.blocked(v, "UNREADABLE_FILE")

    def test_orphan_release_and_tamper(self):
        d = fresh("orphan")
        n, s = put(d, lease_doc())
        put_release(d, n, "a" * 64)
        self.blocked(chk(d), "ORPHAN_RELEASE")
        d2 = fresh("tamper")
        n, s = put(d2, lease_doc())
        put_release(d2, n, s)
        f = d2 / n
        f.write_bytes(f.read_bytes().replace(b"unit test", b"unit tast"))   # edit after release
        self.blocked(chk(d2), "ORPHAN_RELEASE")
        d3 = fresh("orphname")
        n, s = put(d3, lease_doc())
        put_release(d3, "lease_20261021T110000Z_t_00000000.json", s)
        self.blocked(chk(d3), "ORPHAN_RELEASE")

    def test_release_not_by_owner(self):
        d = fresh("relowner")
        n, s = put(d, lease_doc())
        put_release(d, n, s, by="sess-B")
        self.blocked(chk(d), "RELEASE_NOT_BY_OWNER")
        res = m.release(str(d), n, "sess-B", "x", NOW)
        self.assertEqual(res["result"], "BLOCKED")

    def test_duplicate_release(self):
        d = fresh("duprel")
        n, s = put(d, lease_doc())
        put_release(d, n, s)
        put_release(d, n, s)
        self.blocked(chk(d), "DUPLICATE_RELEASE")

    def test_release_time_checks(self):
        d = fresh("relfuture")
        n, s = put(d, lease_doc())
        put_release(d, n, s, when=NOW + timedelta(minutes=6))
        self.blocked(chk(d), "FUTURE_DATED")
        d2 = fresh("relbefore")
        n, s = put(d2, lease_doc())
        put_release(d2, n, s, when=NOW - timedelta(hours=2))
        self.blocked(chk(d2), "MALFORMED_RELEASE")

    def test_malformed_release(self):
        d = fresh("malrel")
        n, s = put(d, lease_doc())
        put_release(d, n, s[:40])
        self.blocked(chk(d), "MALFORMED_RELEASE")
        d2 = fresh("malrel2")
        n, s = put(d2, lease_doc())
        put_release(d2, n, s, extra="x")
        self.blocked(chk(d2), "MALFORMED_RELEASE")

    def test_duplicate_lease_bytes(self):
        d = fresh("duplease")
        n, s = put(d, lease_doc())
        shutil.copyfile(d / n, d / "lease_20261021T110000Z_t_11112222.json")
        self.blocked(chk(d), "DUPLICATE_LEASE")


class Writers(Base):
    def test_acquire_lf_exclusive_and_check(self):
        d = fresh("acq")
        r = m.acquire(str(d), "lane-a", "sess-A", REPO, "main", SHA, ["src/"],
                      timedelta(hours=2), "work", NOW)
        self.assertEqual(r["result"], "ACQUIRED")
        raw = (d / r["lease_file"]).read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), r["lease_sha256"])
        self.ok(chk(d))

    def test_write_exclusive_never_overwrites(self):
        d = fresh("excl")
        p = d / "x.json"
        p.write_bytes(b"original\n")
        with self.assertRaises(FileExistsError):
            m.write_exclusive(str(p), b"new\n")
        self.assertEqual(p.read_bytes(), b"original\n")

    def test_acquire_refusals(self):
        d = fresh("acqref")
        m.acquire(str(d), "lane-a", "sess-A", REPO, "main", SHA, ["src/"], timedelta(hours=2), "w", NOW)
        r = m.acquire(str(d), "lane-b", "sess-B", REPO, "main", SHA, ["src/x/"], timedelta(hours=2), "w", NOW)
        self.assertEqual(r["result"], "BLOCKED")
        self.assertIn("OVERLAP", r["reason_codes"])
        for kw in (dict(ttl=timedelta(hours=24, seconds=1)), dict(ttl=timedelta(0)),
                   dict(base="abc1234"), dict(paths=[])):
            with self.subTest(kw=kw), self.assertRaises(m.LeaseError):
                m.acquire(str(d), "lane-c", "sess-C", REPO, "main", kw.get("base", SHA),
                          kw.get("paths", ["docs/"]), kw.get("ttl", timedelta(hours=1)), "w", NOW)
        self.assertEqual(len(list(d.iterdir())), 1)

    def test_release_flow_appends_only(self):
        d = fresh("relflow")
        r = m.acquire(str(d), "lane-a", "sess-A", REPO, "main", SHA, ["src/"], timedelta(hours=2), "w", NOW)
        before = sorted(p.name for p in d.iterdir())
        rr = m.release(str(d), r["lease_file"], "sess-A", "done", NOW + timedelta(minutes=1))
        self.assertEqual(rr["result"], "RELEASED")
        after = sorted(p.name for p in d.iterdir())
        self.assertEqual(len(after), 2)
        self.assertTrue(set(before) <= set(after))
        self.blocked(chk(d, now=NOW + timedelta(minutes=2)), "LEASE_RELEASED")
        again = m.release(str(d), r["lease_file"], "sess-A", "done", NOW + timedelta(minutes=3))
        self.assertEqual(again["result"], "BLOCKED")
        with self.assertRaises(m.LeaseError):
            m.release(str(d), "../" + r["lease_file"], "sess-A", "x", NOW)


def mkrepo(tag):
    """Fresh git repo with one commit whose message is unique (distinct shas per repo)."""
    d = fresh(tag)

    def g(*a):
        p = subprocess.run([GIT, *a], cwd=str(d), capture_output=True, text=True)
        if p.returncode:      # fixture failure, not a verdict: say why (e.g. Windows MAX_PATH)
            raise RuntimeError(f"git fixture failed rc={p.returncode} len(path)={len(str(d))}: "
                               + p.stderr.strip()[:300])
        return p.stdout.strip()
    g("init", "-q")
    g("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q",
      "--allow-empty", "-m", f"init {d.name}")
    return d, g("rev-parse", "--abbrev-ref", "HEAD"), g("rev-parse", "HEAD")


@unittest.skipUnless(GIT, "git not on PATH")
class GitBase(Base):
    """F11: the current base sha is read from git, and a supplied sha must agree."""

    def setUp(self):
        self.repo, self.branch, self.head = mkrepo("gr")      # short: Windows MAX_PATH
        self.d = fresh("gl")

    def g(self, base=None, git_dir=None, paths=("src/a.py",)):
        return m.check(str(self.d), REPO, list(paths), "sess-A", base, NOW,
                       git_dir=str(self.repo) if git_dir is None else git_dir)

    def lease(self, **kw):
        put(self.d, lease_doc(**dict({"base_branch": self.branch, "base_sha": self.head}, **kw)))

    def test_git_read_when_not_supplied(self):
        self.lease()
        v = self.g()
        self.ok(v)
        self.assertEqual(v["base_sha_source"], "GIT")
        self.assertEqual(v["current_base_sha"], self.head)

    def test_supplied_and_git_agree(self):
        self.lease()
        v = self.g(base=self.head)
        self.ok(v)
        self.assertEqual(v["base_sha_source"], "GIT_AND_SUPPLIED")

    def test_supplied_disagrees_with_git_is_stale(self):
        self.lease(base_sha=SHA)                     # lease and caller agree; git does not
        v = self.g(base=SHA)
        self.blocked(v, "STALE_BASE")
        self.assertTrue(any("disagrees with git" in r["detail"] for r in v["reasons"]), v)

    def test_git_head_differs_from_lease_is_stale(self):
        self.lease(base_sha=SHA)
        self.blocked(self.g(), "STALE_BASE")

    def test_unreadable_git_without_supplied_sha_blocks(self):
        self.lease()
        self.blocked(self.g(git_dir=str(fresh("notrepo"))), "BASE_UNREADABLE")
        sub = self.repo / "inner"
        os.makedirs(sub)
        self.blocked(self.g(git_dir=str(sub)), "BASE_UNREADABLE")      # not the top level
        self.blocked(self.g(git_dir=str(SCRATCH / "no_such_dir_xyz")), "BASE_UNREADABLE")
        d2 = fresh("gitnobranch")
        put(d2, lease_doc(base_branch="no-such-branch", base_sha=self.head))
        v = m.check(str(d2), REPO, ["src/a.py"], "sess-A", None, NOW, git_dir=str(self.repo))
        self.blocked(v, "BASE_UNREADABLE")
        self.assertIsNone(v["base_sha_source"])

    def test_unreadable_git_with_supplied_sha_is_unverified(self):
        self.lease(base_sha=SHA)
        v = self.g(base=SHA, git_dir=str(fresh("notrepo2")))
        self.ok(v)
        self.assertEqual(v["base_sha_source"], "SUPPLIED_UNVERIFIED")
        v = chk(self.d, base=SHA)                     # no git_dir at all: same trust level
        self.ok(v)
        self.assertEqual(v["base_sha_source"], "SUPPLIED_UNVERIFIED")

    def test_missing_git_binary_blocks(self):
        self.lease()
        real = m._git_exe
        m._git_exe = lambda: None
        try:
            v = self.g()
        finally:
            m._git_exe = real
        self.blocked(v, "BASE_UNREADABLE")

    def test_git_output_must_be_a_full_sha(self):
        self.lease()
        real = m._run_git

        def fake(git_dir, *a):
            if "--show-toplevel" in a:
                return real(git_dir, *a)
            return 0, "deadbeef\n"
        m._run_git = fake
        try:
            v = self.g()
        finally:
            m._run_git = real
        self.blocked(v, "BASE_UNREADABLE")

    def test_git_environment_cannot_redirect_the_read(self):
        other, _, other_head = mkrepo("or")
        self.assertNotEqual(other_head, self.head)
        self.lease()
        os.environ["GIT_DIR"] = str(other / ".git")
        try:
            v = self.g()
        finally:
            del os.environ["GIT_DIR"]
        self.ok(v)
        self.assertEqual(v["current_base_sha"], self.head)


class AcquireLock(Base):
    """F12: acquire.lock serialises acquires; a held/stale lock is never removed."""

    def acq(self, d, owner="sess-A", lane="lane-a", paths=("src/",)):
        return m.acquire(str(d), lane, owner, REPO, "main", SHA, list(paths),
                         timedelta(hours=2), "w", NOW)

    @staticmethod
    def leases_in(d):
        return sorted(p.name for p in Path(d).iterdir() if p.name.startswith("lease_"))

    def test_held_lock_blocks_and_is_never_removed(self):
        d = fresh("lockheld")
        lock = d / m.LOCK_NAME
        lock.write_bytes(b"stale lock from a crashed acquire\n")
        for _ in range(2):
            r = self.acq(d)
            self.assertEqual(r["result"], "BLOCKED")
            self.assertEqual(r["reason_codes"], ["LEASE_LOCK_HELD"])
            COVERED.add("LEASE_LOCK_HELD")
        self.assertEqual(lock.read_bytes(), b"stale lock from a crashed acquire\n")
        self.assertEqual(self.leases_in(d), [])
        put(d, lease_doc())                              # check() is not blocked by the lock
        self.ok(chk(d))
        self.assertTrue(m.list_leases(str(d), NOW)["acquire_lock"]["held"])
        os.remove(lock)                                  # operator action
        r = self.acq(d, owner="sess-B", lane="lane-b", paths=["docs/"])
        self.assertEqual(r["result"], "ACQUIRED", r)
        self.assertFalse(lock.exists())

    def test_lock_dropped_after_acquire_and_after_refusal(self):
        d = fresh("lockdrop")
        self.assertEqual(self.acq(d)["result"], "ACQUIRED")
        self.assertFalse((d / m.LOCK_NAME).exists())
        r = self.acq(d, owner="sess-B", lane="lane-b", paths=["src/x/"])
        self.assertEqual(r["result"], "BLOCKED")
        self.assertIn("OVERLAP", r["reason_codes"])
        self.assertFalse((d / m.LOCK_NAME).exists())
        self.assertFalse(m.list_leases(str(d), NOW)["acquire_lock"]["held"])

    def test_lock_is_held_across_scan_and_write(self):
        d = fresh("lockspan")
        seen = []
        real_scan, real_write = m.scan, m.write_exclusive

        def s(*a, **k):
            seen.append(("scan", (d / m.LOCK_NAME).exists()))
            return real_scan(*a, **k)

        def w(*a, **k):
            seen.append(("write", (d / m.LOCK_NAME).exists()))
            return real_write(*a, **k)
        m.scan, m.write_exclusive = s, w
        try:
            r = self.acq(d)
        finally:
            m.scan, m.write_exclusive = real_scan, real_write
        self.assertEqual(r["result"], "ACQUIRED")
        self.assertEqual(seen, [("scan", True), ("write", True)])
        self.assertFalse((d / m.LOCK_NAME).exists())

    def test_foreign_lock_is_not_removed(self):
        d = fresh("lockforeign")
        real = m.scan

        def swap(*a, **k):                               # lock replaced mid-acquire
            p = d / m.LOCK_NAME
            os.remove(p)
            p.write_bytes(b"replaced by someone else\n")
            return real(*a, **k)
        m.scan = swap
        try:
            r = self.acq(d)
        finally:
            m.scan = real
        self.assertEqual(r["result"], "ACQUIRED")
        self.assertEqual((d / m.LOCK_NAME).read_bytes(), b"replaced by someone else\n")

    def test_concurrent_overlapping_acquires_threads(self):
        d = fresh("lockrace")
        n = 6
        real = m.scan
        barrier = threading.Barrier(n)

        def slow(*a, **k):                               # widen the race window
            time.sleep(0.4)
            return real(*a, **k)

        def go(i):
            barrier.wait()
            return self.acq(d, owner=f"sess-{i}", lane=f"lane-{i}",
                            paths=["src/"] if i % 2 else ["src/a.py"])
        m.scan = slow
        try:
            with cf.ThreadPoolExecutor(n) as ex:
                res = list(ex.map(go, range(n)))
        finally:
            m.scan = real
        got = [r for r in res if r["result"] == "ACQUIRED"]
        self.assertEqual(len(got), 1, res)
        for r in res:
            if r["result"] != "ACQUIRED":
                self.assertTrue(r["reason_codes"] == ["LEASE_LOCK_HELD"] or "OVERLAP" in r["reason_codes"], r)
        self.assertEqual(len(self.leases_in(d)), 1)
        passes = [i for i in range(n)
                  if chk(d, ["src/a.py"], claimant=f"sess-{i}")["verdict"] == "PASS"]
        self.assertEqual(len(passes), 1, passes)

    def test_concurrent_overlapping_acquires_processes(self):
        d = fresh("lockprocs")
        n = 6
        e = dict(os.environ)
        e.pop("PYTHONSAFEPATH", None)
        procs = [subprocess.Popen(
            [sys.executable, "-I", "-B", str(MODULE), "acquire", "--leases-dir", str(d),
             "--lane", f"lane-{i}", "--owner", f"sess-{i}", "--repo", REPO, "--base-branch", "main",
             "--base-sha", SHA, "--path", "src/" if i % 2 else "src/a.py", "--ttl-hours", "2",
             "--purpose", "race"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e)
            for i in range(n)]
        outs = [p.communicate(timeout=120) for p in procs]
        rcs = [p.returncode for p in procs]
        self.assertTrue(all(rc in (0, 2) for rc in rcs), (rcs, outs))
        self.assertLessEqual(rcs.count(0), 1, rcs)
        self.assertEqual(len(self.leases_in(d)), rcs.count(0))
        now = datetime.now(timezone.utc)
        passes = [i for i in range(n) if m.check(str(d), REPO, ["src/a.py"], f"sess-{i}", SHA,
                                                 now)["verdict"] == "PASS"]
        self.assertLessEqual(len(passes), 1, passes)
        self.assertEqual(len(passes), rcs.count(0))


def cli(*args):
    e = dict(os.environ)
    e.pop("PYTHONSAFEPATH", None)
    return subprocess.run([sys.executable, "-I", "-B", str(MODULE), *args], capture_output=True,
                          text=True, timeout=60, env=e)


class CLI(Base):
    SHAPES = re.compile(r"(?i)([a-z]:[\\/]|[\\/]users[\\/]|/home/)")

    def clean(self, p, d):
        low = p.stdout.lower().replace("\\\\", "/")
        self.assertNotIn(str(d).lower().replace("\\", "/"), low)
        self.assertFalse(self.SHAPES.search(p.stdout), p.stdout)

    def test_cli_lifecycle_and_exit_codes(self):
        d = fresh("cli")
        base = ["--leases-dir", str(d)]
        p = cli("check", *base, "--repo", REPO, "--path", "src/a.py", "--claimant", "sess-A", "--base-sha", SHA)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.clean(p, d)
        p = cli("acquire", *base, "--lane", "lane-a", "--owner", "sess-A", "--repo", REPO,
                "--base-branch", "main", "--base-sha", SHA, "--path", "src/", "--ttl-hours", "2",
                "--purpose", "cli test")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.clean(p, d)
        lease_file = json.loads(p.stdout)["lease_file"]
        p = cli("check", *base, "--repo", REPO, "--path", "src/a.py", "--claimant", "sess-A", "--base-sha", SHA)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(json.loads(p.stdout)["verdict"], "PASS")
        self.clean(p, d)
        p = cli("check", *base, "--repo", REPO, "--path", "src/a.py", "--claimant", "sess-A", "--base-sha", SHA2)
        self.assertEqual(p.returncode, 2)
        self.assertIn("STALE_BASE", json.loads(p.stdout)["reason_codes"])
        p = cli("list", *base)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["leases"][0]["status"], "ACTIVE")
        self.clean(p, d)
        p = cli("release", *base, "--lease-file", lease_file, "--by", "sess-A", "--reason", "done")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = cli("check", *base, "--repo", REPO, "--path", "src/a.py", "--claimant", "sess-A", "--base-sha", SHA)
        self.assertEqual(p.returncode, 2)
        self.assertIn("LEASE_RELEASED", json.loads(p.stdout)["reason_codes"])
        (d / "stray.tmp").write_text("x")
        self.assertEqual(cli("list", *base).returncode, 2)

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_cli_check_reads_base_from_git(self):
        repo, branch, head = mkrepo("cligit")
        d = fresh("cligitleases")
        base = ["--leases-dir", str(d)]
        p = cli("acquire", *base, "--lane", "lane-a", "--owner", "sess-A", "--repo", REPO,
                "--base-branch", branch, "--base-sha", head, "--path", "src/", "--ttl-hours", "2",
                "--purpose", "cli git")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        q = ["check", *base, "--repo", REPO, "--path", "src/a.py", "--claimant", "sess-A"]
        p = cli(*q, "--git-dir", str(repo))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(json.loads(p.stdout)["base_sha_source"], "GIT")
        self.clean(p, d)
        p = cli(*q, "--git-dir", str(repo), "--base-sha", SHA2)
        self.assertEqual(p.returncode, 2)
        self.assertIn("STALE_BASE", json.loads(p.stdout)["reason_codes"])
        p = cli(*q, "--git-dir", str(fresh("clinotrepo")))
        self.assertEqual(p.returncode, 2)
        self.assertIn("BASE_UNREADABLE", json.loads(p.stdout)["reason_codes"])

    def test_emit_suppresses_local_path(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            m._emit({"leak": "C:\\Users\\someone\\x"})
        self.assertEqual(cm.exception.code, 2)
        self.assertNotIn("someone", buf.getvalue())
        self.assertIn("OUTPUT_REDACTION", buf.getvalue())

    def test_cli_usage_errors_exit_1(self):
        d = fresh("cliuse")
        self.assertEqual(cli().returncode, 1)
        self.assertEqual(cli("check", "--leases-dir", str(d)).returncode, 1)
        self.assertEqual(cli("bogus").returncode, 1)
        self.assertEqual(cli("check", "--leases-dir", str(d), "--repo", REPO, "--path", "src/a.py",
                             "--claimant", "sess-A").returncode, 1)   # neither base nor git dir
        p = cli("acquire", "--leases-dir", str(d), "--lane", "lane-a", "--owner", "sess-A", "--repo", REPO,
                "--base-branch", "main", "--base-sha", "abc1234", "--path", "src/", "--ttl-hours", "2",
                "--purpose", "x")
        self.assertEqual(p.returncode, 1)
        for ttl in ("25", "nan", "0"):
            p = cli("acquire", "--leases-dir", str(d), "--lane", "lane-a", "--owner", "sess-A", "--repo", REPO,
                    "--base-branch", "main", "--base-sha", SHA, "--path", "src/", "--ttl-hours", ttl,
                    "--purpose", "x")
            self.assertEqual(p.returncode, 1, ttl)
        self.assertEqual(list(d.iterdir()), [])


@unittest.skipUnless(PATCHED, "SZL_COORD_PATCHED not set")
class CoordinatorIntegration(unittest.TestCase):
    """Coordinator 2.2.0 + this lease module, run as a subprocess in a fresh root."""

    def setUp(self):
        self.work = fresh("coord")
        shutil.copyfile(PATCHED, self.work / "szl_coordinator.py")
        shutil.copyfile(MODULE, self.work / "szl_lane_lease.py")
        self.root = fresh("coordroot")
        self.leases = fresh("coordleases")

    def run_coord(self, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("SZL_LEASE")}
        e.pop("PYTHONSAFEPATH", None)
        e["SZL_WORK_ROOT"] = str(self.root)
        e.update(env)
        p = subprocess.run([sys.executable, "-I", "-B", str(self.work / "szl_coordinator.py")],
                           cwd=str(self.root), env=e, capture_output=True, text=True, timeout=120)
        out = self.root / "szl_execution_receipts"
        head = json.loads((out / "HEAD.json").read_text())
        doc = json.loads((out / head["receipt"]).read_text())
        step = [r for r in doc["receipts"] if r["step"] == "ownership_reconciliation"]
        self.assertEqual(len(step), 1)
        return p, doc, step[0]

    def cfg(self, **over):
        c = {"SZL_LEASES_DIR": str(self.leases), "SZL_LEASE_REPO": REPO,
             "SZL_LEASE_PATHS": "src/a.py,docs/", "SZL_LEASE_CLAIMANT": "sess-A",
             "SZL_LEASE_BASE_SHA": SHA}
        c.update(over)
        return {k: v for k, v in c.items() if v is not None}

    def test_unconfigured_is_blocked_not_pending_not_pass(self):
        p, doc, s = self.run_coord()
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("LEASE_NOT_CONFIGURED", s["evidence"])
        self.assertEqual(p.returncode, 2)

    def test_partial_config_blocked(self):
        # 2.2.0: SZL_LEASE_BASE_SHA is optional (read from git), so "partial" means a
        # REQUIRED key is missing. Each required key is tried on its own.
        for k in ("SZL_LEASES_DIR", "SZL_LEASE_REPO", "SZL_LEASE_PATHS", "SZL_LEASE_CLAIMANT"):
            with self.subTest(missing=k):
                p, doc, s = self.run_coord(**self.cfg(**{k: None}))
                self.assertEqual(s["status"], "BLOCKED")
                self.assertIn("LEASE_CONFIG_INCOMPLETE", s["evidence"])
                self.assertIn(k, s["evidence"])
                self.assertEqual(p.returncode, 2)
        p, doc, s = self.run_coord(SZL_LEASE_BASE_SHA=SHA)        # only the optional key
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("LEASE_CONFIG_INCOMPLETE", s["evidence"])

    def test_no_base_sha_and_no_git_is_blocked(self):
        m.acquire(str(self.leases), "lane-a", "sess-A", REPO, "main", SHA, ["src/", "docs/"],
                  timedelta(hours=1), "integration", datetime.now(timezone.utc))
        p, doc, s = self.run_coord(**self.cfg(SZL_LEASE_BASE_SHA=None))   # root is not a repo
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("BASE_UNREADABLE", s["evidence"])
        self.assertEqual(p.returncode, 2)

    def _repo_root(self):
        g = lambda *a: subprocess.run([GIT, *a], cwd=str(self.root), capture_output=True,
                                      text=True, check=True).stdout.strip()
        g("init", "-q")
        g("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q",
          "--allow-empty", "-m", "integration")
        return g("rev-parse", "--abbrev-ref", "HEAD"), g("rev-parse", "HEAD")

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_base_read_from_git_passes(self):
        branch, head = self._repo_root()
        m.acquire(str(self.leases), "lane-a", "sess-A", REPO, branch, head, ["src/", "docs/"],
                  timedelta(hours=1), "integration", datetime.now(timezone.utc))
        p, doc, s = self.run_coord(**self.cfg(SZL_LEASE_BASE_SHA=None))
        self.assertEqual(s["status"], "PASS", s["evidence"])
        self.assertEqual(json.loads(s["evidence"])["base_sha_source"], "GIT")
        self.assertEqual(p.returncode, 0, p.stdout)

    @unittest.skipUnless(GIT, "git not on PATH")
    def test_supplied_base_disagreeing_with_git_blocked(self):
        branch, head = self._repo_root()
        m.acquire(str(self.leases), "lane-a", "sess-A", REPO, branch, SHA, ["src/", "docs/"],
                  timedelta(hours=1), "integration", datetime.now(timezone.utc))
        p, doc, s = self.run_coord(**self.cfg())                  # supplies SHA; git says head
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("STALE_BASE", s["evidence"])
        self.assertEqual(p.returncode, 2)

    def test_valid_lease_passes(self):
        m.acquire(str(self.leases), "lane-a", "sess-A", REPO, "main", SHA, ["src/", "docs/"],
                  timedelta(hours=1), "integration", datetime.now(timezone.utc))
        p, doc, s = self.run_coord(**self.cfg())
        self.assertEqual(s["status"], "PASS", s["evidence"])
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertNotIn("ownership_reconciliation", doc["open_steps"])

    def test_stale_base_blocked(self):
        m.acquire(str(self.leases), "lane-a", "sess-A", REPO, "main", SHA, ["src/", "docs/"],
                  timedelta(hours=1), "integration", datetime.now(timezone.utc))
        p, doc, s = self.run_coord(**self.cfg(SZL_LEASE_BASE_SHA=SHA2))
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("STALE_BASE", s["evidence"])
        self.assertIn("ownership_reconciliation", doc["blocking_steps"])

    def test_check_error_blocked(self):
        (self.work / "szl_lane_lease.py").write_text(
            "def check(*a, **k):\n    raise RuntimeError('boom')\n", encoding="utf-8")
        p, doc, s = self.run_coord(**self.cfg())
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("LEASE_CHECK_ERROR", s["evidence"])

    def test_missing_module_blocked(self):
        os.remove(self.work / "szl_lane_lease.py")
        p, doc, s = self.run_coord(**self.cfg())
        self.assertEqual(s["status"], "BLOCKED")
        self.assertIn("LEASE_MODULE_UNAVAILABLE", s["evidence"])


if __name__ == "__main__":
    os.makedirs(SCRATCH, exist_ok=True)
    prog = unittest.main(verbosity=1, exit=False)
    full_run = len(sys.argv) == 1          # coverage is only meaningful for the whole suite
    missing = sorted(set(m.REASONS) - COVERED) if full_run else []
    print(f"reason-code coverage: {len(COVERED & set(m.REASONS))}/{len(m.REASONS)}"
          + (f" missing={missing}" if missing else ""), file=sys.stderr)
    ok = prog.result.wasSuccessful() and not missing
    sys.exit(0 if ok else 1)
