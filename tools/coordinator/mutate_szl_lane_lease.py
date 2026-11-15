"""Mutation harness for szl_lane_lease.py.

Each mutant disables or weakens exactly ONE guard (single textual replacement that
must match exactly once). The full test suite is run against each mutant via
SZL_LEASE_UNDER_TEST. A mutant is KILLED when the suite exits non-zero.
The unmutated module must pass first (otherwise the harness refuses to score).

Run:  python -I -B mutate_szl_lane_lease.py   (from the folder holding both files)
1.1.0: +12 mutants for F11 (git base read) and F12 (acquire lock); stale_base_unchecked
re-anchored to the 1.1.0 comparison; +1 integration mutant (coord_git_dir_not_passed).
      SZL_COORD_PATCHED=<patched szl_coordinator.py> additionally scores 6 integration
      mutants of the coordinator diff against the CoordinatorIntegration tests.
      The path is resolved against the process cwd before tests run in a temp work dir.
Writes mutation_results.json next to this script; prints a summary table.
"""
import concurrent.futures as cf
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "szl_lane_lease.py"
TESTS = HERE / "test_szl_lane_lease.py"
WORK = HERE / "_mutants"

# (id, guard description, old, new)
MUTANTS = [
    ("skip_expiry", "expired leases treated as active",
     '            and now < l["expires"]]', '            and True]'),
    ("expiry_off_by_one", "lease still active at exactly expires_utc",
     '            and now < l["expires"]]', '            and now <= l["expires"]]'),
    ("skip_overlap", "overlap loop never reports",
     "            if l is selected:\n                continue\n", "            if True:\n                continue\n"),
    ("case_sensitive_paths", "path compare is case-sensitive",
     "def norm(p: str) -> str:\n    return p.lower()", "def norm(p: str) -> str:\n    return p"),
    ("accept_7char_sha", "short sha accepted",
     'SHA1_RE = re.compile(r"[0-9a-f]{40}")', 'SHA1_RE = re.compile(r"[0-9a-f]{7,40}")'),
    ("ignore_release", "release records not applied",
     'l["sha256"] not in releases\n', 'True\n'),
    ("ignore_malformed_lease", "malformed lease skipped silently",
     'bad("MALFORMED_LEASE", name, e.detail)', "pass"),
    ("owner_check_removed", "any owner's lease counts for the claimant",
     'mine = [l for l in active if l["doc"]["owner_session"] == claimant_session]', "mine = list(active)"),
    ("ttl_unchecked", "TTL > 24 h accepted",
     "if exp - acq > MAX_TTL:", "if False:"),
    ("skew_unchecked", "future-dated acquired_utc accepted",
     "if acq > now + MAX_SKEW:", "if False:"),
    ("stale_base_unchecked", "base_sha not compared (1.1.0 anchor: effective base)",
     'if effective is not None and selected["doc"]["base_sha"] != effective:', "if False:"),
    ("ambiguity_allowed", "more than one covering lease accepted",
     "elif len(covering) > 1:", "elif False:"),
    ("unreadable_ignored", "unreadable file skipped silently",
     'bad("UNREADABLE_FILE", name, type(e).__name__)', "pass"),
    ("orphan_release_ignored", "orphan release skipped silently",
     'bad("ORPHAN_RELEASE", name, "no lease with that file name and sha256")', "pass"),
    ("file_lease_as_prefix", "file lease treated as a string prefix",
     "    return a == b\n\n\ndef overlaps", "    return b.startswith(a)\n\n\ndef overlaps"),
    ("repo_filter_removed", "leases on other repos compared",
     'same_repo = [l for l in leases if l["doc"]["repo"].lower() == repo.lower()]', "same_repo = list(leases)"),
    ("dot_segments_allowed", "'.'/'..' segment check removed",
     'if seg in (".", ".."):', "if False:"),
    ("overwrite_allowed", "exclusive create replaced by overwrite",
     'with open(path, "xb") as f:', 'with open(path, "wb") as f:'),
    ("release_owner_unchecked", "release by non-owner accepted",
     'if doc["released_by"] != target["doc"]["owner_session"]:', "if False:"),
    ("duplicate_keys_accepted", "duplicate JSON keys accepted",
     "        if k in d:\n", "        if False:\n"),
    ("unknown_keys_accepted", "extra lease keys accepted",
     "if set(doc) != LEASE_KEYS:", "if not LEASE_KEYS <= set(doc):"),
    ("cr_accepted", "CR bytes accepted",
     r'if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:', r'if raw.startswith(b"\xef\xbb\xbf"):'),
    ("unrecognized_ignored", "stray files ignored",
     'bad("UNRECOGNIZED_ENTRY", name, "not a lease/release file name")', "pass"),
    ("duplicate_release_ignored", "second release accepted",
     'if doc["lease_sha256"] in releases:', "if False:"),
    ("dir_unreadable_ignored", "missing leases dir not reported",
     'bad("LEASES_DIR_UNREADABLE", None, type(e).__name__)', "pass"),
    ("bad_request_ignored", "invalid check() arguments not reported",
     '            reasons.append({"code": "BAD_REQUEST", "file": None, "detail": detail})\n            req_ok = False',
     "            pass"),
    ("pass_needs_lease_removed", "belt-and-braces PASS-requires-lease removed",
     'if verdict == "PASS" and selected is None:', "if False:"),
    ("cli_blocked_exit_0", "CLI check exits 0 on BLOCKED",
     'return 0 if v["verdict"] == "PASS" else 2', "return 0"),
    ("usage_exit_2", "usage errors exit 2 (collides with BLOCKED)",
     "        raise SystemExit(1)", "        raise SystemExit(2)"),
    ("output_redaction_removed", "local-path output backstop removed",
     "if LOCAL_PATH_SHAPES.search(text):", "if False:"),
    ("release_time_order_unchecked", "release dated before acquisition accepted",
     'if rel < target["acquired"]:', "if False:"),
    # ---- 1.1.0: F11 base sha read from git
    ("f11_git_disagreement_ignored", "supplied sha that disagrees with git accepted",
     "if supplied is not None and supplied != git_sha:", "if False:"),
    ("f11_unreadable_ignored", "no supplied sha + unreadable git not reported",
     '                    if supplied is None:\n                        reasons.append({"code": "BASE_UNREADABLE"',
     '                    if False:\n                        reasons.append({"code": "BASE_UNREADABLE"'),
    ("f11_none_base_without_git", "base sha None accepted without git_dir",
     "((supplied is None and git_dir is not None)", "((supplied is None)"),
    ("f11_toplevel_unchecked", "subdirectory of a repo accepted as git_dir",
     "same = rc == 0 and bool(top) and os.path.samefile(top, git_dir)", "same = rc == 0"),
    ("f11_git_output_unvalidated", "non-sha git output accepted",
     "if rc != 0 or not SHA1_RE.fullmatch(sha):", "if rc != 0:"),
    ("f11_git_rc_ignored", "git exit code ignored for rev-parse",
     "if rc != 0 or not SHA1_RE.fullmatch(sha):", "if not SHA1_RE.fullmatch(sha):"),
    ("f11_git_env_inherited", "GIT_* environment can redirect the read",
     'e = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}', "e = dict(os.environ)"),
    # ---- 1.1.0: F12 acquire lock
    ("f12_lock_held_ignored", "acquire proceeds when the lock is held",
     '    if lock is None:\n        return {"result": "BLOCKED", "reason_codes": ["LEASE_LOCK_HELD"],',
     '    if False:\n        return {"result": "BLOCKED", "reason_codes": ["LEASE_LOCK_HELD"],'),
    ("f12_lock_not_exclusive", "lock opened without O_EXCL",
     "os.O_WRONLY | os.O_CREAT | os.O_EXCL |", "os.O_WRONLY | os.O_CREAT |"),
    ("f12_stale_lock_auto_removed", "existing lock deleted and retaken",
     "    except FileExistsError:\n        return None\n",
     "    except FileExistsError:\n        os.remove(path)\n        return _take_lock(leases_dir, owner_session, now)\n"),
    ("f12_foreign_lock_removed", "lock removed without byte comparison",
     "    if cur == data:\n        os.remove(path)", "    if True:\n        os.remove(path)"),
    ("f12_lock_dropped_before_write", "lock released before scan + write",
     "        return _acquire_locked(leases_dir, lane, repo, paths, doc, now)\n    finally:\n        _drop_lock(lock)",
     "        _drop_lock(lock)\n        return _acquire_locked(leases_dir, lane, repo, paths, doc, now)\n    finally:\n        pass"),
]

# Mutants that are expected to survive, with the reason the behaviour is unchanged.
EQUIVALENT = {
    "dot_segments_allowed": ("'.' and '..' both end with '.', so the trailing-dot guard "
                             "(Windows alias rule) rejects them first; the dot-segment "
                             "check is redundant defence-in-depth."),
    "pass_needs_lease_removed": ("Every path to an empty reason list sets `selected` "
                                 "(no covering lease adds NO_COVERING_LEASE, >1 adds "
                                 "AMBIGUOUS_LEASE, BAD_REQUEST skips selection), so the "
                                 "belt-and-braces branch is unreachable by construction."),
    "f11_git_rc_ignored": ("rev-parse --verify --quiet prints nothing on stdout when it fails, "
                           "so the 40-hex check rejects the empty output; the rc test is "
                           "redundant defence-in-depth."),
}


# Integration mutants: applied to the PATCHED coordinator (SZL_COORD_PATCHED), scored by
# the CoordinatorIntegration tests only. Each turns one fail-closed branch into PASS/PENDING.
COORD_MUTANTS = [
    ("coord_unconfigured_pending", "unconfigured lease reverts to PENDING",
     'self.record(step, "BLOCKED", "lane lease", started=started,\n                        evidence="LEASE_NOT_CONFIGURED',
     'self.record(step, "PENDING", "lane lease", started=started,\n                        evidence="LEASE_NOT_CONFIGURED'),
    ("coord_partial_config_pass", "partial configuration recorded as PASS",
     'self.record(step, "BLOCKED", "lane lease", started=started,\n                        evidence="LEASE_CONFIG_INCOMPLETE',
     'self.record(step, "PASS", "lane lease", started=started,\n                        evidence="LEASE_CONFIG_INCOMPLETE'),
    ("coord_module_missing_pass", "missing lease module recorded as PASS",
     'self.record(step, "BLOCKED", target, started=started,\n                        evidence=f"LEASE_MODULE_UNAVAILABLE',
     'self.record(step, "PASS", target, started=started,\n                        evidence=f"LEASE_MODULE_UNAVAILABLE'),
    ("coord_check_error_pass", "lease check exception recorded as PASS",
     'self.record(step, "BLOCKED", target, started=started,\n                        evidence=f"LEASE_CHECK_ERROR',
     'self.record(step, "PASS", target, started=started,\n                        evidence=f"LEASE_CHECK_ERROR'),
    ("coord_verdict_ignored", "lease verdict ignored (always PASS)",
     'self.record(step, "PASS" if ok else "BLOCKED", target,', 'self.record(step, "PASS", target,'),
    ("coord_git_dir_not_passed", "2.2.0: coordinator does not ask the lease module to read git",
     "datetime.now(timezone.utc), git_dir=str(self.root))", "datetime.now(timezone.utc), git_dir=None)"),
]


def run_integration(coord_path, tag):
    d = WORK / f"{tag}_{uuid.uuid4().hex[:6]}"
    os.makedirs(d)
    test_copy = d / "test_szl_lane_lease.py"
    test_copy.write_bytes(TESTS.read_bytes())
    e = child_env(SRC)
    e["SZL_COORD_PATCHED"] = str(Path(coord_path).expanduser().resolve())
    p = subprocess.run([sys.executable, "-I", "-B", str(test_copy), "CoordinatorIntegration"],
                       cwd=str(d), env=e, capture_output=True, text=True, timeout=600)
    failed = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\w+)", p.stderr, re.M)))
    ran = re.search(r"Ran (\d+) tests", p.stderr)
    skipped = re.search(r"skipped=(\d+)", p.stderr)
    return {"rc": p.returncode, "failed_tests": failed, "ran": int(ran.group(1)) if ran else None,
            "skipped": int(skipped.group(1)) if skipped else 0}


def score_coordinator(coord_path):
    src = Path(coord_path).read_text(encoding="utf-8")
    base = run_integration(coord_path, "coord_baseline")
    if base["rc"] != 0 or base["skipped"]:
        return {"error": "integration baseline fails or skipped", "baseline": base}
    out = []
    for mid, desc, old, new in COORD_MUTANTS:
        n = src.count(old)
        if n != 1:
            return {"error": f"anchor for {mid} matches {n} times"}
        mp = WORK / f"coordmut_{mid}_{uuid.uuid4().hex[:6]}" / "szl_coordinator.py"   # re-runnable
        os.makedirs(mp.parent)
        mp.write_text(src.replace(old, new), encoding="utf-8", newline="\n")
        r = run_integration(mp, mid)
        out.append({"id": mid, "guard": desc, "status": "KILLED" if r["rc"] != 0 else "SURVIVED",
                    "killing_tests": r["failed_tests"]})
    return {"baseline": base, "mutants": len(out), "killed": sum(x["status"] == "KILLED" for x in out),
            "results": out}


def child_env(mutant_path):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SZL_LEASE")}
    e.pop("PYTHONSAFEPATH", None)
    e.pop("SZL_COORD_PATCHED", None)        # integration tests are not part of scoring
    e["SZL_LEASE_UNDER_TEST"] = str(mutant_path)
    return e


def run_suite(module_path, tag):
    # short work dir: deep paths exceed Windows MAX_PATH inside git fixtures and produce
    # spurious kills ("Filename too long"); the mutant id is kept in the results instead
    d = WORK / f"s{uuid.uuid4().hex[:8]}"
    os.makedirs(d)
    test_copy = d / "test_szl_lane_lease.py"
    test_copy.write_bytes(TESTS.read_bytes())
    p = subprocess.run([sys.executable, "-I", "-B", str(test_copy)], cwd=str(d),
                       env=child_env(module_path), capture_output=True, text=True, timeout=600)
    failed = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\w+)", p.stderr, re.M)))
    first = re.search(r"^(?:FAIL|ERROR): .*?(?=^={20,}\s*$|^-{20,}\s*\nRan |\Z)", p.stderr, re.M | re.S)
    cov = re.search(r"reason-code coverage: [^\n]*", p.stderr)
    ran = re.search(r"Ran (\d+) tests", p.stderr)
    return {"rc": p.returncode, "failed_tests": failed, "ran": int(ran.group(1)) if ran else None,
            "coverage_line": cov.group(0) if cov else None, "tail": p.stderr.strip().splitlines()[-1:],
            "first_failure": first.group(0)[:3000] if first else None,
            "all_failures": re.findall(r"^(?:FAIL|ERROR): .*?(?=^={20,}\s*$|^-{20,}\s*\nRan |\Z)", p.stderr, re.M | re.S)}


def main():
    os.makedirs(WORK, exist_ok=True)
    src = SRC.read_text(encoding="utf-8")
    ids = [m[0] for m in MUTANTS]
    assert len(ids) == len(set(ids)), "duplicate mutant id"
    base = run_suite(SRC, "baseline")
    if base["rc"] != 0:
        print(json.dumps({"error": "baseline suite fails; refusing to score", "baseline": base}, indent=2))
        return 1
    jobs = {}
    for mid, desc, old, new in MUTANTS:
        n = src.count(old)
        if n != 1:
            print(json.dumps({"error": f"anchor for {mid} matches {n} times"}))
            return 1
        mp = WORK / f"mutant_{mid}.py"
        mp.write_text(src.replace(old, new), encoding="utf-8", newline="\n")
        jobs[mid] = (desc, mp)
    results = []
    with cf.ThreadPoolExecutor(min(8, os.cpu_count() or 2)) as ex:
        futs = {ex.submit(run_suite, mp, mid): (mid, desc, mp) for mid, (desc, mp) in jobs.items()}
        for f in cf.as_completed(futs):
            mid, desc, mp = futs[f]
            r = f.result()
            killed = r["rc"] != 0
            results.append({"id": mid, "guard": desc, "status": "KILLED" if killed else "SURVIVED",
                            "killing_tests": r["failed_tests"], "coverage_line": r["coverage_line"],
                            "first_failure": r["first_failure"], "all_failures": r["all_failures"],
                            "mutant_sha256": hashlib.sha256(mp.read_bytes()).hexdigest(),
                            "equivalent_justification": EQUIVALENT.get(mid) if not killed else None})
    results.sort(key=lambda x: ids.index(x["id"]))
    killed = sum(r["status"] == "KILLED" for r in results)
    survivors = [r["id"] for r in results if r["status"] == "SURVIVED"]
    unjustified = [s for s in survivors if s not in EQUIVALENT]
    summary = {"module_sha256": hashlib.sha256(SRC.read_bytes()).hexdigest(),
               "tests_sha256": hashlib.sha256(TESTS.read_bytes()).hexdigest(),
               "baseline": base, "mutants": len(results), "killed": killed,
               "survived": len(survivors), "survivors": survivors,
               "unjustified_survivors": unjustified, "results": results}
    coord = os.environ.get("SZL_COORD_PATCHED")
    if coord:
        resolved = Path(coord).expanduser().resolve()
        if not resolved.is_file():
            summary["coordinator_integration"] = {
                "error": f"SZL_COORD_PATCHED is not a file: {coord}",
                "resolved": str(resolved),
            }
        else:
            # Integration tests run with cwd in WORK, so a repo-relative path
            # such as tools/coordinator/szl_coordinator.py would 404 there.
            summary["coordinator_integration"] = score_coordinator(str(resolved))
    else:
        summary["coordinator_integration"] = "not run (SZL_COORD_PATCHED unset)"
    (HERE / "mutation_results.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"baseline rc={base['rc']} ran={base['ran']} {base['coverage_line']}")
    for r in results:
        k = ",".join(r["killing_tests"][:3]) + ("..." if len(r["killing_tests"]) > 3 else "")
        print(f"{r['status']:8s} {r['id']:30s} {k}")
    print(f"killed {killed}/{len(results)}; survivors={survivors}; unjustified={unjustified}")
    ci = summary["coordinator_integration"]
    coord_ok = True
    if isinstance(ci, dict) and "results" in ci:
        for r in ci["results"]:
            print(f"{r['status']:8s} {r['id']:30s} {','.join(r['killing_tests'])}")
        print(f"coordinator integration: killed {ci['killed']}/{ci['mutants']} "
              f"(baseline ran={ci['baseline']['ran']})")
        coord_ok = ci["killed"] == ci["mutants"]
    else:
        print(f"coordinator integration: {ci}")
        coord_ok = not isinstance(ci, dict)
    return 0 if not unjustified and coord_ok else 1


if __name__ == "__main__":
    sys.exit(main())
