"""Mutation harness: each mutant re-introduces one 2.0.0 defect (or breaks one new
guard). The suite must FAIL on every mutant; a surviving mutant means a check that
passes without testing anything.

Run:  python -I -B mutate_szl_coordinator.py [legacy_2_0_0.py]
Exit 0 only if the clean copy passes with NO skipped test (tail exactly "OK") and every
mutant is killed. The JSON records the hashes of the source, suite and legacy file,
the interpreter, and the openssl used, so the result can be audited from the record alone.
Aborts (exit 2) if free disk on the work drive drops below SZL_MIN_FREE_GB (default 5).
"""
import hashlib
import json
import platform
import shutil
import os
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = (HERE / "szl_coordinator.py").read_text(encoding="utf-8")
TESTS = HERE / "test_szl_coordinator.py"

MUTANTS = {
    "M01_subdir_accepted_as_root":
        ("elif os.path.normcase(os.path.realpath(top)) != os.path.normcase(str(self.root)):",
         "elif False:"),
    "M02_repo_root_not_cached":
        ("        if self._repo_ok is not None:\n            return self._repo_ok\n", ""),
    "M03_terminal_state_always_prepared":
        ('        if any(r.status in BLOCKING for r in self.receipts):\n            return "BLOCKED"\n', ""),
    "M04_exit_code_always_zero":
        ("    return EXIT[state]\n\n\nif __name__", "    return 0\n\n\nif __name__"),
    "M05_overwrite_instead_of_exclusive":
        ('stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")\n        name = f"receipt_{stamp}_{os.getpid()}_{secrets.token_hex(3)}.json"',
         'stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%MZ")\n        name = f"receipt_{stamp}.json"'),
    "M06_no_lock":
        ("    with ChainLock(out):\n", "    if True:\n"),
    "M07_no_previous_link":
        ('doc["previous_receipt"] = prev', 'doc["previous_receipt"] = None'),
    "M08_verify_skips_file_hash":
        ('if hashlib.sha256(raw).hexdigest() != link["sha256"]:', "if False:"),
    "M09_verify_skips_evidence_hash":
        ('if sha256_text(r.get("evidence", "")) != r.get("evidence_sha256"):', "if False:"),
    "M10_verify_ignores_orphans":
        ('problems += [f"orphan receipt not on chain {n}" for n in orphans]', "pass"),
    "M11_prepare_mode_runs_probes":
        ("    else:\n        c.immutable_preflight()", "    if True:\n        c.immutable_preflight()"),
    "M12_probe_ignores_returncode":
        ('"PASS" if p.returncode == 0 else "FAIL"', '"PASS"'),
    "M13_no_redaction_of_evidence":
        ("ev = self.redact(evidence)[-EVIDENCE_KEEP:]", "ev = str(evidence)[-EVIDENCE_KEEP:]"),
    "M14_guard_disabled_and_no_generic_pass":
        ('        return HOME_SHAPES.sub("<HOME>", s)', "        return s"),
    "M15_lock_stolen_on_contention":
        ("                if time.monotonic() > deadline:\n                    raise TimeoutError",
         "                if time.monotonic() > deadline:\n                    os.remove(str(self.path)); continue\n                    raise TimeoutError"),
    "M16_adopted_hash_not_checked":
        ('if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != h:', "if not f.exists():"),
    "M17_legacy_readopted_each_run":
        ("if f.name not in on_chain and f.name not in adopted_before)", "if f.name not in on_chain)"),
    "M18_verify_passes_empty_dir":
        ('problems.append("no receipts found")', "pass"),
    "M19_missing_tool_reported_pass":
        ('"PASS" if found else "TOOL_NOT_AVAILABLE"', '"PASS"'),
    "M20_crlf_receipt_bytes":
        ('data = (json.dumps(doc, indent=2, sort_keys=False) + "\\n").encode("utf-8")',
         'data = (json.dumps(doc, indent=2, sort_keys=False) + "\\n").replace("\\n", "\\r\\n").encode("utf-8")'),
    "M22_signature_result_ignored":
        ('    if not ed25519_verify(pub, dsse_pae(PAYLOAD_TYPE, body), sig):\n        return ["Ed25519 signature invalid"]\n', ""),
    "M23_payload_type_unchecked":
        ('        if env.get("payloadType") != PAYLOAD_TYPE:', "        if False:"),
    "M24_keyid_unbound":
        ('        if sigs[0].get("keyid") != keyid_of(pub):', "        if False:"),
    "M25_payload_not_bound_to_head":
        ('        if not headf.exists() or body != headf.read_bytes():', "        if False:"),
    "M26_missing_envelope_accepted":
        ('        return ["signature required but HEAD.dsse.json missing"]', "        return []"),
    "M27_unsigned_downgrade_allowed":
        ('    elif (c.out / "HEAD.dsse.json").exists():', "    elif False:"),
    "M28_malleable_s_accepted":
        ("    if s >= _Q:                      # reject malleable (non-canonical) signatures\n        return False\n", ""),
    "M29_bad_key_ignored":
        ('            seed = load_hex32(args.signing_key, "signing key")\n        except (OSError, ValueError) as e:',
         '            seed = load_hex32(args.signing_key, "signing key")\n        except (OSError, ValueError) as e:\n            seed = None\n        if False:'),
    "M30_keygen_overwrites":
        ('with open(d / "szl_coordinator_ed25519.key", "x"', 'with open(d / "szl_coordinator_ed25519.key", "w"'),
    "M31_wrong_clamp":
        ("    a &= (1 << 254) - 8\n", "    a &= (1 << 254) - 1\n"),
    "M21_guard_returns_nothing":
        ("    walk(doc)\n    return hits", "    walk(doc)\n    return []"),
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest() if p else None


def disk_ok():
    floor = float(os.environ.get("SZL_MIN_FREE_GB", "5"))
    return shutil.disk_usage(str(HERE)).free / 1e9 >= floor


def run_suite(script: Path, legacy):
    env = {k: v for k, v in os.environ.items() if k != "SZL_COORD_LEGACY"}
    env["SZL_COORD_UNDER_TEST"] = str(script)
    if legacy:
        env["SZL_COORD_LEGACY"] = str(legacy)
    p = subprocess.run([sys.executable, "-I", "-B", str(TESTS)], cwd=str(HERE), env=env,
                       capture_output=True, text=True, timeout=900)
    tail = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else ""
    return p.returncode, tail


def main():
    legacy = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
    mdir = HERE / "_mutants" / uuid.uuid4().hex[:8]
    os.makedirs(mdir)
    results = {}
    if not disk_ok():
        print(json.dumps({"state": "DISK_FLOOR", "note": "free disk below floor; nothing run"}))
        return 2
    rc, tail = run_suite(HERE / "szl_coordinator.py", legacy)
    results["CLEAN"] = {"suite_exit": rc, "tail": tail, "ok": rc == 0 and tail == "OK"}
    for name, (old, new) in MUTANTS.items():
        if not disk_ok():
            results[name] = {"ok": False, "error": "aborted: disk floor"}
            continue
        n = SRC.count(old)
        if n != 1:
            results[name] = {"ok": False, "error": f"anchor matched {n} times"}
            continue
        f = mdir / f"{name}.py"
        f.write_text(SRC.replace(old, new), encoding="utf-8", newline="\n")
        rc, tail = run_suite(f, legacy)
        results[name] = {"suite_exit": rc, "tail": tail, "ok": rc != 0}  # killed
    killed = sum(1 for k, v in results.items() if k != "CLEAN" and v["ok"])
    openssl = os.environ.get("SZL_OPENSSL") or shutil.which("openssl")
    summary = {"provenance": {
                   "source_sha256": sha(HERE / "szl_coordinator.py"),
                   "suite_sha256": sha(TESTS), "harness_sha256": sha(__file__),
                   "legacy": ("real 2.0.0 script" if legacy else "built-in synthetic fixture"),
                   "legacy_sha256": sha(legacy), "python": sys.version.split()[0],
                   "platform": platform.platform(),
                   "openssl": bool(openssl)},
               "clean_passes": results["CLEAN"]["ok"], "mutants": len(MUTANTS),
               "killed": killed, "survivors": [k for k, v in results.items()
                                               if k != "CLEAN" and not v["ok"]],
               "results": results}
    print(json.dumps(summary, indent=2))
    return 0 if summary["clean_passes"] and killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
