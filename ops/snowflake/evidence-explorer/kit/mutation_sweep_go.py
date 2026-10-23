#!/usr/bin/env python3
"""Mutation sweep for szl_ee_go.py v0.3.0 DRAFT: one textual mutant per guard.

WRITTEN, NOT YET RUN. Run on the VM only:
  python -I -B mutation_sweep_go.py <dir with szl_ee_go.py, test_szl_ee_go.py, itest_output_no_env.txt> <out.json>

Each mutant replaces one exact snippet (which must occur exactly once in the clean
source, else INVALID), copies the mutated runner plus the unchanged test file and
fixture into a fresh directory under <dir of out.json>/mutants, runs
`python -I -B test_szl_ee_go.py` and records KILLED (suite failed) or SURVIVED.
The clean copy must pass first. Before every run two gates are read: available
physical RAM (GlobalMemoryStatusEx on Windows, /proc/meminfo on Linux) must be
>= 2 GiB and free disk space at the output location must be >= 15 GB (the owner's
floor); otherwise the mutant is recorded BLOCKED and nothing runs.
"""
import ctypes
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

MIN_RAM_GIB, MIN_DISK_GB = 2.0, 15.0

MUTANTS = [
    # --- carried over from v0.1.1 / v0.2 (G01-G17), re-expressed on v0.3 code ---
    ("G01", "child env keeps secrets",
     "    env = {k: v for k, v in base.items() if not _SECRETISH.search(k)}\n", "    env = dict(base)\n"),
    ("G02", "shutdown failure ignored", "            if not shutdown_ok and code in", "            if False and code in"),
    ("G03", "deployed flag never set", "    state[\"deployed\"] = True     # from here on",
     "    state[\"deployed\"] = False     # from here on"),
    ("G04", "approved-account check bypassed", "    if approved not in {str(a).upper(), org_acct}:\n", "    if False:\n"),
    ("G05", "NOT_RUN reported as PASS",
     "{\"PASS\": EXIT_OK, \"NOT_RUN_OR_PARTIAL\": EXIT_PARTIAL}", "{\"PASS\": EXIT_OK, \"NOT_RUN_OR_PARTIAL\": EXIT_OK}"),
    ("G06", "temp credentials not removed",
     "                shutil.rmtree(tmp, ignore_errors=True)\n                gone", "                pass\n                gone"),
    ("G07", "verify failure not gating",
     "    if c != 0:\n        return EXIT_BLOCKED if c == 4 else EXIT_FAIL\n",
     "    if False:\n        return EXIT_BLOCKED if c == 4 else EXIT_FAIL\n"),
    ("G08", "scrub disabled", "        if s and s in text:\n", "        if False:\n"),
    ("G09", "chain link dropped", "\"utc\": now_utc(), \"prev_entry_sha256\": self.prev}",
     "\"utc\": now_utc(), \"prev_entry_sha256\": \"0\" * 64}"),
    ("G10", "dry-run-only ignored", "    if \"--dry-run-only\" in flags:\n        return EXIT_PARTIAL\n",
     "    if False:\n        return EXIT_PARTIAL\n"),
    ("G11", "unknown argv accepted",
     "            raise Refused(\"unknown argument (credentials are never accepted on argv)\")\n", "            pass\n"),
    ("G12", "explicit encrypted-key (header) check removed",
     "    if _ENCRYPTED_HEADER.search(t):\n        raise Refused(\"encrypted private keys are not supported by this runner (regenerate with -nocrypt)\")\n", ""),
    ("G13", "no credential reported OK",
     "detail=\"no Snowflake credential in environment\")\n        return EXIT_BLOCKED",
     "detail=\"no Snowflake credential in environment\")\n        return EXIT_OK"),
    ("G14", "integration FAIL mapped to OK", ".get(res[\"overall\"], EXIT_FAIL)", ".get(res[\"overall\"], EXIT_OK)"),
    ("G15", "shutdown PARTIAL not downgrading", "                if shutdown_ok and partial and code == EXIT_OK:\n",
     "                if False:\n"),
    ("G16", "deploy partial-state failure continues",
     "\"deploy_json_present\": ev is not None})\n        return EXIT_FAIL\n", "\"deploy_json_present\": ev is not None})\n"),
    ("G17", "SNOWFLAKE_HOME not set before import", "            os.environ[\"SNOWFLAKE_HOME\"] = tmp\n", "            pass\n"),
    # --- v0.2 guards (N01-N28), re-expressed ---
    ("N01", "run id random part constant", "\"-\" + _secrets.token_hex(4)", "\"-\" + \"0\" * 8"),
    ("N02", "run id missing from QUERY_TAG", "\"szl_ee_go:%s:%s\" % (run_id, key)", "\"szl_ee_go:%s:%s\" % (\"\", key)"),
    ("N03", "run id missing from receipt entries", "e = {\"i\": n, \"run_id\": self.run_id, ", "e = {\"i\": n, "),
    ("N04", "earlier run directory reused", "os.makedirs(out_dir, exist_ok=False)", "os.makedirs(out_dir, exist_ok=True)"),
    ("N05", "existing pilot objects ignored", "    if inv[\"existing_pilot_objects\"]:\n", "    if False:\n"),
    ("N06", "exact-name filter loosened to prefix", "put(\"database\", r, _name(r) == DATABASE, _name(r))",
     "put(\"database\", r, _name(r).startswith(DATABASE), _name(r))"),
    ("N06b", "exact-name filter made case-sensitive", "    return str(r.get(col, \"\") or \"\").upper()\n",
     "    return str(r.get(col, \"\") or \"\")\n"),
    ("N07", "incomplete inventory tolerated", "    if not inv[\"complete\"]:\n", "    if False:\n"),
    ("N08", "pre-run inventory readback not written", "    rec.write_json(\"inventory_pre.json\", inv)\n", "    pass\n"),
    ("N09", "global deadline not applied to child timeouts", "        return min(cap, r)\n", "        return cap\n"),
    ("N10", "deadline never enforced", "        if r <= 0:\n            raise DeadlineExceeded",
     "        if False:\n            raise DeadlineExceeded"),
    ("N11", "no reserved shutdown budget", "sclk = _Clock(clock, SHUTDOWN_BUDGET_SECONDS)", "sclk = _Clock(clock, 0)"),
    ("N12", "automatic retry after uncertain deploy",
     "    except StepTimeout:\n        state[\"uncertain\"] = True\n        return EXIT_UNCERTAIN\n    except Refused:\n"
     "        return EXIT_FAIL\n    ev = _load_json(deploy_json)\n",
     "    except StepTimeout:\n        c, so, se = run_py(\"sf_deploy_pilot.py\", [\"--execute\", \"--manifest\", manifest, "
     "\"--approval-file\", opts[\"--approval\"], \"--out\", deploy_json], kit, cenv_setup, t, runner=runner)\n"
     "    except Refused:\n        return EXIT_FAIL\n    ev = _load_json(deploy_json)\n"),
    ("N13", "uncertain resume treated as success",
     "        state[\"uncertain\"] = True\n        return EXIT_UNCERTAIN\n\n    ienv", "        pass\n\n    ienv"),
    ("N14", "step stdout logs not written",
     "        _durable_write(os.path.join(self.logs, \"%02d_%s.stdout\" % (n, step)), so)\n", ""),
    ("N15", "cleanup erases the run directory",
     "                shutil.rmtree(tmp, ignore_errors=True)\n                gone",
     "                shutil.rmtree(tmp, ignore_errors=True); shutil.rmtree(out_dir, ignore_errors=True); "
     "os.makedirs(rec.logs, exist_ok=True)\n                gone"),
    ("N16", "UNKNOWN core shutdown check accepted", "all(v == \"PASS\" for v in core.values())",
     "all(v in (\"PASS\", \"UNKNOWN\") for v in core.values())"),
    ("N17", "billable list not written", "    rec.write_json(\"potentially_billable.json\", billable)\n", "    pass\n"),
    ("N18", "runtime warehouse readback ignored", "and wh_state == \"SUSPENDED\" and setup_wh", "and setup_wh"),
    ("N18b", "setup warehouse readback ignored", " and setup_wh in (\"SUSPENDED\", None))", ")"),
    ("N19", "itests PASS from exit code/status line only",
     "    elif code == 0 and all(v == \"PASS\" for v in vals) and word in (None, \"PASS\"):\n",
     "    elif code == 0 and word in (None, \"PASS\"):\n"),
    ("N20", "deploy post_checks ignored", "        if not checks or bad:\n", "        if False:\n"),
    ("N21", "runner exception propagates (no record)",
     "    except (Exception, KeyboardInterrupt) as exc:\n        rec.add(\"runner_exception\"",
     "    except ZeroDivisionError as exc:\n        rec.add(\"runner_exception\""),
    ("N22", "direct SQL not time-bounded", "    return bounded(work, DIRECT_SQL_TIMEOUT if timeout is None else timeout)\n",
     "    return work()\n"),
    ("N23", "deploy intent (STARTED) entry not written", "    rec.begin(\"deploy\", detail=",
     "    (lambda *a, **k: None)(\"deploy\", detail="),
    ("N24", "encrypted check reverted to v0.1.1 substring test", "    if _ENCRYPTED_HEADER.search(t):\n",
     "    if \"ENCRYPTED\" in t:\n"),
    ("N25", "unexpected deploy exit treated as definite",
     "detail=\"unexpected exit code; effect UNKNOWN\")\n        state[\"uncertain\"] = True\n        return EXIT_UNCERTAIN\n",
     "detail=\"unexpected exit code; effect UNKNOWN\")\n        return EXIT_FAIL\n"),
    ("N26", "deploy exit 0 without evidence accepted",
     "        if ev is None:\n            rec.add(\"deploy\", \"UNKNOWN\"", "        if False:\n            rec.add(\"deploy\", \"UNKNOWN\""),
    ("N27", "deploy refusal after changes treated as definite",
     "        if ev is None or ev.get(\"changes_begun\") is True or (\n", "        if ev is None or (\n"),
    ("N28", "monitor requirement dropped", "    if inv[\"monitor_exact_count\"] != 1:\n", "    if False:\n"),
    # --- v0.3: digest pins (P) ---
    ("P01", "KIT_SHA256SUMS digest not compared",
     "    if actual != expected_sha:\n        raise Refused(\"%s sha256 does not match --kit-sums-sha256\"",
     "    if False:\n        raise Refused(\"%s sha256 does not match --kit-sums-sha256\""),
    ("P02", "kit file digest not compared", "        if a != listed[f]:\n", "        if False:\n"),
    ("P03", "unlisted kit script accepted",
     "        if f not in listed:\n            raise Refused(\"kit file not listed in %s: %s\" % (KIT_SUMS_FILE, f))\n",
     "        if f not in listed:\n            continue\n"),
    ("P04", "listed-but-missing kit script accepted",
     "        if _KIT_PY.match(os.path.basename(p)) and \"/\" not in p and p not in present:\n", "        if False:\n"),
    ("P05", "required kit scripts not required", "    for f in KIT_REQUIRED:\n        if f not in present:\n",
     "    for f in KIT_REQUIRED:\n        if False:\n"),
    ("P06", "MANIFEST digest not compared",
     "    if actual != expected_sha:\n        raise Refused(\"MANIFEST.json sha256",
     "    if False:\n        raise Refused(\"MANIFEST.json sha256"),
    ("P07", "unpinned executed bundle file accepted",
     "        if f not in mp:\n            raise Refused(\"bundle file executed by the runner is not pinned in MANIFEST.json: \" + f)\n",
     "        if f not in mp:\n            continue\n"),
    ("P08", "bundle file digest not compared", "        if a != mp[f]:\n", "        if False:\n"),
    ("P09", "no pin re-check before each child", "    changed = recheck_pins(state[\"pins\"], paths)\n    if changed:\n",
     "    changed = []\n    if changed:\n"),
    ("P10", "no pin re-check before deploy starts",
     "    if recheck_pins(state[\"pins\"], _kit_paths(state, \"sf_deploy_pilot.py\")):\n", "    if False:\n"),
    ("P11", "shutdown verifier run without pin re-check",
     "    changed = recheck_pins(state[\"pins\"], _kit_paths(state, \"sf_shutdown_verify.py\"))\n", "    changed = []\n"),
    ("P12", "malformed/escaping sums lines accepted",
     "        if not m or not _safe_rel(m.group(\"p\")):\n", "        if not m:\n"),
    # --- v0.3: live-test prerequisite (Q) ---
    ("Q01", "snowpark probe result ignored", "        if not ok:\n            rec.add(\"prerequisites\", \"BLOCKED\"",
     "        if False:\n            rec.add(\"prerequisites\", \"BLOCKED\""),
    ("Q02", "probe timeout treated as importable", "            ok, why = False, \"probe timed out\"\n",
     "            ok, why = True, \"probe timed out\"\n"),
    ("Q03", "probe skipped", "    if \"--dry-run-only\" not in flags:\n", "    if False:\n"),
    ("Q04", "probe failure classed FAIL instead of BLOCKED",
     "probe_stderr_tail\": why})\n            return EXIT_BLOCKED\n", "probe_stderr_tail\": why})\n            return EXIT_FAIL\n"),
    # --- v0.3: two identities (A) ---
    ("A01", "setup profile names an admin role", "SETUP_PROFILE, acct, du, fs, SETUP_ROLE,",
     "SETUP_PROFILE, acct, du, fs, \"SYSADMIN\","),
    ("A02", "forbidden available roles not checked", "    bad = sorted(avail & set(must_not))\n", "    bad = []\n"),
    ("A03", "runtime operator role not required", "    lacking = sorted(set(must_have) - avail)\n", "    lacking = []\n"),
    ("A04", "primary role not checked", "    if role != expected_role:\n", "    if False:\n"),
    ("A05", "same user on both profiles accepted", "    if len(users) != 2:\n", "    if False:\n"),
    ("A06", "profiles in different accounts accepted", "    if len(locators) != 1:\n", "    if False:\n"),
    ("A07", "suspend issued on the setup profile",
     "direct_sql(connector, prof[\"runtime\"], \"suspend\", run_id, timeout=t_direct())",
     "direct_sql(connector, prof[\"setup\"], \"suspend\", run_id, timeout=t_direct())"),
    ("A08", "warehouse control without secondary operator role",
     "WAREHOUSE_CONTROL = {\"resume\": (\"operator_on\", \"resume\"), \"suspend\": (\"operator_on\", \"suspend\")}",
     "WAREHOUSE_CONTROL = {\"resume\": (\"resume\",), \"suspend\": (\"suspend\",)}"),
    ("A09", "shutdown verifier given the setup profile",
     "opts[\"--kit\"], state[\"cenv_runtime\"],", "opts[\"--kit\"], state[\"cenv_setup\"],"),
    ("A10", "deploy given the runtime profile", "\"--out\", deploy_json], kit, cenv_setup, runner, t, state,",
     "\"--out\", deploy_json], kit, cenv_runtime, runner, t, state,"),
    ("A11", "same deploy/runtime user accepted in mode A", "    if du.upper() == ru.upper():\n", "    if False:\n"),
    ("A12", "same deploy/runtime key accepted in mode A", "    if pd == pr:\n", "    if False:\n"),
    ("A13", "retired v0.2 credential contract not refused", "    if any(env.get(k) for k in LEGACY_VARS):\n",
     "    if False:\n"),
    ("A14", "child env keeps both connection names",
     "    for k in LEGACY_VARS + MODE_B_VARS + (\"SNOWFLAKE_DEFAULT_CONNECTION_NAME\",):\n        env.pop(k, None)\n", ""),
    ("A15", "both credential modes accepted", "    if has_a and has_b:\n", "    if False:\n"),
    # --- v0.3: owner-created warehouse requirements (W) ---
    ("W01", "warehouse owner not checked", "        if _name(wh, \"owner\") != WAREHOUSE_OWNER:\n", "        if False:\n"),
    ("W02", "warehouse auto_resume not checked",
     "        if wh.get(\"auto_resume\") is None or _truthy(wh.get(\"auto_resume\")):\n", "        if False:\n"),
    ("W03", "warehouse problems ignored", "    if inv[\"warehouse_problems\"]:\n", "    if False:\n"),
    ("W04", "warehouse monitor not checked", "        if _name(wh, \"resource_monitor\") != MONITOR:\n", "        if False:\n"),
    ("W05", "pre-run warehouse state not checked", "        if str(wh.get(\"state\", \"\")).upper() != \"SUSPENDED\":\n",
     "        if False:\n"),
]


def avail_gib():
    if os.name == "nt":
        class M(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("ml", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in
                                                                          ("t", "a", "tp", "ap", "tv", "av", "x")]
        m = M()
        m.l = ctypes.sizeof(M)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return m.a / 2 ** 30
    with open("/proc/meminfo") as fh:
        for line in fh:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 2 ** 20
    return 0.0


def gates(path):
    a, d = avail_gib(), shutil.disk_usage(path).free / 1e9
    return (a >= MIN_RAM_GIB and d >= MIN_DISK_GB), {"avail_ram_gib": round(a, 2), "free_disk_gb": round(d, 2)}


def run_suite(d, env):
    r = subprocess.run([sys.executable, "-I", "-B", "test_szl_ee_go.py"], cwd=d, capture_output=True,
                       env=env, timeout=900)
    tail = r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
    return r.returncode, (tail[0] if tail else "")


def main():
    src_dir, out_json = sys.argv[1], sys.argv[2]
    base = os.path.dirname(os.path.abspath(out_json))
    work = os.path.join(base, "mutants")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(src_dir, "szl_ee_go.py"), encoding="utf-8") as fh:
        clean = fh.read()
    with open(os.path.join(src_dir, "test_szl_ee_go.py"), "rb") as fh:
        tests_sha = hashlib.sha256(fh.read()).hexdigest()
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("SNOWFLAKE") or k.startswith("SZL_") or "TOKEN" in k.upper() or "SECRET" in k.upper())}
    results = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
               "python": sys.version.split()[0], "platform": sys.platform,
               "runner_sha256": hashlib.sha256(clean.encode("utf-8")).hexdigest(), "tests_sha256": tests_sha,
               "gates": {"min_ram_gib": MIN_RAM_GIB, "min_free_disk_gb": MIN_DISK_GB}, "mutants": []}

    def stage(name, text):
        d = os.path.join(work, name)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        with open(os.path.join(d, "szl_ee_go.py"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        for f in ("test_szl_ee_go.py", "itest_output_no_env.txt"):
            shutil.copyfile(os.path.join(src_dir, f), os.path.join(d, f))
        return d

    ok, g = gates(base)
    if not ok:
        results["clean"] = dict(status="BLOCKED", **g)
    else:
        rc, tail = run_suite(stage("clean", clean), env)
        results["clean"] = dict(status="PASS" if rc == 0 else "FAIL", exit=rc, tail=tail, **g)
    ids = [m[0] for m in MUTANTS]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate mutant id")
    for mid, desc, old, new in MUTANTS:
        row = {"id": mid, "description": desc, "old": old, "new": new}
        if results["clean"]["status"] != "PASS":
            row["status"] = "NOT_RUN"
        elif clean.count(old) != 1:
            row.update(status="INVALID", occurrences=clean.count(old))
        else:
            ok, g = gates(base)
            if not ok:
                row.update(status="BLOCKED", **g)
            else:
                try:
                    rc, tail = run_suite(stage(mid, clean.replace(old, new)), env)
                    row.update(status="KILLED" if rc != 0 else "SURVIVED", exit=rc, tail=tail)
                except subprocess.TimeoutExpired:
                    row.update(status="KILLED_TIMEOUT")
                shutil.rmtree(os.path.join(work, mid), ignore_errors=True)   # keep disk use flat
        results["mutants"].append(row)
        print(mid, row["status"], row.get("tail", ""), flush=True)
    results["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    st = [m["status"] for m in results["mutants"]]
    results["summary"] = {s: st.count(s) for s in sorted(set(st))}
    with open(out_json, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(results, fh, indent=1)
    print(json.dumps(results["summary"]))


if __name__ == "__main__":
    main()
