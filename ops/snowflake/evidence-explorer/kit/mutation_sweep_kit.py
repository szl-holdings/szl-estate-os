#!/usr/bin/env python3
"""Mutation sweep for the operator kit (stdlib). Each mutant is ONE exact text
edit (must match exactly once) applied to a temp copy; the suite is then run
with `python -I -B test_operator_kit.py`. Killed = suite fails. The clean copy
must pass first. Writes mutation_results_kit.json next to this file only if it
does not already exist, and prints a table. v0.1.2: M25/M26 retired, M37-M61 added. v0.3.0: M49/M55 retired, M17 retargeted, M62-M92 added; written, NOT run.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mutation_support
FILES = ("sf_kit_common.py", "sf_verify_account_readonly.py", "sf_deploy_pilot.py",
         "sf_shutdown_verify.py", "test_operator_kit.py", "SNOWSIGHT_SETUP.sql",
         "szl_ee_go.py")  # test_operator_kit imports the runner's offline boundary
C, V, D, S = FILES[:4]
MUTANTS = [
    ("M01", C, 'if n not in allowed:', 'if False:', "allowlist membership check disabled"),
    ("M02", C, '        if ";" in n:\n            raise RefusedStatement("multiple statements")\n        if n not in allowed:',
     '        if n not in allowed:', "allowlist multi-statement check removed"),
    ("M03", C, '    out = {"error_class": type(exc).__name__}', '    out = {"error_class": type(exc).__name__, "message": str(exc)}',
     "driver error message leaked into evidence"),
    ("M04", C, '    if state == "STARTED":', '    if True:', "warehouse gate allows a SUSPENDED current warehouse"),
    ("M05", C, '    if not current:\n        return {"allowed": True', '    if not current:\n        return {"allowed": False',
     "gate closed when no current warehouse (over-restrictive)"),
    ("M06", C, 'text = json.dumps(scrub(evidence, secret_values(env)), indent=1, sort_keys=True)',
     'text = json.dumps(evidence, indent=1, sort_keys=True)', "secret scrub removed from emit"),
    ("M07", C, '        kwargs["connection_name"] = name\n', '        kwargs["connection_name"] = name\n    kwargs["password"] = env.get("SNOWFLAKE_PASSWORD")\n',
     "connect() receives a password from env"),
    ("M08", V, '            if cid in GATED and not gate["allowed"]:', '            if False:', "verifier gate bypassed"),
    ("M09", V, '"account": K.redact_identifier(acct),', '"account": acct,', "account identifier not redacted"),
    ("M10", V, '"resource_monitor", "owner", "resumed_on", "updated_on")',
     '"resource_monitor", "owner", "resumed_on", "updated_on", "comment")', "free-text warehouse comment kept in evidence"),
    ("M11", V, '        if len(argv) == 2 and argv[0] == "--out":', '        if True:', "verifier accepts arbitrary argv"),
    ("M12", D, '    if n > CAP_CREDITS:', '    if n > CAP_CREDITS + 1:', "credit cap off by one"),
    ("M13", D, '    m = _APPROVAL_RE.fullmatch(text)', '    m = _APPROVAL_RE.match(text)', "approval accepts trailing text"),
    ("M14", D, '    if until <= today:', '    if until < today:', "approval valid on its own end date"),
    ("M15", D, '        if actual != digest:', '        if False:', "manifest digest check disabled"),
    ("M16", D, '        if approval["account"] not in cands:', '        if False:', "account match disabled"),
    ("M17", D, "        if _exact(K.rows_as_dicts(cur), {DB}):", "        if False:",
     "existing database check disabled (v0.3.0 retarget: warehouse must now exist)"),
    ("M18", D, '    if not opts["execute"]:\n        out.write("# DRY RUN', '    if False:\n        out.write("# DRY RUN',
     "dry-run path removed (falls through toward execution)"),
    ("M19", D, '    r"\\bDROP\\b", ', '    ', "DROP deny token removed"),
    ("M20", D, 'r"\\bACCOUNTADMIN\\b",', '', "ACCOUNTADMIN deny token removed"),
    ("M21", D, '        if len(mons) != 1:', '        if False:', "monitor-exists-before-warehouse check disabled"),
    ("M22", D, '        if quota != float(approval["credits"]) or quota > CAP_CREDITS:', '        if False:',
     "monitor quota check disabled"),
    ("M23", D, '        if os.path.isabs(rel) or ".." in rel.replace("\\\\", "/").split("/"):', '        if False:',
     "manifest path-escape check disabled"),
    ("M24", D, 'AUTO_SUSPEND = 60 AUTO_RESUME = FALSE INITIALLY_SUSPENDED = TRUE',
     'AUTO_SUSPEND = 60 AUTO_RESUME = TRUE INITIALLY_SUSPENDED = TRUE', "owner-block warehouse statement with AUTO_RESUME TRUE (v0.3.0: owner sheet test kills)"),
    # M25/M26 RETIRED in v0.1.2: the INSERT-only and grantee-suffix rules were removed; both are
    # subsumed by GRANT_MATRIX / ROLE_GRANTS (mutants M42-M46 below).
    ("M27", D, '        if rx.search(bare):', '        if rx.search(n):', "deny tokens checked inside literals (false refusals)"),
    ("M28", D, '            if K.sha256_file(fp) != files["_digests"][kind]:', '            if False:',
     "pre-execution digest re-check removed (TOCTOU)"),
    ("M29", S, '                add("W1", "PASS" if st == "SUSPENDED" else "FAIL", "state=%s" % st, qid)',
     '                add("W1", "PASS", "state=%s" % st, qid)', "shutdown W1 always PASS"),
    ("M30", S, '            add("T1", "FAIL" if started else "PASS",', '            add("T1", "PASS",', "shutdown T1 always PASS"),
    ("M31", D, '        if approval_sha and m.group("h") != approval_sha:', '        if False:',
     "approval-reference mismatch in SQL file accepted"),
    ("M32", D, '            if os.path.exists(os.path.join(base, nm + ".py")) and (nm + ".py") not in pinned:', '            if False:',
     "unpinned local app import accepted"),
    ("M33", D, '        if len(parts) == 3 and not (parts[0] == "SZL_EE_DB" and parts[1] in ("EE_DATA", "EE_APP")):',
     '        if False:', "three-part name confinement disabled"),
    ("M34", D, '        mons = _exact(K.rows_as_dicts(cur), {RM})', '        mons = K.rows_as_dicts(cur)',
     "monitor exact-name filter removed (LIKE wildcard)"),
    ("M35", D, '    if GUARD_LINE in rest:', '    if False:', "guard token outside line 1 accepted"),
    ("M36", D, '        if not rx.match(K.normalize_sql(s)):', '        if False:', "per-file statement-type restriction removed"),
    # ---- v0.1.2 privilege-guard mutants (one per new guard) ----
    ('M37', D, '    if "\\\\" in stmt:', '    if False:', 'backslash refusal removed'),
    ('M38', D, '    if "$$" in stmt:', '    if False:', 'dollar-quote refusal removed'),
    ('M39', D, '    if "\'" in outside.replace("\'\'", ""):', '    if False:', 'unbalanced-quote refusal removed'),
    ('M40', D, '    if not _RAW_OK.fullmatch(outside):', '    if False:', 'non-ASCII refusal removed'),
    ('M41', D, '    if "--" in outside or "/*" in outside or "*/" in outside or "//" in outside:', '    if False:', 'in-statement comment refusal removed'),
    ('M42', D, '    if \'"\' in outside or "`" in outside:', '    if False:', 'quoted-identifier refusal removed'),
    ('M43', D, '        if (m.group("granted"), m.group("role")) not in ROLE_GRANTS:', '        if False:', 'role-grant pair check removed (admin escalation)'),
    ('M44', D, '    if cell is None:\n        raise K.RefusedStatement("grant target not in privilege matrix")', '    if cell is None:\n        return', 'privilege-matrix target check removed'),
    ('M45', D, '    if not set(privs) <= cell:', '    if False:', 'privilege subset check removed'),
    ('M46', D, '    if len(set(privs)) != len(privs):', '    if False:', 'duplicate-privilege check removed'),
    ('M47', D, '    g = re.sub(r"\\s*,\\s*", ", ", bare)', '    g = bare', 'comma canonicalisation removed (over-restrictive)'),
    ('M48', D, '        raise K.RefusedStatement("malformed or unsupported GRANT form")', '        return', 'malformed GRANT accepted'),
    # M49 RETIRED in v0.3.0: CREATE ROLE is no longer a kit statement type (roles are owner-created in D0).
    ('M50', D, '        if not re.fullmatch(r"CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 1( COMMENT = \'\')?", bare):', '        if False:', 'CREATE DATABASE shape check removed'),
    ('M51', D, '        if not re.fullmatch(r"CREATE SCHEMA SZL_EE_DB\\.EE_(DATA|APP) WITH MANAGED ACCESS "', '        if False and (r"CREATE SCHEMA "', 'CREATE SCHEMA shape check removed'),
    ('M52', D, '        if not re.match(r"CREATE TABLE SZL_EE_DB\\.EE_DATA\\." + _IDENT + r" ?\\(", bare):', '        if False:', 'CREATE TABLE qualification removed'),
    ('M53', D, '        if _TABLE_DENY.search(bare):', '        if False:', 'table option deny (CLUSTER BY etc.) removed'),
    ('M54', D, '        if any(v != "1" for v in re.findall(', '        if False and any(v != "1" for v in re.findall(', 'table retention check removed'),
    # M55 RETIRED in v0.3.0: CREATE WAREHOUSE is no longer a kit statement type (owner-created in D0).
    ('M56', D, '        if n != K.normalize_sql(STAGE_SQL):', '        if False:', 'CREATE STAGE exact match removed'),
    ('M57', D, '        if n != K.normalize_sql(STREAMLIT_SQL):', '        if False:', 'CREATE STREAMLIT exact match removed'),
    ('M58', D, '        if not _PUT_RX.fullmatch(n):', '        if False:', 'PUT shape check removed'),
    ('M59', D, '    _lexical_check(stmt)\n    n = K.normalize_sql(stmt)', '    n = K.normalize_sql(stmt)', 'whole lexical pre-check removed'),
    ('M60', D, '    if bare.startswith("GRANT "):\n        _grant_check(n, bare)', '    if False:\n        _grant_check(n, bare)', 'whole GRANT matrix check removed'),
    ('M61', D, '        if quota != float(approval["credits"]) or quota > CAP_CREDITS:', '        if quota > CAP_CREDITS:', 'monitor quota may differ from approval (only cap checked)'),
    # ---- v0.3.0 mutants: owner-object preflight, identity, progress file, run id, owner-run grants ----
    ('M62', D, '        if len(whs) != 1:', '        if False:', 'owner warehouse existence check removed'),
    ('M63', D, '        if bad:\n            refuse("SZL_EE_WH differs', '        if False:\n            refuse("SZL_EE_WH differs', 'warehouse property refusal removed'),
    ('M64', D, '    if str(row.get("state", "")).upper() != EXPECTED_WAREHOUSE["state"]:', '    if False:', 'warehouse state check removed'),
    ('M65', D, '    if _norm_size(row.get("size")) != EXPECTED_WAREHOUSE["size"]:', '    if False:', 'warehouse size check removed'),
    ('M66', D, '    if "auto_resume" not in row or K.truthy(row.get("auto_resume")):', '    if K.truthy(row.get("auto_resume")):', 'missing auto_resume column accepted'),
    ('M67', D, '    if "auto_resume" not in row or K.truthy(row.get("auto_resume")):', '    if "auto_resume" not in row:', 'AUTO_RESUME TRUE accepted'),
    ('M68', D, '    if str(row.get("auto_suspend")) != EXPECTED_WAREHOUSE["auto_suspend"]:', '    if False:', 'auto_suspend check removed'),
    ('M69', D, '    if str(row.get("resource_monitor", "")).upper() != EXPECTED_WAREHOUSE["resource_monitor"]:', '    if False:', 'warehouse resource-monitor check removed'),
    ('M70', D, '    if str(row.get("owner", "")).upper() != EXPECTED_WAREHOUSE["owner"]:', '    if False:', 'warehouse owner check removed'),
    ('M71', D, '    if str(row.get("type", "")).upper() != EXPECTED_WAREHOUSE["type"]:', '    if False:', 'warehouse type check removed'),
    ('M72', D, '        if col in row and str(row.get(col)) != "1":', '        if False:', 'cluster-count check removed'),
    ('M73', D, '        if str(params.get(key)) != want:', '        if False:', 'warehouse timeout parameter check removed'),
    ('M74', D, '        if missing:\n            refuse("owner-created roles', '        if False:\n            refuse("owner-created roles', 'owner roles existence check removed'),
    ('M75', D, '        missing = [r for r in ROLES if found.count(r) != 1]', '        missing = [r for r in ROLES if found.count(r) < 1]', 'duplicate role rows accepted'),
    ('M76', D, '        if problems:\n            refuse("connected identity', '        if False:\n            refuse("connected identity', 'identity refusal removed'),
    ('M77', D, '    if adm:', '    if False:', 'admin role reachable by setup identity accepted'),
    ('M78', D, '    if rt:', '    if False:', 'runtime role reachable by setup identity accepted'),
    ('M79', D, '    if SETUP_ROLE not in up:', '    if False:', 'setup role availability not required'),
    ('M80', D, '        return ["CURRENT_AVAILABLE_ROLES unreadable"]', '        return []', 'unreadable CURRENT_AVAILABLE_ROLES accepted (fail-open)'),
    ('M81', D, '                             "statement_sha256": K.sha256_text(s), "started_utc": K.utc_now()}\n            save()', '                             "statement_sha256": K.sha256_text(s), "started_utc": K.utc_now()}', 'pending record not written before a statement'),
    ('M82', C, '            f.flush()\n            os.fsync(f.fileno())\n        os.replace(tmp, self.path)', '            f.flush()\n        os.replace(tmp, self.path)', "progress write not fsync'ed"),
    ('M83', C, '        with open(path, "x", encoding="utf-8", newline="\\n") as f:\n            f.write("{}\\n")', '        with open(path, "w", encoding="utf-8", newline="\\n") as f:\n            f.write("{}\\n")', 'progress file overwrites an existing --out'),
    ('M84', C, '    if not isinstance(v, str) or not _RUN_ID.fullmatch(v):', '    if False:', 'malformed SZL_EE_RUN_ID accepted'),
    ('M85', C, '    return base if rid is None else "%s:%s" % (base, rid)', '    return base', 'run id omitted from QUERY_TAG'),
    ('M86', D, 'ROLE_GRANTS = frozenset()', 'ROLE_GRANTS = frozenset({("SZL_EE_APP", "SYSADMIN")})', 'SYSADMIN hierarchy grant re-admitted'),
    ('M87', D, 'GRANT_MATRIX = {\n', 'GRANT_MATRIX = {\n    ("WAREHOUSE", "SZL_EE_WH"): {"SZL_EE_APP": {"USAGE"}},\n', 'kit may grant warehouse USAGE again'),
    ('M88', D, 'USE ROLE (SZL_EE_SETUP|SZL_EE_OWNER|SZL_EE_APP)$', 'USE ROLE (SZL_EE_SETUP|SZL_EE_OWNER|SZL_EE_APP|SYSADMIN)$', 'kit may USE ROLE SYSADMIN'),
    ('M89', D, '        sess.run("USE ROLE " + SETUP_ROLE)\n        cur, _ = sess.run("SHOW RESOURCE MONITORS', '        cur, _ = sess.run("SHOW RESOURCE MONITORS', 'preflight not run as SZL_EE_SETUP'),
    ('M90', V, '    try:\n        ev["run_id"] = K.run_id(env)\n', '    try:\n        ev["run_id"] = None\n', 'verify: early run-id refusal removed'),
    ('M91', S, '    try:\n        ev["run_id"] = K.run_id(env)\n', '    try:\n        ev["run_id"] = None\n', 'shutdown: early run-id refusal removed'),
    ('M92', D, '"GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR"),', '"GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_INGEST"),', 'OPERATE drifts to the loader role in the owner list'),
]


def run_suite(d):
    env = dict(os.environ)
    env.setdefault("SZL_KIT_TEST_TMP", d)
    return mutation_support.run_suite("test_operator_kit.py", d, env, 120)


def main(out_path=None):
    out = out_path or os.path.join(HERE, "mutation_results_kit.json")
    if os.path.exists(out):
        raise SystemExit("refusing to reuse an existing result; choose a new output path")
    base_tmp = os.environ.get("SZL_KIT_TEST_TMP") or None
    results = []
    with tempfile.TemporaryDirectory(dir=base_tmp) as root:
        clean = os.path.join(root, "clean")
        os.makedirs(clean)
        for f in FILES:
            shutil.copy2(os.path.join(HERE, f), clean)
        baseline = run_suite(clean)
        if not mutation_support.baseline_passed(baseline):
            print("CLEAN SUITE FAILED (%s); sweep aborted" % baseline)
            return 2
        for mid, fname, old, new, desc in MUTANTS:
            with open(os.path.join(HERE, fname), encoding="utf-8") as fh:
                src = fh.read()
            cnt = src.count(old)
            if cnt != 1:
                results.append({"id": mid, "file": fname, "desc": desc, "result": "INVALID(match=%d)" % cnt})
                continue
            d = os.path.join(root, mid)
            os.makedirs(d)
            for f in FILES:
                shutil.copy2(os.path.join(HERE, f), d)
            with open(os.path.join(d, fname), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(src.replace(old, new))
            run = run_suite(d)
            results.append({"id": mid, "file": fname, "desc": desc,
                            "result": mutation_support.classification(run, baseline["tests"]),
                            "rc": run["exit"], "run": run})
    k = sum(r["result"] == "KILLED" for r in results)
    sv = sum(r["result"] == "SURVIVED" for r in results)
    inv = sum(r["result"].startswith("INVALID") for r in results)
    for r in results:
        print("%s %-9s %-30s %s" % (r["id"], r["result"], r["file"], r["desc"]))
    print("TOTAL %d mutants: %d killed, %d survived, %d invalid" % (len(results), k, sv, inv))
    with open(out, "x", encoding="utf-8", newline="\n") as fh:
        json.dump({"mutants": results, "killed": k, "survived": sv, "invalid": inv,
                   "baseline": baseline}, fh, indent=1)
    # An exit-zero process must not hide an incomplete qualification result.
    return 0 if results and k == len(MUTANTS) and not sv and not inv else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
