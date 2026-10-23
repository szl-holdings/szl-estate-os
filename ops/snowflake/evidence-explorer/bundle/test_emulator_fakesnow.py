"""EMULATOR check of schema.sql and evidence_core query builders (fakesnow).

EMULATOR RESULTS ARE NOT SNOWFLAKE RESULTS. fakesnow translates Snowflake SQL
to DuckDB via sqlglot. A PASS here means "accepted and behaved as expected in
fakesnow/DuckDB"; it says nothing about the real account, roles, grants,
CHECK enforcement level, costs or Streamlit in Snowflake. Every I.01-I.11
integration check stays NOT_RUN.

Statuses: PASS / FAIL / UNSUPPORTED_BY_EMULATOR. Role and privilege
statements (USE ROLE, CREATE ROLE, GRANT) are ALWAYS UNSUPPORTED_BY_EMULATOR,
even when fakesnow accepts them as a no-op, because it does not implement
access control.

Run (separate env with fakesnow):  python -I -B test_emulator_fakesnow.py [out.json]
No network, no credentials: SNOWFLAKE_HOME is pointed at an empty temp folder.
Exit 0 iff no FAIL; exit 4 = NOT_RUN (emulator unavailable).
"""
import datetime as _dt
import decimal
import hashlib
import json
import logging
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_core as ec  # noqa: E402
import make_fixture as mf  # noqa: E402

GUARD = "<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>"
AS_OF = "2026-10-21T00:00:00Z"
RESULTS = []
WARNINGS = []
UTC_OFFSET_REASON = (
    "accepted: DuckDB TIMESTAMPTZ does not retain the input offset (MEASURED: "
    "DATE_PART(timezone_hour) returns the session time zone's offset, not the value's), "
    "so the UTC CHECK cannot be exercised in the emulator. Snowflake behaviour UNKNOWN; "
    "evidence_core rejects non-Z timestamps before SQL (unit-tested).")


class _Capture(logging.Handler):
    def emit(self, record):
        WARNINGS.append(record.getMessage())


def rec(rid, category, status, detail, sql=None):
    RESULTS.append({"id": rid, "category": category, "status": status, "detail": detail,
                    "statement_sha256": hashlib.sha256(sql.encode()).hexdigest() if sql else None,
                    "statement_head": (sql or "")[:90]})


def statements(path):
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if not lines or lines[0] != GUARD:
        raise SystemExit("approval guard line missing from %s" % path)
    body = "\n".join(l for l in lines[1:] if not l.strip().startswith("--"))
    return [s.strip() for s in re.split(r";\s*(?:\n|$)", body) if s.strip()]


def norm(v):
    if isinstance(v, _dt.datetime):
        return v.astimezone(_dt.timezone.utc).replace(tzinfo=None).isoformat()
    if isinstance(v, decimal.Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, str) and ec.TS_RE.fullmatch(v):
        return ec.parse_utc(v).replace(tzinfo=None).isoformat()
    return v


def nrows(rows):
    return [{k.lower(): norm(v) for k, v in r.items()} for r in rows]


def main(out_path):
    tmp = tempfile.mkdtemp(prefix="sfhome-")
    os.environ["SNOWFLAKE_HOME"] = tmp
    try:
        import importlib.metadata as md
        import fakesnow
        import snowflake.connector
        from snowflake.connector import DictCursor
        versions = {p: md.version(p) for p in ("fakesnow", "snowflake-connector-python",
                                                "duckdb", "sqlglot")}
    except Exception as exc:
        sys.stdout.write(json.dumps({"not_run_reason": "emulator unavailable: %s: %s"
                                     % (type(exc).__name__, exc)}) + "\n")
        return 4
    fx = mf.build()
    store = ec.LocalStore()
    for b in fx["batches"]:
        ec.ingest_batch(store, b["payload"], fx["as_of_utc"],
                        {k: v.encode("utf-8") for k, v in b["local_content"].items()})
    with fakesnow.patch():
        conn = snowflake.connector.connect(paramstyle="qmark")
        cur = conn.cursor()
        dcur = conn.cursor(DictCursor)

        logging.getLogger().addHandler(_Capture(level=logging.WARNING))

        def run(sql, params=None, cursor=cur):
            cursor.execute(sql, params)
            return cursor.fetchall()

        def run_watch(sql):
            n = len(WARNINGS)
            run(sql)
            return [w for w in WARNINGS[n:] if "nsupported" in w]

        # ---- 1. schema.sql, statement by statement
        for n, sql in enumerate(statements(os.path.join(HERE, "schema.sql"))):
            sid = "DDL%02d" % n
            head = sql.split("(")[0].upper()
            if re.match(r"(USE ROLE|CREATE ROLE|GRANT )", sql.upper()):
                try:
                    run(sql)
                    d = "accepted by fakesnow as a no-op; access control not emulated"
                except Exception as exc:
                    d = "rejected by fakesnow parser (%s); access control not emulated" % \
                        type(exc).__name__
                rec(sid, "ROLE_OR_PRIVILEGE", "UNSUPPORTED_BY_EMULATOR", d, sql)
                continue
            try:
                warned = run_watch(sql)
                props = re.findall(r"(WITH MANAGED ACCESS|DATA_RETENTION_TIME_IN_DAYS|COMMENT =)", sql)
                if warned or props:
                    warned = sorted(set(warned) | set(props))
                    rec(sid, "DDL", "UNSUPPORTED_BY_EMULATOR",
                        "executed, but fakesnow ignored part of it (%s): object properties "
                        "such as DATA_RETENTION_TIME_IN_DAYS / COMMENT are not emulated"
                        % "; ".join(sorted(set(warned)))[:160], sql)
                    rec(sid + "b", "DDL_CORE", "PASS", "statement core accepted "
                        "(columns, types, NOT NULL, DEFAULT, CHECKs where present)", sql)
                else:
                    rec(sid, "DDL", "PASS", "executed", sql)
                continue
            except Exception as exc:
                err = "%s: %s" % (type(exc).__name__, str(exc).splitlines()[0][:160])
            sub = re.sub(r"\s+WITH MANAGED ACCESS", "", sql)
            sub = re.sub(r"\s+DATA_RETENTION_TIME_IN_DAYS = \d+", "", sub)
            sub = re.sub(r"\s+COMMENT = '[^']*'", "", sub).strip()
            if sub != sql:
                try:
                    run(sub)
                    rec(sid, "DDL", "UNSUPPORTED_BY_EMULATOR",
                        "original rejected (%s); emulator substitute without object "
                        "properties (MANAGED ACCESS / retention / comment) executed" % err, sql)
                    if head.startswith("CREATE TABLE"):
                        rec(sid + "b", "DDL_CORE", "PASS",
                            "columns, types, NOT NULL, DEFAULT and CHECKs accepted", sub)
                    continue
                except Exception as exc2:
                    err += " | substitute: %s: %s" % (type(exc2).__name__,
                                                      str(exc2).splitlines()[0][:160])
            rec(sid, "DDL", "FAIL", err, sql)

        for n, sql in enumerate(statements(os.path.join(HERE, "reader_grants.sql"))):
            rec("RG%02d" % n, "ROLE_OR_PRIVILEGE", "UNSUPPORTED_BY_EMULATOR",
                "not executed meaningfully: access control not emulated", sql)

        # ---- 3. fixture ingestion through build_merge with qmark binds
        order = ("EXCLUSIONS", "RIGHTS_RECORDS", "ASSETS", "REVISIONS", "OBSERVATIONS",
                 "INGESTION_BATCHES", "REJECTED_ROWS")

        def load():
            inserted, failed = {}, {}
            for t in order:
                inserted[t] = 0
                for row in store.rows(t):
                    spec = ec.build_merge(t, row)
                    try:
                        res = run(spec.sql, list(spec.params))
                        inserted[t] += int(res[0][0]) if res else 0
                    except Exception as exc:
                        failed.setdefault(t, "%s: %s" % (type(exc).__name__,
                                                         str(exc).splitlines()[0][:160]))
            return inserted, failed

        def counts():
            return {t: int(run("SELECT COUNT(*) FROM %s.%s" % (ec.DEFAULT_DATA_SCHEMA, t))[0][0])
                    for t in order}

        expected = store.counts()
        ins, failed = load()
        for t in order:
            st = "PASS" if (t not in failed and ins[t] == expected[t]) else "FAIL"
            rec("ING_" + t, "INGEST_MERGE", st, "inserted %d of %d rows%s"
                % (ins[t], expected[t], ("; first error " + failed[t]) if t in failed else ""))
        c1 = counts()
        rec("ING_COUNTS", "INGEST_MERGE", "PASS" if c1 == expected else "FAIL",
            "emulator counts %r vs LocalStore %r" % (c1, expected))
        ins2, failed2 = load()
        c2 = counts()
        rec("RERUN", "IDEMPOTENT_RERUN",
            "PASS" if (c2 == c1 and sum(ins2.values()) == 0 and not failed2) else "FAIL",
            "rerun inserted %d rows; counts unchanged=%s" % (sum(ins2.values()), c2 == c1))

        # ---- 4. screen queries vs reference semantics (local_execute)
        specs = [ec.q_asset_inventory(), ec.q_asset_inventory("GITHUB"),
                 ec.q_asset_inventory("RUNTIME"), ec.q_asset_revisions("demo-gh-evidence-kit"),
                 ec.q_evidence_detail("demo-rev-kit-a"),
                 ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b"),
                 ec.q_all_observations(), ec.q_all_observations(limit=5),
                 ec.q_evidence_detail("demo-rev-kit-a", limit=2),
                 ec.q_ingestion_batches(), ec.q_rejected_rows(), ec.q_rejected_rows(limit=3),
                 ec.q_exclusions()]
        live = {}
        for spec in specs:
            key = "%s(%s)[%d]" % (spec.name, ",".join(spec.params), spec.limit)
            try:
                got = nrows(run(spec.sql, list(spec.params), dcur))
            except Exception as exc:
                rec("Q_" + key, "SCREEN_QUERY", "FAIL", "%s: %s" % (
                    type(exc).__name__, str(exc).splitlines()[0][:200]), spec.sql)
                continue
            ref = nrows(ec.local_execute(store, spec))
            live[key] = got
            same_set = sorted(map(repr, got)) == sorted(map(repr, ref))
            same_order = got == ref
            st = "PASS" if (same_set and same_order) else "FAIL"
            d = "rows=%d ref=%d same_rows=%s same_order=%s" % (len(got), len(ref), same_set,
                                                               same_order)
            if not same_set:
                d += "; first diff emu=%r ref=%r" % (
                    [r for r in got if r not in ref][:1], [r for r in ref if r not in got][:1])
            rec("Q_" + key, "SCREEN_QUERY", st, d, spec.sql)

        # ---- 5. presentation over emulator rows: comparison, gaps, display exclusions
        k = "revision_comparison(demo-rev-kit-a,demo-rev-kit-b)[50]"
        if k in live:
            p = ec.present_joined(ec.rows_from_records(_tz(live[k])), AS_OF)
            cmp = {c["observation_type"]: c["change"] for c in ec.compare_revisions(
                [x for x in p if x["revision_id"] == "demo-rev-kit-a"],
                [x for x in p if x["revision_id"] == "demo-rev-kit-b"])}
            want = {"CARD_FIELD": "SAME", "CHECKSUM_RECORD": "ONLY_IN_A",
                    "ILLUSTRATIVE_SCORE": "DIFFERENT", "RUNTIME_PROBE": "NOT_COMPARABLE",
                    "TEST_RUN_SUMMARY": "DIFFERENT"}
            rec("PRES_COMPARISON", "PRESENTATION", "PASS" if cmp == want else "FAIL", repr(cmp))
        k = "all_observations()[200]"
        if k in live and "exclusions()[200]" in live:
            p = ec.present_joined(ec.rows_from_records(_tz(live[k])), AS_OF)
            kept, hidden = ec.apply_display_exclusions(p, live["exclusions()[200]"])
            gaps = sorted((g["observation_id"], g["gap_reasons"]) for g in ec.classify_gaps(p))
            ref = ec.present_joined(ec.rows_from_records(
                ec.local_execute(store, ec.q_all_observations())), AS_OF)
            rgaps = sorted((g["observation_id"], g["gap_reasons"]) for g in ec.classify_gaps(ref))
            rec("PRES_GAPS", "PRESENTATION", "PASS" if (gaps == rgaps and len(gaps) == 10)
                else "FAIL", "emulator gaps=%d reference gaps=%d equal=%s"
                % (len(gaps), len(rgaps), gaps == rgaps))
            rec("PRES_DISPLAY_EXCLUSION", "PRESENTATION", "PASS" if hidden == 1 else "FAIL",
                "hidden=%d" % hidden)
        # ---- 6. CHECK constraint probes in a SEPARATE database (DuckDB semantics,
        #         not Snowflake); never touches the fixture tables above.
        run("CREATE DATABASE PROBE_DB")
        run("CREATE SCHEMA PROBE_DB.EE_DATA")
        for sql in statements(os.path.join(HERE, "schema.sql")):
            if sql.startswith("CREATE TABLE SZL_EE_DB.EE_DATA."):
                run(sql.replace("CREATE TABLE SZL_EE_DB.EE_DATA.", "CREATE TABLE PROBE_DB.EE_DATA."))
        good = store.rows("OBSERVATIONS")[0]
        probes = [
            ("ASSETS", dict(store.rows("ASSETS")[0], asset_id="probe-a1", provider="GITLAB")),
            ("ASSETS", dict(store.rows("ASSETS")[0], asset_id="probe-a2", is_synthetic=False)),
            ("OBSERVATIONS", dict(good, observation_id="probe-o1", value_state="MISSING")),
            ("OBSERVATIONS", dict(good, observation_id="probe-o2",
                                  observed_at_utc="2026-10-01T10:00:00+02:00")),
            ("REVISIONS", dict(store.rows("REVISIONS")[0], revision_id="probe-r1",
                               immutable_source_revision="main")),
            ("RIGHTS_RECORDS", dict(store.rows("RIGHTS_RECORDS")[0], rights_record_id="probe-rr",
                                    training_allowed=True, training_evidence_ref=None)),
            ("REJECTED_ROWS", dict(store.rows("REJECTED_ROWS")[0], rejected_row_id="probe-rej",
                                   reason_code="SECRET_FIELD", row_digest="0" * 64)),
            ("INGESTION_BATCHES", dict(store.rows("INGESTION_BATCHES")[0], batch_id="probe-b",
                                       input_manifest_digest="1" * 64, status="DONE")),
        ]
        for n, (table, row) in enumerate(probes):
            spec = ec.build_merge(table, row, schema="PROBE_DB.EE_DATA")
            try:
                run(spec.sql, list(spec.params))
                if row.get("observation_id") == "probe-o2":
                    rec("CK%02d" % n, "CHECK_PROBE", "UNSUPPORTED_BY_EMULATOR",
                        "OBSERVATIONS +02:00 offset " + UTC_OFFSET_REASON)
                else:
                    rec("CK%02d" % n, "CHECK_PROBE", "FAIL",
                        "%s: violating row was ACCEPTED (CHECK not enforced or wrong)" % table)
            except Exception as exc:
                ok = "constraint" in (type(exc).__name__ + str(exc)).lower()
                rec("CK%02d" % n, "CHECK_PROBE", "PASS" if ok else "FAIL",
                    "%s: violating row refused (%s)" % (table, type(exc).__name__))

        conn.close()
    summary = {s: sum(1 for r in RESULTS if r["status"] == s)
               for s in ("PASS", "FAIL", "UNSUPPORTED_BY_EMULATOR")}
    doc = {"label": "EMULATOR (fakesnow %s) - NOT Snowflake results" % versions["fakesnow"],
           "versions": versions, "summary": summary, "results": RESULTS}
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    for r in RESULTS:
        sys.stdout.write("%-24s %-24s %s | %s\n" % (r["id"][:24], r["status"], r["category"],
                                                    r["detail"][:150]))
    sys.stdout.write(json.dumps(dict(summary, fakesnow_version=versions["fakesnow"])) + "\n")
    return 0 if summary["FAIL"] == 0 else 1


def _tz(rows):
    """Emulator rows were normalised to naive-UTC ISO; restore 'Z' strings."""
    out = []
    for r in rows:
        d = {}
        for kk, v in r.items():
            if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?", v):
                v = v + "Z" if "." in v else v + "Z"
            d[kk] = v
        out.append(d)
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  os.path.join(HERE, "emulator_results.json")))
