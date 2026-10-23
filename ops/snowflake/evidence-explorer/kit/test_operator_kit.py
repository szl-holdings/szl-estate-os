"""Tests for the SZL Evidence Explorer operator kit (stdlib unittest; synthetic only).

Run: python -I -B test_operator_kit.py
No network, no Snowflake connector, no credentials: a fake connector object
stands in for snowflake.connector. All data is synthetic.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sf_kit_common as K  # noqa: E402
import sf_verify_account_readonly as V  # noqa: E402
import sf_deploy_pilot as D  # noqa: E402
import sf_shutdown_verify as S  # noqa: E402

SENTINEL = "s3cr3t-SENTINEL-9f2c"
FAKE_ACCOUNT = "ZZ99999"          # synthetic locator, not the owner's
FAKE_ORG, FAKE_NAME = "SYNORG", "SYNACCT"
TODAY = dt.date(2026, 10, 21)

WH_COLS = ["name", "state", "type", "size", "auto_suspend", "auto_resume", "is_current", "is_default",
           "resource_monitor", "owner", "comment"]


def wh(name, state="SUSPENDED", auto_resume="true", current="N", rm="null", auto_suspend=600):
    return [name, state, "STANDARD", "X-Small", auto_suspend, auto_resume, current, "N", rm, "SYSADMIN",
            "comment " + SENTINEL]


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = []
        self.sfqid = None

    def execute(self, stmt):
        self.conn.executed.append(stmt)
        self.conn.n += 1
        self.sfqid = "01fake-%04d" % self.conn.n
        res = self.conn.responder(K.normalize_sql(stmt), self.conn)
        if isinstance(res, Exception):
            raise res
        cols, rows = res
        self.description = [(c,) for c in cols]
        self._rows = [tuple(r) for r in rows]
        return self

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    def __init__(self, responder):
        self.responder = responder
        self.executed = []
        self.n = 0
        self.closed = False
        self.state = {}

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


class FakeConnector:
    def __init__(self, responder=None, connect_error=None):
        self.responder = responder
        self.connect_error = connect_error
        self.calls = []
        self.conn = None

    def connect(self, **kw):
        self.calls.append(kw)
        if self.connect_error is not None:
            raise self.connect_error
        self.conn = FakeConn(self.responder)
        return self.conn


class DriverError(Exception):
    def __init__(self, msg, errno=390100, sqlstate="08004"):
        super().__init__(msg)
        self.errno, self.sqlstate = errno, sqlstate


# v0.3.0: the owner-created pilot warehouse as SHOW WAREHOUSES LIKE 'SZL_EE_WH' returns it, and the
# setup identity's CURRENT_AVAILABLE_ROLES() (synthetic).
PILOT_WH = {"name": "SZL_EE_WH", "state": "SUSPENDED", "type": "STANDARD", "size": "X-Small", "auto_suspend": 60,
            "auto_resume": "false", "is_current": "N", "is_default": "N", "resource_monitor": "SZL_EE_RM",
            "owner": "ACCOUNTADMIN", "comment": "SZL synthetic pilot 1"}
SETUP_AVAIL = json.dumps(["SZL_EE_SETUP", "SZL_EE_OWNER", "SZL_EE_APP", "PUBLIC"])


def base_responder(warehouses=None, account=FAKE_ACCOUNT, existing=(), monitor=(10, "NEVER"),
                   tasks=(), fail_on=None, metering_rows=2, pilot_wh=None, wh_params=None, roles=None,
                   avail=SETUP_AVAIL):
    warehouses = warehouses if warehouses is not None else [wh("COMPUTE_WH")]

    def r(n, conn):
        st = conn.state
        if fail_on and n.startswith(fail_on):
            return DriverError("statement failed near " + SENTINEL)
        if n == "SHOW WAREHOUSES":
            rows = list(warehouses)
            if st.get("wh_created"):
                rows.append(wh("SZL_EE_WH", "SUSPENDED", "false", "N", "SZL_EE_RM", 60))
            return WH_COLS, rows
        if n == "SHOW DATABASES":
            return ["name", "created_on", "owner", "retention_time", "kind", "comment"], [
                ["SNOWFLAKE", "2026-01-01", "", "1", "APPLICATION", SENTINEL]]
        if n == "SHOW RESOURCE MONITORS":
            return ["name", "credit_quota", "used_credits", "frequency", "notify_users"], [
                ["SZL_EE_RM", "10.00", "0.00", "NEVER", SENTINEL]]
        if n.startswith("SELECT CURRENT_ACCOUNT(), CURRENT_ACCOUNT_NAME()"):
            return ["a", "b", "c", "d", "e", "f", "g"], [[account, FAKE_NAME, FAKE_ORG, "AWS_CA_CENTRAL_1",
                                                           "SYSADMIN", "9.99.0", None]]
        if n == K.normalize_sql(D.CONTEXT_SQL):
            return ["a", "b", "c", "d"], [[account, FAKE_ORG, FAKE_NAME, avail]]
        if n == K.normalize_sql(D.SHOW_PARAMS_SQL):
            prm = dict(D.EXPECTED_WH_PARAMS, **(wh_params or {}))
            return ["key", "value", "default", "level", "description", "type"], [
                [k, v, "", "WAREHOUSE", "", "NUMBER"] for k, v in prm.items() if v is not None]
        if n.startswith("SELECT WAREHOUSE_NAME, SUM(CREDITS_USED)"):
            return ["warehouse_name", "credits_used", "first_hour", "last_hour"], [["COMPUTE_WH", 0.5, "x", "y"]]
        if n.startswith("SELECT DATE, CURRENCY"):
            return DriverError("view not available")
        if n == "SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'":
            if monitor is None:
                return ["name", "credit_quota", "used_credits", "frequency"], []
            return ["name", "credit_quota", "used_credits", "frequency"], [
                ["SZL_EE_RM", "%.2f" % monitor[0], "%.2f" % st.get("used", 0.0), monitor[1]]]
        if n == "SHOW WAREHOUSES LIKE 'SZL_EE_WH'":
            if pilot_wh is False:
                return WH_COLS, []
            over = dict(pilot_wh or {})
            drop = set(over.pop("_drop", ()))
            row = dict(PILOT_WH, **over)
            row["state"] = st.get("pilot_state", row["state"])
            row["auto_resume"] = st.get("pilot_ar", row["auto_resume"])
            cols = [c for c in list(WH_COLS) + [k for k in row if k not in WH_COLS] if c not in drop]
            return cols, [[row.get(c) for c in cols]]
        if n == "SHOW DATABASES LIKE 'SZL_EE_DB'":
            return ["name"], ([["SZL_EE_DB"]] if "db" in existing else [])
        if n == "SHOW ROLES LIKE 'SZL_EE_%'":
            return ["name"], [[r] for r in (D.ROLES if roles is None else roles)]
        if n == "SHOW TASKS IN ACCOUNT":
            return ["name", "warehouse", "state"], [list(t) for t in tasks]
        if n.startswith("SELECT START_TIME, END_TIME"):
            return ["start_time", "credits_used"], [["t%d" % i, 0.25] for i in range(metering_rows)]
        if n.startswith("CREATE WAREHOUSE"):
            st["wh_created"] = True
        return [], []
    return r


def _jload(p):
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _jdump(obj, p):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def run(mod, argv, connector, env=None, **kw):
    out = io.StringIO()
    code = mod.main(argv=argv, connector=connector, env=env if env is not None else {}, out=out, **kw)
    return code, out.getvalue()


SYN_SCHEMA = (
    "<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>\n-- SYNTHETIC test schema in the SQL/app track's style\n"
    "-- v4 style: roles and warehouse are owner-created (D0); the database is created by SZL_EE_SETUP\n"
    "USE ROLE SZL_EE_SETUP;\n"
    "CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 1 COMMENT = 'synthetic';\n"
    "GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER REVOKE CURRENT GRANTS;\nUSE ROLE SZL_EE_OWNER;\n"
    "CREATE SCHEMA SZL_EE_DB.EE_DATA WITH MANAGED ACCESS DATA_RETENTION_TIME_IN_DAYS = 1;\n"
    "CREATE SCHEMA SZL_EE_DB.EE_APP WITH MANAGED ACCESS DATA_RETENTION_TIME_IN_DAYS = 1;\n"
    "CREATE TABLE SZL_EE_DB.EE_DATA.ASSETS (ASSET_ID VARCHAR(64) NOT NULL, VISIBILITY VARCHAR(16) NOT NULL, "
    "NOTE VARCHAR(80) DEFAULT 'drop; not a statement', "
    "CONSTRAINT CK_VIS CHECK (VISIBILITY IN ('PUBLIC', 'PRIVATE')));\n"
    "GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP;\nGRANT USAGE ON SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_APP;\n"
    "GRANT SELECT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP;\n"
    "GRANT SELECT, INSERT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_INGEST;\n"
    "GRANT USAGE ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_APP;\n"
    "GRANT CREATE STREAMLIT ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_APP;\n")
SYN_GRANTS = ("<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>\n-- SYNTHETIC\nUSE ROLE SZL_EE_OWNER;\n"
              "GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_VIEWER;\n"
              "GRANT USAGE ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_VIEWER;\n"
              "GRANT USAGE ON STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER TO ROLE SZL_EE_VIEWER;\n")


def make_bundle(d, n=10, until="2026-10-30", account=FAKE_ACCOUNT, schema=None, grants=None, app=None,
                extra=None, pin_extra=True):
    files = {
        "schema.sql": schema or SYN_SCHEMA,
        "reader_grants.sql": grants or SYN_GRANTS,
        "streamlit_app.py": app or "# SYNTHETIC DEMONSTRATION DATA\nimport datetime\nprint('synthetic')\n",
    }
    if extra:
        files.update(extra)
    man = {"files": {}}
    for name, text in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        if name in (extra or {}) and not pin_extra:
            continue
        man["files"][name] = {"path": name, "sha256": hashlib.sha256(text.encode()).hexdigest()}
    mp = os.path.join(d, "MANIFEST.json")
    with open(mp, "w", encoding="utf-8") as f:
        json.dump(man, f)
    ap = os.path.join(d, "approval.txt")
    with open(ap, "w", encoding="utf-8", newline="\n") as f:
        f.write("I approve SZL Evidence Explorer pilot 1: max %d credits, warehouse XS, auto_suspend 60, "
                "until %s, account %s\n" % (n, until, account))
    return mp, ap


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(dir=os.environ.get("SZL_KIT_TEST_TMP"))
        self.d = self._td.name

    def tearDown(self):
        self._td.cleanup()


# ---------------------------------------------------------------- allowlist
class TestAllowlist(unittest.TestCase):
    def test_verify_allowlist_refuses_non_listed(self):
        for bad in ("ALTER WAREHOUSE COMPUTE_WH RESUME", "SELECT 1", "SHOW WAREHOUSES; DROP DATABASE X",
                    "SHOW USERS", "USE WAREHOUSE COMPUTE_WH", "SHOW WAREHOUSES LIKE 'X'"):
            with self.assertRaises(K.RefusedStatement, msg=bad):
                V.CHECK(bad)
        V.CHECK("  show   warehouses ; ")  # whitespace/case-normalized equivalent is allowed

    def test_shutdown_allowlist_refuses(self):
        for bad in ("ALTER WAREHOUSE SZL_EE_WH SUSPEND", "SHOW WAREHOUSES; SELECT 1", "SELECT 1"):
            with self.assertRaises(K.RefusedStatement):
                S.CHECK(bad)

    def test_guarded_session_refuses_before_execute(self):
        conn = FakeConn(base_responder())
        sess = K.GuardedSession(conn, V.CHECK)
        with self.assertRaises(K.RefusedStatement):
            sess.run("ALTER WAREHOUSE COMPUTE_WH RESUME")
        self.assertEqual(conn.executed, [])
        self.assertEqual(len(sess.refused), 1)


# ---------------------------------------------------------------- verify
class TestVerify(unittest.TestCase):
    def test_full_run_partial_and_redaction(self):
        fc = FakeConnector(base_responder())
        code, out = run(V, [], fc)
        ev = json.loads(out)
        self.assertEqual(code, K.EXIT_PARTIAL)   # remaining-balance view errors -> partial
        st = {c["id"]: c["status"] for c in ev["checks"]}
        self.assertEqual(st["context"], "DONE")
        self.assertEqual(st["remaining_balance_7d"], "ERROR")
        self.assertNotIn(FAKE_ACCOUNT, out)
        self.assertNotIn(FAKE_ORG, out)
        self.assertTrue(fc.conn.closed)

    def test_exit0_when_every_check_runs(self):
        base = base_responder()

        def r(n, c):
            if n.startswith("SELECT DATE, CURRENCY"):
                return ["date"], [["2026-10-20"]]
            return base(n, c)
        code, _ = run(V, [], FakeConnector(r))
        self.assertEqual(code, K.EXIT_OK)

    def test_gated_not_run_when_current_warehouse_suspended(self):
        fc = FakeConnector(base_responder([wh("COMPUTE_WH", "SUSPENDED", "true", current="Y")]))
        code, out = run(V, [], fc)
        ev = json.loads(out)
        self.assertEqual(code, K.EXIT_PARTIAL)
        st = {c["id"]: c["status"] for c in ev["checks"]}
        for cid in V.GATED:
            self.assertEqual(st[cid], "NOT_RUN")
        self.assertFalse(any(s.upper().startswith("SELECT") for s in fc.conn.executed))

    def test_select_runs_when_current_warehouse_started(self):
        fc = FakeConnector(base_responder([wh("COMPUTE_WH", "STARTED", "true", current="Y")]))
        run(V, [], fc)
        self.assertTrue(any(s.upper().startswith("SELECT CURRENT_ACCOUNT") for s in fc.conn.executed))

    def test_secrets_never_printed_on_connection_failure(self):
        env = {"SNOWFLAKE_PASSWORD": SENTINEL, "SZL_SF_CONNECTION_NAME": "pilot"}
        fc = FakeConnector(connect_error=DriverError("auth failed for user x pw %s at "
                                                     "zz99999.snowflakecomputing.com" % SENTINEL))
        code, out = run(V, [], fc, env=env)
        self.assertEqual(code, K.EXIT_CONNECTION)
        self.assertNotIn(SENTINEL, out)
        self.assertNotIn("snowflakecomputing", out)
        self.assertIn("DriverError", out)

    def test_secrets_never_printed_from_rows(self):
        code, out = run(V, [], FakeConnector(base_responder()), env={"SNOWFLAKE_TOKEN": SENTINEL})
        self.assertNotIn(SENTINEL, out)

    def test_scrub_catches_secret_in_allowed_field(self):
        base = base_responder()

        def r(n, c):
            if n == "SHOW WAREHOUSES":
                row = wh("COMPUTE_WH")
                row[WH_COLS.index("owner")] = "ROLE_" + SENTINEL
                return WH_COLS, [row]
            return base(n, c)
        _, out = run(V, [], FakeConnector(r), env={"SNOWFLAKE_PASSWORD": SENTINEL})
        self.assertNotIn(SENTINEL, out)
        self.assertIn("<scrubbed>", out)

    def test_free_text_columns_not_in_evidence(self):
        _, out = run(V, [], FakeConnector(base_responder()))
        ev = json.loads(out)
        whd = [c for c in ev["checks"] if c["id"] == "show_warehouses"][0]["data"]
        self.assertTrue(whd and all("comment" not in w for w in whd))
        self.assertNotIn("comment " , out)
        rm = [c for c in ev["checks"] if c["id"] == "show_resource_monitors"][0]["data"]
        self.assertTrue(rm and all("notify_users" not in m for m in rm))

    def test_connect_never_receives_credentials(self):
        fc = FakeConnector(base_responder())
        run(V, [], fc, env={"SNOWFLAKE_PASSWORD": SENTINEL, "SZL_SF_CONNECTION_NAME": "pilot"})
        kw = fc.calls[0]
        self.assertLessEqual(set(kw), {"session_parameters", "client_session_keep_alive", "connection_name"})
        self.assertEqual(kw["connection_name"], "pilot")
        self.assertNotIn(SENTINEL, json.dumps(kw))

    def test_argv_connection_params_refused(self):
        fc = FakeConnector(base_responder())
        code, _ = run(V, ["--account", "x", "--password", "y"], fc)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertEqual(fc.calls, [])

    def test_connector_missing_fails_closed(self):
        orig = K.load_connector

        def missing():
            raise K.ConnectorUnavailable("ModuleNotFoundError")
        K.load_connector = missing
        try:
            code, out = run(V, [], None)
        finally:
            K.load_connector = orig
        self.assertEqual(code, K.EXIT_CONNECTION)
        self.assertIn("CONNECTOR_NOT_INSTALLED", out)

    def test_account_match_against_expected_env(self):
        _, out = run(V, [], FakeConnector(base_responder()), env={"SZL_SF_EXPECTED_ACCOUNT": "synorg-synacct"})
        ctx = [c for c in json.loads(out)["checks"] if c["id"] == "context"][0]
        self.assertIs(ctx["data"]["account_matches_expected"], True)
        _, out = run(V, [], FakeConnector(base_responder()), env={"SZL_SF_EXPECTED_ACCOUNT": "OTHER-ACCT"})
        ctx = [c for c in json.loads(out)["checks"] if c["id"] == "context"][0]
        self.assertIs(ctx["data"]["account_matches_expected"], False)

    def test_out_file_never_overwritten(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("SZL_KIT_TEST_TMP")) as d:
            p = os.path.join(d, "ev.json")
            with open(p, "w") as f:
                f.write("keep")
            with self.assertRaises(FileExistsError):
                run(V, ["--out", p], FakeConnector(base_responder()))
            with open(p) as f:
                self.assertEqual(f.read(), "keep")


# ---------------------------------------------------------------- approval / manifest
GOOD = ("I approve SZL Evidence Explorer pilot 1: max 10 credits, warehouse XS, auto_suspend 60, "
        "until 2026-10-30, account ZZ99999")


class TestApproval(unittest.TestCase):
    def test_good(self):
        a = D.parse_approval((GOOD + "\n").encode(), TODAY)
        self.assertEqual((a["credits"], a["until"], a["account"]), (10, "2026-10-30", "ZZ99999"))

    def test_mismatch_refused(self):
        bad = [GOOD.replace("warehouse XS", "warehouse S"), GOOD.replace("auto_suspend 60", "auto_suspend 600"),
               GOOD + " ", " " + GOOD, GOOD.lower(), GOOD + "\nsecond line", GOOD.replace("pilot 1", "pilot 2"),
               D.APPROVAL_TEMPLATE, GOOD.replace("max 10", "max 010"), GOOD.replace(":", ""),
               GOOD + " and more"]
        for b in bad:
            with self.assertRaises(K.RefusedStatement, msg=b):
                D.parse_approval(b.encode(), TODAY)
        with self.assertRaises(K.RefusedStatement):
            D.parse_approval(b"\xef\xbb\xbf" + GOOD.encode(), TODAY)

    def test_budget_above_cap_refused(self):
        with self.assertRaises(K.RefusedStatement):
            D.parse_approval(GOOD.replace("max 10", "max 11").encode(), TODAY)
        with self.assertRaises(K.RefusedStatement):
            D.parse_approval(GOOD.replace("max 10", "max 0").encode(), TODAY)
        self.assertEqual(D.parse_approval(GOOD.replace("max 10", "max 1").encode(), TODAY)["credits"], 1)

    def test_date_rules(self):
        for d in ("2026-10-21", "2026-10-20", "2026-12-31", "2026-02-30"):
            with self.assertRaises(K.RefusedStatement, msg=d):
                D.parse_approval(GOOD.replace("2026-10-30", d).encode(), TODAY)
        D.parse_approval(GOOD.replace("2026-10-30", "2026-10-22").encode(), TODAY)


class TestManifest(TempDirCase):
    def test_digest_mismatch_refused(self):
        mp, ap = make_bundle(self.d)
        with open(os.path.join(self.d, "streamlit_app.py"), "a") as f:
            f.write("# tampered\n")
        with self.assertRaises(K.RefusedStatement):
            D.load_manifest(mp)
        fc = FakeConnector(base_responder())
        code, _ = run(D, ["--execute", "--manifest", mp, "--approval-file", ap], fc, today=TODAY)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertEqual(fc.calls, [])

    def test_missing_and_escaping_entries_refused(self):
        mp, _ = make_bundle(self.d)
        man = _jload(mp)
        del man["files"]["reader_grants.sql"]
        _jdump(man, mp)
        with self.assertRaises(K.RefusedStatement):
            D.load_manifest(mp)
        man["files"]["reader_grants.sql"] = {"path": "../reader_grants.sql", "sha256": "0" * 64}
        _jdump(man, mp)
        with self.assertRaises(K.RefusedStatement):
            D.load_manifest(mp)

    def test_path_escape_refused_even_with_correct_digest(self):
        inner = os.path.join(self.d, "inner")
        os.makedirs(inner)
        mp, _ = make_bundle(inner)
        text = "GRANT SELECT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP;\n"
        with open(os.path.join(self.d, "reader_grants.sql"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        man = _jload(mp)
        man["files"]["reader_grants.sql"] = {"path": "../reader_grants.sql",
                                             "sha256": hashlib.sha256(text.encode()).hexdigest()}
        _jdump(man, mp)
        with self.assertRaises(K.RefusedStatement) as cm:
            D.load_manifest(mp)
        self.assertIn("escapes", str(cm.exception))

    def test_list_form_accepted(self):
        mp, _ = make_bundle(self.d)
        man = _jload(mp)
        man["files"] = [{"path": k, "sha256": v["sha256"]} for k, v in man["files"].items()]
        _jdump(man, mp)
        self.assertEqual(set(D.load_manifest(mp)), set(D.REQUIRED_FILES))


# ---------------------------------------------------------------- deploy guard
class TestDeployGuard(unittest.TestCase):
    def test_denied_statements(self):
        bad = ["DROP TABLE SZL_EE_DB.EE_DATA.ASSETS", "CREATE OR REPLACE TABLE T (A INT)",
               "GRANT SELECT ON TABLE T TO ROLE PUBLIC", "GRANT SELECT ON TABLE T TO ROLE SZL_EE_APP WITH GRANT OPTION",
               "USE ROLE ACCOUNTADMIN", "ALTER WAREHOUSE SZL_EE_WH RESUME", "CREATE TABLE IF NOT EXISTS T (A INT)",
               "INSERT INTO T VALUES (1)", "CREATE TABLE T AS SELECT 1 AS A", "GRANT CREATE DATABASE ON ACCOUNT TO ROLE SZL_EE_OWNER",
               "GRANT OWNERSHIP ON TABLE T TO ROLE SZL_EE_APP", "CREATE USER SVC", "CREATE TASK T1 AS SELECT 1",
               "GRANT SELECT ON FUTURE TABLES IN SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_APP",
               "GRANT INSERT ON TABLE T TO ROLE SZL_EE_APP", "GRANT SELECT ON TABLE T TO ROLE SYSADMIN",
               "GRANT ROLE SZL_EE_VIEWER TO USER JDOE", "CREATE TABLE T (A INT); DROP TABLE U",
               "CREATE OR ALTER TABLE T (A INT)", "CREATE TABLE T CLONE U",
               "GRANT MODIFY ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_OWNER", "UNDROP TABLE T",
               "CREATE TABLE OTHERDB.SOMESCHEMA.T (A INT)", "GRANT USAGE ON STREAMLIT SZL_EE_DB.EE_APP.X TO ROLE SZL_EE_VIEWER WITH GRANT OPTION",
               "GRANT EMBED ON STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER TO ROLE SZL_EE_VIEWER",
               "CREATE WAREHOUSE SZL_EE_WH WITH AUTO_RESUME = TRUE",
               "GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP REVOKE CURRENT GRANTS"]
        for b in bad:
            with self.assertRaises(K.RefusedStatement, msg=b):
                D.deploy_check(b)

    def test_tokens_inside_allowed_prefixes(self):
        # v0.1.2: ALTER TABLE is no longer an allowed statement type; these pass the prefix and
        # CREATE TABLE shape checks, so only the deny tokens stop them.
        for b in ("CREATE TABLE SZL_EE_DB.EE_DATA.T (DROP INT)",
                  "CREATE TABLE SZL_EE_DB.EE_DATA.T (ACCOUNTADMIN INT)"):
            with self.assertRaises(K.RefusedStatement, msg=b) as cm:
                D.deploy_check(b)
            self.assertTrue(str(cm.exception).startswith("denied token"), b)
        for b in ("ALTER TABLE ASSETS DROP COLUMN NOTE", "GRANT ROLE ACCOUNTADMIN TO ROLE SZL_EE_OWNER"):
            with self.assertRaises(K.RefusedStatement, msg=b):
                D.deploy_check(b)

    def test_plan_statements_pass_and_local_path_words_ok(self):
        for _, s in D.build_plan(None):
            if not s.startswith("--"):
                D.deploy_check(s)
        D.deploy_check("PUT 'file://C:/Users/x/Documents/Codex/2026-10-13/task-7/public/streamlit_app.py' "
                       "@SZL_EE_DB.EE_APP.APP_SRC/v1 AUTO_COMPRESS = FALSE OVERWRITE = FALSE")

    def test_accountadmin_only_in_manual_block(self):
        plan = " ".join(s for _, s in D.build_plan(None)).upper()
        self.assertNotIn("ACCOUNTADMIN", plan)
        self.assertIn("USE ROLE ACCOUNTADMIN", " ".join(D.manual_accountadmin_block(None)))

    def test_split_sql(self):
        st = D.split_sql("-- c;\nCREATE TABLE A (X VARCHAR DEFAULT 'a;b''c'); /* x; */ CREATE VIEW V AS SELECT 1;")
        self.assertEqual(len(st), 2)
        self.assertIn("'a;b''c'", st[0])
        with self.assertRaises(K.RefusedStatement):
            D.split_sql("CREATE TABLE A ('unterminated)")


class TestBundleRules(TempDirCase):
    def test_guard_line_bound_and_ref_mismatch_refused(self):
        a = D.parse_approval((GOOD + "\n").encode(), TODAY)
        text, note = D.bind_guard("schema.sql", SYN_SCHEMA, a["approval_sha256"])
        self.assertIn(a["approval_sha256"], text.splitlines()[0])
        self.assertNotIn(D.GUARD_LINE, text)
        ok = "-- DEPLOYMENT_APPROVAL_REF: %s\nUSE ROLE SZL_EE_OWNER;\n" % a["approval_sha256"]
        self.assertEqual(D.bind_guard("reader_grants.sql", ok, a["approval_sha256"])[0], ok)
        bad = "-- DEPLOYMENT_APPROVAL_REF: %s\nUSE ROLE SZL_EE_OWNER;\n" % ("0" * 64)
        with self.assertRaises(K.RefusedStatement):
            D.bind_guard("reader_grants.sql", bad, a["approval_sha256"])
        with self.assertRaises(K.RefusedStatement):
            D.bind_guard("schema.sql", "USE ROLE SYSADMIN;\n" + D.GUARD_LINE + "\n", None)

    def test_unpinned_local_import_refused_and_pinned_staged(self):
        app = "import evidence_core as core\nprint(core)\n"
        mp, ap = make_bundle(self.d, app=app, extra={"evidence_core.py": "X = 1\n"}, pin_extra=False)
        code, out = run(D, ["--manifest", mp], None, today=TODAY)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertIn("unpinned local module", out)
        mp, ap = make_bundle(self.d, app=app, extra={"evidence_core.py": "X = 1\n"}, pin_extra=True)
        code, out = run(D, ["--manifest", mp], None, today=TODAY)
        self.assertEqual(code, K.EXIT_OK)
        self.assertEqual(out.count("[B10] PUT 'file://"), 2)

    def test_file_statement_types_restricted(self):
        for kind, stmt in (("reader_grants.sql", "CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT)"),
                           ("schema.sql", "CREATE STAGE SZL_EE_DB.EE_APP.APP_SRC"),
                           ("schema.sql", "CREATE WAREHOUSE SZL_EE_WH WITH WAREHOUSE_SIZE = XSMALL"),
                           ("schema.sql", "USE ROLE SZL_EE_APP"),
                           ("schema.sql", "USE ROLE SYSADMIN"), ("schema.sql", "USE ROLE USERADMIN"),
                           ("schema.sql", "CREATE ROLE SZL_EE_OWNER COMMENT = 'x'"),
                           ("schema.sql", "GRANT ROLE SZL_EE_OWNER TO ROLE SYSADMIN")):
            with self.assertRaises(K.RefusedStatement, msg=stmt):
                D.validate_file_statements(kind, [stmt])

    def test_three_part_names_confined(self):
        # v0.1.2: CREATE VIEW is no longer an allowed statement type (schema.sql v3 has no views)
        with self.assertRaises(K.RefusedStatement):
            D.deploy_check("CREATE TABLE SZL_EE_DB.EE_DATA.V (X INT REFERENCES OTHERDB.S.T (X))")
        D.deploy_check("CREATE TABLE SZL_EE_DB.EE_DATA.V (X INT REFERENCES SZL_EE_DB.EE_DATA.T (X))")
        with self.assertRaises(K.RefusedStatement):
            D.deploy_check("CREATE VIEW SZL_EE_DB.EE_DATA.V AS SELECT a.X FROM SZL_EE_DB.EE_DATA.T a")


# ---------------------------------------------------------------- deploy flow
class TestDeploy(TempDirCase):
    def _exec(self, responder, **kw):
        mp, ap = make_bundle(self.d, **kw)
        fc = FakeConnector(responder)
        code, out = run(D, ["--execute", "--manifest", mp, "--approval-file", ap], fc, today=TODAY)
        return code, out, fc

    def test_dry_run_executes_nothing(self):
        mp, ap = make_bundle(self.d)

        class Exploding:
            calls = 0

            def connect(self, **kw):
                Exploding.calls += 1
                raise AssertionError("dry run must not connect")
        for argv in ([], ["--dry-run"], ["--manifest", mp, "--approval-file", ap]):
            code, out = run(D, argv, Exploding(), today=TODAY)
            self.assertEqual(code, K.EXIT_OK, argv)
            self.assertIn("DRY RUN - nothing executed", out)
        self.assertEqual(Exploding.calls, 0)

    def test_dry_run_orders_monitor_before_warehouse(self):
        mp, ap = make_bundle(self.d)
        _, out = run(D, ["--manifest", mp, "--approval-file", ap], None, today=TODAY)
        i_rm, i_wh = out.index("CREATE RESOURCE MONITOR"), out.index("CREATE WAREHOUSE")
        self.assertLess(i_rm, i_wh)
        head, tail = out.split("# STEPS EXECUTED BY THE KIT", 1)
        self.assertIn("ACCOUNTADMIN", head)
        self.assertNotIn("ACCOUNTADMIN", tail)
        self.assertIn("CREDIT_QUOTA = 10", head)

    def test_happy_path(self):
        code, out, fc = self._exec(base_responder())
        ev = json.loads(out)
        self.assertEqual(code, K.EXIT_OK, ev.get("refusals"))
        ex = [K.normalize_sql(s) for s in fc.conn.executed]
        i_mon = ex.index("SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'")
        i_wh = ex.index("SHOW WAREHOUSES LIKE 'SZL_EE_WH'")
        i_prm = ex.index(K.normalize_sql(D.SHOW_PARAMS_SQL))
        i_roles = ex.index("SHOW ROLES LIKE 'SZL_EE_%'")
        i_first_create = next(i for i, s in enumerate(ex) if s.startswith("CREATE "))
        self.assertLess(max(i_mon, i_wh, i_prm, i_roles), i_first_create)
        self.assertLess(ex.index("USE ROLE SZL_EE_SETUP"), i_mon)   # preflight runs as the setup role
        joined = " ".join(ex)
        for tok in ("ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "DROP ", "REPLACE", "IF NOT EXISTS",
                    " RESUME", "CREATE WAREHOUSE", "CREATE ROLE", "GRANT ROLE", "ON WAREHOUSE"):
            self.assertNotIn(tok, joined)
        self.assertTrue(all(c["status"] == "PASS" for c in ev["post_checks"]))
        self.assertEqual(ev["identity_check"], "PASS")
        self.assertEqual(ev["warehouse_check"], {"problems": []})
        self.assertNotIn(FAKE_ACCOUNT, out)

    def test_account_mismatch_refused(self):
        code, out, fc = self._exec(base_responder(account="YY11111"))
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertFalse(any(K.normalize_sql(s).startswith("CREATE ") for s in fc.conn.executed))

    def test_org_account_name_form_accepted(self):
        code, _, _ = self._exec(base_responder(), account="SYNORG-SYNACCT")
        self.assertEqual(code, K.EXIT_OK)

    def _assert_refused(self, responder, reason_part):
        code, out, fc = self._exec(responder)
        ev = json.loads(out)
        self.assertEqual(code, K.EXIT_REFUSED, out)
        self.assertTrue(any(reason_part in r for r in ev["refusals"]), (reason_part, ev["refusals"]))
        self.assertFalse(any(K.normalize_sql(s).startswith(("CREATE ", "GRANT ", "PUT ")) for s in fc.conn.executed))

    def test_existing_database_refused(self):
        self._assert_refused(base_responder(existing=("db",)), "object already exists: SZL_EE_DB")

    def test_owner_warehouse_required_with_exact_properties(self):
        self._assert_refused(base_responder(pilot_wh=False), "owner-created warehouse SZL_EE_WH must exist first")
        for over, prop in (({"state": "STARTED"}, "state"), ({"size": "Small"}, "size"),
                           ({"auto_resume": "true"}, "auto_resume"), ({"_drop": ["auto_resume"]}, "auto_resume"),
                           ({"auto_suspend": 600}, "auto_suspend"), ({"resource_monitor": "null"}, "resource_monitor"),
                           ({"owner": "SYSADMIN"}, "owner"), ({"type": "SNOWPARK-OPTIMIZED"}, "type"),
                           ({"max_cluster_count": 2}, "max_cluster_count"), ({"min_cluster_count": 2}, "min_cluster_count")):
            self._assert_refused(base_responder(pilot_wh=over), "SZL_EE_WH differs from the owner spec: " + prop)
        for prm, key in (({"STATEMENT_TIMEOUT_IN_SECONDS": "3600"}, "STATEMENT_TIMEOUT_IN_SECONDS"),
                         ({"STATEMENT_QUEUED_TIMEOUT_IN_SECONDS": "0"}, "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS"),
                         ({"STATEMENT_TIMEOUT_IN_SECONDS": None}, "STATEMENT_TIMEOUT_IN_SECONDS")):
            self._assert_refused(base_responder(wh_params=prm), "SZL_EE_WH differs from the owner spec: " + key)
        code, _, _ = self._exec(base_responder(pilot_wh={"min_cluster_count": 1, "max_cluster_count": 1,
                                                         "size": "XSMALL"}))
        self.assertEqual(code, K.EXIT_OK)

    def test_owner_roles_required(self):
        for r in D.ROLES:
            self._assert_refused(base_responder(roles=[x for x in D.ROLES if x != r]),
                                 "owner-created roles missing (owner block D0): " + r)
        self._assert_refused(base_responder(roles=list(D.ROLES) + ["SZL_EE_OWNER"]),
                             "owner-created roles missing (owner block D0): SZL_EE_OWNER")

    def test_identity_must_be_narrow_setup(self):
        for roles, part in ((["SZL_EE_SETUP", "SYSADMIN"], "admin role reachable: SYSADMIN"),
                            (["SZL_EE_SETUP", "SECURITYADMIN", "ACCOUNTADMIN"], "admin role reachable: ACCOUNTADMIN,SECURITYADMIN"),
                            (["szl_ee_setup", "useradmin"], "admin role reachable: USERADMIN"),
                            (["SZL_EE_SETUP", "SZL_EE_OPERATOR"], "reachable by the setup identity: SZL_EE_OPERATOR"),
                            (["SZL_EE_SETUP", "SZL_EE_INGEST"], "reachable by the setup identity: SZL_EE_INGEST"),
                            (["SZL_EE_OWNER", "SZL_EE_APP"], "SZL_EE_SETUP not available")):
            self._assert_refused(base_responder(avail=json.dumps(roles)), part)
        for raw in ("not json", json.dumps({"a": 1}), json.dumps([1, 2]), None):
            self._assert_refused(base_responder(avail=raw), "CURRENT_AVAILABLE_ROLES unreadable")

    def test_monitor_missing_or_wrong_refused(self):
        for mon in (None, (9, "NEVER"), (10, "MONTHLY")):
            code, _, fc = self._exec(base_responder(monitor=mon))
            self.assertEqual(code, K.EXIT_REFUSED, mon)
            self.assertFalse(any(K.normalize_sql(s).startswith("CREATE ") for s in fc.conn.executed))

    def test_monitor_refusal_reason_and_lookalike_rows(self):
        code, out, fc = self._exec(base_responder(monitor=None))
        self.assertIn("must exist first", out)
        base = base_responder()

        def r(n, c):
            if n == "SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'":
                return ["name", "credit_quota", "used_credits", "frequency"], [
                    ["SZLXEEXRM", "10.00", "0.00", "NEVER"]]
            return base(n, c)
        code, out, fc = self._exec(r)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertFalse(any(K.normalize_sql(s).startswith("CREATE ") for s in fc.conn.executed))

    def test_file_changed_after_preflight_refused(self):
        base = base_responder()
        target = os.path.join(self.d, "streamlit_app.py")

        def r(n, c):
            if n == "SHOW ROLES LIKE 'SZL_EE_%'":
                with open(target, "a", encoding="utf-8") as f:
                    f.write("# swapped after preflight\n")
            return base(n, c)
        code, out, fc = self._exec(r)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertIn("digest changed", out)
        self.assertFalse(any(K.normalize_sql(s).startswith("CREATE ") for s in fc.conn.executed))

    def test_gate_refuses_when_current_warehouse_suspended(self):
        code, _, fc = self._exec(base_responder([wh("COMPUTE_WH", "SUSPENDED", "true", current="Y")]))
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertFalse(any(K.normalize_sql(s).startswith("SELECT") for s in fc.conn.executed))

    def test_exec_error_stops_and_reports_partial(self):
        code, out, fc = self._exec(base_responder(fail_on="CREATE DATABASE"))
        ev = json.loads(out)
        self.assertEqual(code, K.EXIT_EXEC_ERROR)
        self.assertEqual(ev["failed_step"]["step"], "B5-B8 schema.sql")
        self.assertTrue(ev["readback_required"])
        self.assertTrue(K.normalize_sql(fc.conn.executed[-1]).startswith("CREATE DATABASE"))
        self.assertNotIn(SENTINEL, out)

    def test_forbidden_schema_file_refused(self):
        mp, ap = make_bundle(self.d, schema="CREATE TABLE A (X INT);\nDROP TABLE B;\n")
        fc = FakeConnector(base_responder())
        code, _ = run(D, ["--manifest", mp, "--approval-file", ap], fc, today=TODAY)
        self.assertEqual(code, K.EXIT_REFUSED)
        mp, ap = make_bundle(self.d, schema="CREATE TABLE OTHERDB.PUBLIC.T (X INT);\n")
        code, _ = run(D, ["--manifest", mp], None, today=TODAY)
        self.assertEqual(code, K.EXIT_REFUSED)

    def test_execute_requires_approval_and_manifest(self):
        mp, ap = make_bundle(self.d)
        fc = FakeConnector(base_responder())
        for argv in (["--execute"], ["--execute", "--manifest", mp], ["--execute", "--approval-file", ap],
                     ["--execute", "--dry-run"], ["--execute", "--account", "X"]):
            code, _ = run(D, argv, fc, today=TODAY)
            self.assertEqual(code, K.EXIT_REFUSED, argv)
        self.assertEqual(fc.calls, [])

    def test_budget_above_cap_refused_end_to_end(self):
        code, _, fc = self._exec(base_responder(), n=11)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertEqual(fc.calls, [])

    def test_secret_not_printed_on_deploy_connection_failure(self):
        mp, ap = make_bundle(self.d)
        fc = FakeConnector(connect_error=DriverError("pw=" + SENTINEL))
        code, out = run(D, ["--execute", "--manifest", mp, "--approval-file", ap], fc,
                        env={"SNOWFLAKE_PRIVATE_KEY_PASSPHRASE": SENTINEL}, today=TODAY)
        self.assertEqual(code, K.EXIT_CONNECTION)
        self.assertNotIn(SENTINEL, out)


# ---------------------------------------------------------------- shutdown
class TestShutdown(unittest.TestCase):
    def _r(self, pilot_state="SUSPENDED", pilot_ar="false", others=None, tasks=(), current="N", used=2.0):
        others = others if others is not None else [wh("COMPUTE_WH", current=current)]

        def r(n, c):
            c.state.update(used=used)
            if n == "SHOW WAREHOUSES":
                return WH_COLS, others + [wh("SZL_EE_WH", pilot_state, pilot_ar, "N", "SZL_EE_RM", 60)]
            return base_responder(tasks=tasks)(n, c)
        return r

    def _st(self, out):
        return {c["id"]: c["status"] for c in json.loads(out)["checks"]}

    def test_all_pass(self):
        code, out = run(S, [], FakeConnector(self._r()))
        self.assertEqual(code, K.EXIT_OK, out)
        self.assertEqual(set(self._st(out).values()), {"PASS"})

    def test_running_pilot_fails(self):
        code, out = run(S, [], FakeConnector(self._r(pilot_state="STARTED", pilot_ar="true")))
        self.assertEqual(code, K.EXIT_FAIL)
        st = self._st(out)
        self.assertEqual((st["W1"], st["W2"]), ("FAIL", "FAIL"))

    def test_started_task_fails(self):
        code, out = run(S, [], FakeConnector(self._r(tasks=[("T", "SZL_EE_WH", "started")])))
        self.assertEqual(code, K.EXIT_FAIL)
        self.assertEqual(self._st(out)["T1"], "FAIL")

    def test_other_running_warehouse_fails(self):
        code, out = run(S, [], FakeConnector(self._r(others=[wh("COMPUTE_WH", "STARTED")])))
        self.assertEqual(self._st(out)["W3"], "FAIL")

    def test_monitor_over_quota_fails(self):
        code, out = run(S, [], FakeConnector(self._r(used=10.5)))
        self.assertEqual(self._st(out)["R1"], "FAIL")

    def test_metering_gated_unknown(self):
        fc = FakeConnector(self._r(current="Y"))
        code, out = run(S, [], fc)
        self.assertEqual(code, K.EXIT_PARTIAL)
        self.assertEqual(self._st(out)["M1"], "UNKNOWN")
        self.assertFalse(any(s.upper().startswith("SELECT") for s in fc.conn.executed))


class TestNoAdminHierarchyGrants(unittest.TestCase):
    """v0.3.0: the three v3 '... TO ROLE SYSADMIN' hierarchy grants are removed. The kit executes no
    role grant and no warehouse grant; those are owner-run (OWNER_RUN_GRANTS, SNOWSIGHT_SETUP.sql)."""

    def test_v3_hierarchy_and_any_role_grant_refused(self):
        for stmt in ("GRANT ROLE SZL_EE_OWNER TO ROLE SYSADMIN", "GRANT ROLE SZL_EE_INGEST TO ROLE SYSADMIN",
                     "GRANT ROLE SZL_EE_APP TO ROLE SYSADMIN", "GRANT ROLE SZL_EE_OWNER TO ROLE SZL_EE_SETUP",
                     "GRANT ROLE SZL_EE_APP TO ROLE SZL_EE_SETUP", "GRANT ROLE SZL_EE_OPERATOR TO ROLE SZL_EE_INGEST"):
            with self.assertRaises(K.RefusedStatement, msg=stmt) as cm:
                D.deploy_check(stmt)
            self.assertEqual(str(cm.exception), "role grant not permitted", stmt)

    def test_warehouse_grants_are_owner_run_only(self):
        for stmt in ("GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_APP",
                     "GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_INGEST",
                     "GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR"):
            with self.assertRaises(K.RefusedStatement, msg=stmt) as cm:
                D.deploy_check(stmt)
            self.assertEqual(str(cm.exception), "grant target not in privilege matrix", stmt)
        self.assertFalse(any(otype == "WAREHOUSE" for otype, _ in D.GRANT_MATRIX))

    def test_owner_run_grants_operate_only_to_operator_and_no_admin(self):
        stmts = [s for _, _, s in D.OWNER_RUN_GRANTS]
        self.assertEqual([s for s in stmts if " OPERATE " in s],
                         ["GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR"])
        tokens = set(" ".join(stmts).split())
        self.assertFalse(tokens & {"MODIFY", "OWNERSHIP", "ALL", "FUTURE", "ACCOUNTADMIN", "SECURITYADMIN",
                                   "SYSADMIN", "USERADMIN", "ORGADMIN", "PUBLIC"})
        self.assertNotIn("GRANT OPTION", " ".join(stmts))

    def test_user_grants_keep_setup_and_runtime_separate(self):
        ug = {}
        for _, _, s in D.OWNER_RUN_GRANTS:
            m = re.fullmatch(r"GRANT ROLE (\w+) TO USER (\w+)", s)
            if m:
                ug.setdefault(m.group(2), set()).add(m.group(1))
        self.assertEqual(ug, {"SZL_EE_DEPLOY": {"SZL_EE_SETUP"},
                              "SZL_EE_RUNTIME": {"SZL_EE_INGEST", "SZL_EE_OPERATOR"}})



# ---------------------------------------------------------------- v0.1.2 privilege guard (adversarial)
# Every statement below must be refused by deploy_check. Synthetic; none is ever executed.
ADVERSARIAL = {
    'esc_SYSADMIN_to_APP': 'GRANT ROLE SYSADMIN TO ROLE SZL_EE_APP',
    'esc_SECURITYADMIN_to_APP': 'GRANT ROLE SECURITYADMIN TO ROLE SZL_EE_APP',
    'esc_USERADMIN_to_INGEST': 'GRANT ROLE USERADMIN TO ROLE SZL_EE_INGEST',
    'esc_ORGADMIN_to_OWNER': 'GRANT ROLE ORGADMIN TO ROLE SZL_EE_OWNER',
    'esc_ACCOUNTADMIN_to_APP': 'GRANT ROLE ACCOUNTADMIN TO ROLE SZL_EE_APP',
    'esc_quoted_SYSADMIN': 'GRANT ROLE "SYSADMIN" TO ROLE SZL_EE_APP',
    'esc_OWNER_to_VIEWER': 'GRANT ROLE SZL_EE_OWNER TO ROLE SZL_EE_VIEWER',
    'esc_APP_to_VIEWER': 'GRANT ROLE SZL_EE_APP TO ROLE SZL_EE_VIEWER',
    'esc_unrelated_role_to_APP': 'GRANT ROLE ANALYST_ROLE TO ROLE SZL_EE_APP',
    'grantee_unrelated': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE ANALYST',
    'grantee_SYSADMIN_db': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SYSADMIN',
    'grantee_VIEWER_to_SYSADMIN': 'GRANT ROLE SZL_EE_VIEWER TO ROLE SYSADMIN',
    'grantee_user': 'GRANT ROLE SZL_EE_APP TO USER BOB',
    'grantee_PUBLIC': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE PUBLIC',
    'grantee_share': 'GRANT USAGE ON DATABASE SZL_EE_DB TO SHARE S1',
    'grantee_dbrole': 'GRANT USAGE ON SCHEMA SZL_EE_DB.EE_APP TO DATABASE ROLE SZL_EE_DB.R1',
    'grantee_application': 'GRANT USAGE ON DATABASE SZL_EE_DB TO APPLICATION APP1',
    'grantee_application_role': 'GRANT USAGE ON DATABASE SZL_EE_DB TO APPLICATION ROLE APP1.R',
    'wild_pct': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_%',
    'lookalike_APPX': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APPX',
    'lookalike_quoted_lower': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE "szl_ee_app"',
    'lookalike_quoted_upper': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE "SZL_EE_APP"',
    'lookalike_greek_A': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_ΑPP',
    'lookalike_dotless_i_create': 'CREATE ROLE szl_ee_vıewer',
    'lookalike_dotless_i_use': 'USE ROLE sysadmın',
    'lookalike_zwsp_grantee': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP\u200b',
    'nbsp_whitespace': 'GRANT\xa0ROLE SYSADMIN TO ROLE SZL_EE_APP',
    'fullwidth_semicolon': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP； DROP DATABASE X',
    'comment_dashdash_grantee': 'GRANT ROLE SZL_EE_APP TO ROLE ANALYST -- TO ROLE SZL_EE_APP',
    'comment_dashdash_newline': 'GRANT ROLE SZL_EE_APP TO ROLE ANALYST --\nTO ROLE SZL_EE_APP',
    'comment_slashslash': 'GRANT ROLE SZL_EE_APP TO ROLE ANALYST // TO ROLE SZL_EE_APP',
    'comment_block_hidden': 'GRANT USAGE ON DATABASE SZL_EE_DB /* x */ TO ROLE SZL_EE_APP',
    'backslash_quote_literal': "CREATE ROLE SZL_EE_APP COMMENT = 'a\\'' DROP X ''",
    'dq_ident_with_quote': 'GRANT ROLE SZL_EE_APP TO ROLE "B\'" \' TO ROLE SZL_EE_APP',
    'malformed_no_on': 'GRANT USAGE DATABASE SZL_EE_DB TO ROLE SZL_EE_APP',
    'malformed_dup_to': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP TO ROLE SZL_EE_APP',
    'malformed_empty_priv': 'GRANT ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP',
    'malformed_trailing_comma': 'GRANT SELECT, ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP',
    'malformed_two_stmts': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP; DROP DATABASE SZL_EE_DB',
    'malformed_bare_GRANT': 'GRANT ',
    'with_grant_option': 'GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP WITH GRANT OPTION',
    'grant_all': 'GRANT ALL ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP',
    'grant_all_privileges': 'GRANT ALL PRIVILEGES ON SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_INGEST',
    'grant_on_all_tables': 'GRANT SELECT ON ALL TABLES IN SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_APP',
    'grant_future': 'GRANT SELECT ON FUTURE TABLES IN SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_APP',
    'grant_ownership_table': 'GRANT OWNERSHIP ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP',
    'grant_ownership_db_to_app': 'GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_APP',
    'grant_ownership_copy': 'GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER COPY CURRENT GRANTS',
    'on_account_create_db': 'GRANT CREATE DATABASE ON ACCOUNT TO ROLE SZL_EE_APP',
    'on_account_execute_task': 'GRANT EXECUTE TASK ON ACCOUNT TO ROLE SZL_EE_APP',
    'manage_grants': 'GRANT MANAGE GRANTS ON ACCOUNT TO ROLE SZL_EE_OWNER',
    'insert_to_app': 'GRANT INSERT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP',
    'update_to_ingest': 'GRANT UPDATE ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_INGEST',
    'delete_to_ingest': 'GRANT DELETE ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_INGEST',
    'truncate_to_ingest': 'GRANT TRUNCATE ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_INGEST',
    'modify_wh_to_app': 'GRANT MODIFY ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_APP',
    'operate_wh_to_app': 'GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_APP',
    'usage_wh_viewer': 'GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_VIEWER',
    'usage_other_wh': 'GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE SZL_EE_APP',
    'usage_other_db': 'GRANT USAGE ON DATABASE SNOWFLAKE TO ROLE SZL_EE_APP',
    'imported_privs_snowflake': 'GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE SZL_EE_APP',
    'select_other_table_2part': 'GRANT SELECT ON TABLE OTHERDB.T TO ROLE SZL_EE_APP',
    'viewer_select_data': 'GRANT SELECT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_VIEWER',
    'viewer_usage_data_schema': 'GRANT USAGE ON SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_VIEWER',
    'write_stage_app': 'GRANT WRITE ON STAGE SZL_EE_DB.EE_APP.APP_SRC TO ROLE SZL_EE_APP',
    'create_stage_on_schema': 'GRANT CREATE STAGE ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_APP',
    'create_table_on_data': 'GRANT CREATE TABLE ON SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_INGEST',
    'modify_schema': 'GRANT MODIFY ON SCHEMA SZL_EE_DB.EE_DATA TO ROLE SZL_EE_INGEST',
    'monitor_rm': 'GRANT MONITOR ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_APP',
    'embed_streamlit': 'GRANT EMBED ON STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER TO ROLE SZL_EE_VIEWER',
    'hierarchy_with_option': 'GRANT ROLE SZL_EE_APP TO ROLE SYSADMIN WITH GRANT OPTION',
    'hierarchy_viewer': 'GRANT ROLE SZL_EE_VIEWER TO ROLE SYSADMIN',
    'hierarchy_tab_ws': 'GRANT\tROLE\nSZL_EE_APP   TO ROLE SECURITYADMIN',
    'create_table_unqualified': 'CREATE TABLE X (A INT)',
    'create_view_2part_other': 'CREATE VIEW SZL_EE_DB.EE_APP.V AS SELECT * FROM OTHERSCHEMA.T',
    'alter_table_retention': 'ALTER TABLE SZL_EE_DB.EE_DATA.ASSETS SET DATA_RETENTION_TIME_IN_DAYS = 90',
    'alter_table_swap': 'ALTER TABLE SZL_EE_DB.EE_DATA.ASSETS SWAP WITH SZL_EE_DB.EE_DATA.REVISIONS',
    'comment_on_table': "COMMENT ON TABLE SZL_EE_DB.EE_DATA.ASSETS IS 'x'",
    'create_stage_external': "CREATE STAGE SZL_EE_DB.EE_APP.APP_SRC URL = 's3://bucket/x' COMMENT = 'x'",
    'create_wh_big': 'CREATE WAREHOUSE SZL_EE_WH WITH WAREHOUSE_SIZE = X6LARGE AUTO_RESUME = FALSE',
    'create_wh_no_monitor': 'CREATE WAREHOUSE SZL_EE_WH WITH WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 0',
    'create_db_retention90': 'CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 90',
    'create_streamlit_other_wh': "CREATE STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER FROM '@SZL_EE_DB.EE_APP.APP_SRC/v1' MAIN_FILE = 'x.py' QUERY_WAREHOUSE = COMPUTE_WH",
    'put_overwrite_true': "PUT 'file://C:/x/streamlit_app.py' @SZL_EE_DB.EE_APP.APP_SRC/v1 AUTO_COMPRESS = FALSE OVERWRITE = TRUE",
    'put_other_stage': "PUT 'file://C:/x/streamlit_app.py' @~/v1",
    'use_role_accountadmin_lower': 'use role accountadmin',
    'use_role_securityadmin': 'USE ROLE SECURITYADMIN',
    'comment_hides_cluster_by': "CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) --'\nCLUSTER BY (A) --'",
    'slashslash_hides_cluster_by': "CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) //'\nCLUSTER BY (A) //'",
    'dq_ident_hides_cluster_by': 'CREATE TABLE SZL_EE_DB.EE_DATA.T ("A\'" INT) CLUSTER BY ("A\'")',
    'backslash_hides_cluster_by': "CREATE TABLE SZL_EE_DB.EE_DATA.T (A VARCHAR DEFAULT 'x\\'') CLUSTER BY (A) COMMENT = 'y\\''",
    'dollar_hides_cluster_by': "CREATE TABLE SZL_EE_DB.EE_DATA.T (A VARCHAR DEFAULT '$$') CLUSTER BY (A) COMMENT = '$$'",
    'unbalanced_quote': "CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) COMMENT = 'x",
    'table_cluster_by': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) CLUSTER BY (A)',
    'table_change_tracking': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) CHANGE_TRACKING = TRUE',
    'table_retention_90': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (A INT) DATA_RETENTION_TIME_IN_DAYS = 90',
    'table_in_app_schema': 'CREATE TABLE SZL_EE_DB.EE_APP.T (A INT)',
    'table_drop_column_name': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (DROP INT)',
    'table_accountadmin_column_name': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (ACCOUNTADMIN INT)',
    'table_references_other_db': 'CREATE TABLE SZL_EE_DB.EE_DATA.T (X INT REFERENCES OTHERDB.S.T (X))',
    'role_with_tag': "CREATE ROLE SZL_EE_APP COMMENT = 'a' TAG (X = 'b')",
    'db_collation': "CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 1 DEFAULT_DDL_COLLATION = 'x'",
    'schema_collation': "CREATE SCHEMA SZL_EE_DB.EE_APP WITH MANAGED ACCESS DATA_RETENTION_TIME_IN_DAYS = 1 DEFAULT_DDL_COLLATION = 'x'",
    'dup_priv': 'GRANT SELECT, SELECT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_APP',
    'grant_role_to_role_with_option': 'GRANT ROLE SZL_EE_APP TO ROLE SYSADMIN WITH GRANT OPTION',
    'stage_other_name_ok_prefix': "CREATE STAGE SZL_EE_DB.EE_APP.APP_SRC ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE')"}

# Exact refusal reason for selected cases: pins WHICH guard refuses, so a mutant that disables a
# single guard is detected even when another layer would also refuse.
# v0.3.0 additions: everything the kit no longer runs (owner-run in D0) or no longer needs.
ADVERSARIAL.update({
    'create_wh_exact_v012': ("CREATE WAREHOUSE SZL_EE_WH WITH WAREHOUSE_SIZE = XSMALL MAX_CLUSTER_COUNT = 1 "
                             "MIN_CLUSTER_COUNT = 1 AUTO_SUSPEND = 60 AUTO_RESUME = FALSE INITIALLY_SUSPENDED = TRUE "
                             "RESOURCE_MONITOR = SZL_EE_RM STATEMENT_TIMEOUT_IN_SECONDS = 120 "
                             "STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = 60 COMMENT = 'SZL synthetic pilot 1'"),
    'create_role_pilot': "CREATE ROLE SZL_EE_OWNER COMMENT = 'x'",
    'use_role_sysadmin': 'USE ROLE SYSADMIN',
    'use_role_useradmin': 'USE ROLE USERADMIN',
    'v3_hierarchy_app_to_sysadmin': 'GRANT ROLE SZL_EE_APP TO ROLE SYSADMIN',
    'grant_operate_operator': 'GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR',
    'grant_usage_wh_ingest': 'GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_INGEST',
    'show_params_other_wh': "SHOW PARAMETERS LIKE 'STATEMENT%' IN WAREHOUSE COMPUTE_WH",
    'show_params_account': 'SHOW PARAMETERS IN ACCOUNT',
    'grant_create_db_on_account_setup': 'GRANT CREATE DATABASE ON ACCOUNT TO ROLE SZL_EE_SETUP',
})

REASON_PINS = {
    'esc_SYSADMIN_to_APP': 'role grant not permitted',
    'grant_role_to_role_with_option': 'denied token: \\bWITH\\s+GRANT\\s+OPTION\\b',
    'insert_to_app': 'privilege not permitted for this grantee and object',
    'operate_wh_to_app': 'grant target not in privilege matrix',
    'usage_other_db': 'grant target not in privilege matrix',
    'viewer_select_data': 'grant target not in privilege matrix',
    'grant_on_all_tables': 'malformed or unsupported GRANT form',
    'malformed_no_on': 'malformed or unsupported GRANT form',
    'dup_priv': 'duplicate privilege in GRANT',
    'comment_hides_cluster_by': 'comment inside statement',
    'slashslash_hides_cluster_by': 'comment inside statement',
    'dq_ident_hides_cluster_by': 'quoted identifiers not permitted',
    'backslash_hides_cluster_by': 'backslash not permitted (string-escape lexing differs)',
    'dollar_hides_cluster_by': 'dollar-quoted text not permitted',
    'unbalanced_quote': 'unbalanced string literal',
    'lookalike_dotless_i_create': 'non-ASCII or control character outside string literals',
    'nbsp_whitespace': 'non-ASCII or control character outside string literals',
    'create_table_unqualified': 'CREATE TABLE must name SZL_EE_DB.EE_DATA.<table>',
    'table_cluster_by': 'table option not permitted (background cost or policy)',
    'table_change_tracking': 'table option not permitted (background cost or policy)',
    'table_retention_90': 'DATA_RETENTION_TIME_IN_DAYS must be 1',
    'role_with_tag': 'statement type not permitted',
    'db_collation': 'CREATE DATABASE form not permitted',
    'schema_collation': 'CREATE SCHEMA form not permitted',
    'create_wh_big': 'statement type not permitted',
    'create_wh_exact_v012': 'statement type not permitted',
    'create_role_pilot': 'statement type not permitted',
    'use_role_sysadmin': 'statement type not permitted',
    'use_role_useradmin': 'statement type not permitted',
    'v3_hierarchy_app_to_sysadmin': 'role grant not permitted',
    'grant_operate_operator': 'grant target not in privilege matrix',
    'grant_usage_wh_ingest': 'grant target not in privilege matrix',
    'create_stage_external': 'CREATE STAGE differs from the kit statement',
    'create_streamlit_other_wh': 'CREATE STREAMLIT differs from the kit statement',
    'put_overwrite_true': 'PUT form not permitted'}

POSITIVE = {
    'comma_no_space': 'GRANT SELECT,INSERT ON TABLE SZL_EE_DB.EE_DATA.ASSETS TO ROLE SZL_EE_INGEST',
    'lowercase': 'grant usage on database szl_ee_db to role szl_ee_app',
    'tabs_newlines': 'GRANT\tUSAGE\nON DATABASE SZL_EE_DB\r\nTO ROLE SZL_EE_APP;',
    'use_role_setup': 'USE ROLE SZL_EE_SETUP',
    'show_params': "SHOW PARAMETERS LIKE 'STATEMENT%' IN WAREHOUSE SZL_EE_WH",
    'ownership': 'GRANT OWNERSHIP ON DATABASE SZL_EE_DB TO ROLE SZL_EE_OWNER REVOKE CURRENT GRANTS',
    'nonascii_in_literal': "CREATE DATABASE SZL_EE_DB DATA_RETENTION_TIME_IN_DAYS = 1 COMMENT = 'synthetic — only'",
    'table_refs_same_db': 'CREATE TABLE SZL_EE_DB.EE_DATA.V (X INT REFERENCES SZL_EE_DB.EE_DATA.T (X))',
    'put_task7_path': "PUT 'file://C:/Users/x/Documents/Codex/2026-10-13/task-7/public/streamlit_app.py' @SZL_EE_DB.EE_APP.APP_SRC/v1 AUTO_COMPRESS = FALSE OVERWRITE = FALSE"}


class TestPrivilegeGuardAdversarial(unittest.TestCase):
    def test_every_adversarial_statement_refused(self):
        for name, stmt in ADVERSARIAL.items():
            with self.assertRaises(K.RefusedStatement, msg=name):
                D.deploy_check(stmt)

    def test_refusal_reasons_pinned(self):
        for name, reason in REASON_PINS.items():
            with self.assertRaises(K.RefusedStatement, msg=name) as cm:
                D.deploy_check(ADVERSARIAL[name])
            self.assertEqual(str(cm.exception), reason, name)

    def test_positive_forms_accepted(self):
        for name, stmt in POSITIVE.items():
            try:
                D.deploy_check(stmt)
            except K.RefusedStatement as exc:
                self.fail("%s refused: %s" % (name, exc))

    def test_every_matrix_cell_accepted_and_nothing_wider(self):
        n = 0
        for (otype, obj), cells in D.GRANT_MATRIX.items():
            for role, privs in cells.items():
                for p in sorted(privs):
                    D.deploy_check("GRANT %s ON %s %s TO ROLE %s" % (p, otype, obj, role))
                    n += 1
                for other in ("SZL_EE_OWNER", "SZL_EE_INGEST", "SZL_EE_APP", "SZL_EE_VIEWER", "SYSADMIN"):
                    if other not in cells:
                        with self.assertRaises(K.RefusedStatement):
                            D.deploy_check("GRANT %s ON %s %s TO ROLE %s" % (sorted(privs)[0], otype, obj, other))
        self.assertEqual(n, 31)   # v0.3.0: the two warehouse USAGE cells are owner-run (D0)
        # VIEWER never gets data, warehouse or write access
        for (otype, obj), cells in D.GRANT_MATRIX.items():
            if "SZL_EE_VIEWER" in cells:
                self.assertEqual(cells["SZL_EE_VIEWER"], {"USAGE"})
                self.assertNotIn(otype, ("TABLE", "WAREHOUSE"))
                self.assertNotEqual(obj, "SZL_EE_DB.EE_DATA")

    def test_role_grants_are_empty_in_v030(self):
        self.assertEqual(D.ROLE_GRANTS, frozenset())
        for admin in ("ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN", "USERADMIN", "SYSADMIN"):
            for pilot in D.ROLES:
                with self.assertRaises(K.RefusedStatement, msg=(admin, pilot)):
                    D.deploy_check("GRANT ROLE %s TO ROLE %s" % (admin, pilot))
        for pilot in D.ROLES:
            for target in ("SYSADMIN", "SECURITYADMIN", "USERADMIN", "PUBLIC", "ORGADMIN") + tuple(r for r in D.ROLES if r != pilot):
                with self.assertRaises(K.RefusedStatement, msg=(pilot, target)):
                    D.deploy_check("GRANT ROLE %s TO ROLE %s" % (pilot, target))

    def test_plan_statements_equal_kit_constants(self):
        plan = [s for _, s in D.build_plan(None) if not s.startswith("--")]
        for const in (D.STAGE_SQL, D.STREAMLIT_SQL):
            self.assertIn(const, plan)
        self.assertNotIn(D.WAREHOUSE_SQL, plan)
        self.assertFalse(any(K.normalize_sql(s).startswith(("CREATE WAREHOUSE", "CREATE ROLE", "GRANT ROLE",
                                                            "USE ROLE SYSADMIN", "USE ROLE USERADMIN"))
                             for s in plan))
        self.assertIn(D.WAREHOUSE_SQL, D.manual_accountadmin_block(None))


class TestAllowlistMultiStatement(unittest.TestCase):
    """Kit survivor M02 (allowlist ';' check removed). The ';' check is REDUNDANT for the
    accept/refuse decision because no allowlist entry contains ';' (first test), so membership
    alone already refuses any normalised text containing ';'. The second test pins the refusal
    reason, which is the only observable difference, so M02 is now killed."""

    def test_no_allowlist_entry_contains_semicolon(self):
        for al in (V.ALLOWLIST, S.ALLOWLIST):
            self.assertTrue(al)
            self.assertFalse(any(";" in a for a in al))

    def test_multi_statement_reason_is_specific(self):
        for chk, al in ((V.CHECK, V.ALLOWLIST), (S.CHECK, S.ALLOWLIST)):
            first = sorted(al)[0]
            for bad in (first + ";;", first + "; DROP DATABASE X", first + " ; " + first):
                with self.assertRaises(K.RefusedStatement, msg=bad) as cm:
                    chk(bad)
                self.assertEqual(str(cm.exception), "multiple statements", bad)
            chk(first + " ;")  # a single trailing ';' is stripped and allowed


# ---------------------------------------------------------------- v0.3.0 progress file, run id, owner sheet
class TestProgressAndRunId(TempDirCase):
    RID = "20261023T101500Z-0a1b2c3d"

    def _argv(self, out=True):
        mp, ap = make_bundle(self.d)
        argv = ["--execute", "--manifest", mp, "--approval-file", ap]
        dj = os.path.join(self.d, "deploy.json")
        return (argv + ["--out", dj] if out else argv), dj

    def test_progress_file_final_record_and_fsync(self):
        argv, dj = self._argv()
        calls = []
        orig = K.os.fsync
        K.os.fsync = lambda fd: calls.append(fd)
        try:
            fc = FakeConnector(base_responder())
            code, out = run(D, argv, fc, today=TODAY)
        finally:
            K.os.fsync = orig
        self.assertEqual(code, K.EXIT_OK, out)
        ev = _jload(dj)
        self.assertFalse(ev["in_progress"])
        self.assertIsNone(ev["pending"])
        self.assertEqual(ev["exit_code"], K.EXIT_OK)
        self.assertEqual(ev["phase"], "done")
        self.assertEqual(len(ev["executed"]), len(fc.conn.executed))
        n_changes = len([s for _, s in D.build_plan({"schema.sql": D.split_sql(SYN_SCHEMA.split("\n", 1)[1]),
                                                     "reader_grants.sql": D.split_sql(SYN_GRANTS.split("\n", 1)[1]),
                                                     "_uploads": ["x"]}) if not s.startswith("--")])
        self.assertGreaterEqual(len(calls), 2 * n_changes)   # one fsync before and one after every statement
        self.assertFalse(os.path.exists(dj + ".tmp"))
        self.assertNotIn(FAKE_ACCOUNT, open(dj, encoding="utf-8").read())

    def test_killed_deploy_leaves_pending_record(self):
        argv, dj = self._argv()
        base = base_responder()

        def r(n, c):
            if n.startswith("CREATE SCHEMA"):
                raise KeyboardInterrupt
            return base(n, c)
        with self.assertRaises(KeyboardInterrupt):
            run(D, argv, FakeConnector(r), today=TODAY)
        ev = _jload(dj)
        self.assertTrue(ev["in_progress"])
        self.assertEqual(ev["phase"], "changes")
        self.assertTrue(K.normalize_sql(ev["pending"]["statement"]).startswith("CREATE SCHEMA"))
        self.assertTrue(any(K.normalize_sql(e["statement"]).startswith("CREATE DATABASE") for e in ev["executed"]))

    def test_failed_statement_recorded_with_readback_required(self):
        argv, dj = self._argv()
        code, _ = run(D, argv, FakeConnector(base_responder(fail_on="CREATE SCHEMA")), today=TODAY)
        self.assertEqual(code, K.EXIT_EXEC_ERROR)
        ev = _jload(dj)
        self.assertFalse(ev["in_progress"])
        self.assertTrue(ev["readback_required"])
        self.assertTrue(K.normalize_sql(ev["pending"]["statement"]).startswith("CREATE SCHEMA"))
        self.assertNotIn(SENTINEL, open(dj, encoding="utf-8").read())

    def test_existing_out_never_overwritten(self):
        argv, dj = self._argv()
        with open(dj, "w", encoding="utf-8") as f:
            f.write("keep")
        fc = FakeConnector(base_responder())
        code, _ = run(D, argv, fc, today=TODAY)
        self.assertEqual(code, K.EXIT_REFUSED)
        self.assertEqual(fc.calls, [])
        with open(dj, encoding="utf-8") as f:
            self.assertEqual(f.read(), "keep")

    def test_run_id_in_query_tags(self):
        env = {"SZL_EE_RUN_ID": self.RID}
        argv, _ = self._argv(out=False)
        fc = FakeConnector(base_responder())
        code, out = run(D, argv, fc, env=env, today=TODAY)
        self.assertEqual(code, K.EXIT_OK, out)
        self.assertEqual(fc.calls[0]["session_parameters"]["QUERY_TAG"], "szl-ee-kit-deploy:" + self.RID)
        self.assertEqual(json.loads(out)["run_id"], self.RID)
        for mod, tag in ((V, "szl-ee-kit-verify-readonly"), (S, "szl-ee-kit-shutdown-verify")):
            fc = FakeConnector(base_responder())
            run(mod, [], fc, env=env)
            self.assertEqual(fc.calls[0]["session_parameters"]["QUERY_TAG"], tag + ":" + self.RID)
            fc = FakeConnector(base_responder())
            run(mod, [], fc)
            self.assertEqual(fc.calls[0]["session_parameters"]["QUERY_TAG"], tag)

    def test_malformed_run_id_refused_before_connect(self):
        argv, _ = self._argv(out=False)
        for bad in ("x", "20261023T101500Z-0A1B2C3D", "20261023T101500Z-0a1b2c3d; DROP", "../20261023T101500Z-0a1b2c3d"):
            env = {"SZL_EE_RUN_ID": bad}
            fc = FakeConnector(base_responder())
            code, out = run(D, argv, fc, env=env, today=TODAY)
            self.assertEqual(code, K.EXIT_REFUSED, bad)
            self.assertEqual(fc.calls, [], bad)
            self.assertIn("SZL_EE_RUN_ID malformed", out)
            for mod in (V, S):
                fc = FakeConnector(base_responder())
                code, out = run(mod, [], fc, env=env)
                self.assertEqual(code, K.EXIT_REFUSED, (mod.__name__, bad))
                self.assertEqual(fc.calls, [], (mod.__name__, bad))


class TestOwnerSheetMatchesKit(unittest.TestCase):
    """SNOWSIGHT_SETUP.sql (the owner sheet) must contain every CREATE/GRANT the kit expects the owner to
    have run, keep its fail-closed first line, and never grant an admin role or MODIFY/OWNERSHIP/ALL."""

    def _sheet(self):
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SNOWSIGHT_SETUP.sql")
        with open(p, encoding="utf-8") as f:
            text = f.read()
        first, rest = text.split("\n", 1)
        self.assertTrue(first.startswith("<<") and first.endswith(">>"), "fail-closed first line missing")
        return [K.normalize_sql(s) for s in D.split_sql(rest)]

    def test_owner_block_and_grants_in_sheet(self):
        sheet = set(self._sheet())
        for s in D.manual_accountadmin_block({"credits": 10, "until": "2026-11-21"}):
            if s.startswith(("CREATE ", "GRANT ")):
                self.assertIn(K.normalize_sql(s), sheet, s)
        for _, _, s in D.OWNER_RUN_GRANTS:
            self.assertIn(K.normalize_sql(s), sheet, s)

    def test_sheet_never_grants_admin_or_wide_privileges(self):
        for s in self._sheet():
            if s.startswith("GRANT "):
                self.assertFalse(re.match(r"GRANT ROLE (ACCOUNTADMIN|SECURITYADMIN|SYSADMIN|USERADMIN|ORGADMIN) ", s), s)
                self.assertFalse(set(s.split()) & {"MODIFY", "OWNERSHIP", "ALL", "FUTURE", "PUBLIC"}, s)
                self.assertNotIn("GRANT OPTION", s)
            if s.startswith("CREATE USER "):
                self.assertIn("DISABLED = TRUE", s)
                self.assertIn("DEFAULT_SECONDARY_ROLES = ()", s)
                self.assertNotIn("RSA_PUBLIC_KEY", s)
                self.assertNotIn("PASSWORD", s)


if __name__ == "__main__":
    unittest.main(verbosity=1)
