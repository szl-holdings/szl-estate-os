"""Snowflake integration checks (mission section 8, account part) - NOT_RUN by default.

An inherited environment is not a live switch. The process opens a session only
when argv contains --live-approved AND all four variables below are set:
  SZL_EE_INTEGRATION_APPROVAL_REF   approval reference for this exact run
  SZL_EE_SNOWFLAKE_CONNECTION_NAME  name of a connection in the owner's local
                                    Snowflake connections config (credentials
                                    stay there; this file never reads secrets)
  SZL_EE_EXPECTED_ACCOUNT_SHA256    sha256 of the upper-case expected account
  SZL_EE_EXPECTED_WAREHOUSE         expected dedicated warehouse name
run_local_evidence.py does not pass --live-approved and does not forward those
variables. A failed identity check raises before any MERGE. Failures and errors
exit 1 even when later checks skip. A skipped test is NOT_RUN. It is never a pass.
Run: python -I -B test_integration_snowflake.py -v
"""
import hashlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_core as ec  # noqa: E402
import make_fixture as mf  # noqa: E402

REQUIRED_ENV = ("SZL_EE_INTEGRATION_APPROVAL_REF", "SZL_EE_SNOWFLAKE_CONNECTION_NAME",
                "SZL_EE_EXPECTED_ACCOUNT_SHA256", "SZL_EE_EXPECTED_WAREHOUSE")
LIVE_SWITCH = "--live-approved"
FORBIDDEN_ROLES = ("ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "ORGADMIN")


def _consume_live_switch(argv):
    kept = []
    requested = False
    for arg in argv:
        if arg == LIVE_SWITCH:
            requested = True
        else:
            kept.append(arg)
    return requested, kept


def classify_launch(argv, env):
    """offline unless --live-approved is present. Environment alone is offline."""
    requested, _kept = _consume_live_switch(argv)
    if not requested:
        return "offline"
    if any(not env.get(name) for name in REQUIRED_ENV):
        return "not_configured"
    return "live"


def identity_matches(row, env):
    """True only for the approved account, schema, warehouse and a non-admin role."""
    try:
        digest = hashlib.sha256(str(row.get("A", "")).upper().encode()).hexdigest()
        if digest != env.get("SZL_EE_EXPECTED_ACCOUNT_SHA256"):
            return False
        if (row.get("D"), row.get("S")) != tuple(ec.DEFAULT_DATA_SCHEMA.split(".")):
            return False
        if row.get("W") != env.get("SZL_EE_EXPECTED_WAREHOUSE"):
            return False
        if row.get("R") in FORBIDDEN_ROLES:
            return False
        return True
    except Exception:
        return False


def integration_process_code(result):
    """Failures and errors outrank skips. Exit 3 is a clean NOT_RUN only."""
    if result.failures or result.errors or not result.wasSuccessful():
        return 1
    if result.skipped:
        return 3
    return 0


LAUNCH = classify_launch(sys.argv, os.environ)
_LIVE_REQUESTED, _KEPT_ARGV = _consume_live_switch(sys.argv)
BLOCKER = None
if LAUNCH == "offline":
    BLOCKER = ("NOT_RUN: --live-approved is absent; an inherited environment "
               "is not authorization to open a Snowflake session")
elif LAUNCH == "not_configured":
    _missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    BLOCKER = ("NOT_RUN: integration not approved/configured; missing env vars: "
               + ", ".join(_missing))
else:
    try:
        from snowflake.snowpark import Session  # noqa: F401
    except Exception:
        BLOCKER = "NOT_RUN: snowflake-snowpark-python is not installed in this environment"

MANUAL = "NOT_RUN: requires manual, owner-observed evidence; cannot be asserted from code"
SESSION = None
IDENTITY_OK = None


def setUpModule():
    global SESSION
    if BLOCKER is not None:
        return
    from snowflake.snowpark import Session
    SESSION = Session.builder.config(
        "connection_name", os.environ["SZL_EE_SNOWFLAKE_CONNECTION_NAME"]).create()


def tearDownModule():
    if SESSION is not None:
        SESSION.close()


def q(sql, params=()):
    return [r.as_dict() for r in SESSION.sql(sql, params=list(params)).collect()]


def run_spec(spec):
    return ec.rows_from_records(q(spec.sql, spec.params))


def local_store():
    fx = mf.build()
    store = ec.LocalStore()
    for b in fx["batches"]:
        ec.ingest_batch(store, b["payload"], fx["as_of_utc"],
                        {k: v.encode("utf-8") for k, v in b["local_content"].items()})
    return store


def ensure_identity():
    """One identity read. A failed or uncertain result forbids later MERGEs."""
    global IDENTITY_OK
    if IDENTITY_OK is not None:
        return IDENTITY_OK
    try:
        row = q("SELECT CURRENT_ACCOUNT() AS A, CURRENT_DATABASE() AS D, "
                "CURRENT_SCHEMA() AS S, CURRENT_WAREHOUSE() AS W, CURRENT_ROLE() AS R")[0]
    except Exception:
        IDENTITY_OK = False
        return False
    IDENTITY_OK = identity_matches(row, os.environ)
    return IDENTITY_OK


def load_fixture():
    """Validated rows only, insert-only MERGE, executed as SZL_EE_INGEST."""
    if not ensure_identity():
        raise RuntimeError("identity precondition failed; MERGE not executed")
    store = local_store()
    for table in ("EXCLUSIONS", "RIGHTS_RECORDS", "ASSETS", "REVISIONS", "OBSERVATIONS",
                  "INGESTION_BATCHES", "REJECTED_ROWS"):
        for row in store.rows(table):
            spec = ec.build_merge(table, row)
            q(spec.sql, spec.params)
    return store


def counts():
    return {t: q("SELECT COUNT(*) AS N FROM %s.%s" % (ec.DEFAULT_DATA_SCHEMA, t))[0]["N"]
            for t in ("ASSETS", "REVISIONS", "OBSERVATIONS", "RIGHTS_RECORDS", "EXCLUSIONS",
                      "INGESTION_BATCHES", "REJECTED_ROWS")}


@unittest.skipIf(BLOCKER is not None, BLOCKER or "")
class I_SnowflakeIntegration(unittest.TestCase):
    def test_i01_exact_identity(self):
        row = q("SELECT CURRENT_ACCOUNT() AS A, CURRENT_DATABASE() AS D, "
                "CURRENT_SCHEMA() AS S, CURRENT_WAREHOUSE() AS W, CURRENT_ROLE() AS R")[0]
        self.assertTrue(identity_matches(row, os.environ))

    def test_i02_expected_rows_and_deterministic_queries(self):
        store = load_fixture()
        self.assertEqual(counts(), store.counts())
        for spec in (ec.q_asset_inventory(), ec.q_all_observations(), ec.q_exclusions()):
            self.assertEqual(len(run_spec(spec)), len(ec.local_execute(store, spec)), spec.name)

    def test_i03_duplicate_safe_rerun(self):
        before = counts()
        load_fixture()
        self.assertEqual(counts(), before)

    def test_i04_filters_and_revision_comparison(self):
        store = local_store()
        for spec in (ec.q_asset_inventory("GITHUB"),
                     ec.q_revision_comparison("demo-rev-kit-a", "demo-rev-kit-b")):
            live = sorted(r[k] for r in run_spec(spec) for k in ("asset_id",) if k in r)
            ref = sorted(r[k] for r in ec.rows_from_records(ec.local_execute(store, spec))
                         for k in ("asset_id",) if k in r)
            self.assertEqual(live, ref, spec.name)

    def test_i05_rejected_rows_retained(self):
        rows = run_spec(ec.q_rejected_rows(limit=ec.MAX_QUERY_LIMIT))
        self.assertEqual(len(rows), local_store().counts()["REJECTED_ROWS"])

    def test_i06_least_privilege_viewer(self):
        grants = q("SHOW GRANTS TO ROLE SZL_EE_VIEWER")
        got = sorted((g["privilege"], g["granted_on"]) for g in grants)
        self.assertEqual(got, [("USAGE", "DATABASE"), ("USAGE", "SCHEMA"),
                               ("USAGE", "STREAMLIT")])

    def test_i07_unauthorized_role_denied(self):
        self.skipTest(MANUAL + " (needs a separate viewer-role session; run the "
                      "negative statements in reader_grants.sql and record query IDs)")

    def test_i08_no_unintended_sharing(self):
        shares = q("SHOW SHARES")
        self.assertFalse([s for s in shares if "SZL_EE_DB" in str(s.get("database_name"))])

    def test_i09_query_ids_and_sanitized_evidence(self):
        self.skipTest(MANUAL)

    def test_i10_warehouse_activity_measured_and_suspended(self):
        self.skipTest(MANUAL + " (cost plan owns the procedure)")

    def test_i11_app_fails_visibly_without_live_dependency(self):
        self.skipTest(MANUAL + " (observe deployed app with warehouse unavailable)")


if __name__ == "__main__":
    sys.argv = _KEPT_ARGV
    prog = unittest.main(exit=False)
    res = prog.result
    code = integration_process_code(res)
    if code == 3:
        sys.stderr.write("INTEGRATION STATUS: NOT_RUN (%d of %d skipped; skipped is "
                         "not passing)\n" % (len(res.skipped), res.testsRun))
        sys.exit(3)
    if code == 1:
        sys.stderr.write("INTEGRATION STATUS: FAIL (failures=%d errors=%d skipped=%d)\n" % (
            len(res.failures), len(res.errors), len(res.skipped)))
        sys.exit(1)
    sys.exit(0)
