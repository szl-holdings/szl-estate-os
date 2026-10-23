#!/usr/bin/env python3
"""Read-only Snowflake account verifier for the SZL Evidence Explorer pilot.

DRAFT 2026-10-21. Run by the account owner on his own machine, with his own
connection. It never resumes, creates, alters or drops anything.

Connection: ONLY the Snowflake Python connector's own config (connections.toml
named connection via SZL_SF_CONNECTION_NAME, or the connector's documented
default). Connection parameters are never accepted on argv and never printed.

Exit codes: 0 verified (every check ran), 2 partial (some NOT_RUN/ERROR),
3 refused (a guard refused a statement or argv), 4 connector missing or
connection failure.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sf_kit_common as K  # noqa: E402

STATEMENTS = {
    # id: (statement, warehouse requirement, doc basis)
    "show_warehouses": ("SHOW WAREHOUSES",
                        "none expected",
                        "REPORTED: SHOW is a metadata command; the SHOW WAREHOUSES page fetched 2026-10-21 does not state it explicitly"),
    "show_databases": ("SHOW DATABASES",
                       "none expected",
                       "REPORTED: as above; not stated on a fetched page"),
    "show_resource_monitors": ("SHOW RESOURCE MONITORS",
                               "none",
                               "docs show-resource-monitors: 'doesn't require a running warehouse'"),
    "context": ("SELECT CURRENT_ACCOUNT(), CURRENT_ACCOUNT_NAME(), CURRENT_ORGANIZATION_NAME(), "
                "CURRENT_REGION(), CURRENT_ROLE(), CURRENT_VERSION(), CURRENT_WAREHOUSE()",
                "UNKNOWN (treated as possibly needing compute; gated)",
                "context functions; warehouse need not established in fetched docs"),
    "metering_30d": ("SELECT WAREHOUSE_NAME, SUM(CREDITS_USED) AS CREDITS_USED, MIN(START_TIME) AS FIRST_HOUR, "
                     "MAX(END_TIME) AS LAST_HOUR FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY "
                     "WHERE START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP()) GROUP BY WAREHOUSE_NAME "
                     "ORDER BY WAREHOUSE_NAME",
                     "needs a warehouse (gated)",
                     "docs warehouse_metering_history: latency up to 3 h (6 h for cloud services)"),
    "remaining_balance_7d": ("SELECT DATE, CURRENCY, FREE_USAGE_BALANCE, CAPACITY_BALANCE, "
                             "ON_DEMAND_CONSUMPTION_BALANCE FROM SNOWFLAKE.ORGANIZATION_USAGE.REMAINING_BALANCE_DAILY "
                             "WHERE DATE >= DATEADD(DAY, -7, CURRENT_DATE()) ORDER BY DATE DESC LIMIT 7",
                             "needs a warehouse (gated)",
                             "docs remaining_balance_daily: latency up to 72 h; availability for trial accounts UNKNOWN; "
                             "trial doc: ACCOUNTADMIN sees the balance tile in Snowsight"),
}
ALLOWLIST = frozenset(K.normalize_sql(s) for s, _, _ in STATEMENTS.values())
CHECK = K.allowlist_check(ALLOWLIST)
GATED = ("context", "metering_30d", "remaining_balance_7d")

WH_COLS = ("name", "state", "type", "size", "min_cluster_count", "max_cluster_count", "auto_suspend",
           "auto_resume", "is_current", "is_default", "resource_monitor", "owner", "resumed_on", "updated_on")
DB_COLS = ("name", "created_on", "owner", "retention_time", "kind")
RM_COLS = ("name", "credit_quota", "used_credits", "remaining_credits", "level", "frequency", "start_time",
           "end_time", "suspend_at", "suspend_immediately_at")


def _account_match(expected, account, org, name):
    if not expected:
        return None
    exp = expected.strip().upper()
    cands = set()
    if account:
        cands.add(str(account).upper())
    if org and name:
        cands.add(("%s-%s" % (org, name)).upper())
    return exp in cands


def main(argv=None, connector=None, env=None, out=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    ev = {"kit": K.KIT_NAME, "kit_version": K.KIT_VERSION, "script": "sf_verify_account_readonly",
          "started_utc": K.utc_now(), "label": "MEASURED by operator run (sanitized)",
          "checks": [], "refusals": [], "warehouse_gate": None}
    out_path = None
    if argv:
        if len(argv) == 2 and argv[0] == "--out":
            out_path = argv[1]
        else:
            ev["refusals"].append("argv refused: only '--out <new file>' is accepted; "
                                  "connection parameters come from connector config only")
            ev["exit_code"] = K.EXIT_REFUSED
            K.emit(ev, env, out)
            return K.EXIT_REFUSED
    try:
        ev["run_id"] = K.run_id(env)
    except K.RefusedStatement as exc:
        ev["refusals"].append(str(exc))
        ev["exit_code"] = K.EXIT_REFUSED
        K.emit(ev, env, out, out_path)
        return K.EXIT_REFUSED
    if connector is None:
        try:
            connector = K.load_connector()
        except K.ConnectorUnavailable as exc:
            ev["connection"] = {"status": "CONNECTOR_NOT_INSTALLED", "error_class": str(exc),
                                "hint": "install snowflake-connector-python in a dedicated venv; nothing was run"}
            ev["exit_code"] = K.EXIT_CONNECTION
            K.emit(ev, env, out, out_path)
            return K.EXIT_CONNECTION
    try:
        conn = K.connect(connector, env, "szl-ee-kit-verify-readonly")
    except Exception as exc:
        ev["connection"] = dict(status="CONNECTION_FAILED", **K.safe_error(exc))
        ev["exit_code"] = K.EXIT_CONNECTION
        K.emit(ev, env, out, out_path)
        return K.EXIT_CONNECTION
    ev["connection"] = {"status": "CONNECTED"}
    sess = K.GuardedSession(conn, CHECK)
    gate = {"allowed": False, "reason": "SHOW WAREHOUSES did not complete", "current_warehouse_state": None}
    try:
        for cid in ("show_warehouses", "show_databases", "show_resource_monitors") + GATED:
            stmt, need, basis = STATEMENTS[cid]
            rec = {"id": cid, "warehouse_requirement": need, "doc_basis": basis}
            if cid in GATED and not gate["allowed"]:
                rec.update(status="NOT_RUN", detail="skipped: " + gate["reason"])
                ev["checks"].append(rec)
                continue
            try:
                cur, qid = sess.run(stmt)
                rows = K.rows_as_dicts(cur)
            except K.RefusedStatement as exc:
                rec.update(status="REFUSED", detail=str(exc))
                ev["checks"].append(rec)
                continue
            except Exception as exc:
                rec.update(status="ERROR", **K.safe_error(exc))
                ev["checks"].append(rec)
                continue
            rec.update(status="DONE", query_id=qid, row_count=len(rows))
            if cid == "show_warehouses":
                rec["data"] = K.keep_columns(rows, WH_COLS)
                gate = K.warehouse_gate(rows)
                ev["warehouse_gate"] = gate
            elif cid == "show_databases":
                rec["data"] = K.keep_columns(rows, DB_COLS)
            elif cid == "show_resource_monitors":
                rec["data"] = K.keep_columns(rows, RM_COLS)
            elif cid == "context":
                r = rows[0] if rows else {}
                vals = list(r.values())
                acct, acct_name, org, region, role, version, wh = (vals + [None] * 7)[:7]
                rec["data"] = {"account": K.redact_identifier(acct),
                               "account_name": K.redact_identifier(acct_name),
                               "organization": K.redact_identifier(org),
                               "region": region, "role": role, "version": version,
                               "current_warehouse": wh,
                               "account_matches_expected": _account_match(
                                   env.get(K.EXPECTED_ACCOUNT_ENV), acct, org, acct_name)}
            else:
                rec["data"] = K.keep_columns(rows, tuple(rows[0].keys()) if rows else ())
            ev["checks"].append(rec)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    ev["refusals"] += sess.refused
    statuses = [c["status"] for c in ev["checks"]]
    if "REFUSED" in statuses or sess.refused:
        code = K.EXIT_REFUSED
    elif statuses and all(s == "DONE" for s in statuses):
        code = K.EXIT_OK
    else:
        code = K.EXIT_PARTIAL
    ev["finished_utc"] = K.utc_now()
    ev["exit_code"] = code
    K.emit(ev, env, out, out_path)
    return code


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    sys.exit(main())
