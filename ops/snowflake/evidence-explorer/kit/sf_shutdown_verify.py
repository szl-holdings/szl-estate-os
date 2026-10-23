#!/usr/bin/env python3
"""Read-only shutdown verifier for the SZL Evidence Explorer pilot (DRAFT 2026-10-21).

Checks (each PASS / FAIL / UNKNOWN):
  W1 pilot warehouse SZL_EE_WH is SUSPENDED
  W2 pilot warehouse auto_resume is false
  W3 no other visible warehouse is STARTED (informational FAIL if any)
  T1 no visible STARTED task uses SZL_EE_WH (could resume it repeatedly)
  R1 resource monitor SZL_EE_RM used_credits <= credit_quota (reports both)
  M1 WAREHOUSE_METERING_HISTORY rows for SZL_EE_WH, last 14 days
     (ACCOUNT_USAGE latency up to 3 h; cloud services up to 6 h - a recent
     session may not appear yet; needs compute, so it is gated and never
     resumes a warehouse)

A PASS here does not promise zero future charges (storage, cloud services,
other resources). Exit codes: 0 all PASS, 1 any FAIL, 2 any UNKNOWN (no FAIL),
3 refused, 4 connector missing / connection failure.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sf_kit_common as K  # noqa: E402

PILOT_WH = "SZL_EE_WH"
STATEMENTS = {
    "show_warehouses": "SHOW WAREHOUSES",
    "show_tasks": "SHOW TASKS IN ACCOUNT",
    "show_monitor": "SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'",
    "metering_14d": ("SELECT START_TIME, END_TIME, CREDITS_USED, CREDITS_USED_COMPUTE, CREDITS_USED_CLOUD_SERVICES "
                     "FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY WHERE WAREHOUSE_NAME = 'SZL_EE_WH' "
                     "AND START_TIME >= DATEADD(DAY, -14, CURRENT_TIMESTAMP()) ORDER BY START_TIME"),
}
ALLOWLIST = frozenset(K.normalize_sql(s) for s in STATEMENTS.values())
CHECK = K.allowlist_check(ALLOWLIST)


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main(argv=None, connector=None, env=None, out=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    ev = {"kit": K.KIT_NAME, "kit_version": K.KIT_VERSION, "script": "sf_shutdown_verify",
          "started_utc": K.utc_now(), "label": "MEASURED by operator run (sanitized)",
          "checks": [], "refusals": [],
          "caveat": "PASS does not guarantee zero future charges; metering latency up to 3 h (6 h cloud services)."}
    out_path = None
    if argv:
        if len(argv) == 2 and argv[0] == "--out":
            out_path = argv[1]
        else:
            ev["refusals"].append("argv refused: only '--out <new file>' is accepted")
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
            ev["connection"] = {"status": "CONNECTOR_NOT_INSTALLED", "error_class": str(exc)}
            ev["exit_code"] = K.EXIT_CONNECTION
            K.emit(ev, env, out, out_path)
            return K.EXIT_CONNECTION
    try:
        conn = K.connect(connector, env, "szl-ee-kit-shutdown-verify")
    except Exception as exc:
        ev["connection"] = dict(status="CONNECTION_FAILED", **K.safe_error(exc))
        ev["exit_code"] = K.EXIT_CONNECTION
        K.emit(ev, env, out, out_path)
        return K.EXIT_CONNECTION
    sess = K.GuardedSession(conn, CHECK)
    add = lambda cid, st, detail, qid=None: ev["checks"].append(
        {"id": cid, "status": st, "detail": detail, "query_id": qid})

    def q(key):
        try:
            cur, qid = sess.run(STATEMENTS[key])
            return K.rows_as_dicts(cur), qid, None
        except K.RefusedStatement:
            raise
        except Exception as exc:
            return None, None, K.safe_error(exc)

    gate = {"allowed": False, "reason": "SHOW WAREHOUSES did not complete"}
    try:
        whs, qid, err = q("show_warehouses")
        if whs is None:
            for cid in ("W1", "W2", "W3"):
                add(cid, "UNKNOWN", {"error": err}, None)
        else:
            gate = K.warehouse_gate(whs)
            ev["warehouse_gate"] = gate
            pilot = [w for w in whs if str(w.get("name", "")).upper() == PILOT_WH]
            if not pilot:
                add("W1", "UNKNOWN", "pilot warehouse not visible to this role", qid)
                add("W2", "UNKNOWN", "pilot warehouse not visible to this role", qid)
            else:
                st = str(pilot[0].get("state", "")).upper()
                add("W1", "PASS" if st == "SUSPENDED" else "FAIL", "state=%s" % st, qid)
                ar = pilot[0].get("auto_resume")
                add("W2", "FAIL" if K.truthy(ar) else ("PASS" if ar is not None else "UNKNOWN"),
                    "auto_resume=%s" % ar, qid)
            others = sorted(str(w.get("name")) for w in whs
                            if str(w.get("name", "")).upper() != PILOT_WH
                            and str(w.get("state", "")).upper() in ("STARTED", "RESUMING"))
            add("W3", "FAIL" if others else "PASS",
                {"other_running_warehouses": others, "scope": "warehouses visible to this role"}, qid)
        tasks, qid, err = q("show_tasks")
        if tasks is None:
            add("T1", "UNKNOWN", {"error": err})
        else:
            hits = [t for t in tasks if str(t.get("warehouse", "")).upper() == PILOT_WH]
            started = [t for t in hits if str(t.get("state", "")).lower() == "started"]
            add("T1", "FAIL" if started else "PASS",
                {"tasks_using_pilot_wh": len(hits), "started": len(started),
                 "scope": "tasks visible to this role"}, qid)
        mons, qid, err = q("show_monitor")
        if mons:  # LIKE treats '_' as a wildcard: exact-name rows only
            mons = [m for m in mons if str(m.get("name", "")).upper() == "SZL_EE_RM"]
        if not mons:
            add("R1", "UNKNOWN", {"error": err} if err else "SZL_EE_RM not visible", qid)
        else:
            used, quota = _num(mons[0].get("used_credits")), _num(mons[0].get("credit_quota"))
            if used is None or quota is None:
                add("R1", "UNKNOWN", "credit columns unreadable", qid)
            else:
                add("R1", "PASS" if used <= quota else "FAIL",
                    {"used_credits": used, "credit_quota": quota, "remaining": round(quota - used, 6)}, qid)
        if not gate.get("allowed"):
            add("M1", "UNKNOWN", "NOT_RUN: " + gate.get("reason", "gate closed"))
        else:
            rows, qid, err = q("metering_14d")
            if rows is None:
                add("M1", "UNKNOWN", {"error": err})
            else:
                total = sum(_num(r.get("credits_used")) or 0.0 for r in rows)
                add("M1", "PASS", {"hours": len(rows), "credits_used_sum": round(total, 6),
                                   "note": "latency up to 3 h (6 h cloud services); re-run later to reconcile"}, qid)
    except K.RefusedStatement as exc:
        ev["refusals"].append(str(exc))
    finally:
        try:
            conn.close()
        except Exception:
            pass
    ev["refusals"] += [r for r in sess.refused if r not in ev["refusals"]]
    st = [c["status"] for c in ev["checks"]]
    if ev["refusals"]:
        code = K.EXIT_REFUSED
    elif "FAIL" in st:
        code = K.EXIT_FAIL
    elif "UNKNOWN" in st or not st:
        code = K.EXIT_PARTIAL
    else:
        code = K.EXIT_OK
    ev["finished_utc"] = K.utc_now()
    ev["exit_code"] = code
    K.emit(ev, env, out, out_path)
    return code


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    sys.exit(main())
