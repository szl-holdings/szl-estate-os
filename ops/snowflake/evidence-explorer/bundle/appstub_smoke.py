"""STUB SMOKE TEST for streamlit_app.py - NOT A SNOWFLAKE TEST.

Uses streamlit.testing.v1.AppTest in a separate local environment. The
"session" in scenarios C/D is a LOCAL STUB backed by evidence_core.LocalStore
and the synthetic fixture. It proves only that the UI wiring renders, shows
the synthetic banner and fails visibly; it proves nothing about Snowflake.
Run (separate env with streamlit): python -I -B appstub_smoke.py
"""
import json
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from streamlit.testing.v1 import AppTest  # noqa: E402

import evidence_core as ec  # noqa: E402
import make_fixture as mf  # noqa: E402

APP = os.path.join(HERE, "streamlit_app.py")
RESULTS = []


def record(name, ok, detail):
    RESULTS.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})


class StubRow:
    def __init__(self, d):
        self._d = d

    def as_dict(self):
        return dict(self._d)


class StubResult:
    def __init__(self, rows):
        self._rows = rows

    def collect(self):
        return [StubRow(r) for r in self._rows]


class StubSession:
    """LOCAL STUB. Interprets only the '/* q:name */' tag via local_execute."""

    def __init__(self, store, fail=False):
        self.store, self.fail, self.calls = store, fail, []

    def sql(self, sql, params=None):
        self.calls.append((sql, tuple(params or ())))
        if self.fail:
            raise RuntimeError("stub failure")
        name = re.match(r"/\* q:([a-z_]+) \*/", sql).group(1)
        limit = int(re.search(r"LIMIT (\d+)$", sql).group(1))
        return StubResult(ec.local_execute(self.store,
                                           ec.QuerySpec(name, sql, tuple(params or ()), limit)))


def fixture_store():
    fx = mf.build()
    st = ec.LocalStore()
    for b in fx["batches"]:
        ec.ingest_batch(st, b["payload"], fx["as_of_utc"],
                        {k: v.encode("utf-8") for k, v in b["local_content"].items()})
    return st


def install_snowflake(get_active_session):
    for m in ("snowflake", "snowflake.snowpark", "snowflake.snowpark.context"):
        sys.modules.pop(m, None)
    if get_active_session is None:
        return
    pkg = types.ModuleType("snowflake")
    sp = types.ModuleType("snowflake.snowpark")
    ctx = types.ModuleType("snowflake.snowpark.context")
    ctx.get_active_session = get_active_session
    pkg.snowpark = sp
    sp.context = ctx
    sys.modules.update({"snowflake": pkg, "snowflake.snowpark": sp,
                        "snowflake.snowpark.context": ctx})


def texts(elements):
    return [str(e.value) for e in elements]


def main():
    # A: dependency absent
    install_snowflake(None)
    at = AppTest.from_file(APP, default_timeout=60).run()
    record("A_dependency_absent_visible_failure",
           not at.exception and any("SNOWFLAKE_DEPENDENCY_UNAVAILABLE" in t for t in texts(at.error))
           and len(at.dataframe) == 0 and ec.SYNTHETIC_LABEL in texts(at.warning),
           {"errors": texts(at.error), "dataframes": len(at.dataframe)})

    # B: dependency present but no active session
    def no_session():
        raise RuntimeError("no session")
    install_snowflake(no_session)
    at = AppTest.from_file(APP, default_timeout=60).run()
    record("B_no_active_session_visible_failure",
           not at.exception and any("NO_ACTIVE_SNOWFLAKE_SESSION" in t for t in texts(at.error))
           and len(at.dataframe) == 0,
           {"errors": texts(at.error), "dataframes": len(at.dataframe)})

    # C: LOCAL STUB session backed by the synthetic fixture: all six screens
    stub = StubSession(fixture_store())
    install_snowflake(lambda: stub)
    at = AppTest.from_file(APP, default_timeout=60).run()
    screens = list(at.sidebar.radio[0].options)
    per = {}
    for i, name in enumerate(screens):
        at.sidebar.radio[0].set_value(name).run()
        per[name] = {"exception": bool(at.exception), "dataframes": len(at.dataframe),
                     "errors": texts(at.error), "info": texts(at.info)[:2],
                     "banner": ec.SYNTHETIC_LABEL in texts(at.warning)}
    ok = (len(screens) == 6 and all(not v["exception"] and not v["errors"] and v["banner"]
                                    for v in per.values())
          and all(per[s]["dataframes"] >= 1 for s in screens[:5])
          and per[screens[5]]["dataframes"] == 0
          and any("not measured" in t for t in per[screens[5]]["info"]))
    bound = all(sql.count("?") == len(p) for sql, p in stub.calls)
    record("C_stub_session_six_screens_render", ok, per)
    record("C_stub_every_issued_query_parameterized", bound and len(stub.calls) > 0,
           {"queries_issued": len(stub.calls)})

    # D: LOCAL STUB session whose queries fail
    bad = StubSession(fixture_store(), fail=True)
    install_snowflake(lambda: bad)
    at = AppTest.from_file(APP, default_timeout=60).run()
    record("D_query_failure_shows_error_no_rows",
           not at.exception and any("LIVE QUERY FAILED: RuntimeError" in t for t in texts(at.error))
           and len(at.dataframe) == 0,
           {"errors": texts(at.error), "dataframes": len(at.dataframe)})

    import streamlit
    out = {"label": "LOCAL STUB SMOKE - NOT A SNOWFLAKE TEST",
           "streamlit_version": streamlit.__version__,
           "python": sys.version.split()[0], "results": RESULTS}
    with open(os.path.join(HERE, "appstub_smoke_results.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(out, fh, indent=1, default=str)
        fh.write("\n")
    for r in RESULTS:
        sys.stdout.write("%s %s\n" % (r["status"], r["check"]))
    sys.exit(0 if all(r["status"] == "PASS" for r in RESULTS) else 1)


if __name__ == "__main__":
    main()
