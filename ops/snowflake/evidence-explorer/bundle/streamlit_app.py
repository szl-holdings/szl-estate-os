"""SZL Evidence Explorer - Streamlit in Snowflake app (pilot 1 DRAFT, NOT DEPLOYED).

Thin UI over evidence_core. Data comes ONLY from live queries issued through
the Snowflake-supplied active session. There is no cache, no fallback dataset
and no connection code: if the Snowflake dependency or session is unavailable
the app shows a visible failure state and stops.
Rendering uses text widgets only (no unsafe HTML, no HTML components).
"""
import datetime as _dt

import streamlit as st

import evidence_core as core

st.set_page_config(page_title="SZL Evidence Explorer (synthetic pilot)")
st.warning(core.SYNTHETIC_LABEL)
st.caption("Single-tenant pilot: one private synthetic dataset, one intended "
           "audience. No multi-tenant isolation is claimed. Score displays are "
           "descriptive only and are not model-promotion decisions.")


def get_live_session():
    """Return (session, None) or (None, reason). Never constructs credentials."""
    try:
        from snowflake.snowpark.context import get_active_session
    except Exception:
        return None, "SNOWFLAKE_DEPENDENCY_UNAVAILABLE"
    try:
        return get_active_session(), None
    except Exception:
        return None, "NO_ACTIVE_SNOWFLAKE_SESSION"


SESSION, SESSION_ERROR = get_live_session()
if SESSION is None:
    st.error("LIVE QUERY UNAVAILABLE (%s). This app only shows results of live "
             "Snowflake queries. No data is shown; nothing is cached or "
             "simulated." % SESSION_ERROR)
    st.stop()


def run(spec):
    """Execute one parameterized QuerySpec live; returns a core.ScreenState."""
    try:
        records = SESSION.sql(spec.sql, params=list(spec.params)).collect()
        rows = core.rows_from_records([r.as_dict() for r in records])
    except Exception as exc:
        return core.screen_state([], type(exc).__name__, spec.limit)
    return core.screen_state(rows, None, spec.limit)


def show(state, spec=None, rows=None):
    if state.state == "ERROR":
        st.error(state.message)
        return False
    if state.state == "EMPTY":
        st.info(state.message)
        return False
    st.caption(state.message)
    st.dataframe(rows if rows is not None else state.rows)
    if spec is not None:
        with st.expander("Query provenance (parameterized; values bound separately)"):
            st.code(spec.sql, language="sql")
            st.text("bound parameters: %r" % (spec.params,))
    return True


def now_utc():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SCREENS = ("1. Asset inventory", "2. Evidence detail", "3. Revision comparison",
           "4. Missing / stale / restricted evidence",
           "5. Data quality and ingestion status", "6. Cost and run information")
screen = st.sidebar.radio("Screen", SCREENS)
st.header(screen)

# Exclusions are policy input, so an incomplete result cannot authorize display.
# Fetch them before rendering inventory, selectors, revisions, or observations.
DISPLAY_EXCLUSIONS = []
if screen in SCREENS[:4]:
    exclusions = run(core.q_exclusions())
    if exclusions.state == "ERROR":
        st.error(exclusions.message)
        st.stop()
    if exclusions.truncated:
        st.error("DISPLAY EXCLUSIONS INCOMPLETE: result limit reached. No asset, "
                 "revision, or observation data is shown until a complete "
                 "exclusion result is available.")
        st.stop()
    DISPLAY_EXCLUSIONS = exclusions.rows


def run_visible(spec):
    """Filter inventory and revision rows before rendering or selection."""
    state = run(spec)
    if state.state == "ERROR":
        return state
    rows, _ = core.apply_display_exclusions(state.rows, DISPLAY_EXCLUSIONS)
    visible = core.screen_state(rows, None, None)
    if state.truncated:
        visible = visible._replace(
            truncated=True,
            message=visible.message + " Source result limit reached; more may exist.")
    return visible


if screen == SCREENS[0]:
    provider = st.selectbox("Provider", ("ALL",) + core.PROVIDERS)
    spec = core.q_asset_inventory(None if provider == "ALL" else provider)
    show(run_visible(spec), spec)

elif screen in (SCREENS[1], SCREENS[2]):
    inv = run_visible(core.q_asset_inventory())
    if show(inv):
        candidates = [r["asset_id"] for r in inv.rows
                      if screen == SCREENS[1] or (r["revision_count"] or 0) >= 2]
        if not candidates:
            st.info("No asset has two accepted revisions; nothing to compare.")
        else:
            asset_id = st.selectbox("Asset", candidates)
            revs = run_visible(core.q_asset_revisions(asset_id))
            if show(revs):
                rev_ids = [r["revision_id"] for r in revs.rows]
                if screen == SCREENS[1]:
                    rid = st.selectbox("Revision", rev_ids)
                    spec = core.q_evidence_detail(rid)
                    detail = run(spec)
                    if detail.state == "OK":
                        try:
                            shown, hidden = core.apply_display_exclusions(
                                core.present_joined(detail.rows, now_utc()), DISPLAY_EXCLUSIONS)
                        except Exception as exc:
                            st.error("PRESENTATION FAILED: %s" % type(exc).__name__)
                        else:
                            st.caption("%d row(s) hidden by display exclusions." % hidden)
                            show(core.screen_state(shown, None, None), spec)
                    else:
                        show(detail)
                else:
                    a = st.selectbox("Revision A", rev_ids, index=0)
                    b = st.selectbox("Revision B", rev_ids, index=min(1, len(rev_ids) - 1))
                    if a == b:
                        st.info("Select two different revisions.")
                    else:
                        spec = core.q_revision_comparison(a, b)
                        both = run(spec)
                        if both.state == "OK":
                            p = core.present_joined(both.rows, now_utc())
                            p, hidden = core.apply_display_exclusions(p, DISPLAY_EXCLUSIONS)
                            cmp = core.compare_revisions(
                                [x for x in p if x["revision_id"] == a],
                                [x for x in p if x["revision_id"] == b])
                            st.caption("Descriptive comparison only; %d row(s) hidden by "
                                       "display exclusions." % hidden)
                            show(core.screen_state(cmp, None, None), spec)
                        else:
                            show(both)

elif screen == SCREENS[3]:
    obs_spec = core.q_all_observations()
    obs = run(obs_spec)
    inv = run_visible(core.q_asset_inventory(limit=core.MAX_QUERY_LIMIT))
    failed = [s for s in (obs, inv) if s.state == "ERROR"]
    if failed:
        st.error(failed[0].message)
    else:
        presented = core.present_joined(obs.rows, now_utc())
        presented, hidden = core.apply_display_exclusions(presented, DISPLAY_EXCLUSIONS)
        if obs.truncated or inv.truncated:
            st.warning("Result limit reached: this gap list may be incomplete.")
        st.subheader("Observation-level gaps")
        show(core.screen_state(core.classify_gaps(presented), None, None), obs_spec)
        st.subheader("Asset-level gaps")
        show(core.screen_state(core.inventory_gaps(inv.rows, presented), None, None))
        st.caption("%d observation(s) hidden by display exclusions." % hidden)

elif screen == SCREENS[4]:
    st.subheader("Ingestion batches")
    spec = core.q_ingestion_batches()
    show(run(spec), spec)
    st.subheader("Rejected rows (reason codes and digests only; raw values are "
                 "never stored)")
    spec = core.q_rejected_rows()
    show(run(spec), spec)

else:
    status = core.cost_status(None)
    st.info(status["message"])
    st.text("state: %s" % status["state"])
