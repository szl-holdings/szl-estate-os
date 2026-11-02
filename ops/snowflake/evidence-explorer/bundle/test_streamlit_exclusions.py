"""Offline UI policy regression tests; no Snowflake connector or network.

Run the actual application with a synthetic LocalStore and minimal widget
adapters. This is not a Streamlit framework or Snowflake integration test.
"""
import contextlib
import os
from pathlib import Path
import re
import runpy
import sys
import types
import unittest
from unittest.mock import patch

import evidence_core as core
import make_fixture

APP = Path(os.environ.get("SZL_EE_APP_TEST_PATH", Path(__file__).with_name("streamlit_app.py")))
TARGET_ASSET = "demo-gh-evidence-kit"
SCREENS = ("1. Asset inventory", "2. Evidence detail", "3. Revision comparison",
           "4. Missing / stale / restricted evidence")


class StopDisplay(Exception):
    pass


def fixture_store(extra_exclusions=()):
    fixture = make_fixture.build()
    store = core.LocalStore()
    for batch in fixture["batches"]:
        core.ingest_batch(store, batch["payload"], fixture["as_of_utc"],
                          {k: v.encode() for k, v in batch["local_content"].items()})
    if extra_exclusions:
        result = core.ingest_batch(
            store, {"source_revision": "offline-exclusion-regression",
                    "tables": {"EXCLUSIONS": list(extra_exclusions)}}, fixture["as_of_utc"])
        assert result["accepted"] == len(extra_exclusions)
        assert result["rejected"] == 0
    return store


def exclusion(identifier):
    return {"source_identifier": identifier, "exclusion_reason": "OWNER_EXCLUSION",
            "effective_at_utc": "2026-10-01T00:00:00Z", "scope": "DISPLAY"}


class Session:
    def __init__(self, store, fail_exclusions=False, empty_exclusions=False):
        self.store = store
        self.fail_exclusions = fail_exclusions
        self.empty_exclusions = empty_exclusions
        self.calls = []

    def sql(self, sql, params):
        name = re.match(r"/\* q:([a-z_]+) \*/", sql).group(1)
        limit = int(re.search(r"LIMIT (\d+)$", sql).group(1))
        self.calls.append(name)
        if name == "exclusions" and self.fail_exclusions:
            raise RuntimeError("synthetic exclusion query failure")
        rows = ([] if name == "exclusions" and self.empty_exclusions else
                core.local_execute(self.store, core.QuerySpec(name, sql, tuple(params), limit)))
        return types.SimpleNamespace(collect=lambda: [
            types.SimpleNamespace(as_dict=lambda row=row: row) for row in rows])


def render(session, screen):
    frames, errors, choices = [], [], []
    ui = types.ModuleType("streamlit")
    ui.sidebar = types.SimpleNamespace(radio=lambda label, options: screen)

    def selectbox(label, options, index=0):
        choices.append((label, list(options)))
        if label == "Asset" and TARGET_ASSET in options:
            return TARGET_ASSET
        return options[index]

    ui.selectbox = selectbox
    ui.dataframe = lambda rows: frames.append(list(rows))
    ui.expander = lambda *args, **kwargs: contextlib.nullcontext()
    for name in ("set_page_config", "warning", "caption", "header", "code", "text", "subheader", "info"):
        setattr(ui, name, lambda *args, **kwargs: None)
    ui.error = errors.append

    def stop():
        raise StopDisplay()

    ui.stop = stop
    snowflake = types.ModuleType("snowflake")
    snowpark = types.ModuleType("snowflake.snowpark")
    context = types.ModuleType("snowflake.snowpark.context")
    context.get_active_session = lambda: session
    snowflake.snowpark = snowpark
    snowpark.context = context
    modules = {"streamlit": ui, "snowflake": snowflake,
               "snowflake.snowpark": snowpark, "snowflake.snowpark.context": context}
    with patch.dict(sys.modules, modules):
        try:
            runpy.run_path(str(APP), run_name="__exclusion_regression__")
        except StopDisplay:
            pass
    return [row for frame in frames for row in frame], errors, choices


class DisplayExclusionTests(unittest.TestCase):
    def test_truncated_exclusions_block_all_four_screens_before_data_queries(self):
        store = fixture_store([exclusion("000-filler-%03d" % i) for i in range(200)]
                              + [exclusion(TARGET_ASSET)])
        self.assertGreater(len(store.rows("EXCLUSIONS")), core.MAX_QUERY_LIMIT)
        for screen in SCREENS:
            with self.subTest(screen=screen):
                session = Session(store)
                rows, errors, choices = render(session, screen)
                self.assertEqual(rows, [])
                self.assertEqual(choices, [])
                self.assertTrue(any("EXCLUSIONS INCOMPLETE" in error for error in errors))
                self.assertEqual(session.calls, ["exclusions"])

    def test_exact_limit_also_blocks_because_completeness_is_not_proven(self):
        base_count = len(fixture_store().rows("EXCLUSIONS"))
        store = fixture_store([exclusion("000-filler-%03d" % i)
                               for i in range(core.MAX_QUERY_LIMIT - base_count)])
        self.assertEqual(len(store.rows("EXCLUSIONS")), core.MAX_QUERY_LIMIT)
        session = Session(store)
        rows, errors, _ = render(session, SCREENS[0])
        self.assertEqual(rows, [])
        self.assertTrue(any("EXCLUSIONS INCOMPLETE" in error for error in errors))
        self.assertEqual(session.calls, ["exclusions"])

    def test_failed_exclusion_query_blocks_all_four_screens_before_data_queries(self):
        for screen in SCREENS:
            with self.subTest(screen=screen):
                session = Session(fixture_store(), fail_exclusions=True)
                rows, errors, choices = render(session, screen)
                self.assertEqual(rows, [])
                self.assertEqual(choices, [])
                self.assertTrue(any("LIVE QUERY FAILED" in error for error in errors))
                self.assertEqual(session.calls, ["exclusions"])

    def test_complete_exclusions_hide_asset_from_frames_and_selectors(self):
        store = fixture_store([exclusion(TARGET_ASSET)])
        for screen in SCREENS:
            with self.subTest(screen=screen):
                session = Session(store)
                rows, errors, choices = render(session, screen)
                self.assertEqual(errors, [])
                self.assertTrue(rows, "other synthetic rows remain visible")
                self.assertFalse(any(row.get("asset_id") == TARGET_ASSET for row in rows))
                self.assertFalse(any(TARGET_ASSET in options for _, options in choices))
                self.assertEqual(session.calls[0], "exclusions")
                self.assertEqual(session.calls.count("exclusions"), 1)

    def test_complete_exclusions_hide_revision_before_table_and_selection(self):
        target_revision = "demo-rev-kit-a"
        session = Session(fixture_store([exclusion(target_revision)]))
        rows, errors, choices = render(session, SCREENS[1])
        self.assertEqual(errors, [])
        self.assertFalse(any(row.get("revision_id") == target_revision for row in rows))
        self.assertFalse(any(target_revision in options for label, options in choices
                             if label == "Revision"))

    def test_successful_empty_exclusions_allow_inventory_display(self):
        session = Session(fixture_store(), empty_exclusions=True)
        rows, errors, _ = render(session, SCREENS[0])
        self.assertEqual(errors, [])
        self.assertTrue(any(row.get("asset_id") == TARGET_ASSET for row in rows))
        self.assertEqual(session.calls, ["exclusions", "asset_inventory"])


if __name__ == "__main__":
    unittest.main()
