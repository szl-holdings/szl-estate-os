"""Installed CLI and output behavior; no network or remote writes."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from szl_estate.cli import build_state, main
from szl_estate.inputs import InventorySummary
from szl_estate.storage import load_state


class CliTests(unittest.TestCase):
    def test_empty_inputs_fail_closed_and_are_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "run"
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                result = main(["verify", "--out", str(target)])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(captured.getvalue())["status"], "NOT_RUN")
            state = load_state(target / "estate_state.json")
            self.assertFalse(state.estate_ready)
            self.assertEqual(len(state.evidence), 4)
            for record in state.evidence:
                self.assertEqual(record.status.value, "NOT_RUN")
                self.assertEqual(record.code.value, "OFFLINE_NOT_MEASURED")
                self.assertEqual(record.dimensions.authorization.value, "UNKNOWN")
                self.assertIsNone(record.checked_at_utc)
                self.assertEqual(record.provenance.origin.value, "UNKNOWN")
            first = {p.name: p.read_bytes() for p in target.iterdir()}
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify", "--out", str(target)]), 1)
            self.assertEqual(first, {p.name: p.read_bytes() for p in target.iterdir()})

    def test_installed_module_works_from_an_unrelated_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-m", "szl_estate", "verify"],
                cwd=directory, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "NOT_RUN")
            self.assertTrue((Path(directory) / "outputs/estate_phase0/estate_state.json").is_file())

    def test_missing_input_does_not_create_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                result = main(["verify", "--backend-bundle", str(Path(directory) / "missing.zip"),
                               "--out", str(Path(directory) / "run")])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(captured.getvalue())["status"], "FAIL")

    def test_bad_as_of_fails_without_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "run"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["verify", "--as-of", "not-a-date", "--out", str(target)]), 2)
            self.assertFalse(target.exists())

    def test_timestamp_does_not_manufacture_live_access(self):
        self.assertFalse(build_state(as_of="2026-09-30T05:43:04Z").estate_ready)

    def test_default_time_uses_chronological_order(self):
        summaries = (
            InventorySummary("github_inventory", "2025-01-01T00:00:05Z", "a" * 64, {}),
            InventorySummary("hf_historical_inventory", "2025-01-01T00:00:05.000123Z", "b" * 64, {}),
        )
        self.assertEqual(build_state(summaries).generated_at_utc, "2025-01-01T00:00:05.000123Z")

    def test_supplied_fixture_is_not_assigned_library_identity(self):
        summary = InventorySummary("github_inventory", "2025-01-01T00:00:00Z", "a" * 64, {})
        state = build_state((summary,))
        record = next(item for item in state.evidence if item.evidence_id == "historical-0")
        self.assertEqual(record.provenance.origin.value, "UNKNOWN")
        self.assertEqual(record.provenance.reference, "file:supplied-summary")
        self.assertFalse(state.estate_ready)


if __name__ == "__main__":
    unittest.main()
