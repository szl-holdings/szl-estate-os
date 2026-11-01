"""Regression tests for mutation evidence, including broken test infrastructure."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock as mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_sweep as sweep


def result(code=0, tests=10, failures=0, errors=0):
    return {"exit_code": code, "tests": tests, "failures": failures, "errors": errors,
            "detail": "synthetic test result"}


class MutationEvidence(unittest.TestCase):
    def test_full_passing_suite_is_survivor(self):
        self.assertEqual(sweep.classify_run(result(), 10), "SURVIVED")

    def test_assertion_failure_is_kill(self):
        self.assertEqual(sweep.classify_run(result(1, failures=1), 10), "KILLED")

    def test_syntax_import_timeout_signal_and_error_only_are_invalid(self):
        for run in (result(1, tests=0), result(None, tests=0), result(-9),
                    result(1, errors=1), result(1, tests=9, failures=1)):
            with self.subTest(run=run):
                self.assertEqual(sweep.classify_run(run, 10), "INVALID")

    def test_empty_suite_is_invalid(self):
        self.assertEqual(sweep.classify_run(result(tests=0), 0), "INVALID")

    def test_every_real_mutant_compiles_and_has_unique_anchor(self):
        clean = (Path(sweep.HERE) / sweep.CORE).read_text()
        self.assertEqual(len(sweep.MUTANTS), 48)
        self.assertEqual(len({m[0] for m in sweep.MUTANTS}), 48)
        for mid, _, old, new in sweep.MUTANTS:
            with self.subTest(mutant=mid):
                self.assertEqual(clean.count(old), 1)
                compile(clean.replace(old, new), sweep.CORE, "exec")

    def run_small_sweep(self, mutant_result, replacement="return False"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence_core.py").write_text("def check():\n    return True\n")
            with mock.patch.object(sweep, "HERE", tmp), \
                 mock.patch.object(sweep, "FILES", ("evidence_core.py",)), \
                 mock.patch.object(sweep, "MUTANTS", [("M00", "synthetic", "return True", replacement)]), \
                 mock.patch.object(sweep, "run_suite", side_effect=[result(), mutant_result]), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = sweep.main(str(root / "results.json"))
            return code, json.loads((root / "results.json").read_text())

    def test_survivor_causes_nonzero_exit_and_is_recorded(self):
        code, doc = self.run_small_sweep(result())
        self.assertEqual(code, 1)
        self.assertEqual(doc["summary"]["SURVIVED"], 1)

    def test_invalid_execution_causes_nonzero_exit(self):
        code, doc = self.run_small_sweep(result(1, tests=0))
        self.assertEqual(code, 1)
        self.assertEqual(doc["summary"]["INVALID"], 1)

    def test_syntax_failure_never_counts_as_kill(self):
        code, doc = self.run_small_sweep(result(1, failures=1), "return (")
        self.assertEqual(code, 1)
        self.assertEqual(doc["summary"]["INVALID"], 1)

    def test_success_records_baseline_and_input_digests(self):
        code, doc = self.run_small_sweep(result(1, failures=1))
        self.assertEqual(code, 0)
        self.assertEqual(doc["baseline"]["tests"], 10)
        self.assertEqual(doc["summary"], {"KILLED": 1, "SURVIVED": 0, "INVALID": 0})
        self.assertEqual(len(doc["input_sha256"]["evidence_core.py"]), 64)

    def test_failed_baseline_stops_before_mutants(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(sweep, "run_suite", return_value=result(1, failures=1)) as run:
            output = Path(tmp) / "failed.json"
            with self.assertRaises(SystemExit):
                sweep.main(str(output))
            self.assertEqual(run.call_count, 1)
            self.assertEqual(json.loads(output.read_text())["status"], "ERROR")

    def test_unexpected_subprocess_error_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(sweep, "run_suite", side_effect=OSError("synthetic launch failure")):
            output = Path(tmp) / "failed.json"
            with self.assertRaises(OSError):
                sweep.main(str(output))
            doc = json.loads(output.read_text())
            self.assertFalse(doc["completed"])
            self.assertEqual(doc["error_type"], "OSError")


if __name__ == "__main__":
    unittest.main()
