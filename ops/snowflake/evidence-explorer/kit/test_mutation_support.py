import os
from pathlib import Path
import sys
import tempfile
import unittest
import unittest.mock as mock
import json

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_support as support
import mutation_sweep_go as runner_sweep
import mutation_sweep_kit as kit_sweep


class EvidenceClassification(unittest.TestCase):
    def run_script(self, text, timeout=5):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "suite.py").write_text(text)
            return support.run_suite("suite.py", tmp, {"PATH": os.defpath}, timeout)

    def test_real_assertion_failure_is_kill(self):
        run = self.run_script("import unittest\nclass T(unittest.TestCase):\n def test_one(self): self.fail('synthetic')\nunittest.main()\n")
        self.assertEqual(support.classification(run, 1), "KILLED")

    def test_import_error_is_invalid(self):
        run = self.run_script("import nonexistent_synthetic_module\n")
        self.assertEqual(support.classification(run, 1), "INVALID")

    def test_error_only_suite_is_invalid(self):
        run = self.run_script("import unittest\nclass T(unittest.TestCase):\n def test_one(self): raise RuntimeError('synthetic')\nunittest.main()\n")
        self.assertEqual(support.classification(run, 1), "INVALID")

    def test_passing_suite_is_survivor_and_valid_baseline(self):
        run = self.run_script("import unittest\nclass T(unittest.TestCase):\n def test_one(self): self.assertTrue(True)\nunittest.main()\n")
        self.assertEqual(support.classification(run, 1), "SURVIVED")
        self.assertTrue(support.baseline_passed(run))

    def test_no_tests_is_not_a_baseline(self):
        run = self.run_script("import unittest\nunittest.main()\n")
        self.assertFalse(support.baseline_passed(run))

    def test_timeout_is_invalid(self):
        run = self.run_script("import time\ntime.sleep(5)\n", timeout=0.02)
        self.assertEqual(support.classification(run, 1), "INVALID")

    def test_kit_refuses_existing_result_before_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "existing.json"
            output.write_text("historical evidence")
            with mock.patch.object(kit_sweep, "run_suite") as run, self.assertRaises(SystemExit):
                kit_sweep.main(str(output))
            run.assert_not_called()
            self.assertEqual(output.read_text(), "historical evidence")

    def test_kit_baseline_failure_preserves_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "failed.json"
            with mock.patch.object(kit_sweep, "run_suite", return_value={
                    "exit": 1, "tests": 0, "errors": 0, "failures": 0, "tail": "synthetic import failure"}):
                self.assertEqual(kit_sweep.main(str(output)), 2)
            doc = json.loads(output.read_text())
            self.assertEqual(doc["status"], "BASELINE_FAILED")
            self.assertFalse(doc["completed"])

    def test_runner_refuses_existing_result_before_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "existing.json"
            output.write_text("historical evidence")
            with mock.patch.object(sys, "argv", ["sweep", tmp, str(output)]), \
                 mock.patch.object(runner_sweep, "run_sweep") as run, self.assertRaises(SystemExit):
                runner_sweep.main()
            run.assert_not_called()
            self.assertEqual(output.read_text(), "historical evidence")

    def test_runner_workdirs_are_unique_cleaned_and_do_not_touch_prior_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp) / "mutants"
            prior.mkdir()
            (prior / "sentinel").write_text("other run")
            paths = []

            def run(source, output, base, work):
                self.assertTrue(Path(work).is_dir())
                paths.append(work)
                return 1

            with mock.patch.object(runner_sweep, "run_sweep", side_effect=run):
                for name in ("one.json", "two.json"):
                    with mock.patch.object(sys, "argv", ["sweep", tmp, str(Path(tmp) / name)]):
                        self.assertEqual(runner_sweep.main(), 1)
            self.assertNotEqual(paths[0], paths[1])
            self.assertTrue(all(not Path(p).exists() for p in paths))
            self.assertEqual((prior / "sentinel").read_text(), "other run")


if __name__ == "__main__":
    unittest.main()
