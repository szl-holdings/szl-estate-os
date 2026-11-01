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
    def test_runner_launch_error_preserves_sanitized_failure_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "failed.json"
            with mock.patch.object(sys, "argv", ["sweep", tmp, str(output)]), \
                 mock.patch.object(runner_sweep, "run_sweep", side_effect=OSError("private exception detail")):
                self.assertEqual(runner_sweep.main(), 1)
            doc = json.loads(output.read_text())
            self.assertEqual(doc, {"status": "ERROR", "completed": False, "error_type": "OSError"})

    def test_runner_error_cannot_overwrite_a_concurrent_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"

            def race(*args):
                output.write_text("other writer's report")
                raise OSError("synthetic")

            with mock.patch.object(sys, "argv", ["sweep", tmp, str(output)]), \
                 mock.patch.object(runner_sweep, "run_sweep", side_effect=race):
                self.assertEqual(runner_sweep.main(), 1)
            self.assertEqual(output.read_text(), "other writer's report")

    def test_runner_uses_the_same_snapshotted_tests_for_every_mutant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, work = root / "source", root / "work"
            source.mkdir()
            work.mkdir()
            (source / "szl_ee_go.py").write_text("value = True\n")
            (source / "test_szl_ee_go.py").write_text("# original tests\n")
            (source / "itest_output_no_env.txt").write_text("original fixture\n")
            seen = []

            def run(directory, env):
                seen.append((Path(directory) / "test_szl_ee_go.py").read_bytes())
                (source / "test_szl_ee_go.py").write_text("changed while running\n")
                return {"exit": 0 if len(seen) == 1 else 1, "tests": 1,
                        "failures": 0 if len(seen) == 1 else 1, "errors": 0, "tail": "synthetic"}

            output = root / "report.json"
            with mock.patch.object(runner_sweep, "gates", return_value=(True, {})), \
                 mock.patch.object(runner_sweep, "MUTANTS", [("SYNTH", "synthetic", "True", "False")]), \
                 mock.patch.object(runner_sweep, "run_suite", side_effect=run):
                self.assertEqual(runner_sweep.run_sweep(str(source), str(output), str(root), str(work)), 0)
            self.assertEqual(seen, [b"# original tests\n", b"# original tests\n"])
            doc = json.loads(output.read_text())
            import hashlib
            self.assertEqual(doc["tests_sha256"], hashlib.sha256(seen[0]).hexdigest())
            self.assertEqual(set(doc["input_sha256"]), {"szl_ee_go.py", "test_szl_ee_go.py", "itest_output_no_env.txt"})

    def test_runner_mutants_have_unique_ids_anchors_and_valid_syntax(self):
        source = Path(__file__).with_name("szl_ee_go.py").read_text()
        self.assertEqual(len(runner_sweep.MUTANTS), 83)
        self.assertEqual(len({item[0] for item in runner_sweep.MUTANTS}), 83)
        for name, _, old, new in runner_sweep.MUTANTS:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1)
                compile(source.replace(old, new), "szl_ee_go.py", "exec")

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
