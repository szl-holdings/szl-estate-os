"""Standard-library evidence classification shared by the kit/runner sweeps."""
import re
import subprocess
import sys


def run_suite(script, directory, env, timeout):
    try:
        process = subprocess.run([sys.executable, "-I", "-B", script], cwd=directory,
                                 env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit": None, "tests": 0, "failures": 0, "errors": 0, "tail": "TIMEOUT"}
    stderr = process.stderr.decode("utf-8", "replace")
    count = re.search(r"^Ran (\d+) tests? in ", stderr, re.M)
    tail = (stderr.strip().splitlines() or [""])[-1]
    failures = re.search(r"failures=(\d+)", tail)
    errors = re.search(r"errors=(\d+)", tail)
    return {"exit": process.returncode, "tests": int(count.group(1)) if count else 0,
            "failures": int(failures.group(1)) if failures else 0,
            "errors": int(errors.group(1)) if errors else 0, "tail": tail}


def classification(run, expected_tests):
    if expected_tests < 1 or run["tests"] != expected_tests:
        return "INVALID"
    if run["exit"] == 0 and run["failures"] == run["errors"] == 0:
        return "SURVIVED"
    if run["exit"] == 1 and run["failures"] > 0:
        return "KILLED"
    return "INVALID"


def baseline_passed(run):
    return run["tests"] > 0 and classification(run, run["tests"]) == "SURVIVED"
