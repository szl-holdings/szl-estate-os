"""Run the local evidence steps and write a hash-chained JSON-lines receipt.

LOCAL EVIDENCE ONLY. No network, no Snowflake, no credentials, no signing.
Steps (fixed order): fixture_rebuild, unit_tests, integration_snowflake
(expected NOT_RUN, exit 3), mutation_sweep, verifier_tamper_tests,
emulator_check (EMULATOR evidence
only; NOT_RUN when no emulator interpreter is supplied), then receipt_end.

Usage:
  python -I -B run_local_evidence.py [--emulator-python PATH] [--out DIR]
Writes DIR/local_evidence_receipt.jsonl and DIR/logs/<step>.stdout|.stderr.
Interpreter paths are recorded as tokens (<python>, <emulator-python>) so no
home-directory path enters the receipt.
"""
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = "szl.ee.local_evidence_receipt/v1"
GENESIS = "0" * 64
SIGNATURE_NOT_RUN = "NOT_RUN (signing requires owner approval)"
STEP_ORDER = ("fixture_rebuild", "unit_tests", "integration_snowflake",
              "mutation_sweep", "verifier_tamper_tests", "emulator_check", "receipt_end")
ENTRY_KEYS = ("schema", "seq", "step", "command", "exit_code", "expected_exit_code",
              "status", "evidence_label", "stdout_sha256", "stderr_sha256",
              "stdout_bytes", "stderr_bytes", "input_sha256", "summary", "utc_time",
              "prev_entry_sha256", "entry_sha256")
END_KEYS = ("schema", "seq", "step", "step_count", "chain_head_sha256", "signature",
            "utc_time", "prev_entry_sha256", "entry_sha256")
CORE_INPUTS = ("evidence_core.py", "make_fixture.py", "fixture_v1.json",
               "test_evidence_core.py", "schema.sql", "reader_grants.sql",
               "streamlit_app.py")
STEP_INPUTS = {
    "fixture_rebuild": ("make_fixture.py", "fixture_v1.json"),
    "unit_tests": CORE_INPUTS,
    "integration_snowflake": ("test_integration_snowflake.py", "evidence_core.py",
                              "make_fixture.py"),
    "mutation_sweep": CORE_INPUTS + ("mutation_sweep.py",),
    "verifier_tamper_tests": ("test_verify_receipt.py", "verify_receipt.py",
                              "run_local_evidence.py"),
    "emulator_check": ("test_emulator_fakesnow.py", "evidence_core.py", "schema.sql",
                       "make_fixture.py", "fixture_v1.json"),
}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return sha256_bytes(fh.read())


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def seal(entry):
    """Return entry with entry_sha256 = sha256(canonical(entry without it))."""
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    out = dict(body)
    out["entry_sha256"] = sha256_bytes(canonical(body))
    return out


def utc_now():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_unittest(stderr):
    ran = re.search(r"^Ran (\d+) tests? in", stderr, re.M)
    tail = re.search(r"^(OK|FAILED)(?: \((.*)\))?\s*$", stderr, re.M)
    s = {"ran": int(ran.group(1)) if ran else None, "result": tail.group(1) if tail else None,
         "failures": 0, "errors": 0, "skipped": 0}
    if tail and tail.group(2):
        for k, v in re.findall(r"(\w+)=(\d+)", tail.group(2)):
            if k in ("failures", "errors", "skipped"):
                s[k] = int(v)
    m = re.search(r"INTEGRATION STATUS: NOT_RUN \((\d+) of (\d+) skipped", stderr)
    s["not_run"] = int(m.group(1)) if m else 0
    return s


def decide(step, exit_code, summary):
    if step == "integration_snowflake":
        if exit_code == 3 and summary.get("not_run", 0) > 0:
            return "NOT_RUN"
        if exit_code == 0 and summary.get("skipped") == 0 and summary.get("not_run") == 0:
            return "PASS"
        return "FAIL"
    if step == "emulator_check" and summary.get("not_run_reason"):
        return "NOT_RUN"
    if exit_code != 0:
        return "FAIL"
    if step in ("unit_tests", "verifier_tamper_tests"):
        ok = (summary.get("result") == "OK" and summary.get("failures") == 0
              and summary.get("errors") == 0 and summary.get("skipped") == 0
              and (summary.get("ran") or 0) > 0)
        return "PASS" if ok else "FAIL"
    if step == "mutation_sweep":
        ok = (summary.get("SURVIVED") == 0 and summary.get("INVALID") == 0
              and (summary.get("KILLED") or 0) > 0)
        return "PASS" if ok else "FAIL"
    if step == "fixture_rebuild":
        return "PASS" if summary.get("matches_committed") is True else "FAIL"
    if step == "emulator_check":
        return "PASS" if summary.get("FAIL", 1) == 0 else "FAIL"
    return "FAIL"


def run(argv, env, cwd):
    r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=3600)
    return r.returncode, r.stdout, r.stderr


def main(args):
    out_dir = os.path.join(HERE, "receipt")
    emu = None
    i = 0
    while i < len(args):
        if args[i] == "--out":
            out_dir = os.path.abspath(args[i + 1]); i += 2
        elif args[i] == "--emulator-python":
            emu = args[i + 1]; i += 2
        else:
            raise SystemExit("unknown argument: %s" % args[i])
    logs = os.path.join(out_dir, "logs")
    tmp = os.path.join(out_dir, "tmp")
    for d in (out_dir, logs, tmp):
        os.makedirs(d, exist_ok=True)
    env = dict(os.environ)
    env["TEMP"] = env["TMP"] = tmp
    py = sys.executable
    rebuilt = os.path.join(tmp, "fixture_rebuild.json")
    plan = [
        ("fixture_rebuild", [py, "-I", "-B", "make_fixture.py", rebuilt],
         ["<python>", "-I", "-B", "make_fixture.py", "<tmp>/fixture_rebuild.json"], 0),
        ("unit_tests", [py, "-I", "-B", "test_evidence_core.py", "-v"],
         ["<python>", "-I", "-B", "test_evidence_core.py", "-v"], 0),
        ("integration_snowflake", [py, "-I", "-B", "test_integration_snowflake.py", "-v"],
         ["<python>", "-I", "-B", "test_integration_snowflake.py", "-v"], 3),
        ("mutation_sweep", [py, "-I", "-B", "mutation_sweep.py",
                            os.path.join(tmp, "mutation_results.json")],
         ["<python>", "-I", "-B", "mutation_sweep.py", "<tmp>/mutation_results.json"], 0),
        ("verifier_tamper_tests", [py, "-I", "-B", "test_verify_receipt.py", "-v"],
         ["<python>", "-I", "-B", "test_verify_receipt.py", "-v"], 0),
        ("emulator_check", None if emu is None else
         [emu, "-I", "-B", "test_emulator_fakesnow.py", os.path.join(tmp, "emulator_results.json")],
         ["<emulator-python>", "-I", "-B", "test_emulator_fakesnow.py",
          "<tmp>/emulator_results.json"], 0),
    ]
    entries = []
    prev = GENESIS
    for seq, (step, argv, shown, expected) in enumerate(plan):
        inputs = {f: sha256_file(os.path.join(HERE, f)) for f in STEP_INPUTS[step]
                  if os.path.exists(os.path.join(HERE, f))}
        label = "MEASURED_LOCAL"
        if argv is None:
            code, so, se = None, b"", b""
            summary = {"not_run_reason": "no emulator interpreter supplied"}
            label = "NOT_RUN"
        else:
            code, so, se = run(argv, env, HERE)
            text_e = se.decode("utf-8", "replace")
            text_o = so.decode("utf-8", "replace")
            if step in ("unit_tests", "integration_snowflake", "verifier_tamper_tests"):
                summary = parse_unittest(text_e)
            elif step == "mutation_sweep":
                first = text_o.strip().splitlines()[:1]
                summary = json.loads(first[0]) if first else {}
            elif step == "fixture_rebuild":
                summary = {"rebuilt_sha256": sha256_file(rebuilt) if os.path.exists(rebuilt) else None,
                           "committed_sha256": inputs.get("fixture_v1.json")}
                summary["matches_committed"] = (summary["rebuilt_sha256"] is not None and
                                                summary["rebuilt_sha256"] == summary["committed_sha256"])
            else:
                last = [l for l in text_o.strip().splitlines() if l.startswith("{")][-1:]
                summary = json.loads(last[0]) if last else {}
                label = "EMULATOR (fakesnow %s)" % summary.get("fakesnow_version", "UNKNOWN")
        with open(os.path.join(logs, step + ".stdout"), "wb") as fh:
            fh.write(so)
        with open(os.path.join(logs, step + ".stderr"), "wb") as fh:
            fh.write(se)
        status = decide(step, code, summary) if argv is not None else "NOT_RUN"
        entry = seal({"schema": SCHEMA, "seq": seq, "step": step, "command": shown,
                      "exit_code": code, "expected_exit_code": expected, "status": status,
                      "evidence_label": label, "stdout_sha256": sha256_bytes(so),
                      "stderr_sha256": sha256_bytes(se), "stdout_bytes": len(so),
                      "stderr_bytes": len(se), "input_sha256": inputs, "summary": summary,
                      "utc_time": utc_now(), "prev_entry_sha256": prev})
        entries.append(entry)
        prev = entry["entry_sha256"]
    end = seal({"schema": SCHEMA, "seq": len(entries), "step": "receipt_end",
                "step_count": len(entries), "chain_head_sha256": prev,
                "signature": SIGNATURE_NOT_RUN, "utc_time": utc_now(),
                "prev_entry_sha256": prev})
    entries.append(end)
    # Hygiene gate: no local home/workspace path may appear in any captured log.
    needles = [os.path.expanduser("~"), HERE, os.path.dirname(HERE)]
    leaks = []
    for name in sorted(os.listdir(logs)):
        with open(os.path.join(logs, name), "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        for n in needles:
            if n and len(n) > 3 and (n in text or n.replace("\\", "\\\\") in text):
                leaks.append(name)
    path = os.path.join(out_dir, "local_evidence_receipt.jsonl")
    with open(path, "wb") as fh:
        for e in entries:
            fh.write(canonical(e) + b"\n")
    for e in entries[:-1]:
        sys.stdout.write("%-22s exit=%s status=%s %s\n" % (e["step"], e["exit_code"],
                                                          e["status"], e["evidence_label"]))
    sys.stdout.write("receipt %s sha256=%s head=%s\n" % (
        os.path.basename(path), sha256_file(path), end["entry_sha256"]))
    if leaks:
        sys.stdout.write("HYGIENE FAIL: local path found in logs: %s\n" % ", ".join(sorted(set(leaks))))
        return 1
    return 0 if all(e["status"] in ("PASS", "NOT_RUN") for e in entries[:-1]) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
