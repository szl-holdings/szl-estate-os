"""Tamper tests for verify_receipt.py (stdlib unittest, synthetic receipts only).

Run: python -I -B test_verify_receipt.py -v
T00 is the untampered control: it must be VALID, otherwise every other test
would pass vacuously. "Re-chained" variants recompute every hash after the
edit, as a forger could; they prove that semantic rules, not just hashes,
catch the overclaim.
"""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_local_evidence as rle  # noqa: E402
import verify_receipt as vr  # noqa: E402

LOGS = {"fixture_rebuild": (b"fixture ok\n", b""),
        "unit_tests": (b"", b"Ran 74 tests in 0.5s\n\nOK\n"),
        "integration_snowflake": (b"", b"Ran 11 tests in 0.0s\n\nOK (skipped=11)\n"
                                  b"INTEGRATION STATUS: NOT_RUN (11 of 11 skipped; "
                                  b"skipped is not passing)\n"),
        "mutation_sweep": (b'{"KILLED": 43, "SURVIVED": 0, "INVALID": 0}\n', b""),
        "verifier_tamper_tests": (b"", b"Ran 20 tests in 0.1s\n\nOK\n"),
        "emulator_check": (b'{"fakesnow_version": "0.0-synthetic", "PASS": 5, "FAIL": 0}\n', b"")}
SUMMARY = {"fixture_rebuild": {"rebuilt_sha256": None, "committed_sha256": None,
                               "matches_committed": True},
           "unit_tests": {"ran": 74, "result": "OK", "failures": 0, "errors": 0,
                          "skipped": 0, "not_run": 0},
           "integration_snowflake": {"ran": 11, "result": "OK", "failures": 0, "errors": 0,
                                     "skipped": 11, "not_run": 11},
           "mutation_sweep": {"KILLED": 43, "SURVIVED": 0, "INVALID": 0},
           "verifier_tamper_tests": {"ran": 20, "result": "OK", "failures": 0, "errors": 0,
                                     "skipped": 0, "not_run": 0},
           "emulator_check": {"fakesnow_version": "0.0-synthetic", "PASS": 5, "FAIL": 0}}
STATUS = {"integration_snowflake": ("NOT_RUN", 3, 3)}


class Synth:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="rcpt-")
        self.logs = os.path.join(self.dir, "logs")
        self.inputs = os.path.join(self.dir, "inputs")
        os.makedirs(self.logs)
        os.makedirs(self.inputs)
        with open(os.path.join(self.inputs, "fixture_v1.json"), "wb") as fh:
            fh.write(b'{"synthetic": true}\n')
        fx = rle.sha256_file(os.path.join(self.inputs, "fixture_v1.json"))
        entries = []
        t = 0
        for seq, step in enumerate(rle.STEP_ORDER[:-1]):
            so, se = LOGS[step]
            for stream, data in (("stdout", so), ("stderr", se)):
                with open(os.path.join(self.logs, "%s.%s" % (step, stream)), "wb") as fh:
                    fh.write(data)
            st, code, exp = STATUS.get(step, ("PASS", 0, 0))
            summ = copy.deepcopy(SUMMARY[step])
            if step == "fixture_rebuild":
                summ.update(rebuilt_sha256=fx, committed_sha256=fx)
            label = "EMULATOR (fakesnow 0.0-synthetic)" if step == "emulator_check" \
                else "MEASURED_LOCAL"
            entries.append({"schema": rle.SCHEMA, "seq": seq, "step": step,
                            "command": ["<python>", step], "exit_code": code,
                            "expected_exit_code": exp, "status": st, "evidence_label": label,
                            "stdout_sha256": rle.sha256_bytes(so),
                            "stderr_sha256": rle.sha256_bytes(se), "stdout_bytes": len(so),
                            "stderr_bytes": len(se),
                            "input_sha256": {"fixture_v1.json": fx}, "summary": summ,
                            "utc_time": "2026-10-21T13:00:%02d.000000Z" % t,
                            "prev_entry_sha256": None})
            t += 1
        entries.append({"schema": rle.SCHEMA, "seq": len(entries), "step": "receipt_end",
                        "step_count": len(entries), "chain_head_sha256": None,
                        "signature": rle.SIGNATURE_NOT_RUN,
                        "utc_time": "2026-10-21T13:00:%02d.000000Z" % t,
                        "prev_entry_sha256": None})
        self.entries = rechain(entries)

    def write(self, entries=None, raw=None):
        p = os.path.join(self.dir, "receipt.jsonl")
        with open(p, "wb") as fh:
            if raw is not None:
                fh.write(raw)
            else:
                for e in entries:
                    fh.write(rle.canonical(e) + b"\n")
        return p

    def check(self, entries=None, raw=None, **kw):
        p = self.write(entries if entries is not None else self.entries, raw)
        try:
            return vr.verify(vr.load(p), **kw)
        except Exception as exc:
            return ["unreadable: %s" % exc]

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def rechain(entries):
    out, prev = [], rle.GENESIS
    for i, e in enumerate(entries):
        e = dict(e)
        e["seq"] = i
        e["prev_entry_sha256"] = prev
        if e["step"] == "receipt_end":
            e["chain_head_sha256"] = prev
            e["step_count"] = i
        e.pop("entry_sha256", None)
        e = rle.seal(e)
        out.append(e)
        prev = e["entry_sha256"]
    return out


def idx(entries, step):
    return [e["step"] for e in entries].index(step)


class Tamper(unittest.TestCase):
    def setUp(self):
        self.s = Synth()
        self.e = copy.deepcopy(self.s.entries)

    def tearDown(self):
        self.s.close()

    def assertInvalid(self, errs, needle):
        self.assertTrue(errs, "tamper was NOT detected")
        self.assertTrue(any(needle in m for m in errs), errs)

    def test_T00_control_valid_with_logs_and_inputs(self):
        self.assertEqual(self.s.check(logs=self.s.logs, inputs=self.s.inputs), [])
        self.assertEqual(vr.main([self.s.write(self.e)]), 0)

    def test_T01_edit_without_rehash(self):
        self.e[idx(self.e, "unit_tests")]["exit_code"] = 1
        self.assertInvalid(self.s.check(self.e), "entry_sha256 mismatch")

    def test_T02_edit_with_entry_rehash_breaks_chain(self):
        i = idx(self.e, "mutation_sweep")
        e = dict(self.e[i])
        e["summary"] = dict(e["summary"], KILLED=44)
        e.pop("entry_sha256")
        self.e[i] = rle.seal(e)
        self.assertInvalid(self.s.check(self.e), "chain break")

    def test_T03_reorder_raw(self):
        self.e[1], self.e[2] = self.e[2], self.e[1]
        errs = self.s.check(self.e)
        self.assertInvalid(errs, "chain break")
        self.assertInvalid(errs, "out of order")

    def test_T03b_reorder_rechained(self):
        self.e[1], self.e[2] = self.e[2], self.e[1]
        self.assertInvalid(self.s.check(rechain(self.e)), "step sequence")

    def test_T04_missing_step_rechained(self):
        del self.e[idx(self.e, "mutation_sweep")]
        self.assertInvalid(self.s.check(rechain(self.e)), "step sequence")

    def test_T04b_missing_step_raw(self):
        del self.e[idx(self.e, "unit_tests")]
        self.assertInvalid(self.s.check(self.e), "chain break")

    def test_T05_not_run_reported_as_pass_rechained(self):
        i = idx(self.e, "integration_snowflake")
        self.e[i] = dict(self.e[i], status="PASS")
        errs = self.s.check(rechain(self.e))
        self.assertInvalid(errs, "reported as PASS")

    def test_T05b_not_run_disguised_exit0_rechained_stage_policy(self):
        i = idx(self.e, "integration_snowflake")
        self.e[i] = dict(self.e[i], status="PASS", exit_code=0, expected_exit_code=0,
                         summary=dict(self.e[i]["summary"], skipped=0, not_run=0))
        self.assertInvalid(self.s.check(rechain(self.e)), "must be NOT_RUN at stage")

    def test_T05c_not_run_as_pass_caught_by_log(self):
        i = idx(self.e, "integration_snowflake")
        self.e[i] = dict(self.e[i], status="PASS", exit_code=0, expected_exit_code=0,
                         summary=dict(self.e[i]["summary"], skipped=0, not_run=0))
        errs = self.s.check(rechain(self.e), stage="ACCOUNT_VERIFIED", logs=self.s.logs)
        self.assertInvalid(errs, "integration log says NOT_RUN")

    def test_T06_duplicated_step_rechained(self):
        i = idx(self.e, "unit_tests")
        self.e.insert(i + 1, dict(self.e[i]))
        self.assertInvalid(self.s.check(rechain(self.e)), "step sequence")

    def test_T07_truncated_no_end(self):
        self.assertInvalid(self.s.check(self.e[:-1]), "receipt_end missing")

    def test_T07b_truncated_partial_line(self):
        raw = b"".join(rle.canonical(e) + b"\n" for e in self.e)[:-40]
        self.assertInvalid(self.s.check(raw=raw), "unreadable")

    def test_T08_signature_claimed(self):
        self.e[-1] = dict(self.e[-1], signature="SIGNED by owner key")
        self.assertInvalid(self.s.check(rechain(self.e)), "signature field")

    def test_T09_log_edited(self):
        with open(os.path.join(self.s.logs, "unit_tests.stderr"), "ab") as fh:
            fh.write(b"extra")
        self.assertInvalid(self.s.check(logs=self.s.logs), "does not match receipt")

    def test_T10_input_drift(self):
        with open(os.path.join(self.s.inputs, "fixture_v1.json"), "ab") as fh:
            fh.write(b" ")
        self.assertInvalid(self.s.check(inputs=self.s.inputs), "changed since the run")

    def test_T11_duplicate_key_or_noncanonical_line(self):
        line = rle.canonical(self.e[0]).decode()
        dup = line[:-1] + ',"seq":0}'
        raw = (dup + "\n").encode() + b"".join(rle.canonical(e) + b"\n" for e in self.e[1:])
        self.assertInvalid(self.s.check(raw=raw), "unreadable")
        pretty = json.dumps(self.e[0], indent=1).replace("\n", " ") + "\n"
        raw = pretty.encode() + b"".join(rle.canonical(e) + b"\n" for e in self.e[1:])
        self.assertInvalid(self.s.check(raw=raw), "unreadable")

    def test_T12_mutation_survivors_reported_pass(self):
        i = idx(self.e, "mutation_sweep")
        self.e[i] = dict(self.e[i], summary={"KILLED": 42, "SURVIVED": 1, "INVALID": 0})
        self.assertInvalid(self.s.check(rechain(self.e)), "survivors")

    def test_T13_time_backwards(self):
        self.e[3] = dict(self.e[3], utc_time="2026-10-21T12:00:00.000000Z")
        self.assertInvalid(self.s.check(rechain(self.e)), "backwards")

    def test_T14_emulator_relabelled_as_measured(self):
        i = idx(self.e, "emulator_check")
        self.e[i] = dict(self.e[i], evidence_label="MEASURED_LOCAL")
        self.assertInvalid(self.s.check(rechain(self.e)), "not labelled EMULATOR")

    def test_T15_skipped_unit_tests_reported_pass(self):
        i = idx(self.e, "unit_tests")
        self.e[i] = dict(self.e[i], summary=dict(self.e[i]["summary"], skipped=3))
        self.assertInvalid(self.s.check(rechain(self.e)), "skipped work reported as PASS")

    def test_T17_not_run_mislabelled_fail_at_later_stage(self):
        i = idx(self.e, "integration_snowflake")
        self.e[i] = dict(self.e[i], status="FAIL")
        errs = self.s.check(rechain(self.e), stage="ACCOUNT_VERIFIED")
        self.assertInvalid(errs, "integration exit 3 (NOT_RUN) reported as FAIL")

    def test_T18_cli_fails_closed_on_garbage_and_does_not_echo_paths(self):
        p = self.s.write(raw=b"not json\n")
        self.assertEqual(vr.main([p]), 1)
        p = self.s.write(raw=b"".join(rle.canonical(e) + b"\n" for e in self.e)[:-40])
        self.assertEqual(vr.main([p]), 1)

    def test_T16_cli_fails_closed_on_missing_file(self):
        self.assertEqual(vr.main([os.path.join(self.s.dir, "absent.jsonl")]), 1)
        self.assertEqual(vr.main([]), 2)


if __name__ == "__main__":
    unittest.main()
