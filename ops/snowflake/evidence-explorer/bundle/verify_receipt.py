"""Offline, fail-closed verifier for local_evidence_receipt.jsonl (stdlib only).

Exit 0 = VALID, 1 = INVALID (reasons printed), 2 = usage error.
Any parse error or unexpected condition is INVALID, never VALID.

Checks: exact key sets and schema; per-entry hash; chain linkage from the
genesis value; seq order; the exact step set and order (no missing, extra,
duplicated or reordered steps); status semantics (PASS needs the expected
exit code and clean summary; NOT_RUN may never be reported as PASS; emulator
evidence must be labelled EMULATOR); non-decreasing UTC times; receipt_end
head/count/signature. Optional: --logs DIR re-hashes the stdout/stderr logs
and re-reads the integration log; --inputs DIR re-hashes the input files.

Stage policy (--stage, default LOCAL_TESTED): at LOCAL_TESTED the Snowflake
integration step MUST be NOT_RUN, because no approved account run exists.

LIMIT: the chain is unkeyed and unsigned (signature: NOT_RUN). Anyone can
rewrite every entry and recompute every hash. This verifier detects
accidental or partial tampering and semantic overclaims; it cannot prove
authorship. Only an approved signature or an external anchor can do that.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_local_evidence import (END_KEYS, ENTRY_KEYS, GENESIS, SCHEMA,  # noqa: E402
                                SIGNATURE_NOT_RUN, STEP_ORDER, canonical, sha256_bytes,
                                sha256_file)

HEX64 = re.compile(r"[0-9a-f]{64}")
TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
STATUSES = ("PASS", "FAIL", "NOT_RUN")


def _no_dupes(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate key %r" % k)
        seen[k] = v
    return seen


def load(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw.endswith(b"\n"):
        raise ValueError("receipt does not end with a newline (truncated?)")
    out = []
    for n, line in enumerate(raw.split(b"\n")[:-1]):
        obj = json.loads(line.decode("utf-8"), object_pairs_hook=_no_dupes)
        if type(obj) is not dict:
            raise ValueError("line %d is not an object" % n)
        if canonical(obj) != line:
            raise ValueError("line %d is not in canonical form" % n)
        out.append(obj)
    return out


def verify(entries, stage="LOCAL_TESTED", logs=None, inputs=None):
    errs = []
    if [e.get("step") for e in entries] != list(STEP_ORDER):
        errs.append("step sequence %r != required %r"
                    % ([e.get("step") for e in entries], list(STEP_ORDER)))
    prev = GENESIS
    last_t = ""
    for i, e in enumerate(entries):
        keys = END_KEYS if e.get("step") == "receipt_end" else ENTRY_KEYS
        if tuple(sorted(e)) != tuple(sorted(keys)):
            errs.append("entry %d: key set mismatch" % i)
            continue
        body = {k: v for k, v in e.items() if k != "entry_sha256"}
        if sha256_bytes(canonical(body)) != e["entry_sha256"]:
            errs.append("entry %d (%s): entry_sha256 mismatch (edited)" % (i, e["step"]))
        if e["prev_entry_sha256"] != prev:
            errs.append("entry %d (%s): chain break (prev_entry_sha256)" % (i, e["step"]))
        prev = e["entry_sha256"]
        if e["schema"] != SCHEMA:
            errs.append("entry %d: schema %r" % (i, e["schema"]))
        if type(e["seq"]) is not int or e["seq"] != i:
            errs.append("entry %d: seq %r out of order" % (i, e["seq"]))
        if type(e["utc_time"]) is not str or not TS.fullmatch(e["utc_time"]):
            errs.append("entry %d: malformed utc_time" % i)
        elif e["utc_time"] < last_t:
            errs.append("entry %d: utc_time goes backwards" % i)
        else:
            last_t = e["utc_time"]
        if e["step"] == "receipt_end":
            if e["signature"] != SIGNATURE_NOT_RUN:
                errs.append("receipt_end: signature field %r is not the unsigned marker; "
                            "no signing has been approved" % (e["signature"],))
            if e["step_count"] != i:
                errs.append("receipt_end: step_count %r != %d" % (e["step_count"], i))
            if e["chain_head_sha256"] != e["prev_entry_sha256"]:
                errs.append("receipt_end: chain_head_sha256 != prev_entry_sha256")
            if i != len(entries) - 1:
                errs.append("receipt_end is not the last entry")
            continue
        errs.extend(_semantics(i, e, stage))
        for f in ("stdout_sha256", "stderr_sha256"):
            if type(e[f]) is not str or not HEX64.fullmatch(e[f]):
                errs.append("entry %d: %s malformed" % (i, f))
        if logs is not None:
            errs.extend(_logs(i, e, logs))
        if inputs is not None:
            for name, h in sorted(e["input_sha256"].items()):
                p = os.path.join(inputs, name)
                if not os.path.exists(p):
                    errs.append("entry %d: input %s missing" % (i, name))
                elif sha256_file(p) != h:
                    errs.append("entry %d: input %s changed since the run" % (i, name))
    if not entries or entries[-1].get("step") != "receipt_end":
        errs.append("receipt_end missing (truncated receipt)")
    return errs


def _semantics(i, e, stage):
    errs = []
    st, code, exp, s = e["status"], e["exit_code"], e["expected_exit_code"], e["summary"]
    step, label = e["step"], e["evidence_label"]
    if st not in STATUSES:
        errs.append("entry %d: unknown status %r" % (i, st))
        return errs
    if type(s) is not dict or type(e["input_sha256"]) is not dict:
        errs.append("entry %d: summary/input_sha256 not objects" % i)
        return errs
    if st == "PASS":
        if code != exp or code != 0:
            errs.append("entry %d (%s): PASS with exit_code %r (expected 0)" % (i, step, code))
        if (s.get("not_run") or 0) > 0 or (s.get("skipped") or 0) > 0 or s.get("not_run_reason"):
            errs.append("entry %d (%s): NOT_RUN/skipped work reported as PASS" % (i, step))
    if st == "NOT_RUN" and step not in ("integration_snowflake", "emulator_check"):
        errs.append("entry %d (%s): step may not be NOT_RUN" % (i, step))
    if st == "NOT_RUN" and ((s.get("failures") or 0) or (s.get("errors") or 0)):
        errs.append("entry %d (%s): failures/errors recorded as NOT_RUN" % (i, step))
    if step == "integration_snowflake":
        if code == 3 and st != "NOT_RUN":
            errs.append("entry %d: integration exit 3 (NOT_RUN) reported as %s" % (i, st))
        if stage == "LOCAL_TESTED" and st != "NOT_RUN":
            errs.append("entry %d: integration must be NOT_RUN at stage LOCAL_TESTED, got %s"
                        % (i, st))
        if label != "MEASURED_LOCAL":
            errs.append("entry %d: integration label %r" % (i, label))
    if step in ("unit_tests", "verifier_tamper_tests") and st == "PASS":
        if s.get("result") != "OK" or s.get("failures") or s.get("errors") or not s.get("ran"):
            errs.append("entry %d: unit_tests PASS with non-clean summary" % i)
    if step == "mutation_sweep" and st == "PASS":
        if s.get("SURVIVED") != 0 or s.get("INVALID") != 0 or not s.get("KILLED"):
            errs.append("entry %d: mutation_sweep PASS with survivors/invalid" % i)
    if step == "fixture_rebuild" and st == "PASS":
        if s.get("matches_committed") is not True or s.get("rebuilt_sha256") != \
                e["input_sha256"].get("fixture_v1.json"):
            errs.append("entry %d: fixture_rebuild PASS but rebuilt digest differs" % i)
    if step == "emulator_check":
        if st == "PASS" and not str(label).startswith("EMULATOR (fakesnow "):
            errs.append("entry %d: emulator PASS not labelled EMULATOR" % i)
        if st == "PASS" and s.get("FAIL") != 0:
            errs.append("entry %d: emulator PASS with failing statements" % i)
    if step != "emulator_check" and str(label).startswith("EMULATOR"):
        errs.append("entry %d: EMULATOR label on non-emulator step" % i)
    return errs


def _logs(i, e, logs):
    errs = []
    for stream in ("stdout", "stderr"):
        p = os.path.join(logs, "%s.%s" % (e["step"], stream))
        if not os.path.exists(p):
            errs.append("entry %d: log %s.%s missing" % (i, e["step"], stream))
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        if sha256_bytes(data) != e[stream + "_sha256"] or len(data) != e[stream + "_bytes"]:
            errs.append("entry %d: log %s.%s does not match receipt" % (i, e["step"], stream))
        if (e["step"] == "integration_snowflake" and stream == "stderr"
                and b"INTEGRATION STATUS: NOT_RUN" in data and e["status"] != "NOT_RUN"):
            errs.append("entry %d: integration log says NOT_RUN, receipt says %s"
                        % (i, e["status"]))
    return errs


def main(argv):
    if not argv:
        sys.stderr.write("usage: verify_receipt.py RECEIPT [--logs DIR] [--inputs DIR] "
                         "[--stage LOCAL_TESTED|ACCOUNT_VERIFIED]\n")
        return 2
    path, logs, inputs, stage = argv[0], None, None, "LOCAL_TESTED"
    i = 1
    try:
        while i < len(argv):
            if argv[i] == "--logs":
                logs = argv[i + 1]
            elif argv[i] == "--inputs":
                inputs = argv[i + 1]
            elif argv[i] == "--stage":
                stage = argv[i + 1]
            else:
                raise IndexError
            i += 2
    except IndexError:
        sys.stderr.write("bad arguments\n")
        return 2
    if stage not in ("LOCAL_TESTED", "ACCOUNT_VERIFIED"):
        sys.stderr.write("unknown stage\n")
        return 2
    try:
        errs = verify(load(path), stage, logs, inputs)
    except OSError as exc:  # fail closed; never echo local paths
        errs = ["unreadable receipt: %s: %s" % (type(exc).__name__, exc.strerror)]
    except Exception as exc:  # fail closed
        errs = ["unreadable receipt: %s: %s" % (type(exc).__name__, exc)]
    if errs:
        sys.stdout.write("INVALID\n" + "".join("- %s\n" % m for m in errs))
        return 1
    sys.stdout.write("VALID (unsigned; signature NOT_RUN; integrity only, not authorship)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
