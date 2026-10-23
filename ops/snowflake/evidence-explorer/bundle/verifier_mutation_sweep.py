"""Single-check mutation sweep for verify_receipt.py (stdlib only).

Each mutant disables one verifier check in a temp copy and runs
test_verify_receipt.py. KILLED = tamper tests fail. SURVIVED = gap, unless
the mutant is listed in EQUIVALENT with a reason.
Usage: python -I -B verifier_mutation_sweep.py [results.json]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MUTANTS = [
    ('V01', 'entry hash check off',
     '        if sha256_bytes(canonical(body)) != e["entry_sha256"]:',
     '        if False:'),
    ('V02', 'chain check off',
     '        if e["prev_entry_sha256"] != prev:',
     '        if False:'),
    ('V03', 'seq check off',
     '        if type(e["seq"]) is not int or e["seq"] != i:',
     '        if False:'),
    ('V04', 'step-set check off',
     '    if [e.get("step") for e in entries] != list(STEP_ORDER):',
     '    if False:'),
    ('V05', 'NOT_RUN-as-PASS (exit 3) off',
     '        if code == 3 and st != "NOT_RUN":',
     '        if False:'),
    ('V06', 'stage policy off',
     '        if stage == "LOCAL_TESTED" and st != "NOT_RUN":',
     '        if False:'),
    ('V07', 'signature check off',
     '            if e["signature"] != SIGNATURE_NOT_RUN:',
     '            if False:'),
    ('V08', 'log hash check off',
     '        if sha256_bytes(data) != e[stream + "_sha256"] or len(data) != e[stream + "_bytes"]:',
     '        if False:'),
    ('V09', 'input drift check off',
     '                elif sha256_file(p) != h:',
     '                elif False:'),
    ('V10', 'duplicate-key guard off',
     '        if k in seen:\n            raise ValueError("duplicate key %r" % k)',
     '        if False:\n            pass'),
    ('V11', 'canonical-form guard off',
     '        if canonical(obj) != line:',
     '        if False:'),
    ('V12', 'truncation guard off',
     '    if not entries or entries[-1].get("step") != "receipt_end":',
     '    if False:'),
    ('V13', 'time order off',
     '        elif e["utc_time"] < last_t:',
     '        elif False:'),
    ('V14', 'mutation survivors check off',
     '        if s.get("SURVIVED") != 0 or s.get("INVALID") != 0 or not s.get("KILLED"):',
     '        if False:'),
    ('V15', 'emulator label check off',
     '        if st == "PASS" and not str(label).startswith("EMULATOR (fakesnow "):',
     '        if False:'),
    ('V16', 'skipped-as-PASS check off',
     '        if (s.get("not_run") or 0) > 0 or (s.get("skipped") or 0) > 0 or s.get("not_run_reason"):',
     '        if False:'),
    ('V17', 'integration log cross-check off',
     '                and b"INTEGRATION STATUS: NOT_RUN" in data and e["status"] != "NOT_RUN"):',
     '                and False):'),
    ('V18', 'fail-closed except returns VALID',
     '        errs = ["unreadable receipt: %s: %s" % (type(exc).__name__, exc)]',
     '        errs = []'),
]
EQUIVALENT = {"V10": "A line with a duplicate key can never equal canonical(json.loads(line)), "
                     "so the canonical-form guard (V11) rejects it first; the guard is "
                     "defence in depth."}


def main(out):
    src = open(os.path.join(HERE, "verify_receipt.py"), encoding="utf-8").read()
    res = []
    with tempfile.TemporaryDirectory() as td:
        for f in ("run_local_evidence.py", "test_verify_receipt.py", "verify_receipt.py"):
            shutil.copy2(os.path.join(HERE, f), td)
        r = subprocess.run([sys.executable, "-I", "-B", "test_verify_receipt.py"], cwd=td,
                           capture_output=True, timeout=600)
        if r.returncode != 0:
            raise SystemExit("clean verifier does not pass its tamper tests")
        for mid, desc, old, new in MUTANTS:
            if src.count(old) != 1:
                res.append({"id": mid, "description": desc, "status": "INVALID"})
                continue
            with open(os.path.join(td, "verify_receipt.py"), "w", encoding="utf-8",
                      newline="\n") as fh:
                fh.write(src.replace(old, new))
            r = subprocess.run([sys.executable, "-I", "-B", "test_verify_receipt.py"],
                               cwd=td, capture_output=True, timeout=600)
            st = "KILLED" if r.returncode != 0 else (
                "EQUIVALENT" if mid in EQUIVALENT else "SURVIVED")
            res.append({"id": mid, "description": desc, "status": st,
                        "equivalence_reason": EQUIVALENT.get(mid) if st == "EQUIVALENT" else None})
    summary = {k: sum(1 for x in res if x["status"] == k)
               for k in ("KILLED", "SURVIVED", "EQUIVALENT", "INVALID")}
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"target": "verify_receipt.py", "summary": summary, "results": res}, fh, indent=1)
        fh.write("\n")
    sys.stdout.write(json.dumps(summary) + "\n")
    for x in res:
        sys.stdout.write("%s %-10s %s\n" % (x["id"], x["status"], x["description"]))
    return 0 if summary["SURVIVED"] == 0 and summary["INVALID"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  os.path.join(HERE, "verifier_mutation_results.json")))
