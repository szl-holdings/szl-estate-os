#!/usr/bin/env python3
"""szl_vm_readiness.py - one-command operational readiness check for the SZL VM.

Usage (on the VM, next to szl_vm_master_payload.py 1.1.2):
    python3 -I -B szl_vm_readiness.py --root /path/to/training/run [--manifest M --data-pins P] [--out readiness]

Read-only except receipts under --out. Never launches, kills, pushes or uploads.
Prints OPERATIONAL (exit 0) only if every gate passes; otherwise NOT_OPERATIONAL (exit 1) with reasons.
Independent readback: re-hashes the payload, re-parses every receipt, and walks the hash chain itself.
"""
import argparse, glob, hashlib, json, os, subprocess, sys
PAYLOAD_SHA = "ef05883d3cd8011057d525183ac702407e0ef7c9c4979e60b935199c32172f37"  # 1.1.2 proposed
HERE = os.path.dirname(os.path.abspath(__file__))

def run(args, out):
    p = subprocess.run([sys.executable, "-I", "-B", os.path.join(HERE, "szl_vm_master_payload.py")] + args,
                       capture_output=True, text=True, timeout=1800)
    txt = (p.stdout or "") + (p.stderr or "")
    try:
        js = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
    except ValueError:
        js = None
    return p.returncode, js, txt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--manifest"); ap.add_argument("--data-pins")
    ap.add_argument("--out", default="readiness"); ap.add_argument("--expect-sha", default=PAYLOAD_SHA)
    a = ap.parse_args()
    gates, fail = {}, []
    def gate(name, ok, detail):
        gates[name] = {"pass": bool(ok), "detail": detail}
        if not ok: fail.append(name)
    pl = os.path.join(HERE, "szl_vm_master_payload.py")
    sha = hashlib.sha256(open(pl, "rb").read()).hexdigest() if os.path.exists(pl) else None
    gate("payload_hash", sha == a.expect_sha, sha)
    if sha != a.expect_sha:
        return finish(gates, fail, a.out)  # never run an unpinned payload
    rc, js, _ = run(["selftest"], a.out)
    gate("selftest", rc == 0 and js and js.get("result") == "PASS", {"rc": rc, "result": js and js.get("result")})
    rc, js, txt = run(["preflight", "--out", a.out], a.out)
    gate("preflight", rc == 0 and js and js.get("status") != "BLOCKED", js.get("blockers") if js else txt[-300:])
    rc, js, txt = run(["inventory", a.root, "--out", a.out], a.out)
    gate("inventory_ran", rc == 0 and js is not None, js and js.get("counts"))
    rc, js, txt = run(["training", a.root, "--out", a.out], a.out)
    ev = js and js.get("optimizer_step_evidence")
    gate("training_progress_evidence", rc == 0 and isinstance(ev, str) and not ev.startswith("UNKNOWN"), ev)
    rc, js, txt = run(["failures", a.root, "--out", a.out], a.out)
    gate("failures_scan_ran", rc == 0 and js is not None and js.get("files", 0) > 0,
         {"files": js and js.get("files")})
    ga = ["resume-gate", a.root, "--out", a.out] + (["--manifest", a.manifest] if a.manifest else []) + \
         (["--data-pins", a.data_pins] if a.data_pins else [])
    rc, js, txt = run(ga, a.out)
    gate("resume_gate", rc == 0 and js and js.get("decision") == "ADMIT", js and js.get("failed"))
    # independent readback of the receipt chain
    files = {}
    for f in glob.glob(os.path.join(a.out, "*.json")):
        if os.path.basename(f) == "chain.json": continue
        files[hashlib.sha256(open(f, "rb").read()).hexdigest()] = f
    try:
        h = json.load(open(os.path.join(a.out, "chain.json")))["head"]; n = 0
        while h in files:
            n += 1; h = json.load(open(files[h]))["prev_receipt_sha256"]
        gate("receipt_chain", h is None and n == len(files), {"walked": n, "receipts": len(files)})
    except (OSError, KeyError, ValueError) as e:
        gate("receipt_chain", False, repr(e))
    return finish(gates, fail, a.out)

def finish(gates, fail, out):
    verdict = "OPERATIONAL" if not fail else "NOT_OPERATIONAL"
    rep = {"verdict": verdict, "failed_gates": fail, "gates": gates,
           "note": "OPERATIONAL covers only these gates; governed-service runtime and DSSE signing are not checked here."}
    os.makedirs(out, exist_ok=True)
    p = os.path.join(out, "readiness_verdict.json"); open(p, "w").write(json.dumps(rep, indent=1, default=str))
    print(json.dumps({"verdict": verdict, "failed_gates": fail, "report": p,
                      "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}, indent=1))
    return 0 if not fail else 1

if __name__ == "__main__":
    sys.exit(main())
