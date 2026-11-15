#!/usr/bin/env python3
"""szl_vm_readiness.py 0.2.0 - one-command operational readiness check for the SZL VM.

Usage (on the VM, next to szl_vm_master_payload.py 1.4.0):
    python3 -I -B szl_vm_readiness.py --root RUN --manifest M --data-pins P --data-root D [--out readiness]
        [--deadline-s 9000] [--call-timeout 1800] [--disk-path /] [--min-disk-gb 50] [--min-ram-gb 4]

Read-only except receipts under --out. Never launches, kills (other than its own timed-out payload call's
process group), pushes or uploads. Prints OPERATIONAL (exit 0) only if every gate passes; otherwise
NOT_OPERATIONAL (exit 1). There is no command-line override of the payload pin.

0.2.0 adds gates computed here, independently of the payload:
  manifest_paths_safe        every manifest name for the chosen checkpoint is relative and stays inside it
  manifest_covers_checkpoint every regular file in that checkpoint is listed (unlisted files are not provenance)
  manifest_hashes_independent re-hash of every listed file
  dataset_bytes_match_pins   every pinned train/eval file under --data-root is re-hashed and must match
  heldout_overlap_measured   overlap is MEASURED here (payload `leakage` per train x eval pair), must be 0,
                             and must equal what the pins file claims
A payload call that exceeds its time budget fails its gate as TIMEOUT; the verdict file is still written.
"""
import argparse, glob, hashlib, json, os, signal, subprocess, sys, time

CHECKER_VERSION = "szl-vm-readiness/0.2.0"
PAYLOAD_SHA = "0f17c9316024932192a441f4690c326a49b7148bb40dc40621d4e7f27a4674f0"  # szl-vm-master-payload/1.4.0
HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def safe_rel(base, name):
    """Return the real path of base/name if name is a plain relative path that stays inside base, else None."""
    if not isinstance(name, str) or not name or "\x00" in name or os.path.isabs(name) or name.startswith(("/", "\\")):
        return None
    parts = name.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    rb = os.path.realpath(base)
    rp = os.path.realpath(os.path.join(rb, *parts))
    try:
        return rp if os.path.commonpath([rb, rp]) == rb and rp != rb else None
    except ValueError:
        return None


def list_files(d):
    out = []
    for r, _, fs in os.walk(d):
        for f in fs:
            p = os.path.join(r, f)
            if os.path.isfile(p):
                out.append(os.path.relpath(p, d).replace(os.sep, "/"))
    return sorted(out)


def manifest_gates(root, ckpt_name, manifest, deadline):
    """Independent checks of the checkpoint manifest entry for the checkpoint the payload chose."""
    g = {}
    cdir = safe_rel(root, ckpt_name) if ckpt_name else None
    if cdir is None or not os.path.isdir(cdir):
        msg = "chosen checkpoint unknown or outside root: %r" % (ckpt_name,)
        return {k: (False, msg) for k in ("manifest_paths_safe", "manifest_covers_checkpoint", "manifest_hashes_independent")}
    want = (manifest or {}).get(ckpt_name) if isinstance(manifest, dict) else None
    if not isinstance(want, dict) or not want:
        msg = "manifest has no entry for %s" % ckpt_name
        return {k: (False, msg) for k in ("manifest_paths_safe", "manifest_covers_checkpoint", "manifest_hashes_independent")}
    unsafe = sorted(n for n in want if safe_rel(cdir, n) is None)
    g["manifest_paths_safe"] = (not unsafe, ("unsafe names: %s" % unsafe[:5]) if unsafe else "%d names safe" % len(want))
    present = list_files(cdir)
    unlisted = sorted(set(present) - set(n.replace("\\", "/") for n in want))
    g["manifest_covers_checkpoint"] = (not unlisted, ("unlisted files: %s" % unlisted[:5]) if unlisted
                                       else "all %d files listed" % len(present))
    bad = []
    for n, h in sorted(want.items()):
        if time.time() > deadline:
            g["manifest_hashes_independent"] = (False, "TIMEOUT: budget exhausted while hashing")
            return g
        p = safe_rel(cdir, n)
        if p is None or not os.path.isfile(p) or not isinstance(h, str) or sha256_file(p) != h.lower():
            bad.append(n)
    g["manifest_hashes_independent"] = (not bad, ("mismatch or missing: %s" % bad[:5]) if bad
                                        else "%d files re-hashed and match" % len(want))
    return g


def data_gate(data_root, pins, deadline):
    """Re-hash every pinned dataset file. Returns (ok, detail, train_paths, eval_paths)."""
    if not isinstance(pins, dict):
        return False, "data pins unreadable", [], []
    tr, ev = pins.get("files") or {}, pins.get("eval_files") or {}
    if not tr or not ev:
        return False, "pins need both files and eval_files", [], []
    bad, paths = [], {"files": [], "eval_files": []}
    for kind, d in (("files", tr), ("eval_files", ev)):
        for n, h in sorted(d.items()):
            if time.time() > deadline:
                return False, "TIMEOUT: budget exhausted while hashing", [], []
            p = safe_rel(data_root, n)
            if p is None or not os.path.isfile(p):
                bad.append("%s:%s missing/unsafe" % (kind, n)); continue
            if not isinstance(h, str) or sha256_file(p) != h.lower():
                bad.append("%s:%s hash mismatch" % (kind, n)); continue
            paths[kind].append(p)
    if bad:
        return False, "; ".join(bad[:5]), [], []
    return True, "%d train + %d eval files re-hashed and match" % (len(tr), len(ev)), paths["files"], paths["eval_files"]


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run(args, deadline, call_timeout):
    """Run one payload subcommand in its own process group. Returns (rc, json|None, text); rc 'TIMEOUT' on expiry."""
    left = deadline - time.time()
    if left <= 1:
        return "TIMEOUT", None, "budget exhausted before call"
    t = max(1, min(call_timeout, int(left)))
    proc = subprocess.Popen([sys.executable, "-I", "-B", os.path.join(HERE, "szl_vm_master_payload.py")] + args,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        so, se = proc.communicate(timeout=t)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.communicate()
        return "TIMEOUT", None, "TIMEOUT after %ss" % t
    txt = (so or "") + (se or "")
    try:
        js = json.loads(txt[txt.index("{"):txt.rindex("}") + 1])
    except ValueError:
        js = None
    return proc.returncode, js, txt


def main(argv=None, expect_sha=PAYLOAD_SHA):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--manifest", required=True)
    ap.add_argument("--data-pins", required=True); ap.add_argument("--data-root", required=True)
    ap.add_argument("--out", default="readiness")
    ap.add_argument("--deadline-s", type=float, default=9000); ap.add_argument("--call-timeout", type=int, default=1800)
    ap.add_argument("--disk-path", default="/"); ap.add_argument("--min-disk-gb", type=float, default=50)
    ap.add_argument("--min-ram-gb", type=float, default=4)
    a = ap.parse_args(argv)
    deadline = time.time() + a.deadline_s
    gates, fail = {}, []

    def gate(name, ok, detail):
        gates[name] = {"pass": bool(ok), "detail": detail}
        if not ok:
            fail.append(name)

    def ran(name, rc, ok, detail):
        gate(name, rc != "TIMEOUT" and ok, "TIMEOUT" if rc == "TIMEOUT" else detail)

    pl = os.path.join(HERE, "szl_vm_master_payload.py")
    sha = sha256_file(pl) if os.path.exists(pl) else None
    gate("payload_hash", sha == expect_sha, sha)
    if sha != expect_sha:
        return finish(gates, fail, a.out)  # never run an unpinned payload
    T = a.call_timeout
    rc, js, _ = run(["selftest"], deadline, T)
    ran("selftest", rc, rc == 0 and js and js.get("result") == "PASS", {"rc": rc, "result": js and js.get("result")})
    rc, js, txt = run(["preflight", "--out", a.out, "--disk-path", a.disk_path, "--min-disk-gb", str(a.min_disk_gb),
                       "--min-ram-gb", str(a.min_ram_gb)], deadline, T)
    ran("preflight", rc, rc == 0 and js and js.get("status") != "BLOCKED", js.get("blockers") if js else txt[-300:])
    rc, js, txt = run(["inventory", a.root, "--out", a.out], deadline, T)
    ran("inventory_ran", rc, rc == 0 and js is not None, js and js.get("counts"))
    rc, js, txt = run(["training", a.root, "--out", a.out], deadline, T)
    ev = js and js.get("optimizer_step_evidence")
    ran("training_progress_evidence", rc, rc == 0 and isinstance(ev, str) and not ev.startswith("UNKNOWN"), ev)
    rc, js, txt = run(["failures", a.root, "--out", a.out], deadline, T)
    ran("failures_scan_ran", rc, rc == 0 and js is not None and js.get("files", 0) > 0, {"files": js and js.get("files")})
    rc, js, txt = run(["resume-gate", a.root, "--out", a.out, "--manifest", a.manifest, "--data-pins", a.data_pins],
                      deadline, T)
    ran("resume_gate", rc, rc == 0 and js and js.get("decision") == "ADMIT", js and js.get("failed"))
    # ---- independent gates (0.2.0)
    ckpt = None
    try:
        ckpt = json.load(open(js["receipt"]))["body"]["checkpoint"] if js and js.get("receipt") else None
    except (OSError, ValueError, KeyError, TypeError):
        ckpt = None
    try:
        manifest = json.load(open(a.manifest))
    except (OSError, ValueError):
        manifest = None
    for k, (ok, d) in manifest_gates(a.root, ckpt, manifest, deadline).items():
        gate(k, ok, d)
    try:
        pins = json.load(open(a.data_pins))
    except (OSError, ValueError):
        pins = None
    ok, d, trs, evs = data_gate(a.data_root, pins, deadline)
    gate("dataset_bytes_match_pins", ok, d)
    if not ok:
        gate("heldout_overlap_measured", False, "not measured: dataset pins did not verify")
    else:
        exact = near = 0; problems = []
        for t in trs:
            for e in evs:
                rc, js, txt = run(["leakage", t, e, "--out", a.out], deadline, T)
                if rc == "TIMEOUT" or rc not in (0, 1) or not js or not js.get("train_rows") or not js.get("eval_rows"):
                    problems.append("%s x %s: %s" % (os.path.basename(t), os.path.basename(e),
                                                     "TIMEOUT" if rc == "TIMEOUT" else "not measured (rc=%s)" % rc))
                    continue
                exact += int(js.get("eval_rows_also_in_train") or 0); near += int(js.get("eval_rows_near_dup_of_train") or 0)
        claimed = (pins.get("row_overlap"), pins.get("near_dup_overlap"))
        if problems:
            gate("heldout_overlap_measured", False, "; ".join(problems[:5]))
        else:
            gate("heldout_overlap_measured", exact == 0 and near == 0 and claimed == (exact, near),
                 {"measured_exact": exact, "measured_near_dup": near, "pins_claim": list(claimed)})
    # ---- independent readback of the receipt chain
    files = {}
    for f in glob.glob(os.path.join(a.out, "*.json")):
        if os.path.basename(f) in ("chain.json", "readiness_verdict.json"):
            continue
        files[sha256_file(f)] = f
    try:
        h = json.load(open(os.path.join(a.out, "chain.json")))["head"]; n = 0
        while h in files and n <= len(files):
            n += 1; h = json.load(open(files[h]))["prev_receipt_sha256"]
        gate("receipt_chain", h is None and n == len(files) and n > 0, {"walked": n, "receipts": len(files)})
    except (OSError, KeyError, ValueError, TypeError) as e:
        gate("receipt_chain", False, repr(e))
    return finish(gates, fail, a.out)


def finish(gates, fail, out):
    verdict = "OPERATIONAL" if gates and not fail else "NOT_OPERATIONAL"
    rep = {"checker": CHECKER_VERSION, "verdict": verdict, "failed_gates": fail, "gates": gates,
           "note": "OPERATIONAL covers only these gates (incl. dataset bytes vs pins and measured train/eval overlap); "
                   "governed-service runtime and DSSE signing are not checked here."}
    os.makedirs(out, exist_ok=True)
    p = os.path.join(out, "readiness_verdict.json")
    with open(p, "w") as f:
        f.write(json.dumps(rep, indent=1, default=str))
    print(json.dumps({"verdict": verdict, "failed_gates": fail, "report": p, "sha256": sha256_file(p)}, indent=1))
    return 0 if verdict == "OPERATIONAL" else 1


if __name__ == "__main__":
    sys.exit(main())
