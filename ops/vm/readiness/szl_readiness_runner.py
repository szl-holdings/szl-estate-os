#!/usr/bin/env python3
"""szl_readiness_runner.py - unattended, fail-closed wrapper around szl_vm_readiness.py.

Runs on the VM (Linux, python3, stdlib only). One invocation = one evidence bundle:
  python3 -I -B szl_readiness_runner.py --bundle DIR --root RUN --manifest M --data-pins P --evidence-base E

Guarantees (each is a test in test_szl_readiness_runner.py):
  * refuses unless payload and checker bytes match the pinned sha256 (no override flag exists)
  * refuses unless --root, --manifest and --data-pins all exist (never substitutes M or P)
  * refuses below disk / RAM floors, or when any measurement is UNKNOWN
  * honours a STOP latch file (E/STOP) and an exclusive lock (E/.lock); a stale lock is never removed
  * fresh run directory per invocation; the checker runs with cwd inside it
  * captures argv, exit code, stdout, stderr, durations, host identity, SSH host-key fingerprints,
    GPU state, and sha256 of every file produced; a timeout is recorded, not raised
  * independent readback: verdict file re-parsed, exit code vs verdict vs gates cross-checked,
    receipt chain re-walked; OPERATIONAL_VERIFIED only if every check agrees
  * appends one hash-chained line to E/history.jsonl
Never launches training, kills processes, signs, uploads, pushes, or uses the network.
Exit: 0 OPERATIONAL_VERIFIED, 1 NOT_OPERATIONAL, 2 BLOCKED, 3 INCONSISTENT.
"""
import argparse, base64, datetime, glob, hashlib, json, os, platform, shutil, socket, subprocess, sys, time

RUNNER_VERSION = "szl-readiness-runner/0.1.0"
PINS = {
    "szl_vm_master_payload.py": "ef05883d3cd8011057d525183ac702407e0ef7c9c4979e60b935199c32172f37",  # 1.1.2
    "szl_vm_readiness.py": "b23ea34179f059029e7d97df4f7833e3d243141e84270b61ca59e983e1ca4f96",
}
EXIT = {"OPERATIONAL_VERIFIED": 0, "NOT_OPERATIONAL": 1, "BLOCKED": 2, "INCONSISTENT": 3}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def probe_resources(path):
    """Disk free (GB) at path, RAM available (GiB), GPU summary. Missing values are None (= UNKNOWN)."""
    r = {"disk_free_gb": None, "ram_avail_gib": None, "gpu": "UNKNOWN", "gpu_compute_apps": "UNKNOWN"}
    try:
        r["disk_free_gb"] = round(shutil.disk_usage(path).free / 1e9, 2)
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    r["ram_avail_gib"] = round(int(line.split()[1]) / 2**20, 2)
    except OSError:
        pass
    for key, q in (("gpu", ["--query-gpu=name,memory.total,memory.used,utilization.gpu", "--format=csv,noheader"]),
                   ("gpu_compute_apps", ["--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader"])):
        try:
            p = subprocess.run(["nvidia-smi"] + q, capture_output=True, text=True, timeout=30)
            r[key] = p.stdout.strip().splitlines() if p.returncode == 0 else "UNKNOWN rc=%d" % p.returncode
        except (OSError, subprocess.SubprocessError) as e:
            r[key] = "UNKNOWN " + type(e).__name__
    return r


def identity():
    ident = {"hostname": socket.gethostname(), "platform": platform.platform(), "python": sys.version,
             "python_executable": sys.executable, "runner_version": RUNNER_VERSION,
             "runner_sha256": sha_file(os.path.abspath(__file__)), "machine_id_sha256": None, "ssh_host_keys": []}
    try:
        ident["machine_id_sha256"] = hashlib.sha256(open("/etc/machine-id", "rb").read().strip()).hexdigest()
    except OSError:
        pass
    for pub in sorted(glob.glob("/etc/ssh/ssh_host_*_key.pub")):
        try:
            kt, blob = open(pub).read().split()[:2]
            fp = base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
            ident["ssh_host_keys"].append({"file": pub, "type": kt, "fingerprint": "SHA256:" + fp})
        except (OSError, ValueError):
            ident["ssh_host_keys"].append({"file": pub, "fingerprint": "UNKNOWN"})
    return ident


def walk_chain(out):
    files = {}
    for f in glob.glob(os.path.join(out, "*.json")):
        if os.path.basename(f) in ("chain.json", "readiness_verdict.json"):
            continue
        files[sha_file(f)] = f
    try:
        h = json.load(open(os.path.join(out, "chain.json")))["head"]
        n = 0
        while h in files and n <= len(files):
            n += 1
            h = json.load(open(files[h]))["prev_receipt_sha256"]
        return {"ok": h is None and n == len(files) and n > 0, "walked": n, "receipts": len(files)}
    except (OSError, KeyError, ValueError, TypeError) as e:
        return {"ok": False, "error": repr(e), "receipts": len(files)}


def append_history(base, rec):
    hist = os.path.join(base, "history.jsonl")
    prev = None
    if os.path.exists(hist):
        lines = [l for l in open(hist, "rb").read().splitlines() if l.strip()]
        prev = hashlib.sha256(lines[-1]).hexdigest() if lines else None
    rec = dict(rec, prev_line_sha256=prev)
    with open(hist, "ab") as f:
        f.write(json.dumps(rec, sort_keys=True).encode() + b"\n")


def main(argv=None, pins=PINS, probe=probe_resources):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bundle", required=True, help="dir holding the pinned payload and checker")
    ap.add_argument("--root", required=True, help="training run directory (read-only)")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--data-pins", required=True)
    ap.add_argument("--evidence-base", required=True)
    ap.add_argument("--min-disk-gb", type=float, default=20.0)
    ap.add_argument("--min-ram-gib", type=float, default=4.0)
    ap.add_argument("--timeout", type=int, default=3 * 3600)
    a = ap.parse_args(argv)
    t0 = time.time()
    base = os.path.abspath(a.evidence_base)
    os.makedirs(base, exist_ok=True)
    rec = {"runner": RUNNER_VERSION, "start_utc": utc(), "argv": [sys.executable] + list(argv if argv is not None else sys.argv[1:]),
           "blockers": [], "checks": {}}

    def done(status, run_dir=None):
        rec["status"] = status
        rec["end_utc"] = utc()
        rec["elapsed_s"] = round(time.time() - t0, 2)
        if run_dir:
            rec["files_sha256"] = {os.path.relpath(p, run_dir): sha_file(p)
                                   for p in sorted(glob.glob(os.path.join(run_dir, "**", "*"), recursive=True))
                                   if os.path.isfile(p)}
            cap = os.path.join(run_dir, "capture.json")
            open(cap, "w").write(json.dumps(rec, indent=1, sort_keys=True, default=str))
            rec_line = {"status": status, "run_dir": run_dir, "capture_sha256": sha_file(cap), "end_utc": rec["end_utc"]}
        else:
            rec_line = {"status": status, "run_dir": None, "blockers": rec["blockers"], "end_utc": rec["end_utc"]}
        append_history(base, rec_line)
        print(json.dumps({"status": status, "blockers": rec["blockers"], "run_dir": run_dir}, indent=1))
        return EXIT[status]

    # STOP latch
    if os.path.exists(os.path.join(base, "STOP")):
        rec["blockers"].append("STOP latch present")
        return done("BLOCKED")
    # pins
    rec["checks"]["pins"] = {}
    for name, want in pins.items():
        p = os.path.join(a.bundle, name)
        got = sha_file(p) if os.path.isfile(p) else None
        rec["checks"]["pins"][name] = {"want": want, "got": got}
        if got != want:
            rec["blockers"].append("pin mismatch: %s" % name)
    # inputs (never substituted)
    rec["checks"]["inputs"] = {}
    for label, p, kind in (("root", a.root, "dir"), ("manifest", a.manifest, "file"), ("data_pins", a.data_pins, "file")):
        ok = os.path.isdir(p) if kind == "dir" else os.path.isfile(p)
        rec["checks"]["inputs"][label] = {"path": os.path.abspath(p), "exists": ok,
                                          "sha256": sha_file(p) if ok and kind == "file" else None}
        if not ok:
            rec["blockers"].append("missing input: %s (%s)" % (label, p))
    # resources
    res = probe(base)
    rec["checks"]["resources"] = res
    if res.get("disk_free_gb") is None or res["disk_free_gb"] < a.min_disk_gb:
        rec["blockers"].append("disk floor: %s GB < %s" % (res.get("disk_free_gb"), a.min_disk_gb))
    if res.get("ram_avail_gib") is None or res["ram_avail_gib"] < a.min_ram_gib:
        rec["blockers"].append("RAM floor: %s GiB < %s" % (res.get("ram_avail_gib"), a.min_ram_gib))
    rec["identity"] = identity()
    if rec["blockers"]:
        return done("BLOCKED")
    # exclusive lock; a stale lock is reported, never removed
    lock = os.path.join(base, ".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        rec["blockers"].append("lock held: %s (remove by hand only after confirming no run is active)" % lock)
        return done("BLOCKED")
    try:
        os.write(fd, ("%d %s\n" % (os.getpid(), utc())).encode())
        os.close(fd)
        run_dir = os.path.join(base, "run-%s-%d-%s" % (utc().replace(":", "").replace("-", ""), os.getpid(),
                                                       os.urandom(4).hex()))
        try:
            os.mkdir(run_dir)  # never reuse an existing run directory
        except FileExistsError:
            rec["blockers"].append("run dir collision: %s" % run_dir)
            return done("BLOCKED")
        out = os.path.join(run_dir, "readiness")
        cmd = [sys.executable, "-I", "-B", os.path.join(os.path.abspath(a.bundle), "szl_vm_readiness.py"),
               "--root", os.path.abspath(a.root), "--manifest", os.path.abspath(a.manifest),
               "--data-pins", os.path.abspath(a.data_pins), "--out", out]
        rec["checker_cmd"] = cmd
        try:
            p = subprocess.run(cmd, cwd=run_dir, capture_output=True, text=True, timeout=a.timeout)
            rc, so, se = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc, so, se = None, e.stdout or "", e.stderr or ""
            so = so.decode() if isinstance(so, bytes) else so
            se = se.decode() if isinstance(se, bytes) else se
            rec["blockers"].append("checker timeout after %ss" % a.timeout)
        open(os.path.join(run_dir, "checker.stdout"), "w").write(so)
        open(os.path.join(run_dir, "checker.stderr"), "w").write(se)
        rec["checker_exit"] = rc
        if rc is None:
            return done("BLOCKED", run_dir)
        # independent readback
        vp = os.path.join(out, "readiness_verdict.json")
        try:
            v = json.load(open(vp))
        except (OSError, ValueError) as e:
            rec["blockers"].append("verdict unreadable: %r" % e)
            return done("INCONSISTENT", run_dir)
        gates = v.get("gates", {})
        all_pass = bool(gates) and all(g.get("pass") is True for g in gates.values())
        claimed = v.get("verdict")
        try:
            printed = json.loads(so[so.index("{"):so.rindex("}") + 1])
        except ValueError:
            printed = {}
        chain = walk_chain(out)
        rb = {"verdict": claimed, "failed_gates": v.get("failed_gates"), "all_gates_pass": all_pass,
              "exit_matches_verdict": (rc == 0) == (claimed == "OPERATIONAL"),
              "gates_match_verdict": all_pass == (claimed == "OPERATIONAL") and (not v.get("failed_gates")) == all_pass,
              "printed_sha_matches_file": printed.get("sha256") == sha_file(vp), "chain": chain}
        rec["readback"] = rb
        if not (rb["exit_matches_verdict"] and rb["gates_match_verdict"] and rb["printed_sha_matches_file"]):
            return done("INCONSISTENT", run_dir)
        if claimed == "OPERATIONAL" and chain["ok"]:
            return done("OPERATIONAL_VERIFIED", run_dir)
        if claimed == "OPERATIONAL":
            rec["blockers"].append("independent chain walk failed")
            return done("INCONSISTENT", run_dir)
        return done("NOT_OPERATIONAL", run_dir)
    finally:
        os.remove(lock)  # only the lock this process created


if __name__ == "__main__":
    sys.exit(main())
