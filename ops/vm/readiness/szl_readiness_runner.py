#!/usr/bin/env python3
"""szl_readiness_runner.py 0.2.0 - unattended, fail-closed wrapper around szl_vm_readiness.py.

Runs on the VM (Linux, python3, stdlib only). One invocation = one evidence bundle:
  python3 -I -B szl_readiness_runner.py --bundle DIR --root RUN --manifest M --data-pins P --data-root D --evidence-base E

Guarantees (each is a test in test_szl_readiness_runner.py):
  * refuses unless every file listed in DIR/SHA256SUMS matches, and payload and checker bytes match the
    pinned sha256 (no override flag exists)
  * refuses unless --root, --data-root, --manifest and --data-pins all exist (never substitutes any of them)
  * one floor policy: disk GB (1e9 B) free at E and RAM GB (MemAvailable kB / 1e6, the payload's convention);
    the same numbers and path are handed to the checker's preflight. Refuses when any measurement is UNKNOWN
  * honours a STOP latch file (E/STOP) and an exclusive run lock (E/.lock); a stale lock is never removed
  * every history append, including early refusals, holds an flock on E/.history.lock and first re-verifies
    the whole E/history.jsonl chain; a broken or torn chain is refused (exit 3) and never appended to
  * the checker runs in its own process group with a deadline below --timeout; on timeout or SIGTERM/SIGHUP
    that process group (checker and payload) is killed, the run is recorded BLOCKED, and the lock is released
  * captures argv, exit code, stdout, stderr, durations, host identity, SSH host-key fingerprints,
    GPU state, and sha256 of every file produced
  * independent readback: verdict file re-parsed, exit code vs verdict vs gates cross-checked,
    receipt chain re-walked; OPERATIONAL_VERIFIED only if every check agrees
Never launches training, signs, uploads, pushes, or uses the network. The only processes it kills are its own
checker's process group. Exit: 0 OPERATIONAL_VERIFIED, 1 NOT_OPERATIONAL, 2 BLOCKED, 3 INCONSISTENT.
"""
import argparse, base64, datetime, fcntl, glob, hashlib, json, os, platform, signal, socket, subprocess, sys, time

RUNNER_VERSION = "szl-readiness-runner/0.2.0"
PINS = {
    "szl_vm_master_payload.py": "0f17c9316024932192a441f4690c326a49b7148bb40dc40621d4e7f27a4674f0",  # 1.4.0
    "szl_vm_readiness.py": "e20e04ac26cf6db37e142fb682aaf1216eec66ff9ed3a02109d5f6a2461feae4",  # 0.2.0
}
EXIT = {"OPERATIONAL_VERIFIED": 0, "NOT_OPERATIONAL": 1, "BLOCKED": 2, "INCONSISTENT": 3}


class Terminated(Exception):
    pass


def _on_signal(signum, _frame):
    raise Terminated(signum)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def check_sums(bundle, required):
    """Verify DIR/SHA256SUMS. Returns (ok, detail)."""
    sp = os.path.join(bundle, "SHA256SUMS")
    if not os.path.isfile(sp):
        return False, "SHA256SUMS missing"
    listed, bad = {}, []
    for line in open(sp, encoding="ascii", errors="replace").read().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64 or "/" in parts[1] or parts[1].startswith("."):
            return False, "SHA256SUMS malformed line: %r" % line[:80]
        listed[parts[1].lstrip("*")] = parts[0].lower()
    for name in required:
        if name not in listed:
            bad.append("not listed: %s" % name)
    for name, want in sorted(listed.items()):
        p = os.path.join(bundle, name)
        if not os.path.isfile(p):
            bad.append("missing: %s" % name)
        elif sha_file(p) != want:
            bad.append("mismatch: %s" % name)
    return (not bad), (bad if bad else "%d files match" % len(listed))


def probe_resources(path):
    """Disk free (GB, 1e9 B) at path, RAM available (GB = MemAvailable kB / 1e6), GPU. Missing = None (UNKNOWN)."""
    r = {"disk_free_gb": None, "ram_avail_gb": None, "gpu": "UNKNOWN", "gpu_compute_apps": "UNKNOWN"}
    try:
        r["disk_free_gb"] = round(shutil_free(path) / 1e9, 2)
    except OSError:
        pass
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    r["ram_avail_gb"] = round(int(line.split()[1]) / 1e6, 2)
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


def shutil_free(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


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


def verify_history(hist):
    """Re-walk history.jsonl. Returns (ok, last_line_sha256 or None, lines, error)."""
    if not os.path.exists(hist):
        return True, None, 0, None
    data = open(hist, "rb").read()
    if not data:
        return True, None, 0, None
    if not data.endswith(b"\n"):
        return False, None, 0, "torn last line (no trailing newline)"
    prev, n = None, 0
    for raw in data.split(b"\n")[:-1]:
        n += 1
        try:
            rec = json.loads(raw)
        except ValueError:
            return False, None, n, "line %d is not JSON" % n
        if not isinstance(rec, dict) or rec.get("prev_line_sha256") != prev:
            return False, None, n, "line %d prev_line_sha256 does not match line %d" % (n, n - 1)
        prev = hashlib.sha256(raw).hexdigest()
    return True, prev, n, None


def _test_delay():
    try:
        return min(1.0, float(os.environ.get("SZL_READINESS_TEST_APPEND_DELAY", "0")))
    except ValueError:
        return 0.0


def append_history(base, rec):
    """Append one chained line under an exclusive flock. Returns None, or an error string (nothing appended)."""
    hist = os.path.join(base, "history.jsonl")
    with open(os.path.join(base, ".history.lock"), "a") as lk:
        fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
        try:
            ok, prev, _n, err = verify_history(hist)
            if not ok:
                return "history chain broken: %s" % err
            d = _test_delay()
            if d:
                time.sleep(d)
            line = json.dumps(dict(rec, prev_line_sha256=prev), sort_keys=True).encode() + b"\n"
            with open(hist, "ab") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            return None
        finally:
            fcntl.flock(lk.fileno(), fcntl.LOCK_UN)


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def main(argv=None, pins=PINS, probe=probe_resources):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bundle", required=True, help="dir holding SHA256SUMS, the pinned payload and checker")
    ap.add_argument("--root", required=True, help="training run directory (read-only)")
    ap.add_argument("--data-root", required=True, help="directory the data-pins file names are relative to (read-only)")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--data-pins", required=True)
    ap.add_argument("--evidence-base", required=True)
    ap.add_argument("--min-disk-gb", type=float, default=50.0)
    ap.add_argument("--min-ram-gb", type=float, default=4.0)
    ap.add_argument("--timeout", type=int, default=3 * 3600)
    ap.add_argument("--call-timeout", type=int, default=1800)
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
            with open(cap, "w") as f:
                f.write(json.dumps(rec, indent=1, sort_keys=True, default=str))
            rec_line = {"status": status, "run_dir": run_dir, "capture_sha256": sha_file(cap), "end_utc": rec["end_utc"]}
        else:
            rec_line = {"status": status, "run_dir": None, "blockers": rec["blockers"], "end_utc": rec["end_utc"]}
        err = append_history(base, rec_line)
        if err:
            rec["blockers"].append(err)
            status = "INCONSISTENT"
        print(json.dumps({"status": status, "blockers": rec["blockers"], "run_dir": run_dir}, indent=1))
        return EXIT[status]

    # history must be intact before anything else is recorded
    ok, _p, _n, err = verify_history(os.path.join(base, "history.jsonl"))
    if not ok:
        print(json.dumps({"status": "INCONSISTENT", "blockers": ["history chain broken: %s" % err], "run_dir": None}, indent=1))
        return EXIT["INCONSISTENT"]
    # STOP latch
    if os.path.exists(os.path.join(base, "STOP")):
        rec["blockers"].append("STOP latch present")
        return done("BLOCKED")
    # bundle integrity and pins
    ok, detail = check_sums(a.bundle, list(pins))
    rec["checks"]["sha256sums"] = detail
    if not ok:
        rec["blockers"].append("SHA256SUMS: %s" % (detail if isinstance(detail, str) else "; ".join(detail[:5])))
    rec["checks"]["pins"] = {}
    for name, want in pins.items():
        p = os.path.join(a.bundle, name)
        got = sha_file(p) if os.path.isfile(p) else None
        rec["checks"]["pins"][name] = {"want": want, "got": got}
        if got != want:
            rec["blockers"].append("pin mismatch: %s" % name)
    # inputs (never substituted)
    rec["checks"]["inputs"] = {}
    for label, p, kind in (("root", a.root, "dir"), ("data_root", a.data_root, "dir"),
                           ("manifest", a.manifest, "file"), ("data_pins", a.data_pins, "file")):
        ok = bool(p) and (os.path.isdir(p) if kind == "dir" else os.path.isfile(p))
        rec["checks"]["inputs"][label] = {"path": os.path.abspath(p) if p else p, "exists": ok,
                                          "sha256": sha_file(p) if ok and kind == "file" else None}
        if not ok:
            rec["blockers"].append("missing input: %s (%s)" % (label, p))
    # resources (one policy, shared with the checker's preflight)
    res = probe(base)
    rec["checks"]["resources"] = res
    if res.get("disk_free_gb") is None or res["disk_free_gb"] < a.min_disk_gb:
        rec["blockers"].append("disk floor: %s GB < %s" % (res.get("disk_free_gb"), a.min_disk_gb))
    if res.get("ram_avail_gb") is None or res["ram_avail_gb"] < a.min_ram_gb:
        rec["blockers"].append("RAM floor: %s GB < %s" % (res.get("ram_avail_gb"), a.min_ram_gb))
    grace = min(120, max(1, a.timeout // 10))
    deadline_s = a.timeout - grace
    if deadline_s < 1:
        rec["blockers"].append("timeout %ss too small" % a.timeout)
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
    old = {s: signal.signal(s, _on_signal) for s in (signal.SIGTERM, signal.SIGHUP)}
    run_dir = None
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
               "--data-pins", os.path.abspath(a.data_pins), "--data-root", os.path.abspath(a.data_root), "--out", out,
               "--deadline-s", str(deadline_s), "--call-timeout", str(a.call_timeout),
               "--disk-path", base, "--min-disk-gb", str(a.min_disk_gb), "--min-ram-gb", str(a.min_ram_gb)]
        rec["checker_cmd"] = cmd
        proc = subprocess.Popen(cmd, cwd=run_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        rc = None
        try:
            so, se = proc.communicate(timeout=a.timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rec["process_group_killed"] = _kill_group(proc)
            so, se = proc.communicate()
            rec["blockers"].append("checker timeout after %ss" % a.timeout)
        except Terminated as e:
            rec["process_group_killed"] = _kill_group(proc)
            so, se = proc.communicate()
            rec["blockers"].append("runner terminated by signal %s" % e.args[0])
        with open(os.path.join(run_dir, "checker.stdout"), "w") as f:
            f.write(so or "")
        with open(os.path.join(run_dir, "checker.stderr"), "w") as f:
            f.write(se or "")
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
    except Terminated as e:
        rec["blockers"].append("runner terminated by signal %s" % e.args[0])
        return done("BLOCKED", run_dir)
    finally:
        for s, h in old.items():
            signal.signal(s, h)
        try:
            os.remove(lock)  # only the lock this process created
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    sys.exit(main())
