#!/usr/bin/env python3
"""szl_vm_check.py - read-only SSH check of an SZL VM (Python port of the owner PowerShell check block).

Usage:
  python szl_vm_check.py --host <ip> --user Ubuntu --key ~/.ssh/<key> --expected-fp SHA256:<43 chars> [--known-hosts ~/.ssh/known_hosts]
  python szl_vm_check.py --local        laptop disk / RAM / commit only; no network

Read-only. It never reads private key bytes, never uses a password, and never writes known_hosts or any remote file.
The host key is accepted only if it EXACTLY equals --expected-fp. That value must come from an independent source:
the VM's own console, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. The matched key is pinned into a one-line
temporary known_hosts that is used for this connection only.
Exit codes: 0 VM_KEY_LOGIN_OK (every probe field present and valid), 1 not verified / failed / incomplete, 2 usage.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import szl_session_recovery as rec  # noqa: E402  (shares the tested trust, probe and validation code)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only SSH check of an SZL VM")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--user")
    ap.add_argument("--key", help="path to the existing private key file (never read by this program)")
    ap.add_argument("--expected-fp", help="SHA256:... from the VM console")
    ap.add_argument("--known-hosts", help="existing trusted record to read the host key from (default: ssh-keyscan)")
    ap.add_argument("--local", action="store_true", help="measure this machine only; no network")
    a = ap.parse_args(argv)
    out = {"tool": "szl_vm_check", "controller_version": rec.VERSION, "laptop": rec.measure()}
    if a.local:
        print(json.dumps(out, indent=1, sort_keys=True))
        return 0
    if not (a.host and a.user and a.key and a.expected_fp):
        ap.error("--host, --user, --key and --expected-fp are required (or use --local)")
    rec.VM.update(host=a.host, port=a.port, user=a.user, key=str(Path(a.key).expanduser()), expected_fp=a.expected_fp)
    if a.known_hosts:
        os.environ["SZL_VM_KNOWN_HOSTS"] = str(Path(a.known_hosts).expanduser())
    else:
        os.environ.pop("SZL_VM_KNOWN_HOSTS", None)
    r, why = rec.run_pinned_ssh("python3 -I -S -", stdin_text=rec.REMOTE_PROBE)
    out["host_trust"] = why
    if r is None:
        out["verdict"] = "VM_NOT_VERIFIED: " + why
        print(json.dumps(out, indent=1, sort_keys=True))
        return 1
    out["exit"] = r.returncode
    out["stderr_tail"] = r.stderr[-400:]
    obs = None
    if r.returncode == 0 and len(r.stdout) <= 131072:
        try:
            obs = json.loads(r.stdout)
        except ValueError:
            obs = None
    ok, problems = rec.validate_probe(obs)
    out["observation"] = obs
    if r.returncode != 0:
        out["verdict"] = f"VM_SSH_FAILED exit {r.returncode}"
    elif not ok:
        out["verdict"] = f"VM_PROBE_INCOMPLETE {problems}"
    else:
        out["verdict"] = "VM_KEY_LOGIN_OK"
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0 if out["verdict"] == "VM_KEY_LOGIN_OK" else 1


if __name__ == "__main__":
    sys.exit(main())
