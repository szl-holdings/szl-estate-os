# ops/recovery

Python tools for the SZL session-recovery work. Everything here is standard library only (Python 3.9+), with no third-party dependencies.

| file | purpose |
|---|---|
| `szl_session_recovery.py` | Fail-closed recovery controller **1.2.0-proposed**: read-only status of PRs, CI and owner items; approval-gated write items |
| `szl_vm_check.py` | Read-only SSH check of a VM: identity, GPU, RAM, disk and GPU processes. It is the Python port of the owner PowerShell block |
| `tests/test_recovery_offline.py` | Offline regression tests: fake GitHub transport, no network, no SSH |

## Safety model
- **Write items** run only if `~/szl_recovery/approvals.json` lists the item ID and names `approved_by`. The owner writes that file by hand; agents never create or edit it. A name in that file is not a signature.
- **Re-runs and VM staging** run only against exact pins: `run_id`, `attempt`, `head_sha` (plus `workflow_path` or `commit`). VM staging lists files and hashes and executes nothing.
- **Merges** are admitted only when GitHub reports `mergeable_state == clean` and the check read is complete and green. A merge counts as successful only after a readback; otherwise it is reported as `UNCERTAIN` and never retried.
- **Check reads** that are incomplete or fail (403/404/429/5xx, count mismatch, head moved mid-read) are UNKNOWN, never "no checks".
- **Host trust:** the host key must exactly equal a fingerprint taken from the VM console. Only that key is pinned, for that connection only. Passwords are never used.
- **`status`** reports at most `OWNER_ITEMS_CLOSED_LEDGER_INTACT`. That covers owner-item evidence and ledger integrity only, and is not an operational-readiness claim.
- **The ledger** (`~/szl_recovery/ledger.jsonl`) is an unsigned local hash chain. It catches accidental edits, not a deliberate full rewrite.

## Run
```
python ops/recovery/szl_session_recovery.py selftest
python -m unittest discover -s ops/recovery/tests -v
python ops/recovery/szl_vm_check.py --local
python ops/recovery/szl_vm_check.py --host <ip> --user Ubuntu --key ~/.ssh/<key> --expected-fp SHA256:<from VM console> --known-hosts ~/.ssh/known_hosts
```

## Evidence status (2026-10-28)
- MEASURED (offline, synthetic): the selftest passes 26 gate tests and 43 repair tests, with 20/20 mutants killed, and the `tests/` suite passes 15/15. Both ran on VM1 (Linux 6.8, Python 3.10.12) and in a sandboxed Python 3 kernel, but not yet on the Windows laptop.
- NOT RUN: real GitHub writes, a real SSH probe via `szl_vm_check.py --host`, Windows OpenSSH handling of `-F <devnull>` and `GlobalKnownHostsFile=<devnull>`. These are UNKNOWN until run.
- CI: `ci.yml` runs only listed test files, so these tests are **not** wired into CI. Wiring them is a separate approval.
- Supersedes 1.1.0 (sha256 `735f6572…`), whose write path must not be used: it merged on unstable/has_hooks, read only the first 100 checks, matched fingerprints by substring, and made network calls in offline mode.
