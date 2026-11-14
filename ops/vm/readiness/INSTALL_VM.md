# SZL unattended readiness check 0.2.0: VM install runbook

Status: 0.2.0 replaces 0.1.0 (merged in szl-estate-os#79). The daily timer is NOT enabled by anything in this
repository; enabling it is step 5 and needs the owner's approval of step 4's evidence.

## What it does once installed
Each day at 06:00 UTC, systemd runs `szl_readiness_runner.py` once. It:
- verifies every file in `SHA256SUMS`, and the pinned bytes of payload 1.4.0 and checker 0.2.0
- refuses if the run dir, the data root, the manifest M or the data-pins file P is missing; if disk or RAM is
  below its floor (or UNKNOWN); if a STOP file is present; if a run lock is held; or if `history.jsonl` fails
  its own chain check
- runs the checker in a fresh run directory, in its own process group, with no network access
  (`IPAddressDeny=any`) and a deadline below the runner timeout
- the checker re-hashes every checkpoint file and every pinned dataset file itself, refuses manifest names that
  leave the checkpoint, requires the manifest to list every checkpoint file, and measures train/eval overlap
  itself (payload `leakage`) instead of trusting the pins file
- reads the verdict back itself and writes `capture.json`
- appends one hash-chained line to `/var/lib/szl-readiness/history.jsonl` under a file lock

To stop it: `touch /var/lib/szl-readiness/STOP` (the service will not start while the file exists).
It never trains, signs, uploads, pushes or rents anything. The only processes it kills are its own checker's.

## Install steps
1. Read-only first: `hostname; id -un; df -h; free -g; nvidia-smi; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
   Stop if the host-key fingerprint differs from the pinned one.
2. Find the real inputs: the training run directory R, its checkpoint manifest M, the data-pins file P and the
   data root D that P's file names are relative to. `sha256sum` M and P. If any is missing, leave it empty;
   the runner then BLOCKs. Do not substitute anything.
3. First run without sudo: copy this directory to `~/szl-readiness-0.2.0`, run `sha256sum -c SHA256SUMS` there,
   then `python3 -I -B ~/szl-readiness-0.2.0/szl_readiness_runner.py --bundle ~/szl-readiness-0.2.0 --root R
   --data-root D --manifest M --data-pins P --evidence-base ~/szl-readiness-evidence`. This hand run has
   network access and no systemd sandbox: report it as UNSANDBOXED. Read back `capture.json` and
   `readiness/readiness_verdict.json`.
4. Owner reviews step 3's evidence.
5. Only after that approval: `sudo install -d /opt/szl/readiness /etc/szl`, copy the bundle to
   `/opt/szl/readiness`, `sha256sum -c SHA256SUMS`, write `/etc/szl/readiness.env`, copy the `.service` and
   `.timer` to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now szl-readiness.timer`.

## Known limits
- **OPERATIONAL_VERIFIED is scoped:** it covers only the checker's gates. It does not cover governed-runtime
  integration, model evaluation, DSSE signing, deployment or training.
- **Floors:** one policy, decimal GB, measured at the evidence base and handed unchanged to the payload's
  preflight. Default 50 GB disk, 4 GB RAM (MemAvailable kB / 1e6).
- **Cost:** the checker re-hashes every checkpoint and dataset file and measures overlap per train x eval pair;
  large inputs need a larger `--timeout`. Exceeding the budget fails the affected gates as TIMEOUT.
- **Stale lock:** SIGTERM/SIGHUP release the lock; SIGKILL, power loss or OOM kill can still leave `.lock`,
  which then blocks every run until a human confirms no run is active and removes it.
