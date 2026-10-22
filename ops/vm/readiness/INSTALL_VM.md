# SZL unattended readiness check: VM install runbook (PROPOSAL, not installed)

Status: built and tested on the Windows laptop with a stub checker only. Never installed or run on the VM.
Nothing committed or pushed. Proposed home: `szl-holdings/szl-estate-os: ops/vm/readiness/`.

## What it does once installed
Each day at 06:00 UTC, systemd runs `szl_readiness_runner.py` once. It:
- verifies the pinned bytes: payload 1.1.2 `ef05883d…` and checker `b23ea341…`
- refuses if the run dir, the manifest M or the data-pins file P is missing, if disk or RAM is below its floor (or UNKNOWN), if a STOP file is present, or if a lock is held
- runs the checker in a fresh run directory with no network access (`IPAddressDeny=any`)
- reads the verdict back itself and writes `capture.json` (command, exit code, logs, identity, SSH host-key fingerprints, GPU, hashes)
- appends one hash-chained line to `/var/lib/szl-readiness/history.jsonl`

To stop it: `touch /var/lib/szl-readiness/STOP` (the service will not start while the file exists).

It never trains, kills processes, signs, uploads, pushes or rents anything.

## Install steps (the agent runs these once the VM is registered in Customize → Compute)
1. Read-only first: `hostname; id; df -h; free -g; nvidia-smi; ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Compare the fingerprint with the one the owner reads from the Massed Compute console, and stop on any mismatch.
2. Find the real inputs: locate the training run directory, its manifest and data-pins file, then `sha256sum` them. If any is missing, leave it empty in the env file. The runner will then BLOCK; do not substitute anything.
3. `sudo install -d /opt/szl/readiness /etc/szl` and copy this bundle into `/opt/szl/readiness`. Run `sha256sum -c SHA256SUMS`, and stop on any mismatch.
4. Run it once by hand: `python3 -I -B /opt/szl/readiness/szl_readiness_runner.py --bundle /opt/szl/readiness --root R --manifest M --data-pins P --evidence-base /var/lib/szl-readiness`, then read back `capture.json` and `readiness/readiness_verdict.json`.
5. Only after the owner approves step 4's evidence: write `/etc/szl/readiness.env`, copy the `.service` and `.timer` to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now szl-readiness.timer`.

## Known limits
- **OPERATIONAL_VERIFIED is scoped:** it covers only the checker's gates. It does not cover governed-runtime integration, model evaluation, DSSE signing, deployment or training.
- **UNKNOWN: empty env values:** it is not verified how systemd expands an empty `${SZL_ROOT}`. If the word is dropped, argparse exits 2 without writing a history line. That still fails closed, but the refusal is only visible in `journalctl -u szl-readiness`.
- **Untested on Linux:** tests ran on Windows, where `/proc/meminfo` does not exist (RAM was injected). The Linux probe code is untested until step 4.
- **Unconfirmed user name:** `User=Ubuntu` is REPORTED from the portal; confirm it with `id`.
