#!/usr/bin/env python3
"""SZL master payload for Claude Code on the authorized SZL VM.

One file. Standard library only. Run with `python3 -I -B szl_vm_master_payload.py <cmd>`.

Commands (all read-only except writes under --out):
  brief            write SZL_MASTER_BRIEF.md (the control plan Claude Code follows)
  preflight        host/repo/GPU/disk/process identity -> receipt
  inventory ROOT   find coordinators, registers, locks, leases, heartbeats, checkpoints
  training ROOT    optimizer-step evidence from checkpoints (HF Trainer layout)
  resume-gate ROOT --manifest M --data-pins P [--launch-cmd "..."]
                   ADMIT/REFUSE a resume. Never launches anything.
  leakage TRAIN EVAL   exact + near-duplicate overlap between two JSONL/text files (normalised hashing, MinHash/LSH)
  failures ROOT    scan logs for known prior-failure signatures (read-only)
  verify OUT       independent readback of a receipt chain (hashes, links, orphans); writes nothing
  e2e              end-to-end rehearsal on synthetic data through every CLI command, then verify + tamper test
  certify [--out]  selftest + e2e + preflight + verify in fresh interpreters -> one verdict (CERTIFIED / NOT_CERTIFIED)
  Global: --dry-run on any command computes everything and writes nothing.
  selftest         planted fixtures + mutant gates; exit 0 only if every mutant is caught

Exit codes: 0 ok/ADMIT, 1 REFUSE, BLOCKED, DEGRADED or verify failure, 2 usage error, 3 selftest failed.
Receipts are written atomically (tmp + os.replace) and hash-chained per --out dir.
Nothing here pushes, publishes, deletes, kills processes or launches training.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import uuid

VERSION = "szl-vm-master-payload/1.4.0"
DRY_RUN = False  # set by --dry-run: nothing is written anywhere
UTC = _dt.timezone.utc

BRIEF_MD = r"""# SZL master brief for Claude Code (VM)

You are the single SZL coordinator on this VM. **Resume. Do not restart.**
Never start a duplicate worker, writer, training run, PR, deployment or publication.

## 0. Binding rules
- Read-only first. Before any remote write (push, PR, HF upload, DNS/route change, forum post), show the exact
  command, the diff, the tests and the rollback, then wait for Stephen's approval **of that action by name**.
  A general go-ahead ("push", "green light", "push the frontier") is permission to keep working, not approval of a write.
- Label every claim exactly once: MEASURED (you ran it now), REPORTED (from a named source), MODELED (follows from code),
  CONJECTURE, or UNKNOWN. Missing inventory is UNKNOWN, never zero.
- Never print, copy, upload or commit secrets. Report credentials as what the code *observes*:
  `env_var_set` / `env_var_unset_other_sources_not_checked`. Never write `credentials_present: false` from an unset env var.
- Never handle PHI, patient, clinical, HL7, FHIR, specimen, order or result content. Anatomy / "second brain" are metaphors.
- No paid actions, irreversible deletion, Recycle Bin emptying, process termination, credential/security changes,
  branch-protection bypass, form submission or terms acceptance. Stop on HTTP 403/429 and record the reset guidance.
- Research, prototype, pilot-ready, simulated and live must stay distinct. "Fully operational" only for a named
  end-to-end flow with tests, a receipt, authenticated runtime proof and independent readback. HTTP 200 alone proves nothing.
- Shareable outputs redact hostnames, IPs, local paths, tunnel names, org IDs and session nonces (`--shareable`).

## 1. Read existing work first (in this order)
1. `python3 -I -B szl_vm_master_payload.py preflight --out receipts/` -- identity, repo state, GPU, disk, processes.
2. `... inventory <workspace root> --out receipts/` -- coordinators, registers, locks, leases, heartbeats, checkpoints.
3. Reconcile active writers and owners from that inventory. Reuse the named owner or make a bounded, written handoff;
   never take over silently. Never erase a lock/claim to force a restart.
4. Known state from the Claude Science project (REPORTED; re-verify before use):
   - GitHub szl-holdings: 148 repos (129 public, 19 private, 29 archived). HF SZLHOLDINGS: 54 models, 47 datasets, 46 Spaces.
   - Open draft PRs: szl-holdings/a11oy#2922 (README evidence rows), szl-holdings/szl-skills#65 (typesafe pin),
     szl-holdings/szl-org-health#277 (census counter fix; required checks green). None merged.
   - Mail auth (MEASURED 2026-10-20 via DoH): a-11-oy.com and a11oy.net have SPF -all + DMARC p=reject (census said MISSING);
     szlholdings.com sends mail with no DMARC; alloyszlholdings.com has no SPF/DMARC; killinchu.net does not resolve.
   - The live a11oy Space was reported 6 commits behind a11oy main; README changes reach it only after a redeploy.
   - Phase 0 gate on the laptop is BLOCKED on disk; the VM has its own gate -- run preflight here.

## 2. 50-hour training recovery
- Locate the original plan: model revision, tokenizer, dataset pins and rights, split, seed, optimizer, scheduler,
  batch sizes, precision, checkpoint cadence, lease, deadline (with timezone) and last verified heartbeat.
- `... training <run dir>` reports optimizer steps from checkpoints. **Wall time is not training time.** Optimizer-step
  evidence = increasing `global_step` across checkpoints whose `optimizer.pt` hashes differ.
- `... resume-gate <run dir> --manifest <hashes.json> --data-pins <pins.json> --launch-cmd "<exact cmd>"` must return
  ADMIT before any resume. It refuses on: missing/mismatched checkpoint hashes, incomplete checkpoint, live trainer
  process (name match, or any GPU compute process that is not a known inference server), any lock file (stale or not -- a human resolves it), missing dataset pins or rights, missing deadline.
- Before any resume: `... failures <run dir>` (prior failures: SYSTEM_PYTHON_3_12_REQUIRED, HTTP 404/403/429, CUDA/host
  OOM, NCCL, disk full, checksum mismatch) and `... leakage <train.jsonl> <heldout.jsonl>`; record `eval_files` and
  `row_overlap` and `near_dup_overlap` in the data pins. The gate refuses without separately pinned held-out data and
  a measured zero for both (near-duplicates: exact char-5-gram Jaccard >= 0.8 on MinHash/LSH candidates).
  `... training <run dir> --run-config cfg.json` adds samples seen (steps x batch x grad-accum x world), labelled MODELED.
  Add `--dry-run` to any command to compute everything and write nothing.
- After any run of commands: `... verify receipts/` must print ok=true (independent readback of the receipt chain).
  `... e2e` rehearses the whole flow on synthetic data; PASS means ADMIT + verified chain + tamper detected on THIS host.
  DEGRADED means the only failure was a host capability (e.g. process listing denied) -- fix the host, do not override.
  `... certify --out receipts/` is the single readiness command: CERTIFIED (exit 0) only if selftest PASS, e2e PASS,
  preflight PASS and the receipt chain verifies. Anything else is NOT_CERTIFIED with named reasons.
- ADMIT does not launch. Show Stephen the printed command, then launch **once**, with one writer. Report run dir,
  launch time UTC, deadline with timezone, PID + process start time, first heartbeat, first new optimizer step.
- Do not reset the 50-hour window. Do not repeat a tiny dataset to fill hours. Inference, source study and
  engineering are not weight updates -- report them separately.

## 3. Snowflake and NVIDIA reference study (read-only)
- Use only public pages and Snowflake public docs. The signed-in workspace (app.snowflake.com/...) may be *viewed* by
  Stephen in a browser as a UX reference; do not scrape, export, change settings or copy proprietary code.
  Do not open the snowflake.research.net survey link (personal lead token; it is a form).
- Reuse the Claude Science outputs: snowflake_reference_fit_matrix_2026-10-20.md, snowflake_ux_patterns_2026-10-20.csv,
  phoenix_products_draft_2026-10-20.md. Concept: governed data-to-decision cell (permitted data -> cited analysis ->
  anomaly/decision candidate -> abstain on weak evidence -> human approval -> receipt). Synthetic or rights-cleared data only.
  No live actuation. Never claim the workspace is integrated without a connector, tests and live readback.

## 4. Product, estate and command-surface audit
Order: GitHub source -> Hugging Face publication -> a-11-oy.com product/runtime -> a11oy.net public proof registry.
Start from command_surface_matrix_2026-10-20.csv (10 items: overview/drift, work queue, provenance timeline, registry,
training/eval monitor, approval gate, cost view with no invented numbers, demo gallery with research/prototype/live labels,
release readiness, a11oy.net proof view). For each proposed UI change: owned component + API contract; a real repo/
runtime/model/dataset/receipt behind every card; loading/empty/error/stale/permission/offline states; keyboard, contrast,
responsive, accessible labels; source revision, timestamp, evidence status, confidence; human approval for consequential
actions; API+UI tested together, then independent readback. Keep SZL's own visual system.
One PR per bounded change. Never merge unless exact-head checks, reviews, signatures and the ruleset pass.
Publish to HF only when the GitHub revision, artifact checksum, rights and publication gates match.
Change domains only after authenticated deployment evidence and readback. Never route Cloudflare to ThinLinc, raw
llama-server, laptop tunnels or unauthenticated endpoints.
InVerita demo: synthetic/licensed observation -> cited checklist -> anomaly candidate -> abstain -> human approval ->
modeled ticket -> signed receipt. No targeting, weapons, flight control, navigation, actuation or dispatch.

## 5. Receipts and final report
Every completed item gets a receipt (this script's `receipt` format): UTC time, scope, owner, files, source revision,
commands, tests, security checks, runtime/readback, artifact hashes, publication state, remaining limits.
Final report sections: inspected; changed; commits/PRs/checks/receipts; verified optimizer steps and training time;
Snowflake/NVIDIA findings; product matrix with evidence links; GitHub/HF/domain drift; blockers and approvals needed;
what remains proposed or unverified. Never invent a result.
"""


# ------------------------------------------------------------------ utils
def now() -> str:
    return _dt.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], timeout: int = 20) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"exit": p.returncode, "out": p.stdout.strip()[-4000:], "err": p.stderr.strip()[-400:]}
    except FileNotFoundError:
        return {"exit": None, "out": "", "err": "not installed"}
    except subprocess.TimeoutExpired:
        return {"exit": None, "out": "", "err": f"timeout {timeout}s"}


def redact(obj, shareable: bool):
    if not shareable:
        return obj
    text = json.dumps(obj)
    for s in {socket.gethostname(), os.path.expanduser("~"), os.getcwd()}:
        if s and len(s) > 2:
            text = text.replace(json.dumps(s)[1:-1], "[REDACTED]")
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", text)
    return json.loads(text)


def write_receipt(out_dir: str, kind: str, body: dict, shareable: bool = False) -> str:
    if DRY_RUN:
        data = json.dumps({"schema": VERSION, "kind": kind, "body": redact(body, shareable)}, sort_keys=True).encode()
        return f"DRY-RUN (not written) sha256={hashlib.sha256(data).hexdigest()[:12]}"
    os.makedirs(out_dir, exist_ok=True)
    chain = os.path.join(out_dir, "chain.json")
    prev = json.load(open(chain)).get("head") if os.path.exists(chain) else None
    rec = {"schema": VERSION, "kind": kind, "utc": now(), "prev_receipt_sha256": prev, "body": redact(body, shareable)}
    data = json.dumps(rec, indent=1, sort_keys=True).encode()
    digest = hashlib.sha256(data).hexdigest()
    name = os.path.join(out_dir, f"{rec['utc'].replace(':', '')}_{kind}_{digest[:12]}.json")
    for path, payload in ((name, data), (chain, json.dumps({"head": digest, "last": os.path.basename(name)}).encode())):
        tmp = path + f".tmp{uuid.uuid4().hex[:6]}"
        with open(tmp, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    return name


def credential_observation(var: str) -> str:
    # Name the field for what is observed: an unset env var does not prove absence.
    return "env_var_set" if os.environ.get(var) else "env_var_unset_other_sources_not_checked"


# ------------------------------------------------------------------ preflight
def list_processes(runner=None) -> list[str] | None:
    """None means the listing FAILED (not installed, denied, timeout, empty output). Never coerce it to []:
    an empty list would read as 'no trainer running' and fail open. 1.1.1."""
    runner = runner or run
    r = runner(["tasklist", "/fo", "csv", "/nh"]) if os.name == "nt" else runner(["ps", "-eo", "pid,lstart,args"])
    lines = r["out"].splitlines() if r["exit"] == 0 else []
    return lines or None


TRAINER_PAT = re.compile(r"(?i)(train[\w.-]*\.(py|sh)\b|finetun\w*\.(py|sh)\b|\bsft[\w.-]*\.py\b|accelerate launch|torchrun"
                         r"|deepspeed|axolotl|unsloth|\btrl\b)")  # 1.4.0: train_nemo.py / *_train.sh were missed on the VMs
GPU_SERVER_PAT = re.compile(r"(?i)(llama-server|llama-cli|ollama|tritonserver|triton_python_backend_stub|VLLM::EngineCore"
                            r"|\bvllm\b.*\bserve\b|text-generation-launcher|sglang\.launch_server)")
_SECRET_RE = re.compile(r"(?i)((?:hf_|ghp_|gho_|github_pat_|sk-)[A-Za-z0-9_-]{6,}|(--?(?:token|api[-_]key|password|secret)[= ])\S+)")


def _scrub(s: str) -> str:
    """Redact token-shaped strings and --token/--api-key/--password values from process command lines."""
    return _SECRET_RE.sub(lambda m: (m.group(2) or m.group(1)[:3]) + "[REDACTED]", s)


def list_gpu_apps(runner=None):
    """[(pid, cmdline)] of GPU compute processes. [] when nvidia-smi is not installed (no GPU to train on);
    None when it exists but fails or times out -- fail closed, never read a failed listing as 'idle'. 1.4.0."""
    runner = runner or run
    r = runner(["nvidia-smi", "--query-compute-apps=pid,process_name", "--format=csv,noheader"])
    if r["exit"] is None and r["err"] == "not installed":
        return []
    if r["exit"] != 0:
        return None
    apps = []
    for line in r["out"].splitlines():
        pid = line.split(",")[0].strip()
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            cmd = ""
        apps.append((int(pid), cmd or (line.split(",", 1)[1].strip() if "," in line else "")))
    return apps


def unclassified_gpu(apps) -> list:
    """GPU compute processes that are not a known inference server: treated as possible trainers (a human classifies)."""
    return [_scrub(f"{p} {c}")[:200] for p, c in apps if p not in (os.getpid(), os.getppid()) and not GPU_SERVER_PAT.search(c)]


def ram_available_gb():
    if os.name == "nt":  # 1.2.0: GlobalMemoryStatusEx; None (-> UNKNOWN blocker) if the call fails
        try:
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
                    (n, ctypes.c_ulonglong) for n in ("total", "avail", "tpf", "apf", "tv", "av", "aev")]
            m = _MS(); m.dwLength = ctypes.sizeof(_MS)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return round(m.avail / 1e9, 1)
        except Exception:
            pass
        return None
    try:
        with open("/proc/meminfo") as fh:
            mem = {l.split(":")[0]: int(l.split()[1]) for l in fh if ":" in l}
        return round(mem["MemAvailable"] / 1e6, 1)
    except Exception:
        return None


def cmd_preflight(a) -> int:
    du = shutil.disk_usage(a.disk_path)
    body = {
        "host": socket.gethostname(), "user": os.environ.get("USER") or os.environ.get("USERNAME"),
        "platform": platform.platform(), "python": sys.version.split()[0],
        "disk_path": a.disk_path, "disk_free_gb": round(du.free / 1e9, 1), "disk_total_gb": round(du.total / 1e9, 1),
        "ram_available_gb": ram_available_gb(),
        "gpu": run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used,driver_version", "--format=csv,noheader"]),
        "cuda": (run(["nvcc", "--version"])["out"].splitlines() or ["not found"])[-1],
        "credentials": {v: credential_observation(v) for v in ("GITHUB_TOKEN", "HF_TOKEN")},
        "trainer_processes": (lambda ps: "UNKNOWN: process listing failed" if ps is None
                              else [_scrub(p) for p in ps if _is_trainer(p)])(list_processes()),
        "gpu_unclassified": (lambda g: "UNKNOWN: GPU process listing failed" if g is None
                             else unclassified_gpu(g))(list_gpu_apps()),
        "repos": [],
    }
    for root in a.repo or []:
        g = lambda *c: run(["git", "-C", root, *c])["out"]
        body["repos"].append({"root": root, "branch": g("rev-parse", "--abbrev-ref", "HEAD"), "head": g("rev-parse", "HEAD"),
                              "remotes": g("remote", "-v").splitlines(), "dirty_files": len(g("status", "--porcelain").splitlines())})
    blockers = []
    if isinstance(body["trainer_processes"], str):
        blockers.append("process listing failed; live trainers UNKNOWN")
    if body["disk_free_gb"] < a.min_disk_gb:
        blockers.append(f"disk_free {body['disk_free_gb']} GB < {a.min_disk_gb} GB")
    if body["ram_available_gb"] is None:
        blockers.append("ram_available UNKNOWN (no /proc/meminfo); verify by hand")
    elif body["ram_available_gb"] < a.min_ram_gb:
        blockers.append(f"ram_available {body['ram_available_gb']} GB < {a.min_ram_gb} GB")
    body["status"] = "BLOCKED" if blockers else "PASS"
    body["blockers"] = blockers
    path = write_receipt(a.out, "preflight", body, a.shareable)
    print(json.dumps({"status": body["status"], "blockers": blockers, "receipt": path}))
    return 1 if blockers else 0


# ------------------------------------------------------------------ inventory
INV_PATTERNS = {
    "coordinator": re.compile(r"(?i)(coordinator|task_register|master_register|register)\.(json|md|jsonl|csv)$"),
    "lock": re.compile(r"(?i)(\.lock$|^lock(\.json)?$|\.pid$)"),
    "lease": re.compile(r"(?i)lease.*\.json$"),
    "heartbeat": re.compile(r"(?i)heartbeat.*\.(json|jsonl|txt)$"),
    "trainer_state": re.compile(r"^trainer_state\.json$"),
    "receipt": re.compile(r"(?i)receipt.*\.json$"),
    "plan": re.compile(r"(?i)(training_plan|run_config|train_config).*\.(json|ya?ml|md)$"),
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache"}


def scan(root: str, max_files: int = 200000) -> dict:
    found = {k: [] for k in INV_PATTERNS}
    seen = 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            seen += 1
            for k, pat in INV_PATTERNS.items():
                if pat.search(f):
                    p = os.path.join(d, f)
                    st = os.stat(p)
                    found[k].append({"path": os.path.relpath(p, root), "bytes": st.st_size,
                                     "mtime_utc": _dt.datetime.fromtimestamp(st.st_mtime, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
            if seen >= max_files:
                return {"truncated": True, "files_seen": seen, "found": found}
    return {"truncated": False, "files_seen": seen, "found": found}


def cmd_inventory(a) -> int:
    body = {"root": a.root, **scan(a.root)}
    body["counts"] = {k: len(v) for k, v in body["found"].items()}
    body["note"] = "a zero count means not found under this root, not proof the item does not exist"
    path = write_receipt(a.out, "inventory", body, a.shareable)
    print(json.dumps({"counts": body["counts"], "truncated": body["truncated"], "receipt": path}))
    return 0


# ------------------------------------------------------------------ training evidence
CKPT_RE = re.compile(r"^(?:checkpoint|step)-(\d+)$")  # 1.4.0: also <run>/checkpoints/step-N
REQUIRED = ("trainer_state.json", "optimizer.pt", "scheduler.pt")
WEIGHTS = re.compile(r"^(model.*\.safetensors|pytorch_model.*\.bin|adapter_model\.(safetensors|bin))$")


def checkpoints(run_dir: str) -> list[dict]:
    out = []
    if not os.path.isdir(run_dir):
        return out
    sub = os.path.join(run_dir, "checkpoints")
    entries = [(n, n) for n in os.listdir(run_dir)] + (
        [(n, os.path.join("checkpoints", n)) for n in os.listdir(sub)] if os.path.isdir(sub) else [])
    for base_name, name in entries:
        m = CKPT_RE.match(base_name)
        p = os.path.join(run_dir, name)
        if not (m and os.path.isdir(p)):
            continue
        files = set(os.listdir(p))
        c = {"name": name, "dir_step": int(m.group(1)), "files": sorted(files),
             "complete": all(r in files for r in REQUIRED) and any(WEIGHTS.match(f) for f in files),
             "mtime_utc": _dt.datetime.fromtimestamp(os.stat(p).st_mtime, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}
        ts = os.path.join(p, "trainer_state.json")
        if os.path.exists(ts):
            try:
                st = json.load(open(ts))
                logs = [x for x in st.get("log_history", []) if "loss" in x]
                c.update({"global_step": st.get("global_step", st.get("step")), "max_steps": st.get("max_steps"),
                          "epoch": st.get("epoch"), "last_loss": logs[-1]["loss"] if logs else st.get("train_loss"),
                          "validation_loss": st.get("validation_loss", st.get("eval_loss")),
                          "elapsed_seconds": st.get("elapsed_seconds"), "has_optimizer_state": "optimizer.pt" in files})
            except ValueError:
                c["trainer_state_error"] = "unparseable"
        if "optimizer.pt" in files:
            c["optimizer_sha256"] = sha256_file(os.path.join(p, "optimizer.pt"))
        out.append(c)
    return sorted(out, key=lambda c: c["dir_step"])


def _samples_seen(step, cfg: dict | None):
    """MODELED: optimizer steps x per-device batch x grad-accumulation x world size, from a run config."""
    if step is None or not cfg:
        return None
    try:
        b, ga, ws = (int(cfg[k]) for k in ("per_device_train_batch_size", "gradient_accumulation_steps", "world_size"))
    except (KeyError, TypeError, ValueError):
        return None
    return {"samples_seen": step * b * ga * ws, "per_device_train_batch_size": b, "gradient_accumulation_steps": ga,
            "world_size": ws, "label": "MODELED from run config; optimizer steps are the MEASURED quantity"}


def _fit_signal(cks: list) -> dict | None:
    pts = [(c["global_step"], c["last_loss"], c["validation_loss"]) for c in cks
           if c.get("global_step") is not None and c.get("last_loss") is not None and c.get("validation_loss") is not None]
    if len(pts) < 2:
        return None
    (s0, t0, v0), (s1, t1, v1) = pts[0], pts[-1]
    best = min(pts, key=lambda x: x[2])
    out = {"first": {"step": s0, "train_loss": t0, "validation_loss": v0},
           "last": {"step": s1, "train_loss": t1, "validation_loss": v1},
           "best_validation": {"step": best[0], "validation_loss": best[2]}, "checkpoints_with_losses": len(pts),
           "label": "REPORTED by the trainer's own trainer_state files; compared by this script"}
    if t1 < t0 and v1 > v0:
        out["warning"] = ("train loss fell while validation loss rose: overfitting/memorisation signal; "
                          "the latest checkpoint is not the best on validation")
    return out


def training_evidence(run_dir: str, cfg: dict | None = None) -> dict:
    cks = checkpoints(run_dir)
    steps = [c.get("global_step") for c in cks if c.get("global_step") is not None]
    opt = [c.get("optimizer_sha256") for c in cks if c.get("optimizer_sha256")]
    real = (len(steps) >= 2 and all(b > a for a, b in zip(steps, steps[1:])) and len(opt) >= 2 and len(set(opt)) == len(opt))
    weak = None
    if not real and len(cks) >= 2 and len(steps) >= 2 and all(b > a for a, b in zip(steps, steps[1:])):
        def _wsha(c):
            w = next((f for f in c["files"] if WEIGHTS.match(f)), None)
            return sha256_file(os.path.join(run_dir, c["name"], w)) if w else None
        a_, b_ = _wsha(cks[0]), _wsha(cks[-1])
        if a_ and b_ and a_ != b_:
            weak = ("MEASURED (weaker): step increases across checkpoints and first/last weight files differ; "
                    "no optimizer state, so individual updates are not proven")
    fit = _fit_signal(cks)
    return {"run_dir": run_dir, "checkpoints": cks, "n_checkpoints": len(cks),
            "latest_complete": next((c["name"] for c in reversed(cks) if c["complete"]), None),
            "optimizer_steps_latest": steps[-1] if steps else None,
            "optimizer_step_evidence": "MEASURED: increasing global_step with distinct optimizer states" if real
            else (weak or "UNKNOWN: fewer than 2 checkpoints with increasing steps and distinct optimizer states"),
            "wall_span_between_checkpoints": [cks[0]["mtime_utc"], cks[-1]["mtime_utc"]] if cks else None,
            "wall_span_note": "directory mtimes; wall time, not optimizer time",
            "samples": _samples_seen(steps[-1] if steps else None, cfg),
            "grad_accum_note": "HF global_step counts optimizer updates, i.e. already divided by gradient_accumulation_steps",
            "fit_signal": fit}


def cmd_training(a) -> int:
    body = training_evidence(a.root, json.load(open(a.run_config)) if a.run_config else None)
    path = write_receipt(a.out, "training", body, a.shareable)
    keep = ("n_checkpoints", "latest_complete", "optimizer_steps_latest", "optimizer_step_evidence", "fit_signal")
    print(json.dumps({**{k: body[k] for k in keep}, "receipt": path}))
    return 0


# ------------------------------------------------------------------ resume gate
def _chk_complete(ctx):
    # The NEWEST checkpoint must be complete. Silently falling back to an older one loses progress
    # and is a human decision, so an incomplete newest checkpoint refuses.
    c, latest = ctx["ckpt"], ctx["latest"]
    if latest is None:
        return (False, "no checkpoints found")
    if not latest["complete"]:
        return (False, f"newest checkpoint {latest['name']} is incomplete; fallback to {c['name'] if c else None} needs a human")
    return (c is not None and c["name"] == latest["name"], f"newest checkpoint complete: {latest['name']}")


def _chk_manifest(ctx):
    man, c = ctx["manifest"], ctx["ckpt"]
    if not man or c is None:
        return (False, "no checkpoint manifest (provenance missing)")
    want = man.get(c["name"])
    if not want:
        return (False, f"manifest has no entry for {c['name']}")
    bad = [f for f, h in want.items() if not os.path.exists(os.path.join(ctx["root"], c["name"], f))
           or sha256_file(os.path.join(ctx["root"], c["name"], f)) != h]
    return (not bad, ("hash mismatch or missing: " + ",".join(bad)) if bad else "all manifest hashes match")


SERVER_EXE_PAT = re.compile(r"(?i)^(llama-server|llama-cli|ollama|vllm)(\.exe)?$")


def _argv0(line: str) -> str:
    """Executable of a process line: `ps -eo pid,lstart,args` (pid + 5 lstart tokens) or tasklist CSV/table."""
    s = line.strip()
    if s.startswith('"'):
        return s.split('","')[0].strip('"')
    parts = s.split()
    if parts and parts[0].isdigit():
        return parts[6] if len(parts) > 6 and re.fullmatch(r"\d{4}", parts[5]) else (parts[1] if len(parts) > 1 else "")
    return parts[0] if parts else ""


def _is_trainer(line: str) -> bool:
    """TRAINER_PAT on a process line, minus two false positives: this payload's own process (its --launch-cmd
    text self-matches) and inference servers whose *executable* is a server. Only argv[0] is checked, so a
    trainer whose arguments merely mention a server path (e.g. --out /models/ollama) is still a trainer."""
    parts = line.split()
    if parts and parts[0].isdigit() and int(parts[0]) in (os.getpid(), os.getppid()):
        return False
    if SERVER_EXE_PAT.match(os.path.basename(_argv0(line).replace("\\", "/"))):
        return False
    return bool(TRAINER_PAT.search(line))


def _chk_no_trainer(ctx):
    if ctx["processes"] is None:
        return (False, "process listing failed; cannot rule out a live trainer")
    gpu = ctx.get("gpu_apps", ())
    if gpu is None:
        return (False, "GPU process listing failed; cannot rule out a live trainer")
    live = [_scrub(p)[:200] for p in ctx["processes"] if _is_trainer(p)]
    odd = unclassified_gpu(gpu)
    ok = not live and not odd
    return (ok, f"live trainer processes: {len(live)}; unclassified GPU compute processes: {len(odd)}"
            + ("" if ok else " -> " + " | ".join((live + odd)[:4])))


def _chk_no_lock(ctx):
    locks = [x["path"] for x in scan(ctx["root"])["found"]["lock"]]
    return (not locks, ("locks present (a human resolves them; never delete to force a restart): " + ",".join(locks))
            if locks else "no lock files")


def _chk_data_pins(ctx):
    pins = ctx["pins"]
    if not pins or not pins.get("files"):
        return (False, "no dataset pins")
    if not pins.get("rights"):
        return (False, "dataset rights not recorded")
    if any(not re.fullmatch(r"[0-9a-f]{64}", h or "") for h in pins["files"].values()):
        return (False, "dataset pin is not a sha256")
    return (True, f"{len(pins['files'])} dataset files pinned; rights: {pins['rights']}")


def _chk_deadline(ctx):
    d = (ctx["pins"] or {}).get("deadline_utc")
    try:
        ok = d is not None and bool(_dt.datetime.strptime(d, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        ok = False
    return (ok, f"original deadline (UTC): {d}" if ok else "original deadline with timezone missing")


def _chk_heldout(ctx):
    pins = ctx["pins"] or {}
    tr, ev = pins.get("files") or {}, pins.get("eval_files") or {}
    if not ev:
        return (False, "no held-out eval pins (eval data must be pinned separately from training data)")
    shared = sorted(set(tr.values()) & set(ev.values()))
    if shared:
        return (False, f"{len(shared)} file hash(es) appear in both training and eval pins")
    leak = pins.get("row_overlap")
    if leak is None:
        return (False, "row-level train/eval overlap not measured (run `leakage` and record row_overlap)")
    nd = pins.get("near_dup_overlap")
    if nd is None:
        return (False, "near-duplicate train/eval overlap not measured (run `leakage` and record near_dup_overlap)")
    return (leak == 0 and nd == 0, f"row-level train/eval overlap: {leak}; near-duplicate overlap: {nd}")


GATE_CHECKS = [("checkpoint_complete", _chk_complete), ("checkpoint_hashes", _chk_manifest),
               ("no_live_trainer", _chk_no_trainer), ("no_lock", _chk_no_lock),
               ("dataset_pins_and_rights", _chk_data_pins), ("deadline_recorded", _chk_deadline),
               ("heldout_disjoint", _chk_heldout)]


# ------------------------------------------------------------------ leakage
def _norm_row(line: str, keys: list[str] | None = None) -> str | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        if keys and isinstance(obj, dict):
            obj = {k: obj.get(k) for k in keys}
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except ValueError:
        return " ".join(line.split()).lower()


def row_hashes(path: str, keys=None, norm=_norm_row) -> list[str]:
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n = norm(line, keys)
            if n is not None:
                out.append(hashlib.sha256(n.encode()).hexdigest())
    return out


NEAR_K, NEAR_PERMS, NEAR_BANDS, NEAR_THRESHOLD, NEAR_MARGIN = 5, 64, 16, 0.8, 0.15
_MASKS = [int.from_bytes(hashlib.blake2b(f"szl-minhash-{i}".encode(), digest_size=8).digest(), "big")
          for i in range(NEAR_PERMS)]


def _shingles(text: str, k: int = NEAR_K) -> set:
    t = " ".join(text.split()).lower()
    return {t[i:i + k] for i in range(len(t) - k + 1)} if len(t) >= k else ({t} if t else set())


def _minhash(sh: set) -> tuple:
    hs = [int.from_bytes(hashlib.blake2b(x.encode(), digest_size=8).digest(), "big") for x in sh] or [0]
    return tuple(min(h ^ m for h in hs) for m in _MASKS)


def row_norms(path: str, keys=None, norm=_norm_row):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            n = norm(line, keys)
            if n is not None:
                yield n


def near_duplicates(train: str, ev: str, keys=None, norm=_norm_row, threshold: float = NEAR_THRESHOLD) -> dict:
    """Candidates: MinHash (64 XOR-masked blake2b hashes) over char 5-gram shingles, LSH 16 bands x 4.
    Decision: EXACT Jaccard of shingle sets for every candidate whose estimate is within NEAR_MARGIN of the threshold,
    so estimate noise cannot flip a verdict; only an LSH miss can. Keeps normalised train rows in memory (~row size each).
    Exact duplicates are included."""
    r, buckets, tsig, tnorm = NEAR_PERMS // NEAR_BANDS, {}, [], []
    for idx, n in enumerate(row_norms(train, keys, norm)):
        sig = _minhash(_shingles(n)); tsig.append(sig); tnorm.append(n)
        for b in range(NEAR_BANDS):
            buckets.setdefault(hash((b,) + sig[b * r:(b + 1) * r]), []).append(idx)
    hits, n_eval, examples = 0, 0, []
    for j, n in enumerate(row_norms(ev, keys, norm)):
        n_eval += 1
        sh = _shingles(n)
        sig, cands = _minhash(sh), set()
        for b in range(NEAR_BANDS):
            cands.update(buckets.get(hash((b,) + sig[b * r:(b + 1) * r]), ()))
        best = (0.0, None)
        for i in cands:
            if sum(x == y for x, y in zip(sig, tsig[i])) / NEAR_PERMS >= threshold - NEAR_MARGIN:
                ti = _shingles(tnorm[i])
                jac = len(sh & ti) / len(sh | ti) if (sh | ti) else 1.0
                if jac > best[0]:
                    best = (jac, i)
        if best[0] >= threshold:
            hits += 1
            if len(examples) < 5:
                examples.append({"eval_row": j, "train_row": best[1], "jaccard": round(best[0], 3)})
    return {"eval_rows_near_dup_of_train": hits, "near_dup_examples": examples, "near_dup_eval_rows": n_eval,
            "near_dup_method": f"LSH candidates (MinHash {NEAR_PERMS} perms, char {NEAR_K}-grams, {NEAR_BANDS}x{r} bands), "
                               f"exact Jaccard >= {threshold} on candidates within {NEAR_MARGIN} of it; includes exact "
                               f"duplicates; pairs LSH never proposes are missed"}


def leakage(train: str, ev: str, keys=None, norm=_norm_row) -> dict:
    t, e = row_hashes(train, keys, norm), row_hashes(ev, keys, norm)
    ts = set(t)
    overlap = sum(1 for h in e if h in ts)
    return {"train_rows": len(t), "eval_rows": len(e), "eval_rows_also_in_train": overlap,
            "eval_overlap_fraction": round(overlap / len(e), 6) if e else None,
            "train_internal_duplicates": len(t) - len(ts), "keys": keys,
            "method": "sha256 of canonical JSON (sorted keys) or whitespace/case-normalised text; exact-duplicate only, "
                      "near-duplicates are NOT detected"}


def cmd_leakage(a) -> int:
    keys = a.keys.split(",") if a.keys else None
    body = {"train": a.train, "eval": a.eval, **leakage(a.train, a.eval, keys), **near_duplicates(a.train, a.eval, keys)}
    path = write_receipt(a.out, "leakage", body, a.shareable)
    print(json.dumps({k: body[k] for k in ("train_rows", "eval_rows", "eval_rows_also_in_train",
                                           "eval_rows_near_dup_of_train")} | {"receipt": path}))
    return 0 if body["eval_rows_also_in_train"] == 0 and body["eval_rows_near_dup_of_train"] == 0 else 1


# ------------------------------------------------------------------ prior failures
FAILURE_SIGS = {
    "system_python_3_12_required": re.compile(r"SYSTEM_PYTHON_3_12_REQUIRED"),
    "http_404": re.compile(r"\b(HTTP\s*(Error)?\s*:?\s*404|404:?\s*Not Found|status(_code)?[=: ]+404)\b", re.I),
    "http_403_429": re.compile(r"\b(HTTP\s*(Error)?\s*:?\s*(403|429)|(403|429):?\s*(Forbidden|Too Many Requests))\b", re.I),
    "cuda_oom": re.compile(r"CUDA out of memory|OutOfMemoryError", re.I),
    "host_oom_killed": re.compile(r"\bKilled\b|oom-kill|Out of memory: Killed process", re.I),
    "nccl": re.compile(r"NCCL (error|WARN)|ncclInternalError", re.I),
    "disk_full": re.compile(r"No space left on device|ENOSPC", re.I),
    "checksum_mismatch": re.compile(r"checksum mismatch|hash mismatch|sha256 mismatch", re.I),
    "traceback": re.compile(r"^Traceback \(most recent call last\)"),
}
LOG_RE = re.compile(r"(?i)\.(log|err|out|txt|jsonl)$")


def scan_failures(root: str, max_bytes: int = 50_000_000) -> dict:
    hits = {k: {"count": 0, "first": None, "last": None} for k in FAILURE_SIGS}
    files = scanned = 0
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in fs:
            if not LOG_RE.search(f):
                continue
            p = os.path.join(d, f)
            if scanned > max_bytes:
                return {"truncated": True, "files": files, "hits": hits}
            files += 1
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        scanned += len(line)
                        for k, pat in FAILURE_SIGS.items():
                            if pat.search(line):
                                loc = f"{os.path.relpath(p, root)}:{i}"
                                h = hits[k]; h["count"] += 1; h["first"] = h["first"] or loc; h["last"] = loc
            except OSError:
                continue
    return {"truncated": False, "files": files, "hits": hits}


def cmd_failures(a) -> int:
    body = {"root": a.root, **scan_failures(a.root)}
    body["note"] = "signature matches are leads, not diagnoses; read each location before concluding"
    path = write_receipt(a.out, "failures", body, a.shareable)
    print(json.dumps({k: v["count"] for k, v in body["hits"].items() if v["count"]} | {"files": body["files"], "receipt": path}))
    return 0


def resume_gate(root, manifest, pins, processes, checks=None, gpu_apps=()) -> dict:
    cks = checkpoints(root)
    ckpt = next((c for c in reversed(cks) if c["complete"]), None)
    ctx = {"root": root, "ckpt": ckpt, "latest": cks[-1] if cks else None, "manifest": manifest, "pins": pins,
           "processes": processes, "gpu_apps": gpu_apps}
    results = {}
    for name, fn in (GATE_CHECKS if checks is None else checks):
        try:
            ok, why = fn(ctx)
        except Exception as exc:  # fail closed
            ok, why = False, f"check raised {type(exc).__name__}"
        results[name] = {"pass": bool(ok), "detail": why}
    admit = bool(results) and all(r["pass"] for r in results.values())
    return {"decision": "ADMIT" if admit else "REFUSE", "checkpoint": ckpt["name"] if ckpt else None, "checks": results}


def cmd_resume_gate(a) -> int:
    load = lambda p: json.load(open(p)) if p and os.path.exists(p) else None
    out = resume_gate(a.root, load(a.manifest), load(a.data_pins), list_processes(), gpu_apps=list_gpu_apps())
    out["launch_cmd_for_human_approval"] = a.launch_cmd if out["decision"] == "ADMIT" else None
    out["note"] = "ADMIT does not launch. Launch once, one writer, after Stephen approves this exact command."
    path = write_receipt(a.out, "resume_gate", out, a.shareable)
    print(json.dumps({"decision": out["decision"], "failed": [k for k, v in out["checks"].items() if not v["pass"]],
                      "receipt": path}))
    return 0 if out["decision"] == "ADMIT" else 1


# ------------------------------------------------------------------ verify (independent readback)
def verify_chain(out_dir: str) -> dict:
    """Walk from chain.json head through prev_receipt_sha256 links, re-hashing every file from disk.
    Fails on: no chain, missing/altered receipt, name/hash mismatch, cycle, unparseable file, orphan receipts."""
    chain = os.path.join(out_dir, "chain.json")
    if not os.path.isfile(chain):
        return {"ok": False, "receipts_on_chain": 0, "orphans": [], "problems": ["no chain.json"], "head": None}
    try:
        meta = json.load(open(chain))
    except ValueError:
        return {"ok": False, "receipts_on_chain": 0, "orphans": [], "problems": ["chain.json unparseable"], "head": None}
    head = meta.get("head")
    by_sha = {}
    for f in os.listdir(out_dir):
        if f.endswith(".json") and f != "chain.json" and ".tmp" not in f:
            by_sha[sha256_file(os.path.join(out_dir, f))] = f
    walked, problems, cur = [], [], head
    while cur is not None:
        f = by_sha.get(cur)
        if f is None:
            problems.append(f"receipt with sha256 {str(cur)[:12]} missing or altered"); break
        if f in walked:
            problems.append("cycle in chain"); break
        if f"_{cur[:12]}.json" not in f:
            problems.append(f"file name does not carry its hash: {f}")
        walked.append(f)
        try:
            cur = json.load(open(os.path.join(out_dir, f))).get("prev_receipt_sha256")
        except ValueError:
            problems.append(f"unparseable receipt {f}"); break
    if walked and meta.get("last") != walked[0]:
        problems.append("chain.json 'last' is not the head receipt")
    orphans = sorted(set(by_sha.values()) - set(walked))
    if orphans:
        problems.append(f"{len(orphans)} receipt(s) not on the chain (altered, injected, or write interrupted)")
    return {"ok": bool(walked) and not problems, "receipts_on_chain": len(walked), "orphans": orphans,
            "problems": problems, "head": head}


def cmd_verify(a) -> int:
    r = verify_chain(a.out_dir)
    print(json.dumps(r))
    return 0 if r["ok"] else 1


# ------------------------------------------------------------------ e2e rehearsal
def cmd_e2e(a) -> int:
    """Synthetic end-to-end: every CLI command in a fresh interpreter, then verify, then a tamper test.
    PASS = ADMIT + verified chain + tamper caught. DEGRADED = only host-capability checks failed."""
    base = os.path.abspath(os.path.join(a.workdir, f"_szl_e2e_{uuid.uuid4().hex[:8]}"))
    os.makedirs(base)
    steps, R = [], os.path.join(base, "receipts")

    def cli(*args):
        p = subprocess.run([sys.executable, "-I", "-B", os.path.abspath(__file__), *args], capture_output=True,
                           text=True, timeout=300, cwd=base)
        try:
            out = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
        except ValueError:
            out = {"raw": p.stdout.strip()[-300:]}
        steps.append({"cmd": args[0], "exit": p.returncode, "out": out, "stderr": p.stderr.strip()[-300:]})
        return p.returncode, out

    try:
        run_dir, man, _ = _fixture(base)
        man_p, pins_p = os.path.join(base, "manifest.json"), os.path.join(base, "pins.json")
        json.dump(man, open(man_p, "w"))
        tr, ho = os.path.join(base, "train.jsonl"), os.path.join(base, "heldout.jsonl")
        with open(tr, "w", newline="") as fh:
            fh.writelines(json.dumps({"id": i, "x": hashlib.sha256(f"tr{i}".encode()).hexdigest(), "y": i % 2}) + "\n"
                          for i in range(50))
        with open(ho, "w", newline="") as fh:
            fh.writelines(json.dumps({"id": 1000 + i, "x": hashlib.sha256(f"ho{i}".encode()).hexdigest(), "y": i % 2}) + "\n"
                          for i in range(20))
        os.makedirs(os.path.join(base, "logs"))
        open(os.path.join(base, "logs", "run.log"), "w", newline="").write("step 100 loss 1.9\nstep 200 loss 1.8\n")
        cli("preflight", "--out", R, "--disk-path", base)
        cli("inventory", run_dir, "--out", R)
        cli("training", run_dir, "--out", R)
        rc_l, lk = cli("leakage", tr, ho, "--out", R)
        rec = json.load(open(os.path.join(base, lk["receipt"]) if not os.path.isabs(lk.get("receipt", "")) else lk["receipt"]))
        overlap = rec["body"]["eval_rows_also_in_train"]  # measured, read back from the receipt
        near = rec["body"]["eval_rows_near_dup_of_train"]
        deadline = (_dt.datetime.now(UTC) + _dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        json.dump({"files": {"train.jsonl": sha256_file(tr)}, "eval_files": {"heldout.jsonl": sha256_file(ho)},
                   "row_overlap": overlap, "near_dup_overlap": near, "rights": "synthetic, generated by e2e rehearsal",
                   "deadline_utc": deadline},
                  open(pins_p, "w"))
        # planted near-duplicate (one hex char edited, so not an exact duplicate): leakage CLI must exit 1
        row3 = json.loads(open(tr).read().splitlines()[3])
        row3["x"] = row3["x"][:20] + ("0" if row3["x"][20] != "0" else "1") + row3["x"][21:]
        planted = os.path.join(base, "planted_eval.jsonl")
        open(planted, "w", newline="").write(json.dumps(row3) + "\n")
        rc_p, lk_p = cli("--dry-run", "leakage", tr, planted)
        planted_ok = rc_p == 1 and lk_p.get("eval_rows_also_in_train") == 0 and lk_p.get("eval_rows_near_dup_of_train") == 1
        cli("failures", os.path.join(base, "logs"), "--out", R)
        rc_g, gate = cli("resume-gate", run_dir, "--manifest", man_p, "--data-pins", pins_p,
                         "--launch-cmd", "torchrun --nproc_per_node 1 train.py --resume", "--out", R)
        rc_v, ver = cli("verify", R)
        # tamper test on a copy: flip one byte in the oldest receipt -> verify must fail
        T = os.path.join(base, "tampered"); shutil.copytree(R, T)
        victim = sorted(f for f in os.listdir(T) if f != "chain.json")[0]
        data = bytearray(open(os.path.join(T, victim), "rb").read()); data[-2] ^= 1
        open(os.path.join(T, victim), "wb").write(bytes(data))
        rc_t, tam = cli("verify", T)
        procs_now, gpu_now = list_processes(), list_gpu_apps()
        host_caps = {"no_live_trainer"} if (procs_now is None or gpu_now is None) else set()
        busy = [_scrub(p)[:160] for p in (procs_now or []) if _is_trainer(p)] + unclassified_gpu(gpu_now or [])
        failed = set(gate.get("failed", []))
        core_ok = planted_ok and rc_l == 0 and overlap == 0 and near == 0 and rc_v == 0 and ver.get("ok") is True and rc_t == 1 \
            and ver.get("receipts_on_chain") == 6
        if core_ok and gate.get("decision") == "ADMIT":
            status = "PASS"
        elif core_ok and failed == {"no_live_trainer"} and busy:
            status = "HOST_BUSY"  # the rehearsal worked; the real host has a live trainer, so a resume must refuse
        elif core_ok and failed and failed <= host_caps:
            status = "DEGRADED"
        else:
            status = "FAIL"
        summary = {"e2e": status, "host_capability_failures": sorted(failed & host_caps), "live_on_host": busy[:6],
                   "gate": gate.get("decision"), "gate_failed": sorted(failed), "gate_failed": sorted(failed), "row_overlap": overlap, "near_dup_overlap": near, "planted_near_dup_caught": planted_ok,                   "verify_ok": ver.get("ok"), "receipts_on_chain": ver.get("receipts_on_chain"),
                   "tamper_detected": rc_t == 1, "steps": [(x["cmd"], x["exit"]) for x in steps]}
        print(json.dumps(summary, indent=1) if a.verbose else json.dumps(summary))
        return 0 if status == "PASS" else 1
    finally:
        if not a.keep:
            shutil.rmtree(base, ignore_errors=True)


# ------------------------------------------------------------------ certify (single readiness verdict)
CERTIFY_STEPS = ("selftest", "e2e", "preflight", "verify")


def certify_verdict(steps: dict) -> dict:
    """Pure: CERTIFIED only if every step ran and passed. Missing or unparseable steps are failures."""
    why = []
    for name in CERTIFY_STEPS:
        st = steps.get(name)
        if not st:
            why.append(f"{name}: did not run"); continue
        out, rc = st.get("out") or {}, st.get("exit")
        ok = {"selftest": rc == 0 and out.get("result") == "PASS", "e2e": rc == 0 and out.get("e2e") == "PASS",
              "preflight": rc == 0 and out.get("status") == "PASS", "verify": rc == 0 and out.get("ok") is True}[name]
        if not ok:
            detail = out.get("blockers") or (([out.get("e2e")] + list(out.get("live_on_host") or [])[:3]) if out.get("e2e") else None) \
                or out.get("gate_failed") or out.get("problems") or out.get("result")
            why.append(f"{name}: exit {rc} {detail if detail else ''}".strip())
    return {"verdict": "CERTIFIED" if not why else "NOT_CERTIFIED", "reasons": why}


def cmd_certify(a) -> int:
    steps = {}
    for name, args in (("selftest", ["selftest"]), ("e2e", ["e2e", "--workdir", a.workdir]),
                       ("preflight", ["preflight", "--out", a.out]), ("verify", ["verify", a.out])):
        try:
            p = subprocess.run([sys.executable, "-I", "-B", os.path.abspath(__file__), *args], capture_output=True,
                               text=True, timeout=3600)
            txt = p.stdout.strip()
            try:
                out = json.loads(txt)
            except ValueError:
                out = json.loads(txt.splitlines()[-1]) if txt else {}
            steps[name] = {"exit": p.returncode, "out": out}
        except Exception as exc:  # fail closed: a step that cannot run is a failed step
            steps[name] = {"exit": None, "out": {"result": f"could not run: {type(exc).__name__}"}}
    v = certify_verdict(steps)
    body = {"verdict": v["verdict"], "reasons": v["reasons"], "version": VERSION,
            "payload_sha256": sha256_file(os.path.abspath(__file__)),
            "steps": {k: {"exit": x["exit"], "out": {kk: vv for kk, vv in x["out"].items() if kk not in ("cases", "mutants")}}
                      for k, x in steps.items()}}
    path = write_receipt(a.out, "certify", body, a.shareable)
    after = verify_chain(a.out) if not DRY_RUN else {"ok": None}
    print(json.dumps({"verdict": v["verdict"], "reasons": v["reasons"], "receipt": path, "chain_ok_after": after["ok"]}))
    return 0 if v["verdict"] == "CERTIFIED" and after["ok"] is not False else 1


# ------------------------------------------------------------------ selftest
def _fixture(base: str):
    run_dir = os.path.join(base, "run")
    man = {}
    for step in (100, 200):
        d = os.path.join(run_dir, f"checkpoint-{step}")
        os.makedirs(d, exist_ok=True)
        files = {"trainer_state.json": json.dumps({"global_step": step, "max_steps": 1000, "epoch": step / 500,
                                                   "log_history": [{"step": step, "loss": 2.0 - step / 1000}]}),
                 "optimizer.pt": f"optimizer-state-{step}", "scheduler.pt": f"sched-{step}",
                 "model.safetensors": f"weights-{step}"}
        man[f"checkpoint-{step}"] = {}
        for f, txt in files.items():
            with open(os.path.join(d, f), "w", newline="") as fh:
                fh.write(txt)
            man[f"checkpoint-{step}"][f] = hashlib.sha256(txt.encode()).hexdigest()
    pins = {"files": {"train.jsonl": "a" * 64}, "eval_files": {"heldout.jsonl": "b" * 64}, "row_overlap": 0,
            "near_dup_overlap": 0,
            "rights": "synthetic, generated in-house", "deadline_utc": "2026-10-22T12:00:00Z"}
    return run_dir, man, pins


def cmd_selftest(a) -> int:
    base = os.path.join(os.getcwd(), f"_szl_selftest_{uuid.uuid4().hex[:8]}")
    os.makedirs(base)
    try:
        run_dir, man, pins = _fixture(base)
        ev = training_evidence(run_dir)
        cases = []

        def case(name, expect, **kw):
            args = {"root": run_dir, "manifest": man, "pins": pins, "processes": []}
            args.update(kw)
            cases.append((name, expect, args))

        case("good run", "ADMIT")
        case("no manifest", "REFUSE", manifest=None)
        case("hash mismatch", "REFUSE", manifest={**man, "checkpoint-200": {**man["checkpoint-200"], "optimizer.pt": "0" * 64}})
        case("live trainer", "REFUSE", processes=["4242 Mon Oct 20 python train.py --resume"])
        case("process listing failed", "REFUSE", processes=None)
        case("unclassified GPU process", "REFUSE", gpu_apps=[(999992, "venv/bin/python src/eval_family.py")])
        case("GPU inference servers only", "ADMIT", gpu_apps=[(999991, "VLLM::EngineCore"), (999993, "/opt/llama-server -m x")])
        case("GPU listing failed", "REFUSE", gpu_apps=None)
        case("no data pins", "REFUSE", pins=None)
        case("no rights", "REFUSE", pins={**pins, "rights": ""})
        case("bad pin", "REFUSE", pins={**pins, "files": {"train.jsonl": "latest"}})
        case("no deadline", "REFUSE", pins={k: v for k, v in pins.items() if k != "deadline_utc"})
        case("no held-out eval pins", "REFUSE", pins={k: v for k, v in pins.items() if k != "eval_files"})
        case("eval file identical to train file", "REFUSE", pins={**pins, "eval_files": {"heldout.jsonl": "a" * 64}})
        case("row overlap not measured", "REFUSE", pins={k: v for k, v in pins.items() if k != "row_overlap"})
        case("row overlap > 0", "REFUSE", pins={**pins, "row_overlap": 3})
        case("near-dup overlap not measured", "REFUSE", pins={k: v for k, v in pins.items() if k != "near_dup_overlap"})
        case("near-dup overlap > 0", "REFUSE", pins={**pins, "near_dup_overlap": 2})
        lock_dir, lock_man, _ = _fixture(os.path.join(base, "locked"))
        open(os.path.join(lock_dir, "train.lock"), "w").write("pid 1")
        case("lock present", "REFUSE", root=lock_dir, manifest=lock_man)
        inc_dir, inc_man, _ = _fixture(os.path.join(base, "incomplete"))
        for s in (100, 200):
            os.remove(os.path.join(inc_dir, f"checkpoint-{s}", "optimizer.pt"))
        case("incomplete checkpoints", "REFUSE", root=inc_dir, manifest=inc_man)
        part_dir, part_man, _ = _fixture(os.path.join(base, "partial"))
        os.remove(os.path.join(part_dir, "checkpoint-200", "optimizer.pt"))
        case("newest checkpoint incomplete, older one complete", "REFUSE", root=part_dir, manifest=part_man)

        def run_cases(checks=None):
            return [(n, e, resume_gate(**kw, checks=checks)["decision"]) for n, e, kw in cases]

        base_res = run_cases()
        base_ok = all(e == got for _, e, got in base_res)
        mutants = {}
        for i, (name, _) in enumerate(GATE_CHECKS):
            mutated = [(n, (lambda ctx: (True, "MUTANT")) if j == i else f) for j, (n, f) in enumerate(GATE_CHECKS)]
            flipped = [n for (n, e, got) in run_cases(mutated) if got != e]
            mutants[f"disable {name}"] = {"killed": bool(flipped), "flipped": flipped}
        mutants["always ADMIT"] = {"killed": any(got != e for (_, e, got) in run_cases([("x", lambda c: (True, ""))]))}
        mutants["empty check list"] = {"killed": resume_gate(run_dir, man, pins, [], checks=[])["decision"] == "REFUSE"}
        os.environ.pop("SZL_SELFTEST_VAR", None)
        cred_ok = credential_observation("SZL_SELFTEST_VAR") == "env_var_unset_other_sources_not_checked"
        os.environ["SZL_SELFTEST_VAR"] = "x"
        cred_ok = cred_ok and credential_observation("SZL_SELFTEST_VAR") == "env_var_set"
        os.environ.pop("SZL_SELFTEST_VAR", None)
        r1 = write_receipt(os.path.join(base, "r"), "selftest", {"x": 1})
        r2 = write_receipt(os.path.join(base, "r"), "selftest", {"x": 2})
        chain_ok = json.load(open(r2))["prev_receipt_sha256"] == hashlib.sha256(open(r1, "rb").read()).hexdigest()
        rdir = os.path.join(base, "r")
        v_good = verify_chain(rdir)["ok"]
        vt = os.path.join(base, "rt"); shutil.copytree(rdir, vt)
        open(os.path.join(vt, os.path.basename(r1)), "a").write(" ")
        v_tamper = verify_chain(vt)["ok"]
        vd = os.path.join(base, "rd"); shutil.copytree(rdir, vd); os.remove(os.path.join(vd, os.path.basename(r1)))
        v_delete = verify_chain(vd)["ok"]
        vo = os.path.join(base, "ro"); shutil.copytree(rdir, vo)
        open(os.path.join(vo, "2099-01-01T000000Z_injected_000000000000.json"), "w").write("{}")
        v_orphan = verify_chain(vo)["ok"]
        v_none = verify_chain(os.path.join(base, "nochain"))["ok"]
        ve = os.path.join(base, "re"); os.makedirs(ve)
        open(os.path.join(ve, "chain.json"), "w").write(json.dumps({"head": None, "last": None}))
        v_none = v_none or verify_chain(ve)["ok"]  # a chain that points at no receipt proves nothing
        vr = os.path.join(base, "rr"); shutil.copytree(rdir, vr)  # renamed: content intact, name lies about hash
        os.replace(os.path.join(vr, os.path.basename(r1)), os.path.join(vr, "renamed_ffffffffffff.json"))
        v_rename = verify_chain(vr)["ok"]
        vl = os.path.join(base, "rl"); shutil.copytree(rdir, vl)  # chain.json 'last' points at an older receipt
        cj = json.load(open(os.path.join(vl, "chain.json"))); cj["last"] = os.path.basename(r1)
        open(os.path.join(vl, "chain.json"), "w").write(json.dumps(cj))
        v_last = verify_chain(vl)["ok"]
        fake = lambda res: (lambda cmd: res)
        listing_ok = (list_processes(fake({"exit": 1, "out": "", "err": "denied"})) is None
                      and list_processes(fake({"exit": None, "out": "", "err": "not installed"})) is None
                      and list_processes(fake({"exit": 0, "out": "", "err": ""})) is None
                      and list_processes(fake({"exit": 0, "out": "1 a\n2 b", "err": ""})) == ["1 a", "2 b"])
        verify_ok = listing_ok and v_good and not (v_tamper or v_delete or v_orphan or v_none or v_rename or v_last)
        evidence_ok = ev["optimizer_steps_latest"] == 200 and ev["optimizer_step_evidence"].startswith("MEASURED")
        one_ckpt = os.path.join(base, "one"); _fixture(one_ckpt)
        shutil.rmtree(os.path.join(one_ckpt, "run", "checkpoint-100"))
        evidence_ok = evidence_ok and training_evidence(os.path.join(one_ckpt, "run"))["optimizer_step_evidence"].startswith("UNKNOWN")
        proc_cases = [  # (line, is_trainer) -- 1.0.1: reviewer regression (6eb96eff) + fail-open guard
            (f"{os.getpid()} Tue Oct 20 11:30:00 2026 python3 szl_vm_master_payload.py resume-gate /r --launch-cmd \"torchrun train.py\"", False),
            ("4242 Mon Oct 19 09:31:59 2026 /opt/llama.cpp/llama-server -m /models/unsloth/Qwen3-4B-GGUF/q4.gguf", False),
            ('"llama-server.exe","9000","Console","1","1,234 K"', False),
            ("6001 Tue Oct 20 11:30:00 2026 torchrun --nproc_per_node 1 train.py", True),
            ("6002 Tue Oct 20 11:30:00 2026 python3 /work/unsloth_finetune.py", True),
            ("6003 Tue Oct 20 11:30:00 2026 python3 train.py --out /models/ollama", True),
            ("6004 Tue Oct 20 11:30:00 2026 torchrun train.py --ref /opt/bin/llama-server", True),
            ("116266 Wed Oct 28 18:27:42 2026 venv/bin/python src/train_nemo.py --run nemo-r2 --max-minutes 150", True),
            ("1290793 Wed Oct 28 17:25:52 2026 /bin/bash ./vm1_round2_train.sh", True),
            ("1318273 Wed Oct 28 19:35:24 2026 /home/u/szl-train/venv-small/bin/python /x/torch/_inductor/compile_worker/__main__.py", False),
        ]
        proc_bad = [l for l, want in proc_cases if _is_trainer(l) != want]
        # leakage: a reordered-key duplicate and a whitespace/case duplicate must both be caught
        tr_p, ev_p = os.path.join(base, "train.jsonl"), os.path.join(base, "eval.jsonl")
        open(tr_p, "w", newline="").write('{"q": "a", "y": 1}\n{"q": "b", "y": 0}\nHello  World\n')
        open(ev_p, "w", newline="").write('{"y": 1, "q": "a"}\n{"q": "c", "y": 1}\nhello world\n')
        lk = leakage(tr_p, ev_p)
        raw_norm = lambda line, keys=None: line.strip() or None
        lk_mut = leakage(tr_p, ev_p, norm=raw_norm)
        leak_ok = lk["eval_rows_also_in_train"] == 2 and lk_mut["eval_rows_also_in_train"] != 2
        # near-duplicates: one-character edit of a long row must be caught; unrelated rows and short
        # one-field edits must not be; exact duplicates count as near-duplicates
        long_a = "the quarterly synthetic telemetry summary reports steady queue depth, nominal latency and no failed jobs"
        nd_tr, nd_ev = os.path.join(base, "nd_train.txt"), os.path.join(base, "nd_eval.txt")
        open(nd_tr, "w", newline="").write(long_a + "\nan entirely different sentence about cache eviction policy tuning\n")
        open(nd_ev, "w", newline="").write(long_a.replace("steady", "stezdy") + "\n"
                                           "zebra quilt xylophone marmalade under seventeen violet umbrellas\n"
                                           "an entirely different sentence about cache eviction policy tuning\n")
        nd = near_duplicates(nd_tr, nd_ev)
        nd_clean = near_duplicates(tr_p, ev_p)  # short JSON rows: only the 2 exact duplicates may count
        near_ok = nd["eval_rows_near_dup_of_train"] == 2 and nd_clean["eval_rows_near_dup_of_train"] == 2
        cv_good = {n: {"exit": 0, "out": o} for n, o in (("selftest", {"result": "PASS"}), ("e2e", {"e2e": "PASS"}),
                                                          ("preflight", {"status": "PASS"}), ("verify", {"ok": True}))}
        certify_ok = certify_verdict(cv_good)["verdict"] == "CERTIFIED" and all(
            certify_verdict(bad)["verdict"] == "NOT_CERTIFIED" for bad in (
                {k: v for k, v in cv_good.items() if k != "verify"},
                {**cv_good, "e2e": {"exit": 1, "out": {"e2e": "DEGRADED"}}},
                {**cv_good, "e2e": {"exit": 0, "out": {"e2e": "DEGRADED"}}},
                {**cv_good, "preflight": {"exit": 1, "out": {"status": "BLOCKED"}}},
                {**cv_good, "verify": {"exit": 0, "out": {"ok": False}}},
                {**cv_good, "selftest": {"exit": 0, "out": {}}}, {}))
        # failure scan
        logd = os.path.join(base, "logs"); os.makedirs(logd)
        open(os.path.join(logd, "run.log"), "w", newline="").write(
            "start\nERROR SYSTEM_PYTHON_3_12_REQUIRED\nurllib.error.HTTPError: HTTP Error 404: Not Found\n"
            "torch.OutOfMemoryError: CUDA out of memory\nTraceback (most recent call last):\nall good 4040 ms\n"
            "HTTP/1.1 429 Too Many Requests\nprocessed 404 rows\n")
        fs = scan_failures(logd)["hits"]
        fail_ok = (fs["system_python_3_12_required"]["count"] == 1 and fs["http_404"]["count"] == 1
                   and fs["cuda_oom"]["count"] == 1 and fs["traceback"]["count"] == 1 and fs["disk_full"]["count"] == 0
                   and fs["http_403_429"]["count"] == 1)
        # dry run writes nothing
        global DRY_RUN
        DRY_RUN = True
        try:
            dr = write_receipt(os.path.join(base, "dry"), "selftest", {"x": 1})
        finally:
            DRY_RUN = False
        dry_ok = dr.startswith("DRY-RUN") and not os.path.exists(os.path.join(base, "dry"))
        samples = _samples_seen(200, {"per_device_train_batch_size": 4, "gradient_accumulation_steps": 8, "world_size": 2})
        accum_ok = samples["samples_seen"] == 200 * 4 * 8 * 2 and _samples_seen(200, {"per_device_train_batch_size": 4}) is None
        # 1.4.0: <run>/checkpoints/step-N layout (adapter-only, no optimizer), fit signal, weaker evidence
        lay = os.path.join(base, "steplayout", "checkpoints")
        for st_, tl, vl, w in ((1, 2.58, 4.55, "w1"), (120350, 1e-6, 6.22, "w2")):
            d_ = os.path.join(lay, f"step-{st_:09d}"); os.makedirs(d_)
            open(os.path.join(d_, "trainer_state.json"), "w").write(json.dumps({"step": st_, "train_loss": tl, "validation_loss": vl}))
            open(os.path.join(d_, "adapter_model.safetensors"), "w").write(w)
        lev = training_evidence(os.path.dirname(lay))
        layout_ok = (lev["n_checkpoints"] == 2 and lev["optimizer_steps_latest"] == 120350
                     and lev["optimizer_step_evidence"].startswith("MEASURED (weaker)")
                     and "warning" in (lev["fit_signal"] or {})
                     and resume_gate(os.path.dirname(lay), {}, pins, [])["decision"] == "REFUSE")
        lay2 = os.path.join(base, "steplayout2", "checkpoints")
        for st_ in (1, 2):
            d_ = os.path.join(lay2, f"step-{st_:09d}"); os.makedirs(d_)
            open(os.path.join(d_, "trainer_state.json"), "w").write(json.dumps({"step": st_}))
            open(os.path.join(d_, "adapter_model.safetensors"), "w").write("same")
        layout_ok = layout_ok and training_evidence(os.path.dirname(lay2))["optimizer_step_evidence"].startswith("UNKNOWN")
        fake2 = lambda res: (lambda cmd: res)
        gpu_ok = (list_gpu_apps(fake2({"exit": None, "out": "", "err": "not installed"})) == []
                  and list_gpu_apps(fake2({"exit": 1, "out": "", "err": "NVML error"})) is None
                  and list_gpu_apps(fake2({"exit": None, "out": "", "err": "timeout 20s"})) is None
                  and len(list_gpu_apps(fake2({"exit": 0, "out": "999991, VLLM::EngineCore\n999992, venv/bin/python", "err": ""}))) == 2
                  and len(unclassified_gpu([(999991, "VLLM::EngineCore"), (999992, "venv/bin/python src/train_nemo.py"),
                                            (999993, "/opt/llama.cpp/llama-server -m x"), (999994, "tritonserver --model-repository /m")])) == 1
                  and "abcdef123" not in _scrub("python x.py --token abcdef123")
                  and "hf_abcdef123456" not in _scrub("python x.py hf_abcdef123456"))
        summary = {"cases": [{"case": n, "expect": e, "got": g, "pass": e == g} for n, e, g in base_res],
                   "process_classification_failures": proc_bad, "leakage_ok": leak_ok, "failure_scan_ok": fail_ok,
                   "dry_run_ok": dry_ok, "grad_accum_ok": accum_ok,
                   "mutants": mutants, "credential_observation_ok": cred_ok, "receipt_chain_ok": chain_ok,
                   "training_evidence_ok": evidence_ok, "verify_ok": verify_ok, "near_dup_ok": near_ok,
                   "certify_verdict_ok": certify_ok, "layout_ok": layout_ok, "gpu_listing_ok": gpu_ok}
        ok = base_ok and all(m["killed"] for m in mutants.values()) and cred_ok and chain_ok and evidence_ok and not proc_bad and leak_ok and fail_ok and dry_ok and accum_ok and verify_ok and near_ok and certify_ok and layout_ok and gpu_ok
        summary["result"] = "PASS" if ok else "FAIL"
        print(json.dumps(summary, indent=1))
        return 0 if ok else 3
    finally:
        shutil.rmtree(base, ignore_errors=True)


# ------------------------------------------------------------------ main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("brief"); b.add_argument("--out", default=".")
    p = sub.add_parser("preflight"); p.add_argument("--out", default="receipts"); p.add_argument("--repo", action="append")
    p.add_argument("--disk-path", default="C:\\" if os.name == "nt" else "/")
    p.add_argument("--min-disk-gb", type=float, default=50); p.add_argument("--min-ram-gb", type=float, default=4)
    p.add_argument("--shareable", action="store_true")
    for name in ("inventory", "training"):
        q = sub.add_parser(name); q.add_argument("root"); q.add_argument("--out", default="receipts")
        q.add_argument("--shareable", action="store_true")
        if name == "training":
            q.add_argument("--run-config", help="JSON with per_device_train_batch_size, gradient_accumulation_steps, world_size")
    g = sub.add_parser("resume-gate"); g.add_argument("root"); g.add_argument("--manifest"); g.add_argument("--data-pins")
    g.add_argument("--launch-cmd"); g.add_argument("--out", default="receipts"); g.add_argument("--shareable", action="store_true")
    lk = sub.add_parser("leakage"); lk.add_argument("train"); lk.add_argument("eval"); lk.add_argument("--keys")
    lk.add_argument("--out", default="receipts"); lk.add_argument("--shareable", action="store_true")
    fl = sub.add_parser("failures"); fl.add_argument("root"); fl.add_argument("--out", default="receipts")
    fl.add_argument("--shareable", action="store_true")
    vf = sub.add_parser("verify"); vf.add_argument("out_dir")
    e2 = sub.add_parser("e2e"); e2.add_argument("--workdir", default="."); e2.add_argument("--keep", action="store_true")
    e2.add_argument("--verbose", action="store_true")
    cf = sub.add_parser("certify"); cf.add_argument("--out", default="receipts"); cf.add_argument("--workdir", default=".")
    cf.add_argument("--shareable", action="store_true")
    sub.add_parser("selftest")
    ap.add_argument("--dry-run", action="store_true", help="compute everything, write nothing")
    a = ap.parse_args(argv)
    global DRY_RUN
    DRY_RUN = bool(a.dry_run)
    if a.cmd == "brief":
        os.makedirs(a.out, exist_ok=True)
        path = os.path.join(a.out, "SZL_MASTER_BRIEF.md")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(BRIEF_MD)
        print(json.dumps({"brief": path, "sha256": hashlib.sha256(BRIEF_MD.encode()).hexdigest()}))
        return 0
    return {"preflight": cmd_preflight, "inventory": cmd_inventory, "training": cmd_training,
            "resume-gate": cmd_resume_gate, "leakage": cmd_leakage, "failures": cmd_failures,
            "selftest": cmd_selftest, "verify": cmd_verify, "e2e": cmd_e2e, "certify": cmd_certify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
