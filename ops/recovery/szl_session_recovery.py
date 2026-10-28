#!/usr/bin/env python3
"""szl_session_recovery.py - fail-closed recovery controller for the SZL session estate.

Built 2026-10-23 from an audit of 31 Claude Science sessions in project proj_c00e8eb71f33.
Standard library only. Python 3.9+. Windows first, Linux/macOS tolerated.

Subcommands
  selftest                 gate tests plus mutants that each must be caught (exit 0 only if all pass)
  preflight                disk / RAM / commit measurement against the 15 GB / 1.5 GiB floors
  triage                   read-only: what is filling C: (time-boxed folder sizes, pagefile)
  github                   read-only: live state of every PR the sessions cite, a11oy deploy settings
  vm                       read-only SSH probe of VM1 (BatchMode, key only, never a password)
  queue                    every work item with its computed state
  run ITEM [--execute]     dry-run by default; executes only when every gate passes
  status                   preflight + github + vm + queue, writes a markdown report
  verify-ledger            recompute the hash chain of the receipts ledger

Rules enforced in code (not just in prose)
  * Write items run only if ITEM is listed in approvals.json "approved" AND approvals.json
    names "approved_by". The agent running this script must never create or edit approvals.json.
  * Write items run only if C: free >= 15 GB and RAM available >= 1.5 GiB, unless ITEM is
    listed in approvals.json "below_floor_waiver".
  * Items owned by another session lane are refused unless approvals.json "release_lane" lists them.
  * A merge pins the head SHA that was checked; if checks are not all green the merge is refused.
  * Every action appends a hash-chained receipt to ledger.jsonl. Nothing is deleted.
  * No verdict string "OPERATIONAL" is ever printed. `status` reports OWNER_ITEMS_CLOSED_LEDGER_INTACT at most;
    that covers owner-item evidence and local ledger integrity ONLY - not write completion, tests or runtime health.
  * Dry-run is not offline: it makes live read-only GitHub/SSH calls and appends local ledger entries; it writes nothing remote.
  * The ledger is an UNSIGNED local hash chain: it detects accidental edits, not a full rewrite or truncation.
1.2.0-proposed (2026-10-23) fixes, per SZL_RECOVERY_CONTROLLER_REPAIR_SPEC + CTO addendum section 4:
  complete paginated check reads with HTTP errors -> UNKNOWN; skipped/neutral-only is not green; merge only on 'clean';
  exact parsed host-key fingerprint bound to the SSH command; per-field remote probe validation; pinned rerun targets
  (run_id, attempt, head_sha); W8 pinned commit with no code execution; offline queue makes zero network calls;
  gates re-checked immediately before each step; accepted POSTs reported as ACCEPTED_PENDING after readback.
Exit codes: 0 ok / gates pass, 1 gate refused or check failed, 2 usage or environment error, 3 ledger tamper.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.2.0-proposed"
ORG = "szl-holdings"
FLOOR_DISK_GB = 15.0
EMERGENCY_DISK_GB = 5.0
FLOOR_RAM_GIB = 1.5
HOME = Path.home()
STATE_DIR = Path(os.environ.get("SZL_RECOVERY_DIR", HOME / "szl_recovery"))
APPROVALS = STATE_DIR / "approvals.json"
LEDGER = STATE_DIR / "ledger.jsonl"

# VM1 facts as recorded by the audited sessions. user and fingerprint are UNKNOWN until Stephen
# supplies them (env SZL_VM_USER / SZL_VM_FP or flags). Port 300 (ThinLinc, plain http) is never used.
VM = {
    "host": os.environ.get("SZL_VM_HOST", "64.247.206.118"),
    "port": int(os.environ.get("SZL_VM_PORT", "22")),
    "user": os.environ.get("SZL_VM_USER", ""),
    "key": os.environ.get("SZL_VM_KEY", str(HOME / ".ssh" / "szl_a6000")),
    "expected_fp": os.environ.get("SZL_VM_FP", ""),
}

# PRs cited by the audited sessions (repo, number, citing sessions). State is re-read live.
PRS = [
    ("szl-estate-os", 77, "8127baee"), ("governed-receipt-spec", 37, "8127baee"),
    ("governed-receipt-spec", 38, "8127baee"), ("killinchu", 549, "8127baee"),
    (".github", 935, "8127baee"), ("szl-safe-stack", 33, "8127baee"), ("szl-router", 109, "8127baee,638cfc21"),
    ("yarqa", 79, "8127baee"), ("platform", 945, "9309bbfc"), ("a11oy", 2931, "9309bbfc"),
    ("a11oy", 2914, "9309bbfc"), ("a11oy", 2879, "9309bbfc,cab477c7"), ("killinchu", 543, "9309bbfc,cab477c7"),
    ("a11oy", 2944, "c7fd5762,052718c4"), ("immune", 197, "9309bbfc"), ("lutar-lean", 325, "8127baee"),
    ("szl-evidence-mandate", 13, "052718c4,7f132b41"), ("governed-receipt-spec", 39, "052718c4"),
    ("a11oy", 2940, "18491668"), ("szl-estate-os", 79, "f300d563,dd1d8f00"),
    ("szl-forge", 633, "attached handoff 2026-10-22"),
    ("a11oy", 2955, "Codex 2026-10-22"), ("platform", 957, "Codex 2026-10-22"), ("lyte-services", 54, "Codex 2026-10-22"),
    ("a11oy", 2957, "Codex release order"), ("a11oy", 2958, "Codex thread, needs owner until 10-29"),
    ("szl-estate-os", 82, "30d49aea,41315026"),
]
A11OY_VARS = ["A11OY_EXECUTION_AUTHORITY_PINS_JSON", "A11OY_EXECUTION_HF_REVISION",
              "A11OY_EXECUTION_BOOT_ID", "A11OY_EXECUTION_RUN_NONCE"]
A11OY_SECRETS = ["A11OY_CODE_ADMIN_KEY", "A11OY_CODE_TENANT"]

# ----------------------------------------------------------------------------------------------
# Work items. kind: READ (no approval), OWNER (only Stephen can do it; script checks evidence),
# WRITE (approval + floor gates), LANE (owned by another session; refused unless released).
# ----------------------------------------------------------------------------------------------
ITEMS = [
    {"id": "R1", "kind": "READ", "title": "Measure disk / RAM / commit against floors", "fn": "preflight"},
    {"id": "R2", "kind": "READ", "title": "Triage what is filling C: (read-only, time-boxed)", "fn": "triage"},
    {"id": "R3", "kind": "READ", "title": "Live state of every cited PR (checks, mergeable state) + a11oy settings names + lutar-lean default branch", "fn": "github"},
    {"id": "R4", "kind": "READ", "title": "Probe VM1 over SSH with key (read-only identity/GPU/disk)", "fn": "vm"},
    {"id": "O1", "kind": "OWNER", "title": "Bring C: >= 15 GB free and RAM >= 1.5 GiB: close idle Claude Science sessions, reboot (pagefile), Settings > Storage > Temporary files",
     "evidence": "preflight", "sessions": "all 25 BLOCKED sessions"},
    {"id": "O2", "kind": "OWNER", "title": "Rotate the VM1 password that was pasted in chat (run passwd on the VM)",
     "evidence": "attest", "sessions": "638cfc21 d0e527bf dd1d8f00 7f132b41 c47b0456 1b43b551 0dc4549b 052718c4 18491668"},
    {"id": "O3", "kind": "OWNER", "title": "Install laptop key on VM1, then add VM1 under Customize > Compute > SSH host (port 22, key only)",
     "evidence": "vm", "sessions": "18 sessions wait on this"},
    {"id": "O4", "kind": "OWNER", "title": "Create a11oy repo variables (4) and secrets (2) for the deploy proof chain",
     "evidence": "a11oy_settings", "sessions": "a4c41815 18491668"},
    {"id": "O5", "kind": "OWNER", "title": "Decide lutar-lean default branch (currently a fix branch, not main)",
     "evidence": "lutar_default", "sessions": "9309bbfc fe2b7c3a"},
    {"id": "O6", "kind": "OWNER", "title": "Run Downloads\\SZL_meeting_build_v3_2\\RUN_BROWSER_CHECK.cmd and confirm meeting date (26 or 30 Oct)",
     "evidence": "attest", "sessions": "95af3040"},
    {"id": "O7", "kind": "OWNER", "title": "Cloudflare config rule (a11oy.net, a-11-oy.com) and Snowflake read-only checks, or add scoped credentials",
     "evidence": "attest", "sessions": "fa545291 30d49aea"},
    {"id": "O8", "kind": "OWNER", "title": "Decide stale PRs platform#945, a11oy#2931, a11oy#2914 (hold / close) and the 12 open decisions in FIVE_LANE_STATUS",
     "evidence": "attest", "sessions": "9309bbfc"},
    {"id": "O9", "kind": "OWNER", "title": "Namecheap: sign in, unlock a11oy.net, obtain its EPP code (Cloudflare transfer stays BLOCKED without both)",
     "evidence": "attest", "sessions": "Codex estate thread"},
    {"id": "O10", "kind": "OWNER", "title": "Create fine-grained SZL_READINESS_GH_TOKEN (a11oy only; Contents/Actions/Attestations read) and install it as a Space secret inside the release owner's maintenance window (restarts the Space)",
     "evidence": "attest", "sessions": "Codex a11oy#2958 thread, 30d49aea"},
    {"id": "O11", "kind": "OWNER", "title": "Platform: fix Replit deploy authorization (staging HTTP 403) and provision KHIPU_SIGNING_KEY_B64 (szl_owner_admin_block.ps1 R12-B)",
     "evidence": "secret:platform:KHIPU_SIGNING_KEY_B64", "sessions": "Codex platform thread"},
    {"id": "O12", "kind": "OWNER", "title": "Lyte: approve a durable PostgreSQL destination, OIDC configuration and a cutover window (live service still SAMPLE data on SQLite)",
     "evidence": "attest", "sessions": "Codex lyte thread"},
    {"id": "O13", "kind": "OWNER", "title": "Sentra returns 503 upstream:false: restore its upstream; confirm Amaru and Rosie destinations",
     "evidence": "attest", "sessions": "Codex fleet check"},
    {"id": "W1", "kind": "WRITE", "title": "Squash-merge szl-estate-os#77 if every check is green (head SHA pinned)",
     "steps": [("merge_if_green", "szl-estate-os", 77)], "sessions": "8127baee (its A1)"},
    {"id": "W2", "kind": "WRITE", "title": "Update branch on governed-receipt-spec#37 and #38 (they are behind main)",
     "steps": [("update_branch", "governed-receipt-spec", 37), ("update_branch", "governed-receipt-spec", 38)], "sessions": "8127baee (its A1)"},
    {"id": "W3", "kind": "WRITE", "title": "Squash-merge governed-receipt-spec#37 and #38 if every check is green (run after W2 checks finish)",
     "steps": [("merge_if_green", "governed-receipt-spec", 37), ("merge_if_green", "governed-receipt-spec", 38)], "sessions": "8127baee (its A1)"},
    {"id": "W4", "kind": "WRITE", "title": "Update branch on killinchu#549 (live Space reads from main)",
     "steps": [("update_branch", "killinchu", 549)], "sessions": "8127baee (its A2)"},
    {"id": "W5", "kind": "WRITE", "title": "Squash-merge killinchu#549 if every check is green (run after W4 checks finish)",
     "steps": [("merge_if_green", "killinchu", 549)], "sessions": "8127baee (its A2)"},
    {"id": "W6", "kind": "WRITE", "title": "Re-run failed jobs once on the EXACT pinned szl-router#109 run (pins.W6: run_id, attempt, head_sha)",
     "steps": [("rerun_pinned", "szl-router", "W6", 109, None)], "pin": ["run_id", "attempt", "head_sha"], "sessions": "8127baee (A4) 638cfc21 (A3)"},
    {"id": "W7", "kind": "WRITE", "title": "Re-run the EXACT pinned a11oy deploy run after O4 (pins.W7: run_id, attempt, head_sha, workflow_path)",
     "steps": [("rerun_pinned", "a11oy", "W7", None, None)], "pin": ["run_id", "attempt", "head_sha", "workflow_path"], "requires": ["O4"], "sessions": "a4c41815"},
    {"id": "W8", "kind": "WRITE", "title": "Stage readiness bundle on VM1 at the EXACT pinned szl-estate-os commit (pins.W8.commit); list files + sha256 only, execute nothing",
     "steps": [("vm_stage_readiness", "W8")], "pin": ["commit"], "requires": ["O3"], "sessions": "dd1d8f00 f0dc2fc7 6545ca76 8f178208 f300d563"},
    {"id": "W9", "kind": "WRITE", "title": "Re-run failed jobs ONCE on szl-forge run 39879628870 attempt 1 at merge 7ad9b9ae (built-in pin; refused if attempt changed)",
     "steps": [("rerun_pinned", "szl-forge", "W9", None, {"run_id": 39879628870, "attempt": 1, "head_sha": "7ad9b9aeedfff3c725ab245d00ed809b6372a726"})],
     "sessions": "attached handoff SZL_CLAUDE_CODE_HANDOFF_20261022"},
    {"id": "L1", "kind": "LANE", "title": "a11oy#2944 follow-up branch fix/ayllu-wall-scope-untrusted (V1 tests, R1 push)",
     "owner": "c7fd5762", "sessions": "c7fd5762"},
    {"id": "L2", "kind": "LANE", "title": "Coordinator 2.1.0 -> 2.2.0 with szl_lane_lease.py gate", "owner": "9e2c890a", "sessions": "9e2c890a"},
]

# ============================== pure gate logic (selftested) ==================================

def resource_gate(free_gb, ram_gib, item_id, waivers, floor_disk=FLOOR_DISK_GB, floor_ram=FLOOR_RAM_GIB):
    """Return (ok, reason). Unknown measurements refuse. Emergency floor refuses even with a waiver."""
    if free_gb is None or ram_gib is None:
        return False, "RESOURCE_UNMEASURED"
    if free_gb < EMERGENCY_DISK_GB:
        return False, f"BELOW_EMERGENCY_DISK {free_gb:.2f} < {EMERGENCY_DISK_GB} GB (no waiver possible)"
    if ram_gib < floor_ram:
        return False, f"BELOW_RAM_FLOOR {ram_gib:.2f} < {floor_ram} GiB"
    if free_gb < floor_disk:
        if item_id in (waivers or []):
            return True, f"BELOW_DISK_FLOOR_WAIVED {free_gb:.2f} GB (waiver names {item_id})"
        return False, f"BELOW_DISK_FLOOR {free_gb:.2f} < {floor_disk} GB"
    return True, "RESOURCES_OK"


def approval_gate(item_id, approvals):
    if not isinstance(approvals, dict):
        return False, "NO_APPROVALS_FILE"
    if not str(approvals.get("approved_by", "")).strip():
        return False, "APPROVALS_UNSIGNED (approved_by empty)"
    approved = approvals.get("approved")
    if not isinstance(approved, list) or item_id not in approved:
        return False, f"NOT_APPROVED ({item_id} not in approvals.json approved)"
    return True, "APPROVED"


def lane_gate(item, approvals):
    if item.get("kind") != "LANE":
        return True, "NOT_A_LANE_ITEM"
    rel = (approvals or {}).get("release_lane") or []
    if item["id"] in rel:
        return True, "LANE_RELEASED"
    return False, f"OWNED_BY_LANE {item['owner']}"


GREEN = {"success", "neutral", "skipped"}


def checks_green(check_runs, statuses, complete=True):
    """Green only if the read was complete, nothing is pending or failed, and at least one check
    actually executed (conclusion success / status success). Skipped or neutral alone is not evidence."""
    if not complete:
        return False, "INCOMPLETE_READ"
    if not check_runs and not statuses:
        return False, "NO_CHECKS_REPORTED"
    executed = skipped = 0
    for c in check_runs:
        if c.get("status") != "completed":
            return False, f"PENDING {c.get('name')}"
        if c.get("conclusion") not in GREEN:
            return False, f"FAILED {c.get('name')}={c.get('conclusion')}"
        if c.get("conclusion") == "success":
            executed += 1
        else:
            skipped += 1
    latest = {}
    for s_ in statuses:  # API returns newest first; keep first per context
        latest.setdefault(s_.get("context"), s_.get("state"))
    for ctx, st in latest.items():
        if st != "success":
            return False, f"STATUS {ctx}={st}"
        executed += 1
    if executed == 0:
        return False, f"NO_EXECUTED_CHECKS ({skipped} skipped/neutral only)"
    return True, f"GREEN ({executed} executed, {skipped} skipped/neutral)"


def merge_gate(snap):
    """Admit a merge only for an open, non-draft PR whose checks were read completely, are green,
    and whose GitHub mergeable_state is exactly 'clean' (required checks and reviews satisfied)."""
    if snap.get("state") != "OPEN":
        return False, f"state={snap.get('state')}"
    if snap.get("draft"):
        return False, "draft"
    if not snap.get("checks_complete"):
        return False, f"checks read incomplete: {snap.get('checks_reason')}"
    if not snap.get("checks_green"):
        return False, f"checks not green: {snap.get('checks_reason')} {snap.get('not_green')}"
    if snap.get("mergeable_state") != "clean":
        return False, f"mergeable_state={snap.get('mergeable_state')} (only 'clean' is admitted)"
    return True, "MERGE_GATE_PASS"


def pin_gate(item_id, approvals, required):
    pins = (approvals or {}).get("pins") if isinstance(approvals, dict) else None
    if not isinstance(pins, dict) or not isinstance(pins.get(item_id), dict):
        return False, f"UNPINNED (approvals.json pins.{item_id} must give {', '.join(required)})", None
    pin = pins[item_id]
    missing = [k for k in required if k not in pin]
    if missing:
        return False, f"PIN_INCOMPLETE pins.{item_id} missing {missing}", None
    return True, "PINNED", pin


FAILED_CONCLUSIONS = ("failure", "timed_out", "cancelled")


def run_matches_pin(w, pin):
    try:
        if int(w.get("id", -1)) != int(pin["run_id"]):
            return False, f"RUN_ID_MISMATCH {w.get('id')} != {pin['run_id']}"
        if int(w.get("run_attempt") or 1) != int(pin["attempt"]):
            return False, f"ATTEMPT_CHANGED now {w.get('run_attempt')} (pinned {pin['attempt']}): stop, no further retries"
    except (TypeError, ValueError, KeyError):
        return False, "PIN_MALFORMED"
    if w.get("status") != "completed":
        return False, f"RUN_NOT_COMPLETED status={w.get('status')}"
    if w.get("conclusion") not in FAILED_CONCLUSIONS:
        return False, f"RUN_NOT_FAILED conclusion={w.get('conclusion')}"
    if pin.get("head_sha") and w.get("head_sha") != pin["head_sha"]:
        return False, f"HEAD_MISMATCH run {str(w.get('head_sha'))[:12]} != pin {str(pin['head_sha'])[:12]}"
    if pin.get("workflow_path") and w.get("path") != pin["workflow_path"]:
        return False, f"WORKFLOW_MISMATCH {w.get('path')} != {pin['workflow_path']}"
    return True, "RUN_MATCHES_PIN"


FP_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_ED_PREFIX = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)


def ed25519_fp(b64):
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    if len(blob) != 51 or not blob.startswith(_ED_PREFIX):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def exact_fp_match(expected, text):
    """text: known_hosts/keyscan lines. Pass only if every ed25519 key present has exactly the expected
    fingerprint (full string equality) and there is exactly one. Returns (ok, why, b64_of_matched_key)."""
    if not FP_RE.fullmatch(expected or ""):
        return False, "EXPECTED_FP_INVALID (need full SHA256:<43 chars>)", None
    found = {}
    for line in (text or "").splitlines():
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        if f[0].startswith("@"):
            return False, "MARKER_LINE (@revoked/@cert-authority needs owner review)", None
        if "ssh-ed25519" in f:
            i = f.index("ssh-ed25519")
            fp = ed25519_fp(f[i + 1]) if i + 1 < len(f) else None
            if fp is None:
                return False, "MALFORMED_ED25519_KEY", None
            found[fp] = f[i + 1]
    if not found:
        return False, "NO_ED25519_KEY", None
    if set(found) != {expected}:
        return False, f"FP_MISMATCH observed {sorted(found)}", None
    return True, "FP_EXACT_MATCH", found[expected]


def validate_probe(obs):
    """Every field must be present and valid; the exit status of a final command is never enough."""
    if not isinstance(obs, dict):
        return False, ["not_json_object"]
    problems = []
    for k in ("hostname", "user", "boot_id"):
        if not obs.get(k):
            problems.append(k)
    if not isinstance(obs.get("uid"), int):
        problems.append("uid")
    gpu = obs.get("gpu") or {}
    if gpu.get("exit_code") != 0 or not str(gpu.get("stdout", "")).strip():
        problems.append("gpu")
    if "MemAvailable" not in (obs.get("memory") or {}):
        problems.append("memory")
    if not isinstance((obs.get("root_disk") or {}).get("available_bytes"), int):
        problems.append("disk")
    return (not problems), problems


def redact(text, secrets):
    out = str(text)
    for s in secrets:
        if s and len(s) >= 6:
            out = out.replace(s, "[REDACTED]")
    return out


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def ledger_append(path, kind, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev, seq = "0" * 64, 0
    if path.exists():
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev, seq = last["hash"], last["seq"] + 1
    entry = {"seq": seq, "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
             "kind": kind, "data": data, "prev": prev, "tool": f"szl_session_recovery {VERSION}"}
    entry["hash"] = hashlib.sha256(_canon(entry).encode()).hexdigest()
    with open(path, "a", encoding="utf-8") as f:
        f.write(_canon(entry) + "\n")
    return entry


def ledger_verify(path):
    path = Path(path)
    if not path.exists():
        return True, "EMPTY"
    prev = "0" * 64
    for i, line in enumerate(l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()):
        e = json.loads(line)
        h = e.pop("hash", None)
        if e.get("seq") != i or e.get("prev") != prev:
            return False, f"CHAIN_BREAK at seq {i}"
        if hashlib.sha256(_canon(e).encode()).hexdigest() != h:
            return False, f"HASH_MISMATCH at seq {i}"
        prev = h
    return True, f"OK {i + 1} entries"


# ============================== selftest with mutants =========================================

def _run_tests(rg, ag, cg, lv, la, lg):
    import tempfile
    fails = []
    ran = []
    def t(name, cond):
        ran.append(name)
        if not cond:
            fails.append(name)
    t("rg_ok", rg(20, 4, "W1", [])[0])
    t("rg_disk_refuse", not rg(10, 4, "W1", [])[0])
    t("rg_waiver_names_item", rg(10, 4, "W1", ["W1"])[0])
    t("rg_waiver_other_item", not rg(10, 4, "W1", ["W2"])[0])
    t("rg_emergency_no_waiver", not rg(4.9, 4, "W1", ["W1"])[0])
    t("rg_ram_refuse", not rg(20, 1.0, "W1", [])[0])
    t("rg_unmeasured", not rg(None, 4, "W1", [])[0])
    t("rg_boundary_exact", rg(15.0, 1.5, "W1", [])[0])
    t("ag_ok", ag("W1", {"approved_by": "Stephen", "approved": ["W1"]})[0])
    t("ag_missing", not ag("W2", {"approved_by": "Stephen", "approved": ["W1"]})[0])
    t("ag_unsigned", not ag("W1", {"approved_by": "", "approved": ["W1"]})[0])
    t("ag_nofile", not ag("W1", None)[0])
    t("ag_string_not_list", not ag("W1", {"approved_by": "S", "approved": "W1,W2"})[0])
    t("ag_prefix_not_match", not ag("W1", {"approved_by": "S", "approved": ["W10"]})[0])
    t("lg_lane_refused", not lg({"id": "L1", "kind": "LANE", "owner": "x"}, {"release_lane": []})[0])
    t("lg_lane_released", lg({"id": "L1", "kind": "LANE", "owner": "x"}, {"release_lane": ["L1"]})[0])
    t("cg_green", cg([{"status": "completed", "conclusion": "success", "name": "a"}], [])[0])
    t("cg_empty", not cg([], [])[0])
    t("cg_pending", not cg([{"status": "in_progress", "conclusion": None, "name": "a"}], [])[0])
    t("cg_failed", not cg([{"status": "completed", "conclusion": "failure", "name": "a"}], [])[0])
    t("cg_status_fail", not cg([{"status": "completed", "conclusion": "success", "name": "a"}],
                               [{"context": "gitleaks", "state": "failure"}])[0])
    t("cg_status_newest_wins", cg([], [{"context": "c", "state": "success"}, {"context": "c", "state": "failure"}])[0])
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "l.jsonl"
        la(p, "a", {"x": 1}); la(p, "b", {"x": 2}); la(p, "c", {"x": 3})
        t("ledger_ok", lv(p)[0])
        lines = p.read_text().splitlines()
        lines[1] = lines[1].replace('"x":2', '"x":9')
        p.write_text("\n".join(lines) + "\n")
        t("ledger_tamper_detected", not lv(p)[0])
        p2 = Path(d) / "l2.jsonl"
        la(p2, "a", {}); la(p2, "b", {}); la(p2, "c", {})
        ls = p2.read_text().splitlines()
        p2.write_text("\n".join([ls[0], ls[2]]) + "\n")
        t("ledger_deletion_detected", not lv(p2)[0])
    t("redact", "tok_abcdef123" not in redact("x tok_abcdef123 y", ["tok_abcdef123"]))
    _run_tests.last_count = len(ran)
    return fails


def _run_tests2(cg, mg, fx, pg, rp, vp):
    fails, ran = [], []
    def t(name, cond):
        ran.append(name)
        if not cond:
            fails.append(name)
    ok_run = {"status": "completed", "conclusion": "success", "name": "a"}
    t("cg_skipped_only_not_green", not cg([{"status": "completed", "conclusion": "skipped", "name": "a"}], [])[0])
    t("cg_neutral_only_not_green", not cg([{"status": "completed", "conclusion": "neutral", "name": "a"}], [])[0])
    t("cg_incomplete_not_green", not cg([ok_run], [], False)[0])
    t("cg_success_plus_skip_green", cg([ok_run, {"status": "completed", "conclusion": "skipped", "name": "b"}], [])[0])
    base = {"state": "OPEN", "draft": False, "checks_complete": True, "checks_green": True, "mergeable_state": "clean"}
    t("mg_clean_ok", mg(base)[0])
    for ms in ("unstable", "has_hooks", "blocked", "behind", "dirty", "unknown", None):
        t(f"mg_refuse_{ms}", not mg(dict(base, mergeable_state=ms))[0])
    t("mg_refuse_incomplete", not mg(dict(base, checks_complete=False))[0])
    t("mg_refuse_not_green", not mg(dict(base, checks_green=False))[0])
    t("mg_refuse_draft", not mg(dict(base, draft=True))[0])
    t("mg_refuse_merged", not mg(dict(base, state="MERGED"))[0])
    blob = _ED_PREFIX + b"k" * 32
    b64 = base64.b64encode(blob).decode()
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    oblob = _ED_PREFIX + b"j" * 32
    ob64 = base64.b64encode(oblob).decode()
    ofp = "SHA256:" + base64.b64encode(hashlib.sha256(oblob).digest()).decode().rstrip("=")
    line = f"64.247.206.118 ssh-ed25519 {b64}"
    t("fx_exact", fx(fp, line)[0] and fx(fp, line)[2] == b64)
    t("fx_substring_refused", not fx(fp[:20], line)[0])
    t("fx_prefix_of_real_refused", not fx(fp[:-1], line)[0])
    t("fx_mismatch", not fx(ofp, line)[0])
    t("fx_two_keys_refused", not fx(fp, line + "\n" + f"64.247.206.118 ssh-ed25519 {ob64}")[0])
    t("fx_revoked_refused", not fx(fp, "@revoked " + line)[0])
    t("fx_malformed", not fx(fp, "64.247.206.118 ssh-ed25519 eA==")[0])
    t("fx_empty", not fx(fp, "")[0])
    ap = {"pins": {"W6": {"run_id": 1, "attempt": 1, "head_sha": "a" * 40}}}
    t("pg_ok", pg("W6", ap, ["run_id", "attempt", "head_sha"])[0])
    t("pg_missing_item", not pg("W7", ap, ["run_id"])[0])
    t("pg_missing_key", not pg("W6", {"pins": {"W6": {"run_id": 1}}}, ["run_id", "attempt"])[0])
    t("pg_no_pins", not pg("W6", {}, ["run_id"])[0])
    t("pg_none", not pg("W6", None, ["run_id"])[0])
    pin = {"run_id": 5, "attempt": 1, "head_sha": "a" * 40}
    w = {"id": 5, "run_attempt": 1, "status": "completed", "conclusion": "failure", "head_sha": "a" * 40, "path": ".github/workflows/x.yml"}
    t("rp_ok", rp(w, pin)[0])
    t("rp_attempt_changed", not rp(dict(w, run_attempt=2), pin)[0])
    t("rp_other_run", not rp(dict(w, id=6), pin)[0])
    t("rp_not_failed", not rp(dict(w, conclusion="success"), pin)[0])
    t("rp_pending", not rp(dict(w, status="in_progress"), pin)[0])
    t("rp_head_mismatch", not rp(dict(w, head_sha="b" * 40), pin)[0])
    t("rp_path_mismatch", not rp(w, dict(pin, workflow_path=".github/workflows/y.yml"))[0])
    good = {"hostname": "h", "user": "Ubuntu", "uid": 1001, "boot_id": "x", "gpu": {"exit_code": 0, "stdout": "GPU-1, RTX A6000"},
            "memory": {"MemAvailable": "1 kB"}, "root_disk": {"available_bytes": 1}}
    t("vp_ok", vp(good)[0])
    t("vp_gpu_failed", not vp(dict(good, gpu={"exit_code": 9, "stdout": ""}))[0])
    t("vp_gpu_unavailable", not vp(dict(good, gpu={"state": "UNAVAILABLE"}))[0])
    t("vp_no_disk", not vp(dict(good, root_disk={"state": "UNAVAILABLE"}))[0])
    t("vp_no_mem", not vp(dict(good, memory={}))[0])
    t("vp_no_user", not vp(dict(good, user=""))[0])
    t("vp_not_dict", not vp("hostname ok")[0])
    _run_tests2.last_count = len(ran)
    return fails


def _offline_makes_no_calls():
    global gh
    real, calls = gh, []
    def _no_network(*a, **k):
        calls.append(a)
        raise AssertionError("network call in offline mode")
    gh = _no_network
    try:
        it = {"id": "O11", "kind": "OWNER", "evidence": "secret:platform:X"}
        st, _ = evidence_state(it, {"free_gb": 20, "ram_avail_gib": 4}, None, None, online=False)
    finally:
        gh = real
    return st == "UNKNOWN" and not calls


def cmd_selftest(_a):
    base = _run_tests(resource_gate, approval_gate, checks_green, ledger_verify, ledger_append, lane_gate)
    n_tests = _run_tests.last_count
    mutants = {
        "M1 disk floor ignored": dict(rg=lambda f, r, i, w, **k: (r is not None and f is not None and r >= FLOOR_RAM_GIB, "m"))
        , "M2 waiver accepts any item": dict(rg=lambda f, r, i, w, **k: (f is not None and r is not None and r >= 1.5 and (f >= 15 or bool(w)), "m"))
        , "M3 emergency floor waivable": dict(rg=lambda f, r, i, w, **k: (f is not None and r is not None and r >= 1.5 and (f >= 15 or i in w), "m"))
        , "M4 approval skips signer": dict(ag=lambda i, a: (isinstance(a, dict) and i in (a.get("approved") or []), "m"))
        , "M5 approval substring match": dict(ag=lambda i, a: (isinstance(a, dict) and bool(a.get("approved_by")) and i in str(a.get("approved")), "m"))
        , "M6 empty checks count as green": dict(cg=lambda c, s: (all(x.get("conclusion") in GREEN for x in c) and all(x.get("state") == "success" for x in s), "m"))
        , "M7 pending checks ignored": dict(cg=lambda c, s: ((bool(c) or bool(s)) and all(x.get("conclusion") in GREEN | {None} for x in c), "m"))
        , "M8 ledger verify always ok": dict(lv=lambda p: (True, "m"))
        , "M9 ledger ignores chain links": dict(lv=lambda p: (all(hashlib.sha256(_canon({k: v for k, v in json.loads(l).items() if k != "hash"}).encode()).hexdigest() == json.loads(l)["hash"]
                                                              for l in Path(p).read_text().splitlines() if l.strip()), "m"))
        , "M10 lane gate open": dict(lg=lambda it, ap: (True, "m"))
    }
    killed = 0
    for name, over in mutants.items():
        fns = dict(rg=resource_gate, ag=approval_gate, cg=checks_green, lv=ledger_verify, la=ledger_append, lg=lane_gate)
        fns.update(over)
        f = _run_tests(**fns)
        status = "KILLED" if f else "SURVIVED"
        killed += bool(f)
        print(f"  mutant {name:34s} {status}  ({len(f)} tests caught it)")
    _1_1_0_checks_green = lambda c, s_, complete=True: (bool(c) or bool(s_)) and all(x.get("status") == "completed" and x.get("conclusion") in GREEN for x in c) and all(x.get("state") == "success" for x in s_)
    base2 = _run_tests2(checks_green, merge_gate, exact_fp_match, pin_gate, run_matches_pin, validate_probe)
    n2 = _run_tests2.last_count
    mutants2 = {
        "N1 merge admits unstable/has_hooks (1.1.0)": dict(mg=lambda sn: (sn.get("state") == "OPEN" and not sn.get("draft") and bool(sn.get("checks_complete")) and bool(sn.get("checks_green")) and sn.get("mergeable_state") in ("clean", "unstable", "has_hooks"), "m")),
        "N2 merge ignores incomplete read": dict(mg=lambda sn: (sn.get("state") == "OPEN" and not sn.get("draft") and bool(sn.get("checks_green")) and sn.get("mergeable_state") == "clean", "m")),
        "N3 skipped-only counts as green (1.1.0)": dict(cg=lambda c, s_, complete=True: (_1_1_0_checks_green(c, s_), "m")),
        "N4 incomplete read ignored": dict(cg=lambda c, s_, complete=True: checks_green(c, s_, True)),
        "N5 fingerprint substring (1.1.0)": dict(fx=lambda e, text: (bool(e) and any(e in (ed25519_fp(l.split()[-1]) or "") for l in text.splitlines() if l.strip() and not l.startswith("@")), "m", None)),
        "N6 fingerprint any-of keys": dict(fx=lambda e, text: (bool(FP_RE.fullmatch(e or "")) and any(ed25519_fp(l.split()[-1]) == e for l in text.splitlines() if l.strip()), "m", None)),
        "N7 pin gate ignores missing keys": dict(pg=lambda i, a, r: (isinstance(a, dict) and isinstance((a.get("pins") or {}).get(i), dict), "m", None)),
        "N8 rerun ignores attempt": dict(rp=lambda w, p: run_matches_pin(dict(w, run_attempt=p.get("attempt")), p)),
        "N9 rerun ignores head sha": dict(rp=lambda w, p: run_matches_pin(w, {k: v for k, v in p.items() if k != "head_sha"})),
        "N10 probe trusts last exit code": dict(vp=lambda o: (True, [])),
    }
    killed2 = 0
    for name, over in mutants2.items():
        fns = dict(cg=checks_green, mg=merge_gate, fx=exact_fp_match, pg=pin_gate, rp=run_matches_pin, vp=validate_probe)
        fns.update(over)
        f = _run_tests2(**fns)
        killed2 += bool(f)
        print(f"  mutant {name:44s} {'KILLED' if f else 'SURVIVED'}  ({len(f)} tests caught it)")
    offline_ok = _offline_makes_no_calls()
    print(f"selftest: {n_tests} gate tests, base failures={len(base)} {base if base else ''}; mutants killed {killed}/{len(mutants)}")
    print(f"selftest2: {n2} repair tests, base failures={len(base2)} {base2 if base2 else ''}; mutants killed {killed2}/{len(mutants2)}; offline zero-network: {offline_ok}")
    ok = not base and killed == len(mutants) and not base2 and killed2 == len(mutants2) and offline_ok
    print("SELFTEST_PASS" if ok else "SELFTEST_FAIL")
    return 0 if ok else 1


# ============================== measurement ===================================================

def measure():
    drive = os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"
    du = shutil.disk_usage(drive)
    m = {"drive": drive, "free_gb": round(du.free / 1e9, 2), "total_gb": round(du.total / 1e9, 1),
         "ram_avail_gib": None, "ram_total_gib": None, "commit_used_gib": None, "commit_limit_gib": None, "mem_load_pct": None}
    if os.name == "nt":
        import ctypes
        class MS(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong), ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                        ("tpf", ctypes.c_ulonglong), ("apf", ctypes.c_ulonglong), ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                        ("ae", ctypes.c_ulonglong)]
        s = MS(); s.l = ctypes.sizeof(MS)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
            G = 2 ** 30
            m.update(ram_avail_gib=round(s.ap / G, 2), ram_total_gib=round(s.tp / G, 1), mem_load_pct=s.load,
                     commit_used_gib=round((s.tpf - s.apf) / G, 1), commit_limit_gib=round(s.tpf / G, 1))
    else:
        try:
            info = dict(l.split(":", 1) for l in Path("/proc/meminfo").read_text().splitlines())
            kb = lambda k: int(info[k].strip().split()[0])
            m.update(ram_avail_gib=round(kb("MemAvailable") / 2 ** 20, 2), ram_total_gib=round(kb("MemTotal") / 2 ** 20, 1))
        except Exception:
            pass
    return m


def cmd_preflight(_a, quiet=False):
    m = measure()
    ok, why = resource_gate(m["free_gb"], m["ram_avail_gib"], "-", [])
    m["verdict"] = "FLOORS_MET" if ok else why
    if not quiet:
        print(json.dumps(m, indent=1))
    ledger_append(LEDGER, "preflight", m)
    return m


def _dir_size(path, deadline):
    total, partial, stack = 0, False, [str(path)]
    while stack:
        if time.monotonic() > deadline:
            return total, True
        p = stack.pop()
        try:
            with os.scandir(p) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        partial = True
        except OSError:
            partial = True
    return total, partial


def cmd_triage(a):
    """Read-only. Sizes the biggest known consumers. Deletes nothing."""
    budget = float(getattr(a, "seconds", 240) or 240)
    t0 = time.monotonic()
    rows = []
    if os.name == "nt":
        root = os.environ.get("SystemDrive", "C:") + "\\"
        try:
            with os.scandir(root) as it:
                for e in it:
                    if e.name.lower() in ("pagefile.sys", "hiberfil.sys", "swapfile.sys"):
                        try:
                            rows.append((e.path, e.stat(follow_symlinks=False).st_size, False))
                        except OSError:
                            rows.append((e.path, -1, True))
        except OSError:
            pass
    cands = []
    for p in [HOME / "AppData" / "Local", HOME / "AppData" / "Roaming", HOME / ".claude-science", HOME / ".ollama",
              HOME / ".lmstudio", HOME / "Downloads", HOME / "Documents", HOME / ".cache", HOME / "miniconda3",
              HOME / "anaconda3", HOME / ".conda"]:
        if p.exists():
            if p.name in ("Local", "Roaming"):
                try:
                    cands += [Path(e.path) for e in os.scandir(p) if e.is_dir(follow_symlinks=False)]
                except OSError:
                    rows.append((str(p), -1, True))
            else:
                cands.append(p)
    per = max(5.0, budget / max(1, len(cands)))
    for p in cands:
        size, partial = _dir_size(p, time.monotonic() + per)
        rows.append((str(p), size, partial))
    rows.sort(key=lambda r: -r[1])
    print(f"{'GB':>8}  partial  path   (read-only; elapsed {time.monotonic() - t0:.0f}s)")
    for path, size, partial in rows[:25]:
        print(f"{size / 1e9:8.2f}  {'yes' if partial else ' no':>7}  {path}")
    print("partial=yes means the time box or a permission stopped the walk: the true size is >= the number shown.")
    ledger_append(LEDGER, "triage", {"top": [(p, s, pa) for p, s, pa in rows[:25]]})
    return 0


# ============================== GitHub (REST, stdlib) =========================================

def _token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not t and shutil.which("gh"):
        try:
            t = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            t = ""
    return t or ""


def gh(method, path, body=None, tok=None):
    tok = tok if tok is not None else _token()
    req = urllib.request.Request("https://api.github.com" + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                                          **({"Authorization": f"Bearer {tok}"} if tok else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {"message": str(e)}
    except Exception as e:
        return 0, {"message": redact(str(e), [tok])[:200]}


def gh_paged(path, key, tok, max_pages=20):
    """Read every page. Any non-200, bad shape, page cap or count mismatch -> (None, reason): UNKNOWN, never empty."""
    items, page, total = [], 1, None
    while True:
        sep = "&" if "?" in path else "?"
        st, body = gh("GET", f"{path}{sep}per_page=100&page={page}", tok=tok)
        if st != 200:
            return None, f"HTTP_{st}"
        if key is None:
            chunk = body if isinstance(body, list) else None
        else:
            chunk = body.get(key) if isinstance(body, dict) else None
            if isinstance(body, dict) and isinstance(body.get("total_count"), int):
                total = body["total_count"]
        if not isinstance(chunk, list):
            return None, "BAD_SHAPE"
        items.extend(chunk)
        if len(chunk) < 100 or (total is not None and len(items) >= total):
            break
        page += 1
        if page > max_pages:
            return None, f"PAGE_CAP {max_pages}"
    if total is not None and len(items) != total:
        return None, f"COUNT_MISMATCH {len(items)}/{total}"
    return items, f"OK {len(items)}"


def pr_snapshot(repo, n, tok):
    st, p = gh("GET", f"/repos/{ORG}/{repo}/pulls/{n}", tok=tok)
    if st != 200:
        return {"repo": repo, "n": n, "state": f"HTTP_{st}", "error": str(p.get("message", ""))[:120],
                "checks_green": False, "checks_complete": False, "checks_reason": f"PR_HTTP_{st}", "not_green": []}
    if p.get("mergeable_state") in (None, "unknown") and p["state"] == "open":
        time.sleep(2)
        st2, p2 = gh("GET", f"/repos/{ORG}/{repo}/pulls/{n}", tok=tok)
        if st2 == 200:
            p = p2
    sha = p["head"]["sha"]
    cr, why_r = gh_paged(f"/repos/{ORG}/{repo}/commits/{sha}/check-runs", "check_runs", tok)
    cs, why_s = gh_paged(f"/repos/{ORG}/{repo}/commits/{sha}/statuses", None, tok)
    st3, p3 = gh("GET", f"/repos/{ORG}/{repo}/pulls/{n}", tok=tok)
    head_stable = st3 == 200 and p3.get("head", {}).get("sha") == sha
    complete = cr is not None and cs is not None and head_stable
    runs = [{"name": c.get("name"), "status": c.get("status"), "conclusion": c.get("conclusion")} for c in (cr or [])]
    stats = [{"context": x.get("context"), "state": x.get("state")} for x in (cs or [])]
    green, why = checks_green(runs, stats, complete)
    if not complete:
        why = f"UNKNOWN (check-runs {why_r}; statuses {why_s}; head {'stable' if head_stable else 'CHANGED_OR_UNREADABLE'})"
    bad = [f"{r['name']}={r['conclusion'] or r['status']}" for r in runs if r["status"] != "completed" or r["conclusion"] not in GREEN]
    return {"repo": repo, "n": n, "state": "MERGED" if p.get("merged_at") else p["state"].upper(), "draft": p.get("draft"),
            "mergeable_state": p.get("mergeable_state"), "head_sha": sha, "base": p["base"]["ref"], "title": p["title"][:70],
            "checks_green": green, "checks_complete": complete, "checks_reason": why, "not_green": bad[:6],
            "n_check_runs": len(runs), "n_statuses": len(stats),
            "required_policy": "NOT_READ (GitHub enforces it server-side; merge_gate admits only mergeable_state=clean)"}


def cmd_github(_a, quiet=False):
    tok = _token()
    if not tok:
        print("NO_GITHUB_TOKEN: set GITHUB_TOKEN or run `gh auth login`. Read-only calls may hit rate limits without it.")
    snaps = [pr_snapshot(r, n, tok) | {"cited_by": s} for r, n, s in PRS]
    settings = {}
    st, v = gh("GET", f"/repos/{ORG}/a11oy/actions/variables?per_page=100", tok=tok)
    have_v = {x["name"] for x in v.get("variables", [])} if st == 200 else None
    st2, s = gh("GET", f"/repos/{ORG}/a11oy/actions/secrets?per_page=100", tok=tok)
    have_s = {x["name"] for x in s.get("secrets", [])} if st2 == 200 else None
    settings["a11oy_vars_missing"] = None if have_v is None else [x for x in A11OY_VARS if x not in have_v]
    settings["a11oy_secrets_missing"] = None if have_s is None else [x for x in A11OY_SECRETS if x not in have_s]
    settings["a11oy_settings_http"] = [st, st2]
    st3, lr = gh("GET", f"/repos/{ORG}/lutar-lean", tok=tok)
    settings["lutar_lean_default_branch"] = lr.get("default_branch") if st3 == 200 else f"HTTP_{st3}"
    if not quiet:
        for x in snaps:
            print(f"{x['repo']}#{x['n']:<5} {x['state']:<7} {('draft ' if x.get('draft') else '')}{x.get('mergeable_state','')!s:<9} "
                  f"green={x.get('checks_green')} {x.get('checks_reason','')} {x.get('not_green','') or ''}")
        print(json.dumps(settings, indent=1))
        print("Names only: secret VALUES are never read or printed. None = this token cannot list them (UNKNOWN).")
    out = {"prs": snaps, "settings": settings}
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / "github_snapshot.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    ledger_append(LEDGER, "github", {"sha256": hashlib.sha256(_canon(out).encode()).hexdigest(), "n_prs": len(snaps)})
    return out


# ============================== VM probe ======================================================

REMOTE_PROBE = r"""import json,os,pathlib,pwd,socket,subprocess
def read(p):
    try: return pathlib.Path(p).read_text().strip()
    except OSError: return None
def run(a):
    try:
        r=subprocess.run(a,capture_output=True,text=True,timeout=8,check=False)
        return {"exit_code":r.returncode,"stdout":r.stdout[:16384]}
    except (OSError,subprocess.TimeoutExpired) as e: return {"state":"UNAVAILABLE","error_type":type(e).__name__}
mem={}
for l in (read('/proc/meminfo') or '').splitlines():
    k,_,v=l.partition(':')
    if k in ('MemTotal','MemAvailable','SwapTotal','SwapFree'): mem[k]=v.strip()
try:
    fs=os.statvfs('/'); disk={"available_bytes":fs.f_bavail*fs.f_frsize,"total_bytes":fs.f_blocks*fs.f_frsize}
except OSError: disk={"state":"UNAVAILABLE"}
print(json.dumps({"schema":"szl.vm.readonly-probe.v1","hostname":socket.gethostname(),"uid":os.getuid(),
 "user":pwd.getpwuid(os.getuid()).pw_name,"boot_id":read('/proc/sys/kernel/random/boot_id'),"memory":mem,"root_disk":disk,
 "nproc":os.cpu_count(),
 "gpu":run(['nvidia-smi','--query-gpu=uuid,name,memory.total,memory.used,utilization.gpu','--format=csv,noheader,nounits']),
 "gpu_processes":run(['nvidia-smi','--query-compute-apps=pid,process_name,used_memory','--format=csv,noheader,nounits']),
 "process_names":run(['ps','-eo','pid,user,etimes,comm','--sort=pid'])},sort_keys=True))
"""


def host_trust():
    """Return (ok, why, b64). The host key comes from SZL_VM_KNOWN_HOSTS (an existing trusted record, read with
    ssh-keygen -F) or from ssh-keyscan; either way it must EXACTLY equal SZL_VM_FP, which must come from an
    independent source (the VM console's ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)."""
    if not VM["expected_fp"]:
        return False, "VM_FP_UNKNOWN (set SZL_VM_FP from the VM console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)", None
    kh = os.environ.get("SZL_VM_KNOWN_HOSTS", "")
    hostspec = VM["host"] if VM["port"] == 22 else f"[{VM['host']}]:{VM['port']}"
    try:
        if kh:
            if not shutil.which("ssh-keygen"):
                return False, "SSH_KEYGEN_MISSING", None
            r = subprocess.run(["ssh-keygen", "-F", hostspec, "-f", kh], capture_output=True, text=True, timeout=10)
            text, src = (r.stdout if r.returncode == 0 else ""), f"known_hosts {kh}"
        else:
            if not shutil.which("ssh-keyscan"):
                return False, "SSH_KEYSCAN_MISSING", None
            r = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(VM["port"]), "-t", "ed25519", VM["host"]],
                               capture_output=True, text=True, timeout=30)
            text, src = r.stdout, "ssh-keyscan"
    except Exception as e:
        return False, f"HOSTKEY_READ_ERROR {type(e).__name__}", None
    ok, why, b64 = exact_fp_match(VM["expected_fp"], text)
    return ok, f"{why} (source: {src})", b64


def _ssh_cmd(pin_file):
    if not VM["user"]:
        return None, "VM_USER_UNKNOWN (set SZL_VM_USER to the output of `whoami` on the VM)"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", VM["user"]):
        return None, "VM_USER_INVALID"
    if not Path(VM["key"]).is_file():
        return None, f"VM_KEY_MISSING {VM['key']}"
    if not shutil.which("ssh"):
        return None, "SSH_CLIENT_MISSING"
    if not re.fullmatch(r"[A-Za-z0-9_./:\\-]+", pin_file):
        return None, "PIN_PATH_UNSAFE (OpenSSH would expand it)"
    opts = ["BatchMode=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ConnectTimeout=15",
            "ConnectionAttempts=1", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "ForwardAgent=no",
            "ClearAllForwardings=yes", "ControlMaster=no", "ControlPath=none", "UpdateHostKeys=no",
            "HostKeyAlgorithms=ssh-ed25519", "VerifyHostKeyDNS=no", "GlobalKnownHostsFile=" + os.devnull,
            "UserKnownHostsFile=" + pin_file]
    cmd = ["ssh", "-F", os.devnull, "-T", "-p", str(VM["port"]), "-i", VM["key"]]
    for o in opts:
        cmd += ["-o", o]
    return cmd + [f"{VM['user']}@{VM['host']}"], "OK"


def run_pinned_ssh(remote_cmd, stdin_text=None, timeout=60):
    """Bind the exactly-matched host key into a one-line temporary known_hosts used by this connection only."""
    ok, why, b64 = host_trust()
    if not ok:
        return None, why
    hostspec = VM["host"] if VM["port"] == 22 else f"[{VM['host']}]:{VM['port']}"
    with tempfile.TemporaryDirectory(prefix="szl-pin-") as d:
        pin = os.path.join(d, "known_hosts")
        with open(pin, "w", encoding="ascii", newline="\n") as f:
            f.write(f"{hostspec} ssh-ed25519 {b64}\n")
        cmd, why2 = _ssh_cmd(pin)
        if cmd is None:
            return None, why2
        try:
            r = subprocess.run(cmd + [remote_cmd], input=stdin_text, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, "SSH_TIMEOUT"
    return r, why


def cmd_vm(_a, quiet=False):
    res = {"host": VM["host"], "port": VM["port"], "user": VM["user"] or None, "key": VM["key"]}
    r, why = run_pinned_ssh("python3 -I -S -", stdin_text=REMOTE_PROBE)
    res["host_trust"] = why
    if r is None:
        res["verdict"] = "VM_NOT_VERIFIED: " + why
    else:
        res["exit"] = r.returncode
        res["stderr_tail"] = r.stderr[-400:]
        obs = None
        if r.returncode == 0 and len(r.stdout) <= 131072:
            try:
                obs = json.loads(r.stdout)
            except ValueError:
                obs = None
        valid, problems = validate_probe(obs)
        res["observation"] = obs
        if r.returncode != 0:
            res["verdict"] = f"VM_SSH_FAILED exit {r.returncode}"
        elif not valid:
            res["verdict"] = f"VM_PROBE_INCOMPLETE {problems}"
        else:
            res["verdict"] = "VM_KEY_LOGIN_OK"
    if not quiet:
        print(json.dumps({k: v for k, v in res.items() if k != "observation"}, indent=1))
        if res.get("observation"):
            o = res["observation"]
            print(json.dumps({"hostname": o.get("hostname"), "user": o.get("user"), "uid": o.get("uid"),
                              "gpu": o.get("gpu", {}).get("stdout", "").strip(), "gpu_processes": o.get("gpu_processes", {}).get("stdout", "").strip(),
                              "MemAvailable": o.get("memory", {}).get("MemAvailable"), "root_free_bytes": o.get("root_disk", {}).get("available_bytes")}, indent=1))
    ledger_append(LEDGER, "vm_probe", res)
    return res


# ============================== queue / run ===================================================

def load_approvals():
    if not APPROVALS.exists():
        return None
    try:
        return json.loads(APPROVALS.read_text(encoding="utf-8"))
    except Exception:
        return {"_invalid": True}


def evidence_state(item, m, gh_out, vm_out, online=True):
    ev = item.get("evidence")
    if ev == "preflight":
        ok, why = resource_gate(m["free_gb"], m["ram_avail_gib"], "-", [])
        return ("DONE" if ok else "OPEN"), f"C: {m['free_gb']} GB, RAM {m['ram_avail_gib']} GiB ({why})"
    if ev == "vm":
        if vm_out is None:
            return "UNKNOWN", "vm probe not run"
        return ("DONE" if vm_out.get("verdict") == "VM_KEY_LOGIN_OK" else "OPEN"), vm_out.get("verdict")
    if ev == "a11oy_settings":
        if gh_out is None:
            return "UNKNOWN", "github not run"
        s = gh_out["settings"]
        if s["a11oy_vars_missing"] is None or s["a11oy_secrets_missing"] is None:
            return "UNKNOWN", f"token cannot list settings (HTTP {s['a11oy_settings_http']})"
        miss = s["a11oy_vars_missing"] + s["a11oy_secrets_missing"]
        return ("DONE" if not miss else "OPEN"), ("all present" if not miss else "missing " + ", ".join(miss))
    if ev == "lutar_default":
        if gh_out is None:
            return "UNKNOWN", "github not run"
        b = gh_out["settings"]["lutar_lean_default_branch"]
        return ("DONE" if b == "main" else "OPEN"), f"default_branch={b}"
    if ev and ev.startswith("secret:"):
        _, repo, name = ev.split(":", 2)
        if not online:
            return "UNKNOWN", f"offline: {repo} secret names not read"
        items, why = gh_paged(f"/repos/{ORG}/{repo}/actions/secrets", "secrets", None)
        if items is None:
            return "UNKNOWN", f"cannot list {repo} secrets ({why})"
        if name not in {x.get("name") for x in items}:
            return "OPEN", f"{name} missing in {repo} (MEASURED)"
        att = ((load_approvals() or {}).get("attest") or {}).get(item["id"])
        if att:
            return "ATTESTED", f"{name} name present (MEASURED); owner attests the rest (REPORTED): {att}"
        return "OPEN", f"{name} name present (MEASURED; presence does not prove it is valid); deployment authorization not attested"
    ap = load_approvals() or {}
    att = (ap.get("attest") or {}).get(item["id"])
    return ("ATTESTED" if att else "OPEN"), (f"owner attests: {att}" if att else "needs owner attestation in approvals.json attest")


def item_state(item, m, ap, gh_out=None, vm_out=None, done_owner=None):
    k = item["kind"]
    if k == "READ":
        return "READY", "read-only"
    if k == "OWNER":
        return evidence_state(item, m, gh_out, vm_out, online=gh_out is not None)
    if k == "LANE":
        ok, why = lane_gate(item, ap)
        return ("READY_RELEASED" if ok else "OWNED_BY_LANE"), why
    reasons = []
    for req in item.get("requires", []):
        if done_owner is not None and done_owner.get(req) not in ("DONE",):
            reasons.append(f"REQUIRES {req} (state {done_owner.get(req)})")
    ok, why = approval_gate(item["id"], ap)
    if not ok:
        reasons.append(why)
    if item.get("pin"):
        okp, whyp, _ = pin_gate(item["id"], ap, item["pin"])
        if not okp:
            reasons.append(whyp)
    ok2, why2 = resource_gate(m["free_gb"], m["ram_avail_gib"], item["id"], (ap or {}).get("below_floor_waiver") or [])
    if not ok2:
        reasons.append(why2)
    return ("READY" if not reasons else "BLOCKED"), "; ".join(reasons) or "all gates pass"


def compute_queue(with_remote=True):
    m = measure()
    ap = load_approvals()
    gh_out = cmd_github(None, quiet=True) if with_remote else None
    vm_out = cmd_vm(None, quiet=True) if with_remote else None
    owner = {}
    rows = []
    owner_full = {}
    for it in ITEMS:
        if it["kind"] == "OWNER":
            owner_full[it["id"]] = evidence_state(it, m, gh_out, vm_out, online=with_remote)
            owner[it["id"]] = owner_full[it["id"]][0]
    for it in ITEMS:
        st, why = owner_full[it["id"]] if it["kind"] == "OWNER" else item_state(it, m, ap, gh_out, vm_out, owner)
        rows.append({"id": it["id"], "kind": it["kind"], "state": st, "why": why, "title": it["title"], "sessions": it.get("sessions", "")})
    return m, ap, gh_out, vm_out, rows


def cmd_queue(a):
    m, ap, _, _, rows = compute_queue(with_remote=not getattr(a, "offline", False))
    print(f"C: {m['free_gb']} GB free, RAM {m['ram_avail_gib']} GiB; approvals.json: {'present' if ap else 'ABSENT'} at {APPROVALS}")
    for r in rows:
        print(f"{r['id']:<3} {r['kind']:<5} {r['state']:<14} {r['title'][:78]}\n      -> {r['why']}")
    ledger_append(LEDGER, "queue", {"rows": [(r["id"], r["state"]) for r in rows]})
    return 0


def _step_merge_if_green(repo, n, execute, tok):
    s_ = pr_snapshot(repo, n, tok)
    ok, why = merge_gate(s_)
    if not ok:
        return False, f"{repo}#{n} refused: {why}"
    if not execute:
        return True, f"DRY-RUN would squash-merge {repo}#{n} at head {s_['head_sha'][:12]} ({s_['checks_reason']})"
    st, r = gh("PUT", f"/repos/{ORG}/{repo}/pulls/{n}/merge", {"merge_method": "squash", "sha": s_["head_sha"]}, tok)
    if st != 200 or r.get("merged") is not True:
        return False, f"MERGE_NOT_ACCEPTED HTTP {st} {str(r.get('message', ''))[:120]} (no retry)"
    st2, p = gh("GET", f"/repos/{ORG}/{repo}/pulls/{n}", tok=tok)
    if st2 == 200 and p.get("merged_at") and p.get("merge_commit_sha") == r.get("sha"):
        return True, f"SUCCEEDED_WITH_READBACK merge {str(r.get('sha'))[:12]} at {p.get('merged_at')}"
    return False, f"UNCERTAIN: merge accepted (sha {str(r.get('sha'))[:12]}) but readback HTTP {st2} did not confirm; do not retry, inspect by hand"


def _step_update_branch(repo, n, execute, tok):
    s_ = pr_snapshot(repo, n, tok)
    if s_["state"] != "OPEN":
        return False, f"{repo}#{n} is {s_['state']}"
    if s_.get("mergeable_state") != "behind":
        return True, f"{repo}#{n} mergeable_state={s_.get('mergeable_state')} - not behind, no update needed"
    if not execute:
        return True, f"DRY-RUN would update-branch {repo}#{n} expected_head {s_['head_sha'][:12]}"
    st, r = gh("PUT", f"/repos/{ORG}/{repo}/pulls/{n}/update-branch", {"expected_head_sha": s_["head_sha"]}, tok)
    if st != 202:
        return False, f"UPDATE_NOT_ACCEPTED HTTP {st} {str(r.get('message', ''))[:120]}"
    return True, "ACCEPTED_PENDING (GitHub will create a merge commit; new checks must finish before the merge item)"


def _step_rerun_pinned(repo, item_id, pr, builtin_pin, execute, tok):
    if builtin_pin is not None:
        pin = builtin_pin
    else:
        req = next(i for i in ITEMS if i["id"] == item_id).get("pin", [])
        ok, why, pin = pin_gate(item_id, load_approvals(), req)
        if not ok:
            return False, why
    st, w = gh("GET", f"/repos/{ORG}/{repo}/actions/runs/{int(pin['run_id'])}", tok=tok)
    if st != 200:
        return False, f"run {pin['run_id']} HTTP {st} (UNKNOWN; nothing re-run)"
    ok, why = run_matches_pin(w, pin)
    if not ok:
        return False, why
    if pr is not None:
        s_ = pr_snapshot(repo, pr, tok)
        if s_.get("head_sha") != pin.get("head_sha"):
            return False, f"PR_HEAD_MOVED {repo}#{pr} head {str(s_.get('head_sha'))[:12]} != pin {str(pin.get('head_sha'))[:12]}"
    if not execute:
        return True, f"DRY-RUN would rerun-failed-jobs {repo} run {w['id']} ({w.get('name')}) attempt {w.get('run_attempt')} -> {int(w.get('run_attempt') or 1) + 1}"
    st, r = gh("POST", f"/repos/{ORG}/{repo}/actions/runs/{w['id']}/rerun-failed-jobs", {}, tok)
    if st != 201:
        return False, f"RERUN_NOT_ACCEPTED HTTP {st} {str(r.get('message', ''))[:100]}"
    time.sleep(3)
    st2, w2 = gh("GET", f"/repos/{ORG}/{repo}/actions/runs/{w['id']}", tok=tok)
    if st2 == 200 and int(w2.get("run_attempt") or 1) == int(pin["attempt"]) + 1:
        return True, f"ACCEPTED_PENDING run {w['id']} attempt {w2.get('run_attempt')} status={w2.get('status')} (terminal result not yet known)"
    return False, f"UNCERTAIN: POST accepted but readback HTTP {st2} attempt={w2.get('run_attempt') if isinstance(w2, dict) else None}; do not retry"


def _step_vm_stage_readiness(item_id, execute, tok):
    ok, why, pin = pin_gate(item_id, load_approvals(), ["commit"])
    if not ok:
        return False, why
    sha = str(pin["commit"])
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False, "PIN_COMMIT_INVALID (need a full 40-hex commit)"
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cmd = (f"set -eu; d=\"$HOME/szl_readiness_{stamp}\"; test ! -e \"$d\"; mkdir -p \"$d\"; cd \"$d\"; git init -q; "
           f"git fetch -q --depth 1 https://github.com/{ORG}/szl-estate-os {sha}; git checkout -q --detach FETCH_HEAD; "
           f"test \"$(git rev-parse HEAD)\" = {sha}; git rev-parse HEAD; ls -l ops/vm/readiness; sha256sum ops/vm/readiness/*")
    if not execute:
        return True, f"DRY-RUN would run on VM (no code from the bundle is executed): {cmd}"
    r, why2 = run_pinned_ssh(cmd, timeout=300)
    if r is None:
        return False, why2
    return r.returncode == 0, f"exit {r.returncode}\n{r.stdout[-3000:]}\n{r.stderr[-500:]}"


STEP_FNS = {"merge_if_green": _step_merge_if_green, "update_branch": _step_update_branch,
            "rerun_pinned": _step_rerun_pinned, "vm_stage_readiness": _step_vm_stage_readiness}


def cmd_run(a):
    ids = {i["id"]: i for i in ITEMS}
    item = ids.get(a.item)
    if item is None:
        print(f"UNKNOWN_ITEM {a.item}; known: {', '.join(ids)}"); return 2
    if item["kind"] == "READ":
        fn = {"preflight": cmd_preflight, "triage": cmd_triage, "github": cmd_github, "vm": cmd_vm}[item["fn"]]
        fn(a); return 0
    if item["kind"] == "OWNER":
        print(f"OWNER_ONLY {item['id']}: {item['title']}\nThis script cannot do it for you; `queue` re-checks its evidence."); return 1
    ok_l, why_l = lane_gate(item, load_approvals())
    if not ok_l:
        print(f"REFUSED {item['id']}: {why_l}"); ledger_append(LEDGER, "refused", {"item": item["id"], "why": why_l}); return 1
    m, ap, gh_out, vm_out, rows = compute_queue(with_remote=True)
    row = next(r for r in rows if r["id"] == item["id"])
    execute = bool(a.execute)
    if row["state"] != "READY" and execute:
        print(f"REFUSED {item['id']}: {row['why']}")
        ledger_append(LEDGER, "refused", {"item": item["id"], "why": row["why"],
                                          "approvals_sha256": _sha_file(APPROVALS)})
        return 1
    if row["state"] != "READY":
        print(f"(gates would refuse --execute: {row['why']}) showing dry-run anyway")
    if not execute:
        print("DRY-RUN: makes live read-only GitHub/SSH calls and appends local ledger entries; it writes nothing remote.")
    tok = _token()
    ap_sha0 = _sha_file(APPROVALS)
    all_ok = True
    for step in item["steps"]:
        fn = STEP_FNS[step[0]]
        if execute:  # gates must hold at the moment the step starts, not only at queue time
            m2, ap2 = measure(), load_approvals()
            ok_a, why_a = approval_gate(item["id"], ap2)
            ok_r, why_r = resource_gate(m2["free_gb"], m2["ram_avail_gib"], item["id"], (ap2 or {}).get("below_floor_waiver") or [])
            changed = _sha_file(APPROVALS) != ap_sha0
            if changed or not ok_a or not ok_r:
                why_m = "APPROVALS_CHANGED_MIDRUN" if changed else (why_a if not ok_a else why_r)
                print(f"REFUSED_MIDRUN {item['id']} before {step[0]}: {why_m}")
                ledger_append(LEDGER, "refused", {"item": item["id"], "step": step[0], "why": why_m})
                all_ok = False
                break
        try:
            ok, msg = fn(*step[1:], execute, tok)
        except Exception as e:
            ok, msg = False, f"STEP_ERROR {type(e).__name__}: {redact(e, [tok])}"
        msg = redact(msg, [tok])
        print(f"[{'ok' if ok else 'FAIL'}] {step[0]} {step[1:]} -> {msg}")
        ledger_append(LEDGER, "step", {"item": item["id"], "step": list(map(str, step)), "execute": execute,
                                       "ok": ok, "msg": msg[:2000], "approvals_sha256": _sha_file(APPROVALS)})
        if not ok:
            all_ok = False
            break  # fail closed: stop at the first failed step
    return 0 if all_ok else 1


def _sha_file(p):
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return None


def cmd_status(a):
    m, ap, gh_out, vm_out, rows = compute_queue(with_remote=True)
    lines = [f"# SZL recovery status {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}",
             f"tool szl_session_recovery {VERSION}; host {platform.node() or 'unknown'}; python {platform.python_version()}", "",
             f"## Resources (MEASURED)", f"C: free {m['free_gb']} GB of {m['total_gb']}; RAM available {m['ram_avail_gib']} GiB; "
             f"commit {m['commit_used_gib']}/{m['commit_limit_gib']} GiB; load {m['mem_load_pct']}%", "",
             "## VM1 (MEASURED)", f"{vm_out.get('verdict')}", "", "## PRs (MEASURED, live)",
             "| PR | state | mergeable | checks | cited by |", "|---|---|---|---|---|"]
    for x in gh_out["prs"]:
        lines.append(f"| {x['repo']}#{x['n']} | {x['state']}{' draft' if x.get('draft') else ''} | {x.get('mergeable_state')} | "
                     f"{x.get('checks_reason','')} | {x['cited_by']} |")
    lines += ["", "## Settings (MEASURED; names only)", "```", json.dumps(gh_out["settings"], indent=1), "```", "",
              "## Queue", "| id | kind | state | why | title |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['id']} | {r['kind']} | {r['state']} | {r['why']} | {r['title']} |")
    n_ready_w = sum(1 for r in rows if r["kind"] == "WRITE" and r["state"] == "READY")
    n_open_o = sum(1 for r in rows if r["kind"] == "OWNER" and r["state"] not in ("DONE", "ATTESTED"))  # PARTIAL counts as open
    ok_l, why_l = ledger_verify(LEDGER)
    if not ok_l:
        verdict = "LEDGER_BROKEN"
    elif n_open_o == 0:
        verdict = "OWNER_ITEMS_CLOSED_LEDGER_INTACT"
    else:
        verdict = f"OWNER_ITEMS_OPEN ({n_open_o})"
    lines += ["", f"Ledger: {why_l} (unsigned local hash chain)", f"Write items ready: {n_ready_w}", f"Verdict: {verdict}",
              "Scope of this verdict: owner-item evidence and local ledger integrity ONLY. It does not cover write completion, "
              "test outcomes, approval freshness or runtime health, and it is not an operational-readiness claim."]
    out = STATE_DIR / f"status_{_dt.datetime.now(_dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[-4:]))
    print(f"report: {out}")
    ledger_append(LEDGER, "status", {"report": str(out), "sha256": _sha_file(out), "verdict": verdict})
    return 0 if verdict == "OWNER_ITEMS_CLOSED_LEDGER_INTACT" else 1


def cmd_verify_ledger(_a):
    ok, why = ledger_verify(LEDGER)
    print(f"ledger {LEDGER}: {why}")
    return 0 if ok else 3


def cmd_approvals_template(_a):
    tpl = {"approved_by": "", "approved": [], "below_floor_waiver": [], "release_lane": [], "attest": {},
           "pins": {"W6": {"run_id": 0, "attempt": 1, "head_sha": ""}, "W7": {"run_id": 0, "attempt": 1, "head_sha": "", "workflow_path": ""},
                    "W8": {"commit": ""}},
           "_note": "Stephen edits this file by hand. The agent must never write it. approved_by is a name, not a signature."}
    print(json.dumps(tpl, indent=1))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest"); sub.add_parser("preflight"); sub.add_parser("github"); sub.add_parser("vm")
    sub.add_parser("status"); sub.add_parser("verify-ledger"); sub.add_parser("approvals-template")
    t = sub.add_parser("triage"); t.add_argument("--seconds", type=float, default=240)
    q = sub.add_parser("queue"); q.add_argument("--offline", action="store_true", help="skip GitHub and VM calls")
    r = sub.add_parser("run"); r.add_argument("item"); r.add_argument("--execute", action="store_true")
    r.add_argument("--seconds", type=float, default=240)
    a = ap.parse_args(argv)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if a.cmd not in ("selftest", "verify-ledger", "approvals-template"):
        ok, why = ledger_verify(LEDGER)
        if not ok:
            print(f"LEDGER_TAMPER {why}: refusing to continue. Inspect {LEDGER}."); return 3
    return {"selftest": cmd_selftest, "preflight": lambda x: (cmd_preflight(x), 0)[1], "triage": cmd_triage,
            "github": lambda x: (cmd_github(x), 0)[1], "vm": lambda x: (0 if cmd_vm(x).get("verdict") == "VM_KEY_LOGIN_OK" else 1),
            "queue": cmd_queue, "run": cmd_run, "status": cmd_status, "verify-ledger": cmd_verify_ledger,
            "approvals-template": cmd_approvals_template}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
