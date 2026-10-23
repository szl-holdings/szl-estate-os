#!/usr/bin/env python3
"""
SZL Holdings full-estate coordinator, payload 2.2.0 (2.1.0 + optional signed HEAD).

Safe default: read-only reconciliation and evidence collection.
It never pushes, merges, deploys, spends, deletes, changes credentials/security,
or starts GPU/VM work. The only files it writes are its own receipts, a chain
HEAD pointer and a short-lived lock, all inside <WORK_ROOT>/szl_execution_receipts.

Commands
  run     [--mode read-only|prepare]   collect evidence, append one chained receipt
  verify  [--pubkey FILE]              re-check every receipt offline; with --pubkey also
                                       require a valid DSSE Ed25519 signature over HEAD
  keygen  --out DIR                    create a new Ed25519 key pair (exclusive create)

Signing (optional): run --signing-key FILE (or SZL_SIGNING_KEY) signs HEAD.json into
HEAD.dsse.json. Once a chain is signed, an unsigned run is refused (no silent downgrade).

Exit codes
  0 PREPARED   every probe ran; open HOLD/PENDING/UNKNOWN items are listed, not resolved
  2 BLOCKED    at least one probe FAILED or was BLOCKED (receipt still written)
  3 HELD       a non-implemented mode was requested; nothing beyond the receipt ran
  4 REDACTION  a home/work path survived redaction; no receipt written
  5 SIGNING    key unreadable/invalid, or unsigned run on a signed chain; nothing written
  6 LOCKED     receipt chain lock not acquired; no receipt written (never stolen)
  1 VERIFY_FAIL  verify found a broken, tampered or orphaned receipt
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

COORDINATOR_ID = "01a13ef6-a9a1-7175-a711-8152b79100ed"
PAYLOAD_VERSION = "2.2.0"
PAYLOAD_TYPE = "application/vnd.szl.coordinator-head+json"
CHAIN_SCHEMA = "szl.coordinator.receipt-chain/v1"
EVIDENCE_KEEP = 4000          # characters of redacted evidence stored per step
LOCK_WAIT_S = float(os.environ.get("SZL_LOCK_WAIT_S", "15"))  # then give up; never steal
BLOCKING = {"FAIL", "BLOCKED"}
OPEN = {"HOLD", "PENDING", "UNKNOWN"}
EXIT = {"PREPARED": 0, "VERIFY_FAIL": 1, "BLOCKED": 2, "HELD": 3,
        "REDACTION": 4, "SIGNING": 5, "LOCKED": 6}


@dataclass
class Receipt:
    step: str
    status: str
    target: str
    command: str | None
    started_utc: str
    finished_utc: str
    exit_code: int | None
    evidence: str
    evidence_sha256: str
    limitations: list[str]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _path_regex(p: str) -> str:
    """Case-insensitive regex for a path, matching either separator style."""
    parts = [re.escape(x) for x in re.split(r"[\\/]+", p.rstrip("\\/")) if x]
    lead = r"[\\/]+" if p[:1] in "\\/" else ""
    return "(?i)" + lead + r"[\\/]+".join(parts)


# Generic home-directory shapes; anything matching after redaction trips the guard.
HOME_SHAPES = re.compile(r"(?i)([a-z]:[\\/]+users[\\/]+[^\\/<\s\"']+|/home/[^/<\s\"']+|/Users/[^/<\s\"']+)")


# ---- Ed25519 (RFC 8032 section 6 reference algorithm, stdlib only) ---------
# Pure Python and NOT constant-time: fine for a local operator key, not for a shared
# host where an attacker can time signing. Cross-checked against RFC vectors and OpenSSL.
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _padd(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pmul(k, pt):
    acc = (0, 1, 1, 0)
    while k > 0:
        if k & 1:
            acc = _padd(acc, pt)
        pt = _padd(pt, pt)
        k >>= 1
    return acc


def _peq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _xrec(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _xrec(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _compress(pt):
    zi = pow(pt[2], _P - 2, _P)
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _xrec(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _hq(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % _Q


def ed25519_public(seed: bytes) -> bytes:
    return _compress(_pmul(_expand(seed)[0], _G))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _compress(_pmul(a, _G))
    r = _hq(prefix + msg)
    R = _compress(_pmul(r, _G))
    s = (r + _hq(R + A + msg) * a) % _Q
    return R + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    A, R = _decompress(pub), _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:                      # reject malleable (non-canonical) signatures
        return False
    h = _hq(sig[:32] + pub + msg)
    return _peq(_pmul(s, _G), _padd(R, _pmul(h, A)))


def dsse_pae(ptype: str, body: bytes) -> bytes:
    t = ptype.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def keyid_of(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()


def load_hex32(path, what) -> bytes:
    raw = Path(path).read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", raw):
        raise ValueError(f"{what} must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def make_envelope(seed: bytes, head_bytes: bytes) -> bytes:
    pub = ed25519_public(seed)
    sig = ed25519_sign(seed, dsse_pae(PAYLOAD_TYPE, head_bytes))
    env = {"payloadType": PAYLOAD_TYPE,
           "payload": base64.b64encode(head_bytes).decode(),
           "signatures": [{"keyid": keyid_of(pub), "sig": base64.b64encode(sig).decode()}]}
    return (json.dumps(env, indent=2) + "\n").encode()


def verify_envelope(out: Path, pub: bytes) -> list[str]:
    envf, headf = out / "HEAD.dsse.json", out / "HEAD.json"
    if not envf.exists():
        return ["signature required but HEAD.dsse.json missing"]
    try:
        env = json.loads(envf.read_text(encoding="utf-8"))
        if env.get("payloadType") != PAYLOAD_TYPE:
            return [f"wrong payloadType {env.get('payloadType')!r}"]
        body = base64.b64decode(env["payload"], validate=True)
        if not headf.exists() or body != headf.read_bytes():
            return ["signed payload does not equal current HEAD.json (stale or swapped)"]
        sigs = env.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != 1:
            return ["exactly one signature required"]
        if sigs[0].get("keyid") != keyid_of(pub):
            return ["signature keyid is not bound to the supplied public key"]
        sig = base64.b64decode(sigs[0]["sig"], validate=True)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
        return [f"envelope unreadable: {e!r}"]
    if not ed25519_verify(pub, dsse_pae(PAYLOAD_TYPE, body), sig):
        return ["Ed25519 signature invalid"]
    return []


class Coordinator:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.out = self.root / "szl_execution_receipts"
        self.receipts: list[Receipt] = []
        self._repo_ok: bool | None = None
        subs = [(str(Path(sys.executable).resolve()), "<PYTHON>"), (sys.executable, "<PYTHON>"),
                (str(self.root), "<WORK_ROOT>"), (str(Path.home()), "<HOME>")]
        # longest first so the most specific token wins
        self._subs = [(re.compile(_path_regex(a)), b)
                      for a, b in sorted(subs, key=lambda t: -len(t[0])) if a]

    # ---- evidence -------------------------------------------------------
    def redact(self, s) -> str:
        s = str(s)
        for rx, tok in self._subs:
            s = rx.sub(tok, s)
        # Last pass: Path.home() can be a stand-in (sandboxes, services), so any
        # remaining user-profile prefix is generalised. The guard still backstops.
        return HOME_SHAPES.sub("<HOME>", s)

    def record(self, step, status, target, command=None, started=None,
               exit_code=None, evidence="", limitations=None):
        ev = self.redact(evidence)[-EVIDENCE_KEEP:]
        self.receipts.append(Receipt(
            step, status, self.redact(target),
            self.redact(command) if command else None,
            started or now(), now(), exit_code, ev, sha256_text(ev),
            list(limitations or [])))

    def probe(self, step, target, argv, timeout=30):
        started = now()
        cmd = " ".join(argv)
        try:
            p = subprocess.run(argv, cwd=str(self.root), text=True, capture_output=True,
                               timeout=timeout, check=False)
            self.record(step, "PASS" if p.returncode == 0 else "FAIL", target, cmd, started,
                        p.returncode, (p.stdout or "") + (p.stderr or ""),
                        ["Read-only probe; output may be incomplete."])
            return p
        except subprocess.TimeoutExpired as e:
            self.record(step, "BLOCKED", target, cmd, started, None, repr(e),
                        ["DEVICE_UNREACHABLE or tool timeout; do not duplicate-retry."])
        except Exception as e:  # FileNotFoundError when the tool is absent, etc.
            self.record(step, "BLOCKED", target, cmd, started, None, repr(e),
                        ["Probe failed; preserve UNKNOWN status."])
        return None

    # ---- steps ----------------------------------------------------------
    def verify_repo_root(self) -> bool:
        """Run once; PASS only when git's top level IS the work root (not a subdirectory)."""
        if self._repo_ok is not None:
            return self._repo_ok
        started = now()
        argv = ["git", "rev-parse", "--show-toplevel"]
        try:
            p = subprocess.run(argv, cwd=str(self.root), text=True, capture_output=True,
                               timeout=20, check=False)
        except Exception as e:
            self.record("repo_root", "BLOCKED", str(self.root), " ".join(argv), started,
                        None, repr(e), ["git unavailable; repo root UNKNOWN."])
            self._repo_ok = False
            return False
        top = p.stdout.strip()
        if p.returncode != 0:
            self.record("repo_root", "HOLD", str(self.root), " ".join(argv), started,
                        p.returncode, p.stderr, ["Not a verified Git repository root."])
            self._repo_ok = False
        elif os.path.normcase(os.path.realpath(top)) != os.path.normcase(str(self.root)):
            self.record("repo_root", "HOLD", top, " ".join(argv), started, p.returncode,
                        f"toplevel={top} work_root={self.root}",
                        ["Work root is inside a repository but is not its root."])
            self._repo_ok = False
        else:
            self.record("repo_root", "PASS", top, " ".join(argv), started, 0, p.stdout)
            self._repo_ok = True
        return self._repo_ok

    def immutable_preflight(self):
        self.record("payload_identity", "PASS", "local payload",
                    evidence=f"version={PAYLOAD_VERSION} sha256={_self_sha256()}")
        self.probe("python_identity", "local interpreter", [sys.executable, "--version"])
        self.record("workspace_identity", "PASS", "local workspace",
                    evidence=f"platform={platform.platform()} python={sys.executable}")
        for tool in ("git", "gh", "node", "hf", "ollama", "docker", "wrangler", "cloudflared"):
            found = shutil.which(tool)
            self.record("capability_" + tool, "PASS" if found else "TOOL_NOT_AVAILABLE",
                        tool, evidence=str(found))
        self.verify_repo_root()
        self.record("cleanup_coordinator", "PENDING", COORDINATOR_ID,
                    evidence="Reconcile existing coordinator; never create a competing writer.")
        self.record("ownership_reconciliation", "PENDING", "pinned and recent SZL sessions",
                    evidence="Require current owner, lease, target, revision, and disjointness.")
        self.record("pending_approvals", "PENDING", "all accessible SZL work",
                    evidence="Broad green-light language is not action-specific approval.")
        self.record("active_jobs", "PENDING", "VM, desktop, cloud, and CI jobs",
                    evidence="Do not stop or restart jobs during this audit.")

    def safe_git_snapshot(self):
        if self.verify_repo_root():
            self.probe("git_status", "verified repo root", ["git", "status", "--short", "--branch"])
            self.probe("git_head", "verified repo root", ["git", "rev-parse", "HEAD"])

    def emit_known_holds(self):
        self.record("betterwithage_capacity", "UNKNOWN", "BETTERWITHAGE C:",
                    evidence=("Last measured 2026-10-18T01:07:24.947Z: "
                              "free=20130078720 total=1021821579264 bytes. "
                              "Refresh only when the device is genuinely reachable."),
                    limitations=["Historical observation; not current capacity."])
        self.record("vm_runtime_gate", "HOLD", "Massed Compute VM",
                    evidence=("64.247.206.118:300/agent is ThinLinc, not a governed API; "
                              "VM :8080 is raw llama-server. Require authorized SSH or a "
                              "governed service target, authenticated runtime evidence, "
                              "and independent readback."))
        self.record("cloudflare_ingress", "HOLD", "Cloudflare GPU routes",
                    evidence=("gpu/gpu2 routes were previously observed targeting laptop "
                              "tunnels. Do not repoint shared routes without exact approval."))
        self.record("training_claims", "UNKNOWN", "GPU/VM training",
                    evidence="No training claim until host, model revision, process owner, and receipt are read back.")

    # ---- terminal state -------------------------------------------------
    def terminal_state(self, mode: str) -> str:
        if mode != "read-only":
            return "HELD"
        if any(r.status in BLOCKING for r in self.receipts):
            return "BLOCKED"
        return "PREPARED"

    # ---- receipt chain --------------------------------------------------
    def build_doc(self, mode: str, state: str) -> dict:
        counts: dict[str, int] = {}
        for r in self.receipts:
            counts[r.status] = counts.get(r.status, 0) + 1
        return {
            "payload_version": PAYLOAD_VERSION,
            "chain_schema": CHAIN_SCHEMA,
            "mode": "READ_ONLY",
            "requested_mode": mode,
            "coordinator_id": COORDINATOR_ID,
            "root_redacted": "<WORK_ROOT>",
            "written_utc": now(),
            "receipts": [asdict(r) for r in self.receipts],
            "status_counts": dict(sorted(counts.items())),
            "blocking_steps": [r.step for r in self.receipts if r.status in BLOCKING],
            "open_steps": [r.step for r in self.receipts if r.status in OPEN],
            "terminal_state": state,
            "exit_code": EXIT[state],
            "mutations": [],
            "limitations": [
                "No push, merge, deployment, payment, credential, security, delete, or process action performed.",
                "PREPARED means every probe ran; it does not mean any HOLD/PENDING/UNKNOWN item is resolved.",
                "Signing, when used, covers HEAD.json, which pins the newest receipt and through it the chain.",
            ],
        }


def _self_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return "UNKNOWN"


def redaction_leaks(doc) -> list[str]:
    """Return every string value that still looks like a home directory path."""
    hits: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif isinstance(x, str) and HOME_SHAPES.search(x):
            hits.append(HOME_SHAPES.search(x).group(0))
    walk(doc)
    return hits


class ChainLock:
    def __init__(self, out: Path):
        self.path = out / ".chain.lock"
        self.fd = None

    def __enter__(self):
        deadline = time.monotonic() + LOCK_WAIT_S
        while True:
            try:
                self.fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, f"pid={os.getpid()} utc={now()}".encode())
                return self
            except FileExistsError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"chain lock held: {self.path.name}")
                time.sleep(0.05 + secrets.randbelow(50) / 1000)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
            try:
                os.remove(str(self.path))
            except OSError:
                pass


def _read_head(out: Path):
    h = out / "HEAD.json"
    if not h.exists():
        return None
    return json.loads(h.read_text(encoding="utf-8"))


def _walk_chain(out: Path):
    """Yield (name, expected_sha256) from HEAD back to genesis; raises on a broken link."""
    head = _read_head(out)
    link = None if head is None else {"name": head["receipt"], "sha256": head["sha256"]}
    seen = set()
    while link:
        if link["name"] in seen:
            raise ValueError(f"chain cycle at {link['name']}")
        seen.add(link["name"])
        yield link
        doc = json.loads((out / link["name"]).read_bytes().decode("utf-8"))
        link = doc.get("previous_receipt")


def append_receipt(out: Path, doc: dict, seed: bytes | None = None) -> tuple[str, str]:
    """Exclusive-create one receipt, chained to the current HEAD, under a lock."""
    out.mkdir(parents=True, exist_ok=True)
    with ChainLock(out):
        on_chain, adopted_before = set(), set()
        prev = None
        for i, link in enumerate(_walk_chain(out)):
            if i == 0:
                prev = link
            on_chain.add(link["name"])
            d = json.loads((out / link["name"]).read_bytes().decode("utf-8"))
            adopted_before.update(a["name"] for a in d.get("adopted_unchained", []))
        unchained = sorted(f.name for f in out.glob("receipt_*.json")
                           if f.name not in on_chain and f.name not in adopted_before)
        doc["previous_receipt"] = prev
        doc["adopted_unchained"] = [
            {"name": n, "sha256": hashlib.sha256((out / n).read_bytes()).hexdigest()}
            for n in unchained]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"receipt_{stamp}_{os.getpid()}_{secrets.token_hex(3)}.json"
        data = (json.dumps(doc, indent=2, sort_keys=False) + "\n").encode("utf-8")
        with open(out / name, "xb") as f:        # exclusive create: never overwrite
            f.write(data)
        digest = hashlib.sha256(data).hexdigest()
        head_bytes = (json.dumps({"receipt": name, "sha256": digest}) + "\n").encode()
        tag = f"{os.getpid()}.{secrets.token_hex(3)}"
        tmp = out / f".HEAD.{tag}.tmp"
        tmp.write_bytes(head_bytes)
        etmp = None
        if seed is not None:
            etmp = out / f".HEAD.dsse.{tag}.tmp"
            etmp.write_bytes(make_envelope(seed, head_bytes))
        os.replace(tmp, out / "HEAD.json")
        if etmp is not None:   # a crash between the two replaces leaves a stale envelope -> verify fails
            os.replace(etmp, out / "HEAD.dsse.json")
    return name, digest


def verify_chain(out: Path, pub: bytes | None = None) -> dict:
    problems: list[str] = []
    checked, adopted = [], {}
    try:
        for link in _walk_chain(out):
            f = out / link["name"]
            if not f.exists():
                problems.append(f"missing receipt {link['name']}")
                break
            raw = f.read_bytes()
            if hashlib.sha256(raw).hexdigest() != link["sha256"]:
                problems.append(f"sha256 mismatch {link['name']}")
            doc = json.loads(raw.decode("utf-8"))
            for r in doc.get("receipts", []):
                if sha256_text(r.get("evidence", "")) != r.get("evidence_sha256"):
                    problems.append(f"evidence hash mismatch {link['name']}:{r.get('step')}")
            for a in doc.get("adopted_unchained", []):
                if a["name"] in adopted:
                    problems.append(f"receipt adopted more than once {a['name']}")
                adopted[a["name"]] = a["sha256"]
            checked.append(link["name"])
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as e:
        problems.append(f"chain unreadable: {e!r}")
    for n, h in adopted.items():
        f = out / n
        if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != h:
            problems.append(f"adopted receipt changed or missing {n}")
    present = {f.name for f in out.glob("receipt_*.json")} if out.exists() else set()
    orphans = sorted(present - set(checked) - set(adopted))
    problems += [f"orphan receipt not on chain {n}" for n in orphans]
    if not checked and not present:
        problems.append("no receipts found")
    if pub is not None:
        sig_problems = verify_envelope(out, pub)
        problems += sig_problems
        signature = "INVALID" if sig_problems else "VALID"
    else:
        signature = "NOT_CHECKED" + (" (HEAD.dsse.json present; pass --pubkey)"
                                     if (out / "HEAD.dsse.json").exists() else "")
    return {"verified": not problems, "chain_length": len(checked),
            "adopted_unchained": len(adopted), "signature": signature, "problems": problems}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SZL read-only coordinator")
    ap.add_argument("command", nargs="?", default="run", choices=("run", "verify", "keygen"))
    ap.add_argument("--mode", choices=("read-only", "prepare"), default="read-only")
    ap.add_argument("--signing-key", default=os.environ.get("SZL_SIGNING_KEY"))
    ap.add_argument("--pubkey")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    root = Path(os.environ.get("SZL_WORK_ROOT", Path.cwd()))
    c = Coordinator(root)

    if args.command == "keygen":
        if not args.out:
            print(json.dumps({"state": "SIGNING", "detail": "keygen needs --out DIR"}))
            return EXIT["SIGNING"]
        d = Path(args.out)
        d.mkdir(parents=True, exist_ok=True)
        seed = secrets.token_bytes(32)
        pub = ed25519_public(seed)
        try:
            with open(d / "szl_coordinator_ed25519.key", "x", encoding="ascii", newline="\n") as f:
                f.write(seed.hex() + "\n")
            with open(d / "szl_coordinator_ed25519.pub", "x", encoding="ascii", newline="\n") as f:
                f.write(pub.hex() + "\n")
        except FileExistsError:
            print(json.dumps({"state": "SIGNING", "detail": "key files exist; never overwritten"}))
            return EXIT["SIGNING"]
        print(json.dumps({"keyid": keyid_of(pub), "public_key_hex": pub.hex(),
                          "note": "Keep the .key file private and outside any repository."}))
        return 0

    if args.command == "verify":
        try:
            pub = load_hex32(args.pubkey, "public key") if args.pubkey else None
        except (OSError, ValueError) as e:
            print(json.dumps({"verified": False, "problems": [f"public key unreadable: {e}"]}))
            return EXIT["VERIFY_FAIL"]
        res = verify_chain(c.out, pub)
        print(json.dumps(res, indent=2))
        return 0 if res["verified"] else EXIT["VERIFY_FAIL"]

    seed = None
    if args.signing_key:
        try:
            seed = load_hex32(args.signing_key, "signing key")
        except (OSError, ValueError) as e:
            print(json.dumps({"state": "SIGNING", "detail": f"signing key unusable: {e}",
                              "note": "Nothing written."}))
            return EXIT["SIGNING"]
    elif (c.out / "HEAD.dsse.json").exists():
        print(json.dumps({"state": "SIGNING", "detail": "chain is signed; an unsigned run would "
                          "silently downgrade it. Pass --signing-key.", "note": "Nothing written."}))
        return EXIT["SIGNING"]

    if args.mode != "read-only":
        c.record("mode_gate", "HOLD", args.mode,
                 evidence="Only read-only mode is implemented in this payload.",
                 limitations=["Explicit action-time approval and a separate writer are required."])
    else:
        c.immutable_preflight()
        c.safe_git_snapshot()
        c.emit_known_holds()

    state = c.terminal_state(args.mode)
    doc = c.build_doc(args.mode, state)
    leaks = redaction_leaks(doc)
    if leaks:
        print(json.dumps({"state": "REDACTION", "leak_count": len(leaks),
                          "note": "No receipt written; fix redaction first."}))
        return EXIT["REDACTION"]
    try:
        name, digest = append_receipt(c.out, doc, seed)
    except TimeoutError as e:
        print(json.dumps({"state": "LOCKED", "detail": str(e),
                          "note": "Another writer holds the lock; it is never stolen."}))
        return EXIT["LOCKED"]
    print(json.dumps({"receipt": f"<WORK_ROOT>/szl_execution_receipts/{name}",
                      "sha256": digest, "steps": len(c.receipts), "state": state,
                      "blocking": doc["blocking_steps"], "open": len(doc["open_steps"]),
                      "signed": seed is not None},
                     indent=2))
    return EXIT[state]


if __name__ == "__main__":
    sys.exit(main())

# Claude Code operating contract (unchanged from 2.0.0):
# 1. Run this from the verified repo root with the exact interpreter.
# 2. Reconcile pinned sessions, then recent sessions, one ledger row per target.
# 3. Preserve active writers, leases, worktrees, models, datasets, logs, evidence,
#    credentials, uncommitted work, and unknown files.
# 4. Use disposable worktrees for any later patch preparation. Never reset or
#    overwrite another writer.
# 5. Require exact action-time approval bound to target, revision, path, scope,
#    expiry, rollback, and post-action readback before push/merge/deploy/delete/
#    spend/credentials/security/legal actions.
# 6. Stop on HTTP 403 or 429; record reset guidance.
# 7. READY_FOR_REVIEW, RELEASE_APPROVED, and DEPLOYED are distinct states.
# 8. Never claim production readiness from HTTP 200, a local test, or a generated
#    artifact without source/runtime parity and independent readback.
