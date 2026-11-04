#!/usr/bin/env python3
"""
szl_lane_lease.py - fail-closed lane leases for SZL ownership reconciliation.

Stdlib only, one file. A lease says: session S owns paths P of repo R, based on
commit B, until time T. The coordinator's ownership_reconciliation step can ask
check() for a PASS/BLOCKED verdict instead of recording a hardcoded PENDING.

Storage rules (append-only):
  * A lease is one JSON file  lease_<UTC>_<lane>_<hex8>.json  (schema szl.lane-lease/v1),
    created with open(..., "xb") from LF-only UTF-8 bytes. It is never rewritten.
  * A release is a SEPARATE file  release_<UTC>_<sha12>_<hex8>.json
    (schema szl.lane-lease-release/v1) that names the lease file and its sha256.
    Nothing is ever deleted. Editing a lease changes its sha256, which orphans its
    release and blocks every check in the directory (tamper-evident, fail closed).

Base sha (1.1.0, gap F11): check(..., git_dir=D) reads the current base from git:
`git -C D rev-parse --verify <lease base_branch>^{commit}`, only when D is the
repository top level, with every GIT_* variable removed from git's environment.
  * base sha not supplied: the git value is used; if git cannot be read -> BASE_UNREADABLE.
  * supplied and git readable: they must be equal, else STALE_BASE.
  * supplied and git unreadable (or no git_dir): the supplied value is used and the
    verdict says base_sha_source=SUPPLIED_UNVERIFIED (caller-asserted).

Acquire lock (1.1.0, gap F12): acquire() first exclusive-creates acquire.lock
(O_CREAT|O_EXCL) in the leases directory and holds it across scan + overlap test +
write. If the lock exists, acquire returns BLOCKED / LEASE_LOCK_HELD. A lock is
removed only by the acquire that created it (byte-compared first); a stale lock is
NEVER auto-removed: an operator inspects and deletes it. check() and list() do not
take the lock; list() reports whether it is held.

Verdicts: PASS only if every rule holds; otherwise BLOCKED with every reason code
found (see REASONS). Any unreadable, malformed, unrecognised, future-dated or
over-TTL file in the leases directory blocks every check: it is never ignored.

Path rules: repo-relative POSIX paths; a directory prefix ends with "/".
Segments are restricted to ASCII [A-Za-z0-9._@+-], must not be "." or "..",
must not end in "." (Windows strips trailing dots) and must not be a DOS device
name. "~" is excluded (8.3 short-name aliases). Comparison is case-insensitive
because Windows checkouts are; the ASCII restriction makes lower() exact.

CLI (exit 0 PASS / 2 BLOCKED / 1 usage error; JSON on stdout, no local paths):
  acquire --leases-dir D --lane L --owner S --repo O/N --base-branch B --base-sha SHA
          --path P [--path P ...] --ttl-hours H --purpose TEXT
  release --leases-dir D --lease-file NAME --by S --reason TEXT
  check   --leases-dir D --repo O/N --path P [...] --claimant S
          [--base-sha SHA] [--git-dir REPO_ROOT]     (at least one of the two)
  list    --leases-dir D
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

VERSION = "1.1.0"
LEASE_SCHEMA = "szl.lane-lease/v1"
RELEASE_SCHEMA = "szl.lane-lease-release/v1"
VERDICT_SCHEMA = "szl.lane-lease-verdict/v1"
LOCK_SCHEMA = "szl.lane-lease-lock/v1"
LOCK_NAME = "acquire.lock"
GIT_TIMEOUT_S = 20
MAX_TTL = timedelta(hours=24)
MAX_SKEW = timedelta(minutes=5)
MAX_FILE_BYTES = 64 * 1024
MAX_PATHS = 256

LEASE_KEYS = frozenset({"schema", "lane", "owner_session", "repo", "base_branch",
                        "base_sha", "paths", "acquired_utc", "expires_utc", "purpose"})
RELEASE_KEYS = frozenset({"schema", "lease_file", "lease_sha256", "released_by",
                          "released_utc", "reason"})

REASONS = {
    "BAD_REQUEST": "check() arguments are invalid",
    "LEASES_DIR_UNREADABLE": "leases directory missing or unreadable",
    "UNRECOGNIZED_ENTRY": "a directory entry is not a lease or release file",
    "UNREADABLE_FILE": "a lease/release file could not be read",
    "MALFORMED_LEASE": "a lease file violates szl.lane-lease/v1",
    "MALFORMED_RELEASE": "a release file violates szl.lane-lease-release/v1",
    "TTL_EXCEEDED": "a lease is longer than 24 h",
    "FUTURE_DATED": "a record is dated more than 5 min in the future",
    "DUPLICATE_LEASE": "two lease files have identical bytes",
    "ORPHAN_RELEASE": "a release names no lease with that file name and sha256",
    "RELEASE_NOT_BY_OWNER": "a release was not issued by the lease owner",
    "DUPLICATE_RELEASE": "a lease has more than one release record",
    "NO_COVERING_LEASE": "no active lease owned by the claimant covers every path",
    "LEASE_EXPIRED": "the claimant's covering lease has expired",
    "LEASE_RELEASED": "the claimant's covering lease was released",
    "AMBIGUOUS_LEASE": "more than one active claimant lease covers every path",
    "STALE_BASE": "the lease base_sha differs from the current base sha",
    "OVERLAP": "another active lease on the repo overlaps a requested path",
    "BASE_UNREADABLE": "no base sha supplied and git could not read the base branch",
    "LEASE_LOCK_HELD": "acquire.lock exists; another acquire is running or a stale lock awaits an operator",
}

SHA1_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
LANE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SEG_RE = re.compile(r"[A-Za-z0-9._@+-]{1,255}")
DOS_DEVICES = frozenset({"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                         *(f"lpt{i}" for i in range(1, 10))})
LEASE_NAME_RE = re.compile(r"lease_\d{8}T\d{6}Z_[a-z0-9._-]{1,64}_[0-9a-f]{8}\.json")
RELEASE_NAME_RE = re.compile(r"release_\d{8}T\d{6}Z_[0-9a-f]{12}_[0-9a-f]{8}\.json")
LOCAL_PATH_SHAPES = re.compile(r"(?i)([a-z]:[\\/]|[\\/]users[\\/]|/home/|\\\\)")


class LeaseError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- primitives
def utc_text(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s) -> datetime:
    if not isinstance(s, str) or not TS_RE.fullmatch(s):
        raise LeaseError("BAD_TIMESTAMP", "timestamps must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise LeaseError("BAD_TIMESTAMP", "timestamp is not a real UTC time") from None


def _aware(now) -> bool:
    return isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None


def norm(p: str) -> str:
    return p.lower()


def validate_path(p) -> str:
    if not isinstance(p, str) or not p or len(p) > 1024:
        raise LeaseError("BAD_PATH", "path must be a non-empty string")
    if p.startswith("/"):
        raise LeaseError("BAD_PATH", "path must be repo-relative")
    body = p[:-1] if p.endswith("/") else p
    for seg in body.split("/"):
        if not SEG_RE.fullmatch(seg):
            raise LeaseError("BAD_PATH", "segment empty or has a disallowed character")
        if seg in (".", ".."):
            raise LeaseError("BAD_PATH", "dot segments are not allowed")
        if seg.endswith("."):
            raise LeaseError("BAD_PATH", "segment ends with '.' (Windows alias)")
        if seg.split(".")[0].lower() in DOS_DEVICES:
            raise LeaseError("BAD_PATH", "DOS device name")
    return p


def validate_paths(paths) -> list:
    if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS:
        raise LeaseError("BAD_PATH", "paths must be a non-empty list")
    seen = set()
    for p in paths:
        validate_path(p)
        if norm(p) in seen:
            raise LeaseError("BAD_PATH", "duplicate path (case-insensitive)")
        seen.add(norm(p))
    return paths


def covers(lease_path: str, req: str) -> bool:
    """Lease path covers a requested path (file or dir prefix)."""
    a, b = norm(lease_path), norm(req)
    if a.endswith("/"):
        return b.startswith(a)
    return a == b


def overlaps(x: str, y: str) -> bool:
    a, b = norm(x), norm(y)
    if a == b:
        return True
    if a.endswith("/") and b.startswith(a):
        return True
    if b.endswith("/") and a.startswith(b):
        return True
    return False


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise LeaseError("BAD_JSON", "duplicate key")
        d[k] = v
    return d


def _no_constants(c):
    raise LeaseError("BAD_JSON", "NaN/Infinity not allowed")


def loads_strict(raw: bytes) -> dict:
    if len(raw) > MAX_FILE_BYTES:
        raise LeaseError("BAD_JSON", "file too large")
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:
        raise LeaseError("BAD_JSON", "BOM or CR byte present (LF-only UTF-8 required)")
    try:
        text = raw.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constants)
    except LeaseError:
        raise
    except (UnicodeDecodeError, ValueError):
        raise LeaseError("BAD_JSON", "not valid UTF-8 JSON") from None
    if not isinstance(doc, dict):
        raise LeaseError("BAD_JSON", "top level must be an object")
    return doc


def _text(doc, key, rx=None, maxlen=500):
    v = doc.get(key)
    if not isinstance(v, str) or not v or len(v) > maxlen:
        raise LeaseError("BAD_FIELD", f"{key} must be a non-empty string")
    if rx is not None and not rx.fullmatch(v):
        raise LeaseError("BAD_FIELD", f"{key} has an invalid format")
    return v


def validate_lease(doc: dict) -> dict:
    if set(doc) != LEASE_KEYS:
        raise LeaseError("BAD_FIELD", "lease keys must be exactly the v1 set")
    if doc["schema"] != LEASE_SCHEMA:
        raise LeaseError("BAD_FIELD", "wrong schema")
    _text(doc, "lane", LANE_RE)
    _text(doc, "owner_session", SESSION_RE)
    _text(doc, "repo", REPO_RE)
    _text(doc, "base_branch", BRANCH_RE)
    if ".." in doc["base_branch"]:
        raise LeaseError("BAD_FIELD", "base_branch has '..'")
    _text(doc, "base_sha", SHA1_RE)
    _text(doc, "purpose")
    if LOCAL_PATH_SHAPES.search(doc["purpose"]):
        raise LeaseError("BAD_FIELD", "purpose contains a local path")
    try:
        validate_paths(doc["paths"])
    except LeaseError as e:
        raise LeaseError("BAD_FIELD", "paths: " + e.detail) from None
    a, x = parse_ts(doc["acquired_utc"]), parse_ts(doc["expires_utc"])
    if x <= a:
        raise LeaseError("BAD_FIELD", "expires_utc must be after acquired_utc")
    return doc


def validate_release(doc: dict) -> dict:
    if set(doc) != RELEASE_KEYS:
        raise LeaseError("BAD_FIELD", "release keys must be exactly the v1 set")
    if doc["schema"] != RELEASE_SCHEMA:
        raise LeaseError("BAD_FIELD", "wrong schema")
    _text(doc, "lease_file", LEASE_NAME_RE)
    _text(doc, "lease_sha256", SHA256_RE)
    _text(doc, "released_by", SESSION_RE)
    _text(doc, "reason")
    if LOCAL_PATH_SHAPES.search(doc["reason"]):
        raise LeaseError("BAD_FIELD", "reason contains a local path")
    parse_ts(doc["released_utc"])
    return doc


def canonical_bytes(doc: dict) -> bytes:
    data = (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    assert b"\r" not in data
    return data


def write_exclusive(path: str, data: bytes) -> None:
    if b"\r" in data:
        raise LeaseError("BAD_JSON", "refusing to write CR bytes")
    with open(path, "xb") as f:          # exclusive create: never overwrite
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------- git base (F11)
def _git_exe():
    return shutil.which("git")


def _git_env() -> dict:
    e = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    e.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    return e


def _run_git(git_dir: str, *args):
    exe = _git_exe()
    if not exe:
        raise LeaseError("BASE_UNREADABLE", "git not found")
    try:
        p = subprocess.run([exe, "-C", git_dir, *args], capture_output=True, text=True,
                           timeout=GIT_TIMEOUT_S, env=_git_env(), check=False)
    except (OSError, subprocess.SubprocessError) as e:
        raise LeaseError("BASE_UNREADABLE", "git did not run: " + type(e).__name__) from None
    return p.returncode, p.stdout


def read_base_sha(git_dir, base_branch) -> str:
    """Return the 40-hex commit of base_branch in git_dir (the repo top level), or raise
    LeaseError(BASE_UNREADABLE). Read-only: rev-parse only, optional locks off."""
    if not isinstance(git_dir, str) or not git_dir or not os.path.isdir(git_dir):
        raise LeaseError("BASE_UNREADABLE", "git_dir is not a directory")
    if (not isinstance(base_branch, str) or not BRANCH_RE.fullmatch(base_branch)
            or ".." in base_branch):
        raise LeaseError("BASE_UNREADABLE", "base_branch invalid")
    rc, out = _run_git(git_dir, "rev-parse", "--show-toplevel")
    top = out.strip()
    try:
        same = rc == 0 and bool(top) and os.path.samefile(top, git_dir)
    except OSError:
        same = False
    if not same:
        raise LeaseError("BASE_UNREADABLE", "git_dir is not a repository top level")
    rc, out = _run_git(git_dir, "rev-parse", "--verify", "--quiet", base_branch + "^{commit}")
    sha = out.strip()
    if rc != 0 or not SHA1_RE.fullmatch(sha):
        raise LeaseError("BASE_UNREADABLE", f"rev-parse of base branch failed (rc={rc})")
    return sha


# ---------------------------------------------------------------- directory scan
def scan(leases_dir: str, now: datetime):
    """Return (leases, releases_by_sha, problems). problems are global blockers."""
    leases, releases, problems = [], {}, []

    def bad(code, name, detail):
        problems.append({"code": code, "file": name, "detail": detail})

    try:
        entries = sorted(os.scandir(leases_dir), key=lambda e: e.name)
    except OSError as e:
        bad("LEASES_DIR_UNREADABLE", None, type(e).__name__)
        return leases, releases, problems
    raw_releases = []
    for ent in entries:
        name = ent.name
        if name == LOCK_NAME:            # acquire lock: not a record (see acquire)
            continue
        try:
            is_file = ent.is_file(follow_symlinks=False)
        except OSError:
            is_file = False
        if LEASE_NAME_RE.fullmatch(name):
            kind = "lease"
        elif RELEASE_NAME_RE.fullmatch(name):
            kind = "release"
        else:
            bad("UNRECOGNIZED_ENTRY", name, "not a lease/release file name")
            continue
        if not is_file:
            bad("UNRECOGNIZED_ENTRY", name, "not a regular file")
            continue
        try:
            with open(ent.path, "rb") as f:
                raw = f.read(MAX_FILE_BYTES + 1)
        except OSError as e:
            bad("UNREADABLE_FILE", name, type(e).__name__)
            continue
        sha = hashlib.sha256(raw).hexdigest()
        if kind == "lease":
            try:
                doc = validate_lease(loads_strict(raw))
            except LeaseError as e:
                bad("MALFORMED_LEASE", name, e.detail)
                continue
            acq, exp = parse_ts(doc["acquired_utc"]), parse_ts(doc["expires_utc"])
            if exp - acq > MAX_TTL:
                bad("TTL_EXCEEDED", name, "lease longer than 24 h")
                continue
            if acq > now + MAX_SKEW:
                bad("FUTURE_DATED", name, "acquired_utc beyond 5 min clock skew")
                continue
            leases.append({"file": name, "sha256": sha, "doc": doc,
                           "acquired": acq, "expires": exp})
        else:
            try:
                doc = validate_release(loads_strict(raw))
            except LeaseError as e:
                bad("MALFORMED_RELEASE", name, e.detail)
                continue
            raw_releases.append((name, doc))
    by_sha = {}
    for l in leases:
        if l["sha256"] in by_sha:
            bad("DUPLICATE_LEASE", l["file"], "identical bytes to " + by_sha[l["sha256"]]["file"])
        by_sha[l["sha256"]] = l
    for name, doc in raw_releases:
        target = by_sha.get(doc["lease_sha256"])
        if target is None or target["file"] != doc["lease_file"]:
            bad("ORPHAN_RELEASE", name, "no lease with that file name and sha256")
            continue
        if doc["released_by"] != target["doc"]["owner_session"]:
            bad("RELEASE_NOT_BY_OWNER", name, "released_by differs from owner_session")
            continue
        rel = parse_ts(doc["released_utc"])
        if rel > now + MAX_SKEW:
            bad("FUTURE_DATED", name, "released_utc beyond 5 min clock skew")
            continue
        if rel < target["acquired"]:
            bad("MALFORMED_RELEASE", name, "released before acquired")
            continue
        if doc["lease_sha256"] in releases:
            bad("DUPLICATE_RELEASE", name, "lease already released")
            continue
        releases[doc["lease_sha256"]] = name
    return leases, releases, problems


def _active(leases, releases, now):
    return [l for l in leases
            if l["sha256"] not in releases
            and now < l["expires"]]


# ---------------------------------------------------------------- verdict
def check(leases_dir, repo, paths, claimant_session, current_base_sha, now, *,
          git_dir=None) -> dict:
    reasons: list[dict] = []
    supplied = current_base_sha
    if supplied == "":
        supplied = None
    req_ok = True
    for ok, detail in (
            (_aware(now), "now must be a timezone-aware datetime"),
            (isinstance(repo, str) and bool(REPO_RE.fullmatch(repo)), "repo must be owner/name"),
            (isinstance(claimant_session, str) and bool(SESSION_RE.fullmatch(claimant_session)),
             "claimant_session invalid"),
            ((supplied is None and git_dir is not None)
             or (isinstance(supplied, str) and bool(SHA1_RE.fullmatch(supplied))),
             "current_base_sha must be 40 lowercase hex (or None with git_dir)")):
        if not ok:
            reasons.append({"code": "BAD_REQUEST", "file": None, "detail": detail})
            req_ok = False
    try:
        validate_paths(list(paths) if isinstance(paths, (list, tuple)) else paths)
    except LeaseError as e:
        reasons.append({"code": "BAD_REQUEST", "file": None, "detail": "paths: " + e.detail})
        req_ok = False
    selected = None
    scanned = 0
    base_source, effective = None, None
    if req_ok:
        paths = list(paths)
        now = now.astimezone(timezone.utc)
        leases, releases, problems = scan(leases_dir, now)
        scanned = len(leases) + len(releases) + len(problems)
        reasons += problems
        same_repo = [l for l in leases if l["doc"]["repo"].lower() == repo.lower()]
        active = _active(same_repo, releases, now)
        mine = [l for l in active if l["doc"]["owner_session"] == claimant_session]
        covering = [l for l in mine if all(any(covers(lp, p) for lp in l["doc"]["paths"])
                                           for p in paths)]
        if not covering:
            reasons.append({"code": "NO_COVERING_LEASE", "file": None, "detail": REASONS["NO_COVERING_LEASE"]})
            for l in same_repo:
                if l["doc"]["owner_session"] != claimant_session:
                    continue
                if not all(any(covers(lp, p) for lp in l["doc"]["paths"]) for p in paths):
                    continue
                if l["sha256"] in releases:
                    reasons.append({"code": "LEASE_RELEASED", "file": l["file"], "detail": REASONS["LEASE_RELEASED"]})
                elif not now < l["expires"]:
                    reasons.append({"code": "LEASE_EXPIRED", "file": l["file"], "detail": REASONS["LEASE_EXPIRED"]})
        elif len(covering) > 1:
            reasons.append({"code": "AMBIGUOUS_LEASE", "file": None,
                            "detail": ",".join(l["file"] for l in covering)})
        else:
            selected = covering[0]
            git_sha = None
            if git_dir is not None:
                try:
                    git_sha = read_base_sha(git_dir, selected["doc"]["base_branch"])
                except LeaseError as e:
                    if supplied is None:
                        reasons.append({"code": "BASE_UNREADABLE", "file": selected["file"],
                                        "detail": e.detail})
            if git_sha is not None:
                effective = git_sha
                base_source = "GIT" if supplied is None else "GIT_AND_SUPPLIED"
                if supplied is not None and supplied != git_sha:
                    reasons.append({"code": "STALE_BASE", "file": selected["file"],
                                    "detail": "supplied base sha disagrees with git "
                                              + git_sha[:12]})
            elif supplied is not None:
                effective, base_source = supplied, "SUPPLIED_UNVERIFIED"
            if effective is not None and selected["doc"]["base_sha"] != effective:
                reasons.append({"code": "STALE_BASE", "file": selected["file"],
                                "detail": "lease base_sha " + selected["doc"]["base_sha"][:12]})
        for l in active:
            if l is selected:
                continue
            hit = [p for p in paths if any(overlaps(lp, p) for lp in l["doc"]["paths"])]
            if hit:
                reasons.append({"code": "OVERLAP", "file": l["file"],
                                "detail": f"lane={l['doc']['lane']} owner={l['doc']['owner_session']} paths={','.join(hit)}"})
    codes = sorted({r["code"] for r in reasons})
    verdict = "PASS" if not codes else "BLOCKED"
    if verdict == "PASS" and selected is None:      # belt and braces: PASS needs a lease
        verdict, codes = "BLOCKED", ["NO_COVERING_LEASE"]
    lease = None
    if selected is not None:
        lease = {"file": selected["file"], "sha256": selected["sha256"],
                 "lane": selected["doc"]["lane"], "base_sha": selected["doc"]["base_sha"],
                 "expires_utc": selected["doc"]["expires_utc"]}
    return {"schema": VERDICT_SCHEMA, "tool_version": VERSION, "verdict": verdict,
            "reason_codes": codes, "reasons": reasons,
            "repo": repo if isinstance(repo, str) else None,
            "paths": list(paths) if isinstance(paths, (list, tuple)) else None,
            "claimant_session": claimant_session if isinstance(claimant_session, str) else None,
            "current_base_sha": effective if effective is not None else (
                supplied if isinstance(supplied, str) else None),
            "base_sha_source": base_source,
            "lease": lease, "entries_scanned": scanned,
            "checked_utc": utc_text(now) if _aware(now) else None}


# ---------------------------------------------------------------- acquire lock (F12)
def _take_lock(leases_dir, owner_session, now):
    """Exclusive-create acquire.lock. Returns (path, bytes) or None when it is held.
    Never removes or overwrites an existing lock (a stale lock is for an operator)."""
    path = os.path.join(leases_dir, LOCK_NAME)
    data = canonical_bytes({"schema": LOCK_SCHEMA, "owner_session": owner_session,
                            "created_utc": utc_text(now), "token": secrets.token_hex(16)})
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
    except FileExistsError:
        return None
    except PermissionError:              # Windows: lock in delete-pending state = still held
        return None
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return path, data


def _drop_lock(lock) -> None:
    """Remove the lock only if it still holds exactly the bytes this acquire wrote."""
    if lock is None:
        return
    path, data = lock
    try:
        with open(path, "rb") as f:
            cur = f.read(MAX_FILE_BYTES + 1)
    except OSError:
        return
    if cur == data:
        os.remove(path)


def lock_state(leases_dir) -> dict:
    p = os.path.join(leases_dir, LOCK_NAME)
    return {"held": os.path.lexists(p), "name": LOCK_NAME}


# ---------------------------------------------------------------- writers
def acquire(leases_dir, lane, owner_session, repo, base_branch, base_sha, paths,
            ttl, purpose, now) -> dict:
    """Exclusive-create a lease while holding acquire.lock. Refuses (BLOCKED) if the lock
    is held (LEASE_LOCK_HELD), the directory has any problem, or any active lease on the
    repo overlaps. The lock serialises scan + overlap test + write, so two concurrent
    acquirers on overlapping paths cannot both obtain a lease."""
    if not _aware(now) or not isinstance(ttl, timedelta):
        raise LeaseError("BAD_REQUEST", "now must be aware and ttl a timedelta")
    if ttl <= timedelta(0) or ttl > MAX_TTL:
        raise LeaseError("BAD_REQUEST", "ttl must be > 0 and <= 24 h")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    doc = {"schema": LEASE_SCHEMA, "lane": lane, "owner_session": owner_session,
           "repo": repo, "base_branch": base_branch, "base_sha": base_sha,
           "paths": list(paths), "acquired_utc": utc_text(now),
           "expires_utc": utc_text(now + ttl), "purpose": purpose}
    try:
        validate_lease(doc)
    except LeaseError as e:
        raise LeaseError("BAD_REQUEST", e.detail) from None
    os.makedirs(leases_dir, exist_ok=True)
    lock = _take_lock(leases_dir, owner_session, now)
    if lock is None:
        return {"result": "BLOCKED", "reason_codes": ["LEASE_LOCK_HELD"],
                "reasons": [{"code": "LEASE_LOCK_HELD", "file": LOCK_NAME,
                             "detail": REASONS["LEASE_LOCK_HELD"]}]}
    try:
        return _acquire_locked(leases_dir, lane, repo, paths, doc, now)
    finally:
        _drop_lock(lock)


def _acquire_locked(leases_dir, lane, repo, paths, doc, now) -> dict:
    leases, releases, problems = scan(leases_dir, now)
    blockers = list(problems)
    for l in _active([l for l in leases if l["doc"]["repo"].lower() == repo.lower()], releases, now):
        hit = [p for p in paths if any(overlaps(lp, p) for lp in l["doc"]["paths"])]
        if hit:
            blockers.append({"code": "OVERLAP", "file": l["file"],
                             "detail": f"lane={l['doc']['lane']} owner={l['doc']['owner_session']}"})
    if blockers:
        return {"result": "BLOCKED", "reason_codes": sorted({b["code"] for b in blockers}),
                "reasons": blockers}
    name = f"lease_{now.strftime('%Y%m%dT%H%M%SZ')}_{lane}_{secrets.token_hex(4)}.json"
    data = canonical_bytes(doc)
    write_exclusive(os.path.join(leases_dir, name), data)
    return {"result": "ACQUIRED", "lease_file": name,
            "lease_sha256": hashlib.sha256(data).hexdigest(), "lease": doc}


def release(leases_dir, lease_file, released_by, reason, now) -> dict:
    if not _aware(now):
        raise LeaseError("BAD_REQUEST", "now must be timezone-aware")
    if not isinstance(lease_file, str) or not LEASE_NAME_RE.fullmatch(lease_file):
        raise LeaseError("BAD_REQUEST", "lease_file must be a lease file name, not a path")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    leases, releases, problems = scan(leases_dir, now)
    target = next((l for l in leases if l["file"] == lease_file), None)
    blockers = list(problems)
    if target is None:
        blockers.append({"code": "NO_COVERING_LEASE", "file": lease_file, "detail": "lease not found or invalid"})
    elif target["doc"]["owner_session"] != released_by:
        blockers.append({"code": "RELEASE_NOT_BY_OWNER", "file": lease_file, "detail": "only the owner may release"})
    elif target["sha256"] in releases:
        blockers.append({"code": "DUPLICATE_RELEASE", "file": lease_file, "detail": "already released"})
    if blockers:
        return {"result": "BLOCKED", "reason_codes": sorted({b["code"] for b in blockers}),
                "reasons": blockers}
    doc = {"schema": RELEASE_SCHEMA, "lease_file": lease_file,
           "lease_sha256": target["sha256"], "released_by": released_by,
           "released_utc": utc_text(now), "reason": reason}
    try:
        validate_release(doc)
    except LeaseError as e:
        raise LeaseError("BAD_REQUEST", e.detail) from None
    name = f"release_{now.strftime('%Y%m%dT%H%M%SZ')}_{target['sha256'][:12]}_{secrets.token_hex(4)}.json"
    data = canonical_bytes(doc)
    write_exclusive(os.path.join(leases_dir, name), data)
    return {"result": "RELEASED", "release_file": name,
            "release_sha256": hashlib.sha256(data).hexdigest(), "lease_sha256": target["sha256"]}


def list_leases(leases_dir, now) -> dict:
    now = now.astimezone(timezone.utc)
    leases, releases, problems = scan(leases_dir, now)
    rows = []
    for l in leases:
        st = ("RELEASED" if l["sha256"] in releases else
              "EXPIRED" if not now < l["expires"] else "ACTIVE")
        rows.append({"file": l["file"], "sha256": l["sha256"], "status": st,
                     "lane": l["doc"]["lane"], "owner_session": l["doc"]["owner_session"],
                     "repo": l["doc"]["repo"], "paths": l["doc"]["paths"],
                     "base_sha": l["doc"]["base_sha"], "expires_utc": l["doc"]["expires_utc"]})
    return {"schema": "szl.lane-lease-list/v1", "leases": rows, "problems": problems,
            "acquire_lock": lock_state(leases_dir),
            "result": "BLOCKED" if problems else "OK", "listed_utc": utc_text(now)}


# ---------------------------------------------------------------- CLI
class _Parser(argparse.ArgumentParser):
    def error(self, message):            # usage errors exit 1, never 2 (2 = BLOCKED)
        sys.stderr.write(f"usage error: {message}\n")
        raise SystemExit(1)


def _emit(obj) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True)
    if LOCAL_PATH_SHAPES.search(text):  # never print a local path; fail closed
        text = json.dumps({"result": "BLOCKED", "verdict": "BLOCKED",
                           "reason_codes": ["OUTPUT_REDACTION"],
                           "detail": "output contained a local path shape; suppressed"})
        print(text)
        raise SystemExit(2)
    print(text)


def main(argv=None) -> int:
    ap = _Parser(prog="szl_lane_lease", description="fail-closed lane leases")
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    a = sub.add_parser("acquire")
    a.add_argument("--leases-dir", required=True)
    a.add_argument("--lane", required=True)
    a.add_argument("--owner", required=True)
    a.add_argument("--repo", required=True)
    a.add_argument("--base-branch", required=True)
    a.add_argument("--base-sha", required=True)
    a.add_argument("--path", action="append", required=True)
    a.add_argument("--ttl-hours", type=float, required=True)
    a.add_argument("--purpose", required=True)
    r = sub.add_parser("release")
    r.add_argument("--leases-dir", required=True)
    r.add_argument("--lease-file", required=True)
    r.add_argument("--by", required=True)
    r.add_argument("--reason", required=True)
    c = sub.add_parser("check")
    c.add_argument("--leases-dir", required=True)
    c.add_argument("--repo", required=True)
    c.add_argument("--path", action="append", required=True)
    c.add_argument("--claimant", required=True)
    c.add_argument("--base-sha", default=None)
    c.add_argument("--git-dir", default=None)
    li = sub.add_parser("list")
    li.add_argument("--leases-dir", required=True)
    args = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    try:
        if args.cmd == "check":
            if not args.base_sha and not args.git_dir:
                ap.error("check needs --base-sha, --git-dir, or both")
            v = check(args.leases_dir, args.repo, args.path, args.claimant, args.base_sha or None,
                      now, git_dir=args.git_dir)
            _emit(v)
            return 0 if v["verdict"] == "PASS" else 2
        if args.cmd == "list":
            res = list_leases(args.leases_dir, now)
        elif args.cmd == "acquire":
            ttl = args.ttl_hours
            if not (ttl == ttl) or ttl <= 0 or ttl > 24:     # NaN-safe
                ap.error("--ttl-hours must be in (0, 24]")
            res = acquire(args.leases_dir, args.lane, args.owner, args.repo, args.base_branch,
                          args.base_sha, args.path, timedelta(hours=ttl), args.purpose, now)
        else:
            res = release(args.leases_dir, args.lease_file, args.by, args.reason, now)
    except LeaseError as e:
        if e.code == "BAD_REQUEST":
            ap.error(e.detail)
        raise
    except FileExistsError:
        _emit({"result": "BLOCKED", "reason_codes": ["NAME_COLLISION"], "detail": "file exists; never overwritten"})
        return 2
    _emit(res)
    return 0 if res.get("result") in ("ACQUIRED", "RELEASED", "OK") else 2


if __name__ == "__main__":
    sys.exit(main())
