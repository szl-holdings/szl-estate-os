"""Bounded local metadata observations. Working-file contents are never opened.

Dirty state is UNKNOWN: metadata-only enumeration cannot prove a clean checkout.
The sole Git subprocess parses an already bounded config snapshot from stdin,
without includes, repository discovery, hooks, filters, or remote operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .model import EvidenceStatus, EvidenceValidationError, safe_identifier, utc_timestamp


MAX_ROOTS = 32
MAX_DISCOVERY_DIRS = 256
MAX_DISCOVERY_DEPTH = 3
MAX_CHECKOUTS = 128
MAX_CHECKOUT_PATHS = 8000
MAX_TOTAL_PATHS = 50000
MAX_DIRECTORY_ENTRIES = 8000
MAX_WALK_DEPTH = 16
MAX_CONFIG_BYTES = 64 * 1024
MAX_REF_BYTES = 4096
MAX_PACKED_REFS_BYTES = 1024 * 1024
MAX_REMOTE_OUTPUT = 8192
GIT_TIMEOUT_SECONDS = 5
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DENIED_NAMES = {".git", ".ssh", ".aws", ".azure", ".config", ".netrc", ".git-credentials", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", ".codex", ".agents", "session", "sessions", "sessionlogs", "appdata", "node_modules", ".venv", "venv", "env", "__pycache__", "lfs", "weights", "checkpoints", "datasets", "dataset_rows", "cache", "caches"}
_SECRET_WORDS = {"credential", "credentials", "secret", "secrets", "token", "tokens", "session", "sessions", "sessionlogs", "password", "passwords", "auth", "authentication", "oauth", "apikey"}
_DENIED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".safetensors", ".gguf", ".onnx", ".pt", ".pth", ".bin", ".parquet", ".arrow", ".jsonl", ".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar")


class MetadataError(ValueError):
    """Fixed codes only: rejected paths, config values and errors are not echoed."""


@dataclass(frozen=True, slots=True)
class WorktreeObservation:
    checkout_id: str
    root_index: int
    relative_path: str | None
    head: str | None
    repo_name: str | None
    dirty: None
    dirty_status: EvidenceStatus
    status: EvidenceStatus
    code: str
    counts: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {"checkout_id": self.checkout_id, "root_index": self.root_index,
                "relative_path": self.relative_path, "head": self.head, "repo_name": self.repo_name,
                "dirty": None, "dirty_status": self.dirty_status.value, "status": self.status.value,
                "code": self.code, "counts": dict(self.counts), "estate_ready": False}


@dataclass(frozen=True, slots=True)
class WorktreeInventory:
    observed_at_utc: str
    observations: tuple[WorktreeObservation, ...]
    counts: Mapping[str, int]
    discovery_complete: bool

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "szl.worktree-inventory/v1", "observed_at_utc": self.observed_at_utc,
                "proof_scope": "LOCAL_WORKTREES_METADATA_ONLY", "estate_ready": False,
                "full_estate_coverage": False, "discovery_complete": self.discovery_complete,
                "status": EvidenceStatus.PARTIAL.value if self.observations else EvidenceStatus.UNKNOWN.value,
                "counts": dict(self.counts), "observations": [item.to_dict() for item in self.observations]}


def _absolute(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _contains(path: Path, root: Path) -> bool:
    try:
        return os.path.normcase(os.path.commonpath((str(path), str(root)))) == os.path.normcase(str(root))
    except ValueError:
        return False


def _reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _safe_path(path: Path | str, roots: tuple[Path, ...]) -> Path:
    original = Path(path)
    if any(ord(char) < 32 for char in str(original)) or str(original).startswith(("\\\\", "//")):
        raise MetadataError("UNSAFE_PATH")
    target = _absolute(original)
    if not any(_contains(target, root) for root in roots):
        raise MetadataError("PATH_OUTSIDE_SCOPE")
    # Check the complete explicit path chain, including ancestors and reparse points.
    # Do not permit a dot-dot path to step outside scope and then back inside it.
    current = Path(original.anchor) if original.is_absolute() else Path.cwd()
    for part in original.parts[1:] if original.is_absolute() else original.parts:
        if part == ".":
            continue
        if part == "..":
            current = current.parent
            if not any(_contains(_absolute(current), root) for root in roots):
                raise MetadataError("PATH_OUTSIDE_SCOPE")
        else:
            current = current / part
        try:
            if _reparse(current.lstat()):
                raise MetadataError("REPARSE_PATH")
        except MetadataError:
            raise
        except (OSError, ValueError):
            raise MetadataError("PATH_INACCESSIBLE") from None
    return target


def _read_metadata(path: Path | str, roots: tuple[Path, ...], limit: int) -> bytes:
    safe = _safe_path(path, roots)
    try:
        before = safe.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise MetadataError("METADATA_LIMIT")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(safe, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
                raise MetadataError("METADATA_CHANGED")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        final = safe.lstat()
        if len(raw) > limit:
            raise MetadataError("METADATA_LIMIT")
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino) or _reparse(final):
            raise MetadataError("METADATA_CHANGED")
        return raw
    except MetadataError:
        raise
    except (OSError, ValueError):
        raise MetadataError("METADATA_INACCESSIBLE") from None


def _text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8").strip()
    except UnicodeError:
        raise MetadataError("INVALID_METADATA") from None


def _validate_layout(git_dir: Path, common: Path, roots: tuple[Path, ...]) -> None:
    # A contained pointer alone must not turn arbitrary working files named
    # HEAD/config into metadata. Verify Git's directory signature using stat.
    for path in (common / "objects", common / "refs"):
        if not stat.S_ISDIR(_safe_path(path, roots).lstat().st_mode):
            raise MetadataError("INVALID_GIT_LAYOUT")
    if not stat.S_ISREG(_safe_path(git_dir / "HEAD", roots).lstat().st_mode):
        raise MetadataError("INVALID_GIT_LAYOUT")


def _git_dirs(checkout: Path, roots: tuple[Path, ...]) -> tuple[Path, Path]:
    marker = _safe_path(checkout / ".git", roots)
    try:
        info = marker.lstat()
        if stat.S_ISDIR(info.st_mode):
            git_dir = marker
        elif stat.S_ISREG(info.st_mode):
            pointer = _text(_read_metadata(marker, roots, MAX_REF_BYTES))
            if not pointer.startswith("gitdir: ") or "\n" in pointer or "\r" in pointer:
                raise MetadataError("INVALID_GIT_POINTER")
            pointed = Path(pointer[8:])
            git_dir = _safe_path(pointed if pointed.is_absolute() else checkout / pointed, roots)
        else:
            raise MetadataError("INVALID_GIT_POINTER")
        if not stat.S_ISDIR(git_dir.lstat().st_mode):
            raise MetadataError("INVALID_GIT_POINTER")
        common = git_dir
        try:
            (git_dir / "commondir").lstat()
        except FileNotFoundError:
            _validate_layout(git_dir, common, roots)
            return git_dir, common
        common_text = _text(_read_metadata(git_dir / "commondir", roots, MAX_REF_BYTES))
        if not common_text or "\n" in common_text or "\r" in common_text:
            raise MetadataError("INVALID_COMMON_POINTER")
        pointed = Path(common_text)
        common = _safe_path(pointed if pointed.is_absolute() else git_dir / pointed, roots)
        if not stat.S_ISDIR(common.lstat().st_mode):
            raise MetadataError("INVALID_COMMON_POINTER")
        _validate_layout(git_dir, common, roots)
        return git_dir, common
    except OSError:
        raise MetadataError("METADATA_INACCESSIBLE") from None


def _ref_name(value: str) -> bool:
    return bool(re.fullmatch(r"refs/[A-Za-z0-9_.\-/]{1,240}", value)) and not any(
        part in {"", ".", ".."} or part.startswith(".") or part.endswith(".lock")
        for part in value.split("/")
    ) and ".." not in value


def _head_oid(git_dir: Path, common_dir: Path, allowed_roots: Iterable[Path | str]) -> tuple[str | None, str]:
    roots = tuple(_absolute(root) for root in allowed_roots)
    try:
        original = _read_metadata(git_dir / "HEAD", roots, MAX_REF_BYTES)
        sources = [(git_dir / "HEAD", original, MAX_REF_BYTES)]
        value = _text(original)
        visited = set()
        for _ in range(8):
            if _OID.fullmatch(value):
                for source, recorded, limit in sources:
                    if _read_metadata(source, roots, limit) != recorded:
                        raise MetadataError("METADATA_CHANGED")
                return value, "NONE"
            if not value.startswith("ref: ") or not _ref_name(value[5:]) or value[5:] in visited:
                raise MetadataError("INVALID_HEAD")
            ref = value[5:]
            visited.add(ref)
            loose = common_dir / ref
            try:
                loose.lstat()
            except FileNotFoundError:
                packed_raw = _read_metadata(common_dir / "packed-refs", roots, MAX_PACKED_REFS_BYTES)
                sources.append((common_dir / "packed-refs", packed_raw, MAX_PACKED_REFS_BYTES))
                packed = _text(packed_raw)
                matches = []
                for line in packed.splitlines():
                    if line.startswith("#"):
                        continue
                    if line.startswith("^"):
                        if not _OID.fullmatch(line[1:]):
                            raise MetadataError("INVALID_PACKED_REFS")
                        continue
                    parts = line.split(" ")
                    if len(parts) != 2 or not _OID.fullmatch(parts[0]) or not _ref_name(parts[1]):
                        raise MetadataError("INVALID_PACKED_REFS")
                    if parts[1] == ref:
                        matches.append(parts[0])
                if len(matches) != 1:
                    raise MetadataError("HEAD_UNKNOWN")
                value = matches[0]
            else:
                loose_raw = _read_metadata(loose, roots, MAX_REF_BYTES)
                sources.append((loose, loose_raw, MAX_REF_BYTES))
                value = _text(loose_raw)
        raise MetadataError("REF_LOOP")
    except MetadataError as error:
        return None, str(error)
    except OSError:
        return None, "METADATA_INACCESSIBLE"


def _sanitize_remote(raw: str) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > 2048 or any(ord(char) < 32 for char in raw):
        return None
    scp = re.fullmatch(r"git@github\.com:([^\s]+)", raw)
    if scp:
        host, parts = "github.com", scp[1].split("/")
    else:
        try:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"https", "ssh"} or parsed.query or parsed.fragment:
                return None
            if parsed.port not in ({None, 443} if parsed.scheme == "https" else {None, 22}):
                return None
            host, parts = parsed.hostname, parsed.path.strip("/").split("/")
        except ValueError:
            return None
    if host == "github.com" and len(parts) == 2 and parts[0].casefold() == "szl-holdings":
        prefix, name = "github:szl-holdings/", parts[1]
    elif host == "huggingface.co" and (len(parts) == 2 or len(parts) == 3 and parts[0] in {"datasets", "spaces"}):
        owner, name = parts[-2:]
        if owner != "SZLHOLDINGS":
            return None
        prefix = "hf:SZLHOLDINGS/"
    else:
        return None
    name = name[:-4] if name.endswith(".git") else name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", name) or ".." in name:
        return None
    try:
        return safe_identifier(prefix + name)
    except EvidenceValidationError:
        return None


def _safe_git_environment(cwd: Path | str) -> dict[str, str]:
    # Child environment is constructed from essentials, never from GIT_* secrets,
    # tracing, aliases, discovery overrides, custom redirects or parameter config.
    environment = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "TMP", "TEMP"}}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_COUNT": "0",
                        "GIT_CEILING_DIRECTORIES": str(_absolute(cwd).parent),
                        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0", "GIT_OPTIONAL_LOCKS": "0",
                        "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
                        "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": ""})
    return environment


def _query_origin(config_path: Path, git_executable: Path | str | None) -> tuple[str | None, str]:
    if git_executable is None or not Path(git_executable).is_absolute():
        return None, "GIT_NOT_CONFIGURED"
    try:
        executable = _safe_path(Path(git_executable), (_absolute(Path(git_executable).parent),))
        if not stat.S_ISREG(executable.lstat().st_mode):
            return None, "GIT_NOT_CONFIGURED"
        snapshot = _read_metadata(config_path, (config_path.parent,), MAX_CONFIG_BYTES)
        chunks: list[bytes] = []
        io_failed: list[bool] = []
        with tempfile.TemporaryDirectory(prefix="szl-git-metadata-") as name:
            cwd = Path(name)
            process = subprocess.Popen([str(executable), "--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "diff.external=", "-c", "gc.auto=0", "config", "--file", "-", "--no-includes", "--null", "--get-all", "remote.origin.url"], cwd=cwd, env=_safe_git_environment(cwd), shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            def send_snapshot():
                try:
                    process.stdin.write(snapshot)
                    process.stdin.close()
                except (OSError, ValueError):
                    io_failed.append(True)
            def read_bounded():
                try:
                    raw = process.stdout.read(MAX_REMOTE_OUTPUT + 1)
                    chunks.append(raw)
                    if len(raw) > MAX_REMOTE_OUTPUT:
                        process.kill()
                except (OSError, ValueError):
                    io_failed.append(True)
            writer = threading.Thread(target=send_snapshot, daemon=True)
            reader = threading.Thread(target=read_bounded, daemon=True)
            writer.start()
            reader.start()
            try:
                process.wait(timeout=GIT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                return None, "GIT_TIMEOUT"
            finally:
                writer.join(timeout=2)
                reader.join(timeout=2)
                if not writer.is_alive():
                    process.stdin.close()
                if not reader.is_alive():
                    process.stdout.close()
            raw = chunks[0] if chunks else b""
            if len(raw) > MAX_REMOTE_OUTPUT:
                return None, "GIT_OUTPUT_LIMIT"
            if writer.is_alive() or reader.is_alive() or io_failed or process.returncode != 0:
                return None, "GIT_QUERY_FAILED"
            if not raw.endswith(b"\0"):
                return None, "REMOTE_UNKNOWN"
            values = raw[:-1].split(b"\0")
            if len(values) != 1:
                return None, "DUPLICATE_REMOTE"
            try:
                remote = _sanitize_remote(values[0].decode("utf-8"))
            except UnicodeError:
                remote = None
            return (remote, "NONE") if remote else (None, "REMOTE_UNKNOWN")
    except (MetadataError, OSError, subprocess.SubprocessError):
        return None, "GIT_QUERY_FAILED"


def _excluded(name: str) -> bool:
    lowered = name.casefold()
    words = set(re.split(r"[^a-z0-9]+", lowered))
    return (lowered in _DENIED_NAMES or lowered.startswith(".env")
            or lowered.endswith(_DENIED_SUFFIXES) or bool(words & _SECRET_WORDS)
            or {"api", "key"}.issubset(words))


def _entries(path: Path, limit: int | None = None) -> tuple[list[os.DirEntry], bool]:
    limit = MAX_DIRECTORY_ENTRIES if limit is None else min(MAX_DIRECTORY_ENTRIES, max(0, limit))
    try:
        with os.scandir(path) as iterator:
            result = []
            for entry in iterator:
                result.append(entry)
                if len(result) > limit:
                    return [], False
        return sorted(result, key=lambda entry: (entry.name.casefold(), entry.name)), True
    except OSError:
        raise MetadataError("DIRECTORY_INACCESSIBLE") from None


def _walk_paths(checkout: Path, roots: tuple[Path, ...], budget: int) -> tuple[dict[str, int], bool, str]:
    counts = {"paths_counted": 0, "excluded_paths": 0, "inaccessible_paths": 0}
    limit = min(MAX_CHECKOUT_PATHS, budget)
    pending = [(checkout, 0)]
    complete, code = True, "NONE"
    while pending:
        if counts["paths_counted"] >= limit:
            return counts, False, "PATH_LIMIT"
        directory, depth = pending.pop()
        try:
            _safe_path(directory, roots)
            entries, bounded = _entries(directory, limit - counts["paths_counted"])
            if not bounded:
                complete, code = False, "DIRECTORY_LIMIT"
                continue
        except MetadataError:
            counts["inaccessible_paths"] += 1
            complete, code = False, "DIRECTORY_INACCESSIBLE"
            continue
        for entry in reversed(entries):
            if counts["paths_counted"] >= limit:
                return counts, False, "PATH_LIMIT"
            counts["paths_counted"] += 1
            if _excluded(entry.name):
                counts["excluded_paths"] += 1
                continue
            try:
                path = _safe_path(directory / entry.name, roots)
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    if depth >= MAX_WALK_DEPTH:
                        complete, code = False, "DEPTH_LIMIT"
                    else:
                        pending.append((path, depth + 1))
                elif not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                    counts["excluded_paths"] += 1
            except MetadataError:
                counts["excluded_paths"] += 1
                complete, code = False, "UNSAFE_PATH"
            except OSError:
                counts["inaccessible_paths"] += 1
                complete, code = False, "PATH_INACCESSIBLE"
    return counts, complete, code


def collect_worktrees(roots: Iterable[Path | str] = (), *, git_executable: Path | str | None = None, observed_at_utc: str | None = None) -> WorktreeInventory:
    requested = []
    for root in roots:
        requested.append(_absolute(root))
        if len(requested) > MAX_ROOTS:
            break
    allowed = tuple(requested[:MAX_ROOTS])
    counts = {"roots_requested": len(requested), "roots_accessible": 0, "candidate_dirs_examined": 0, "discovery_entries_examined": 0,
              "path_coverage_count": 0, "checkout_markers_found": 0, "checkouts_inspected": 0,
              "paths_counted": 0, "excluded_paths": 0, "inaccessible_paths": 0}
    complete = len(requested) <= MAX_ROOTS
    pending = []
    for index, root in enumerate(allowed):
        if any(part.casefold() != ".git" and _excluded(part) for part in root.parts):
            counts["excluded_paths"] += 1
            complete = False
            continue
        try:
            if not stat.S_ISDIR(_safe_path(root, allowed).lstat().st_mode):
                raise MetadataError("INVALID_ROOT")
            counts["roots_accessible"] += 1
            pending.append((root, index, 0))
        except (MetadataError, OSError):
            counts["inaccessible_paths"] += 1
            complete = False
    pending.reverse()
    observations = []
    seen = set()
    while pending:
        if counts["candidate_dirs_examined"] >= MAX_DISCOVERY_DIRS or len(observations) >= MAX_CHECKOUTS:
            complete = False
            break
        directory, root_index, depth = pending.pop()
        key = os.path.normcase(str(directory))
        if key in seen:
            continue
        seen.add(key)
        counts["candidate_dirs_examined"] += 1
        counts["path_coverage_count"] += 1
        try:
            directory = _safe_path(directory, allowed)
            try:
                (directory / ".git").lstat()
                marker = True
            except FileNotFoundError:
                marker = False
            if marker:
                counts["checkout_markers_found"] += 1
                head = remote = None
                metadata_code = "NONE"
                try:
                    git_dir, common = _git_dirs(directory, allowed)
                    head, metadata_code = _head_oid(git_dir, common, allowed)
                    remote, remote_code = _query_origin(common / "config", git_executable)
                    if metadata_code == "NONE" and remote_code != "NONE":
                        metadata_code = remote_code
                except MetadataError as error:
                    metadata_code = str(error)
                if metadata_code != "NONE":
                    complete = False
                walk, walked, walk_code = _walk_paths(directory, allowed, MAX_TOTAL_PATHS - counts["paths_counted"] - counts["discovery_entries_examined"])
                for name in walk:
                    counts[name] += walk[name]
                complete = complete and walked
                relative = directory.relative_to(allowed[root_index]).as_posix()
                try:
                    relative = safe_identifier(relative) if relative != "." else "."
                except EvidenceValidationError:
                    relative = None
                code = metadata_code if metadata_code != "NONE" else walk_code if not walked else "DIRTY_NOT_MEASURED"
                observations.append(WorktreeObservation(f"checkout-{len(observations) + 1:04d}", root_index, relative, head, remote, None, EvidenceStatus.UNKNOWN, EvidenceStatus.PARTIAL if head or remote else EvidenceStatus.UNKNOWN, code, walk))
                counts["checkouts_inspected"] += 1
                continue  # checkout contents belong only to the bounded metadata walk
            remaining = MAX_TOTAL_PATHS - counts["paths_counted"] - counts["discovery_entries_examined"]
            entries, bounded = _entries(directory, remaining)
            if not bounded:
                complete = False
                continue
            for entry in reversed(entries):
                if counts["paths_counted"] + counts["discovery_entries_examined"] >= MAX_TOTAL_PATHS:
                    complete = False
                    pending.clear()
                    break
                counts["discovery_entries_examined"] += 1
                if _excluded(entry.name):
                    counts["excluded_paths"] += 1
                    continue
                try:
                    path = _safe_path(directory / entry.name, allowed)
                    if stat.S_ISDIR(path.lstat().st_mode):
                        if depth >= MAX_DISCOVERY_DEPTH:
                            complete = False
                        elif len(pending) + counts["candidate_dirs_examined"] < MAX_DISCOVERY_DIRS:
                            pending.append((path, root_index, depth + 1))
                        else:
                            complete = False
                except (MetadataError, OSError):
                    counts["inaccessible_paths"] += 1
                    complete = False
        except (MetadataError, OSError):
            counts["inaccessible_paths"] += 1
            complete = False
    at = utc_timestamp(observed_at_utc or datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return WorktreeInventory(at, tuple(observations), counts, complete)
