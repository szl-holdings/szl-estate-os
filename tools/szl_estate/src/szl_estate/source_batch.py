"""Bounded existing-auth GitHub reads; candidates are data and never executed."""
from __future__ import annotations

import base64
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time

from szl_estate.content_review import FilePin, ReviewStatus, git_blob_sha1, review_bytes, reconcile_coverage
from szl_estate.model import ProofOrigin
from szl_estate.storage import atomic_write, integrity_bytes

MAX_REQUESTS = 128
MAX_RESPONSE = 512 * 1024
MAX_TREE_ENTRIES = 2048
MAX_TREE_CALLS = 64
MAX_CONTENT_BYTES = 1024 * 1024
OID = re.compile(r"[0-9a-f]{40}\Z")


class ReadError(ValueError):
    def __init__(self, code, status=None, endpoint=None):
        self.code, self.status, self.endpoint = code, status, endpoint
        super().__init__(code)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def unique_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ReadError("JSON_DUPLICATE_KEY")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ReadError("JSON_NONFINITE")))
    except ReadError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ReadError("JSON_INVALID") from None


class GitHubRead:
    def __init__(self, executable, working_directory):
        self.executable, self.working_directory = executable, working_directory
        self.calls = 0
        self.tree_calls = 0
        self.stopped = False
        self.observations = []

    def request(self, endpoint, *, retry=True):
        if self.stopped or self.calls >= MAX_REQUESTS:
            raise ReadError("REQUEST_BUDGET_OR_RATE_STOP")
        if not re.fullmatch(r"repos/szl-holdings/[A-Za-z0-9_.-]+(?:/git/(?:commits|trees|blobs)/[0-9a-f]{40})?", endpoint):
            raise ReadError("ENDPOINT_OUTSIDE_SCOPE")
        if "/git/trees/" in endpoint:
            if self.tree_calls >= MAX_TREE_CALLS:
                raise ReadError("TREE_REQUEST_BOUND")
            self.tree_calls += 1
        self.calls += 1
        url = "https://api.github.com/" + endpoint
        env = dict(os.environ)
        for key in ("GH_DEBUG", "GH_FORCE_TTY", "PAGER", "GH_PAGER"):
            env.pop(key, None)
        env.update({"GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"})
        process = subprocess.Popen([str(self.executable), "api", "--hostname", "github.com", "--method", "GET", "--include", endpoint],
                                   cwd=self.working_directory, env=env, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chunks = [b"", b""]
        overflow = []
        def read_pipe(stream, index, limit):
            result = bytearray()
            while True:
                part = stream.read(4096)
                if not part:
                    break
                result.extend(part)
                if len(result) > limit:
                    overflow.append(True)
                    process.kill()  # this helper's own child only
                    break
            chunks[index] = bytes(result[:limit])
        threads = [threading.Thread(target=read_pipe, args=(process.stdout, 0, MAX_RESPONSE), daemon=True),
                   threading.Thread(target=read_pipe, args=(process.stderr, 1, 8192), daemon=True)]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
            raise ReadError("READ_TIMEOUT", endpoint=url) from None
        finally:
            for thread in threads:
                thread.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
        if overflow or any(thread.is_alive() for thread in threads):
            raise ReadError("RESPONSE_BOUND_EXCEEDED", endpoint=url)
        raw = chunks[0]
        match = re.match(rb"HTTP/[0-9.]+ ([0-9]{3})(?: [^\r\n]*)?\r?\n", raw)
        status = int(match.group(1)) if match else None
        split = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)
        at = utc()
        observation = {"endpoint": url, "http_status": status, "observed_at_utc": at}
        self.observations.append(observation)
        headers = split[0].decode("ascii", errors="ignore") if split else ""
        remaining = re.search(r"(?im)^x-ratelimit-remaining:\s*(\d+)\s*$", headers)
        backoff = re.search(r"(?im)^retry-after:[ \t]*([^\r\n]*)", headers)
        delay = re.fullmatch(r"\d+", backoff[1].strip()) if backoff else None
        rate_limited = status == 429 or status == 403 and (remaining and int(remaining[1]) == 0 or backoff)
        if rate_limited:
            if retry and delay and int(delay[0]) <= 2 and self.calls < MAX_REQUESTS:
                time.sleep(int(delay[0]))
                return self.request(endpoint, retry=False)
            self.stopped = True
            raise ReadError("RATE_LIMIT_STOP", status, url)
        if status in {401, 403, 429}:
            raise ReadError("AUTH_OR_POLICY_DENIED", status, url)
        if status != 200 or process.returncode or len(split) != 2:
            raise ReadError("HTTP_ERROR" if status is not None else "TRANSPORT_HTTP_UNEXPOSED", status, url)
        result = unique_json(split[1])
        if not isinstance(result, dict):
            raise ReadError("OBJECT_RESPONSE_REQUIRED", status)
        return result, observation


def verify_tree(entries, expected):
    if not isinstance(entries, list) or len(entries) > MAX_TREE_ENTRIES:
        raise ReadError("TREE_LIST_OR_SIZE_INVALID")
    names = set()
    projected = []
    modes = {"040000": "tree", "100644": "blob", "100755": "blob", "120000": "blob", "160000": "commit"}
    for item in entries:
        if not isinstance(item, dict):
            raise ReadError("TREE_ENTRY_INVALID")
        name, mode, sha, kind = (item.get(key) for key in ("path", "mode", "sha", "type"))
        if not isinstance(name, str) or not name or name in names or name in {".", ".."} or "/" in name or "\0" in name:
            raise ReadError("TREE_COMPONENT_INVALID")
        if mode not in modes or modes[mode] != kind or not isinstance(sha, str) or not OID.fullmatch(sha):
            raise ReadError("TREE_MODE_OR_PIN_INVALID")
        names.add(name)
        projected.append(item)
    encoded = b"".join(item["mode"].lstrip("0").encode("ascii") + b" " + item["path"].encode("utf-8") + b"\0" + bytes.fromhex(item["sha"])
                       for item in sorted(projected, key=lambda item: (item["path"] + ("/" if item["type"] == "tree" else "")).encode("utf-8")))
    actual = hashlib.sha1(b"tree " + str(len(encoded)).encode("ascii") + b"\0" + encoded).hexdigest()
    if actual != expected:
        raise ReadError("TREE_OBJECT_DIGEST_MISMATCH")
    return {item["path"]: item for item in projected}


def safe_chain(path):
    path = Path(os.path.abspath(path))
    if str(path).startswith(("\\\\", "//")):
        raise ReadError("UNSAFE_LOCAL_PATH")
    for node in (*reversed(path.parents), path):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ReadError("REPARSE_LOCAL_PATH")
    return path


def bounded_input(path, limit):
    safe_chain(path)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ReadError("INPUT_BYTE_BOUND")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read an explicit <=64-file frozen proposal as data; no candidate execution")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--file-index", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--gh-executable", type=Path, required=True, help="Existing explicitly approved absolute GitHub CLI executable")
    parser.add_argument("--source-base-commit", required=True)
    args = parser.parse_args(argv)
    PLAN = safe_chain(args.plan)
    PLAN_SHA = args.expected_plan_sha256
    OUT = safe_chain(args.out)
    GH = safe_chain(args.gh_executable)
    if not args.gh_executable.is_absolute() or not GH.is_file() or not OID.fullmatch(args.source_base_commit):
        raise ReadError("INVALID_APPROVED_EXECUTABLE_OR_BASE")
    raw_plan = bounded_input(PLAN, 1024 * 1024)
    if hashlib.sha256(raw_plan).hexdigest() != PLAN_SHA:
        raise SystemExit("PLAN_CHANGED")
    plan = unique_json(raw_plan)["state"]["github"]
    rows = plan["batch"]
    if not 1 <= len(rows) <= 64 or sum(row["size_bytes"] for row in rows) > MAX_CONTENT_BYTES:
        raise SystemExit("PLAN_COUNT_OR_BYTE_BOUND")
    pins = [FilePin(row["repository_id"], row["snapshot_sha"], row["path"], row["git_object_sha"], row["size_bytes"]) for row in rows]
    if len({pin.key for pin in pins}) != len(rows) or any(row["unread"] is not True or row["epistemic_status"] != "PROPOSAL" for row in rows):
        raise SystemExit("PLAN_DUPLICATE_OR_NONPROPOSAL")
    index_path = args.file_index
    index_raw = bounded_input(index_path, 24 * 1024 * 1024)
    index_expected = unique_json(raw_plan)["state"]["artifacts"]["github_files.jsonl"]["sha256"]
    if hashlib.sha256(index_raw).hexdigest() != index_expected:
        raise ReadError("FILE_INDEX_CHANGED")
    file_index = [unique_json(line) for line in index_raw.splitlines()]
    indexed = {(row["repository_id"], row["snapshot_sha"], row["path"], row["git_object_sha"]): row for row in file_index}
    if len(indexed) != len(file_index) or any(pin.key not in indexed or indexed[pin.key]["size_bytes"] != pin.size_bytes or indexed[pin.key]["entry_type"] != "blob" or indexed[pin.key]["unread"] is not True for pin in pins):
        raise ReadError("PLAN_OUTSIDE_PINNED_FILE_INDEX")
    # A failed run remains intact; explicitly choose a new output for retries.
    if OUT.exists() or OUT == PLAN or OUT == safe_chain(args.file_index) or OUT.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ReadError("EXISTING_OR_PROTECTED_OUTPUT_PRESERVED")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    safe_chain(OUT.parent)
    OUT.mkdir(exist_ok=False)
    cache = OUT / "cache"
    safe_chain(cache)
    cache.mkdir(exist_ok=True)
    client = GitHubRead(GH, OUT.parent)
    repositories, commits, trees, objects, repo_failures = {}, {}, {}, {}, {}
    receipts, documents, failures = [], [], []
    content_total = 0
    for index, pin in enumerate(pins):
        file_id = f"B1-{index + 1:03d}"
        endpoint = f"https://api.github.com/repos/{pin.repository_id}/git/blobs/{pin.blob_sha}"
        membership = []
        raw = None
        transport = "NOT_RUN"
        observation = {"http_status": None, "observed_at_utc": utc()}
        failure = None
        try:
            if pin.repository_id in repo_failures:
                error = repo_failures[pin.repository_id]
                raise ReadError(error.code, error.status, error.endpoint)
            if pin.repository_id not in repositories:
                try:
                    metadata, repo_observed = client.request("repos/" + pin.repository_id)
                    if metadata.get("full_name") != pin.repository_id or metadata.get("private") is not False or metadata.get("visibility") != "public":
                        raise ReadError("PUBLIC_VISIBILITY_NOT_ESTABLISHED", repo_observed["http_status"])
                except ReadError as error:
                    repo_failures[pin.repository_id] = error
                    raise
                repositories[pin.repository_id] = {"repository_id": pin.repository_id, "private": False, "visibility": "public", **repo_observed}
            commit_key = (pin.repository_id, pin.snapshot_sha)
            if commit_key not in commits:
                commit, observed = client.request(f"repos/{pin.repository_id}/git/commits/{pin.snapshot_sha}")
                tree_sha = commit.get("tree", {}).get("sha") if isinstance(commit.get("tree"), dict) else None
                if commit.get("sha") != pin.snapshot_sha or not isinstance(tree_sha, str) or not OID.fullmatch(tree_sha):
                    raise ReadError("COMMIT_TREE_PIN_INVALID", observed["http_status"])
                commits[commit_key] = {"commit_sha": pin.snapshot_sha, "tree_sha": tree_sha, **observed}
            tree_sha = commits[commit_key]["tree_sha"]
            seen = set()
            parts = pin.path.split("/")
            for offset, component in enumerate(parts):
                if tree_sha in seen:
                    raise ReadError("TREE_CURSOR_LOOP")
                seen.add(tree_sha)
                tree_key = (pin.repository_id, tree_sha)
                if tree_key not in trees:
                    if client.tree_calls >= MAX_TREE_CALLS:
                        raise ReadError("TREE_REQUEST_BOUND")
                    value, observed = client.request(f"repos/{pin.repository_id}/git/trees/{tree_sha}")
                    if value.get("sha") != tree_sha or value.get("truncated") is not False:
                        raise ReadError("TRUNCATED_OR_UNPINNED_TREE", observed["http_status"])
                    trees[tree_key] = (verify_tree(value.get("tree"), tree_sha), observed)
                entries, observed = trees[tree_key]
                item = entries.get(component)
                if item is None:
                    raise ReadError("PINNED_PATH_MISSING", observed["http_status"])
                membership.append({"tree_sha": tree_sha, "component": component, "entry_sha": item["sha"], "mode": item["mode"], "http_status": observed["http_status"]})
                if offset < len(parts) - 1:
                    if item["type"] != "tree":
                        raise ReadError("PATH_COMPONENT_NOT_TREE")
                    tree_sha = item["sha"]
                elif item["type"] != "blob" or item["mode"] not in {"100644", "100755"} or item["sha"] != pin.blob_sha or item.get("size") != pin.size_bytes:
                    raise ReadError("PINNED_FILE_IDENTITY_MISMATCH")
            object_key = (pin.repository_id, pin.blob_sha)
            if object_key in objects:
                raw, observation = objects[object_key]
                transport = "IN_RUN_OBJECT_REUSE"
            else:
                value, observation = client.request(f"repos/{pin.repository_id}/git/blobs/{pin.blob_sha}")
                if value.get("sha") != pin.blob_sha or value.get("size") != pin.size_bytes or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
                    raise ReadError("BLOB_RESPONSE_IDENTITY_MISMATCH", observation["http_status"])
                encoded = value["content"].replace("\n", "")
                if len(encoded) > 4 * ((pin.size_bytes + 2) // 3) + 4:
                    raise ReadError("BLOB_ENCODING_BOUND")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except ValueError:
                    raise ReadError("INVALID_BLOB_ENCODING") from None
                if len(raw) != pin.size_bytes or git_blob_sha1(raw) != pin.blob_sha:
                    raise ReadError("BLOB_BYTES_HASH_MISMATCH")
                content_total += len(raw)
                if content_total > MAX_CONTENT_BYTES:
                    raise ReadError("CONTENT_TOTAL_BOUND")
                objects[object_key] = (raw, observation)
                transport = "GITHUB_GIT_BLOB_GET"
        except ReadError as error:
            failure = {"code": error.code, "http_status": error.status, "endpoint": error.endpoint}
            failures.append({"file_id": file_id, **failure})
            raw = None
        result = review_bytes(pin, raw, source_endpoint=endpoint, read_at_utc=observation["observed_at_utc"], source_origin=ProofOrigin.LIVE if raw is not None else ProofOrigin.UNKNOWN,
                              byte_read_status=ReviewStatus.COMPLETE if raw is not None else ReviewStatus.ERROR)
        receipts.append(result.receipt)
        cache_name = f"{file_id}.txt" if result.redacted_text is not None else None
        if cache_name:
            target = cache / cache_name
            safe_chain(target)
            atomic_write(target, result.redacted_text.encode("utf-8"), source_paths=(PLAN,))
        document = {"file_id": file_id, "receipt": result.receipt.to_dict(), "transport": transport,
                    "http_status": observation["http_status"], "membership": membership,
                    "cache_name": cache_name, "failure": failure, "static_review_pending": True}
        documents.append(document)
        safe_chain(OUT / "progress.json")
        atomic_write(OUT / "progress.json", integrity_bytes({"schema_version": "szl.batch1-progress/v1", "plan_sha256": PLAN_SHA, "documents": documents, "complete": False}), source_paths=(PLAN,))
    coverage = reconcile_coverage(file_index, receipts, historical_read_count=plan["historically_inspected_paths"]).to_dict()
    execution = {"schema_version": "szl.content-batch-execution/v1", "plan_sha256": PLAN_SHA, "tool_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 "content_review_source_sha256": hashlib.sha256(Path(__file__).with_name("content_review.py").read_bytes()).hexdigest(),
                 "verification_manifest_sha256": hashlib.sha256(Path(__file__).with_name("verification_manifest.json").read_bytes()).hexdigest(),
                 "source_base_commit": args.source_base_commit, "completed_at_utc": utc(),
                 "source_execution_performed": False, "runtime_status": "NOT_RUN", "estate_ready": False,
                 "repositories": list(repositories.values()), "commits": list(commits.values()),
                 "api_requests": client.calls, "tree_requests": client.tree_calls, "unique_fetched_objects": len(objects), "unique_fetched_bytes": content_total,
                 "documents": documents, "coverage": coverage, "failures": failures}
    safe_chain(OUT / "execution.json")
    atomic_write(OUT / "execution.json", integrity_bytes(execution), source_paths=(PLAN,))
    print(json.dumps({"status": "PARTIAL", "stage": "SOURCE_READS_WITH_STATIC_REVIEW_PENDING", "files": len(documents), "requests": client.calls, "unique_objects": len(objects), "coverage": {k: v for k, v in coverage.items() if k != "completed_file_keys"}, "failures": failures, "runtime_status": "NOT_RUN", "estate_ready": False}, sort_keys=True))
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReadError, OSError, ValueError, TypeError, KeyError):
        print(json.dumps({"status": "FAIL", "code": "INVALID_SOURCE_BATCH_INPUT_OR_RUNTIME", "runtime_status": "NOT_RUN", "estate_ready": False}, sort_keys=True))
        raise SystemExit(2)
