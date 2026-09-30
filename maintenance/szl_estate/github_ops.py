"""Bounded GitHub estate inventory and additive metadata reconciliation.

No credential values, provider response bodies on failure, or subprocess stderr
are logged. Writes are never retried. Every attempted mutation is read back.
Only the topic allowlist and two explicitly scoped audit issues can be changed.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
from email.utils import parsedate_to_datetime
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

ORG = "szl-holdings"
ISSUE_REPOS = ("szl-platform", "platform")
TOPICS = {
    "szl-quant-witness": ["provenance", "quantitative-finance", "szl-holdings"],
    "szl-gpu-bridge": ["ml-infrastructure", "szl-holdings"],
    "evidence-doctrine": ["reproducibility", "szl-holdings"],
    "szl-drift": ["model-monitoring", "szl-holdings"],
    "ayllu-hf-space": ["huggingface", "szl-holdings"],
    "evidence-studio": ["reproducibility", "szl-holdings"],
    "frontier-bench": ["benchmarking", "szl-holdings"],
    "governance-as-code": ["ai-governance", "szl-holdings"],
    "khipu-x1": ["agentic-ai", "szl-holdings"],
    "quant-curve": ["quantitative-finance", "szl-holdings"],
    "retrieval-bench": ["benchmarking", "szl-holdings"],
    "szl-calibration": ["model-monitoring", "szl-holdings"],
    "szl-ci-witness": ["provenance", "continuous-integration", "szl-holdings"],
    "szl-crosscheck": ["provenance", "szl-holdings"],
    "szl-eclipse": ["model-monitoring", "szl-holdings"],
    "szl-engine-bench": ["benchmarking", "szl-holdings"],
    "szl-evidence-litellm": ["reproducibility", "szl-holdings"],
    "szl-gov": ["ai-governance", "szl-holdings"],
    "szl-hf-frontier": ["huggingface", "szl-holdings"],
    "szl-quant-bench": ["quantitative-finance", "benchmarking", "szl-holdings"],
}
HF_TRIAGE = (
    "KILLINCHU-EYE", "a11oy-v19-substrate", "governed-inference-meter",
    "szl-blocked", "szl-energy-attest", "szl-formulas", "szl-govsign",
    "szl-invariants", "szl-khipu", "szl-ouroboros", "szl-provctl",
    "szl-training-scripts",
)


class GitHubError(Exception):
    """A sanitized error that does not retain HTTP bodies or credentials."""

    def __init__(self, code: str, status: int | None = None, *, retry_after: float | None = None):
        super().__init__(code)
        self.code, self.status = code, status
        self.retry_after, self.attempts, self.retry_stopped = retry_after, 1, None


def retry_after_seconds(value: str | None) -> float | None:
    """Read delta seconds or an HTTP date without retaining arbitrary headers."""
    if not value:
        return None
    try:
        if re.fullmatch(r"\d+", value.strip()):
            return float(min(int(value.strip()), 86400))
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            return None
        return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def response_parts(raw: bytes) -> tuple[bytes, int | None, float | None]:
    """Separate gh --include output; only expose status and retry timing."""
    match = re.match(rb"HTTP/\S+\s+(\d{3})[^\r\n]*\r?\n", raw)
    if not match:
        return raw, None, None
    boundary = re.search(rb"\r?\n\r?\n", raw)
    if not boundary:
        raise GitHubError("INVALID_HTTP_RESPONSE")
    header = raw[:boundary.start()]
    retry = re.search(rb"(?im)^retry-after:\s*([^\r\n]+)", header)
    delay = retry_after_seconds(retry[1].decode("ascii", errors="ignore")) if retry else None
    return raw[boundary.end():], int(match[1]), delay


class Client:
    def __init__(self, timeout: int = 30, max_pages: int = 100):
        self.timeout, self.max_pages = timeout, max_pages
        self.gh = shutil.which("gh")
        self.token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.transport = "gh" if self.gh else "https"
        self.diagnostics = {"attempts": 0, "read_retries": 0, "retry_events": [],
                            "retry_events_truncated": False,
                            "max_read_attempts": 3, "max_retry_delay_seconds": 10,
                            "mutation_retries": 0}

    def request(self, path: str, method: str = "GET", body: dict | None = None):
        if not re.fullmatch(r"[A-Za-z0-9_./?=&%+,-]+", path) or path.startswith("/") or ".." in path:
            raise GitHubError("INVALID_API_PATH")
        if method not in ("GET", "PUT", "POST"):
            raise GitHubError("METHOD_NOT_ALLOWED")
        if method != "GET":
            allowed_topics = {f"repos/{ORG}/{repo}/topics" for repo in TOPICS}
            allowed_issues = {f"repos/{ORG}/{repo}/issues" for repo in ISSUE_REPOS}
            if not ((method == "PUT" and path in allowed_topics) or
                    (method == "POST" and path in allowed_issues)):
                raise GitHubError("MUTATION_OUTSIDE_ALLOWLIST")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        for attempt in range(1, 4 if method == "GET" else 2):
            self.diagnostics["attempts"] += 1
            try:
                return self._request_once(path, method, data)
            except GitHubError as error:
                error.attempts = attempt
                retryable = error.status in {429, 502, 503, 504} or (
                    (error.status is None or 200 <= error.status < 300)
                    and error.code in {"TRANSPORT_TIMEOUT", "TRANSPORT_NETWORK_ERROR"})
                if method != "GET" or not retryable:
                    raise
                delay = error.retry_after if error.retry_after is not None else float(2 ** (attempt - 1))
                if attempt == 3:
                    error.retry_stopped = "ATTEMPTS_EXHAUSTED"
                elif delay > 10:
                    # Stop instead of retrying before a longer provider-required delay.
                    error.retry_stopped = "RETRY_AFTER_EXCEEDS_BOUND"
                event = {"path": path, "attempt": attempt, "code": error.code,
                         "http_status": error.status, "will_retry": error.retry_stopped is None}
                if not error.retry_stopped:
                    event["delay_seconds"] = delay
                else:
                    event["retry_stopped"] = error.retry_stopped
                if len(self.diagnostics["retry_events"]) < 100:
                    self.diagnostics["retry_events"].append(event)
                else:
                    self.diagnostics["retry_events_truncated"] = True
                if error.retry_stopped:
                    raise
                self.diagnostics["read_retries"] += 1
                time.sleep(delay)

    def _request_once(self, path: str, method: str, data: bytes | None):
        if self.gh:
            args = [self.gh, "api", "--hostname", "github.com", path, "--method", method,
                    "--include", "-H", "Accept: application/vnd.github+json"]
            if data is not None:
                args += ["--input", "-"]
            try:
                result = subprocess.run(args, input=data, capture_output=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise GitHubError("TRANSPORT_TIMEOUT") from None
            except OSError:
                raise GitHubError("TRANSPORT_UNAVAILABLE") from None
            try:
                raw, header_status, retry_after = response_parts(result.stdout)
            except GitHubError:
                if not result.returncode:
                    raise
                # A transport failure can interrupt even the response headers.
                partial_status = re.match(rb"HTTP/\S+\s+(\d{3})\b", result.stdout)
                raw, header_status, retry_after = result.stdout, int(partial_status[1]) if partial_status else None, None
            if result.returncode:
                status = re.search(rb"HTTP (\d{3})", result.stderr)
                status = header_status or (int(status[1]) if status else None)
                code = "GITHUB_REQUEST_FAILED"
                response_can_be_incomplete = status is None or 200 <= status < 300
                if response_can_be_incomplete and re.search(
                    rb"(?i)timed?\s*out|timeout|context deadline exceeded|TLS handshake timeout", result.stderr
                ):
                    code = "TRANSPORT_TIMEOUT"
                elif response_can_be_incomplete and re.search(
                    rb"(?i)connection reset|connection refused|connection aborted|unexpected EOF|"
                    rb"dial tcp|network is unreachable|no such host|temporary failure in name resolution|"
                    rb"error connecting to api\.github\.com", result.stderr
                ):
                    code = "TRANSPORT_NETWORK_ERROR"
                raise GitHubError(code, status, retry_after=retry_after)
        else:
            headers = {"Accept": "application/vnd.github+json", "User-Agent": "szl-estate-ops"}
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
            if data:
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request("https://api.github.com/" + path, data=data,
                                             headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read(16 * 1024 * 1024 + 1)
                    if len(raw) > 16 * 1024 * 1024:
                        raise GitHubError("RESPONSE_TOO_LARGE")
            except urllib.error.HTTPError as error:
                raise GitHubError("GITHUB_REQUEST_FAILED", error.code,
                                  retry_after=retry_after_seconds(error.headers.get("Retry-After"))) from None
            except (TimeoutError, http.client.RemoteDisconnected, http.client.IncompleteRead):
                raise GitHubError("TRANSPORT_NETWORK_ERROR") from None
            except (urllib.error.URLError, OSError) as error:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                if isinstance(reason, TimeoutError) or getattr(reason, "errno", None) in {
                    errno.ECONNRESET, errno.ECONNREFUSED, errno.ECONNABORTED, errno.ETIMEDOUT,
                    errno.ENETUNREACH, errno.EHOSTUNREACH,
                }:
                    raise GitHubError("TRANSPORT_NETWORK_ERROR") from None
                raise GitHubError("TRANSPORT_UNAVAILABLE") from None
        try:
            value = json.loads(raw)
        except (UnicodeError, ValueError):
            raise GitHubError("INVALID_JSON_RESPONSE") from None
        if not isinstance(value, (dict, list)):
            raise GitHubError("INVALID_RESPONSE_SHAPE")
        return value

    def pages(self, path: str) -> list[dict]:
        result, fingerprints = [], set()
        separator = "&" if "?" in path else "?"
        for page in range(1, self.max_pages + 1):
            batch = self.request(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise GitHubError("INVALID_LIST_RESPONSE")
            if not batch:
                return result
            digest = hashlib.sha256(json.dumps(batch, sort_keys=True).encode()).hexdigest()
            if digest in fingerprints:
                raise GitHubError("PAGINATION_REPEATED_PAGE")
            fingerprints.add(digest)
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise GitHubError("PAGINATION_LIMIT_REACHED")

    def document(self, repo: str, path: str) -> dict:
        endpoint = f"repos/{ORG}/{repo}/contents/{path}"
        try:
            data = self.request(endpoint)
        except GitHubError as error:
            if error.status == 404:
                return {"path": path, "status": "ABSENT"}
            raise
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            raise GitHubError("INVALID_DOCUMENT_RESPONSE")
        try:
            content = base64.b64decode(data["content"]).decode("utf-8")
        except (KeyError, ValueError, UnicodeError):
            raise GitHubError("INVALID_DOCUMENT_ENCODING") from None
        return {"path": path, "status": "READ", "sha": data.get("sha"),
                "html_url": data.get("html_url"), "content": content}


def error_record(error: GitHubError) -> dict:
    result = {"code": error.code, "http_status": error.status, "attempts": error.attempts}
    if error.retry_stopped:
        result["retry_stopped"] = error.retry_stopped
    return result


def compact_repo(repo: dict) -> dict:
    keys = ("name", "full_name", "archived", "disabled", "private", "description",
            "default_branch", "has_issues", "html_url", "pushed_at", "updated_at",
            "topics", "permissions")
    return {key: repo.get(key) for key in keys}


def topic_action(client: Client, repo: str, desired: list[str], apply: bool) -> dict:
    action: dict[str, Any] = {"kind": "github_topics", "target": f"{ORG}/{repo}"}
    attempted = False
    try:
        metadata = client.request(f"repos/{ORG}/{repo}")
        before = client.request(f"repos/{ORG}/{repo}/topics").get("names")
        if not isinstance(before, list) or any(not isinstance(name, str) for name in before):
            raise GitHubError("INVALID_TOPICS_RESPONSE")
        missing = sorted(set(desired) - set(before))
        after = sorted(set(before) | set(desired))
        action.update(before=before, desired=desired, missing=missing, planned=after)
        if not missing:
            return {**action, "status": "ALREADY_CONVERGED"}
        if metadata.get("archived") or metadata.get("disabled"):
            return {**action, "status": "BLOCKED", "reason": "REPOSITORY_READ_ONLY"}
        if len(after) > 20:
            return {**action, "status": "BLOCKED", "reason": "TOPIC_LIMIT_PRESERVE_EXISTING"}
        if not apply:
            return {**action, "status": "PLANNED"}
        if not metadata.get("permissions", {}).get("admin"):
            return {**action, "status": "BLOCKED", "reason": "TOPIC_ADMIN_PERMISSION_UNVERIFIED"}
        # Recheck immediately before PUT; API is replace-all and has no atomic add.
        recheck = client.request(f"repos/{ORG}/{repo}/topics").get("names")
        if not isinstance(recheck, list) or set(recheck) != set(before):
            return {**action, "status": "BLOCKED", "reason": "CONCURRENT_DRIFT"}
        attempted = True
        write_error = None
        try:
            client.request(f"repos/{ORG}/{repo}/topics", "PUT", {"names": after})
        except GitHubError as error:
            write_error = error_record(error)
        observed = client.request(f"repos/{ORG}/{repo}/topics").get("names")
        action["observed"] = observed
        if write_error:
            action["write_error"] = write_error
        if isinstance(observed, list) and set(after) <= set(observed):
            return {**action, "status": "VERIFIED", "write_attempted": True}
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT", "write_attempted": True,
                "reason": "TOPICS_READBACK_MISMATCH"}
    except GitHubError as error:
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT" if attempted else "BLOCKED",
                "write_attempted": attempted, "error": error_record(error)}


def all_issues(client: Client) -> list[dict]:
    issues = []
    for repo in ISSUE_REPOS:
        batch = client.pages(f"repos/{ORG}/{repo}/issues?state=all&sort=created&direction=desc")
        issues.extend({**issue, "repository": repo} for issue in batch if "pull_request" not in issue)
    return issues


def issue_match(issues: list[dict], marker: str, titles: list[str]) -> dict | None:
    titles = {title.casefold() for title in titles}
    for issue in issues:
        if marker in (issue.get("body") or "") or (issue.get("title") or "").casefold() in titles:
            return issue
    return None


def reconcile_issue(client: Client, plan: dict, apply: bool) -> dict:
    action = {"kind": "github_issue", **plan}
    attempted = False
    try:
        found = issue_match(all_issues(client), plan["marker"], plan["aliases"] + [plan["title"]])
        if found:
            return {**action, "status": "ALREADY_TRACKED", "url": found["html_url"],
                    "existing_state": found["state"]}
        if not apply:
            return {**action, "status": "PLANNED"}
        target = client.request(f"repos/{ORG}/{plan['repository']}")
        if target.get("archived") or target.get("disabled") or not target.get("has_issues"):
            return {**action, "status": "BLOCKED", "reason": "ISSUE_TARGET_UNAVAILABLE"}
        # Avoid creating labels as a side effect; reuse only those already defined.
        available = {item["name"] for item in client.pages(f"repos/{ORG}/{plan['repository']}/labels")}
        labels = [name for name in plan.get("labels", []) if name in available]
        # Fresh complete search immediately before POST, including closed issues.
        found = issue_match(all_issues(client), plan["marker"], plan["aliases"] + [plan["title"]])
        if found:
            return {**action, "status": "ALREADY_TRACKED", "url": found["html_url"],
                    "existing_state": found["state"]}
        attempted = True
        response, write_error = None, None
        try:
            response = client.request(f"repos/{ORG}/{plan['repository']}/issues", "POST",
                                      {"title": plan["title"], "body": plan["body"], "labels": labels})
        except GitHubError as error:
            write_error = error_record(error)
        if write_error:
            action["write_error"] = write_error
        if response and isinstance(response.get("number"), int):
            observed = client.request(f"repos/{ORG}/{plan['repository']}/issues/{response['number']}")
        else:
            observed = issue_match(all_issues(client), plan["marker"], [plan["title"]])
        if observed and observed.get("body") == plan["body"] and observed.get("title") == plan["title"]:
            return {**action, "status": "VERIFIED", "write_attempted": True,
                    "url": observed["html_url"], "number": observed["number"], "applied_labels": labels}
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT", "write_attempted": True,
                "reason": "ISSUE_READBACK_UNVERIFIED"}
    except GitHubError as error:
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT" if attempted else "BLOCKED",
                "write_attempted": attempted, "error": error_record(error)}


def build_issue_plans(router: dict, hf_assets: list[dict] | None, timestamp: str) -> list[dict]:
    plans = []
    description = router.get("description") or ""
    if not router.get("archived") and re.search(r"\barchived\b", description, re.I):
        marker = "<!-- szl-estate:router-canonical-conflict:v1 -->"
        plans.append({"repository": "szl-platform", "marker": marker,
                      "title": "RESOLVE: szl-router canonical-status conflict",
                      "aliases": [], "labels": ["estate-audit"],
                      "body": f"{marker}\n\nObserved {timestamp}: the active [szl-router repository]"
                      f"(https://github.com/{ORG}/szl-router) currently has description `{description}` "
                      "and `archived=false`. Review its intended relationship to a11oy and reconcile "
                      "the description with the canonical registry. This issue does not authorize "
                      "archiving or redirecting source. Runtime readiness was not inferred from metadata.\n"})
    if hf_assets is not None:
        expected = {"SZLHOLDINGS/" + name for name in HF_TRIAGE}
        assets = {item.get("id"): item for item in hf_assets if item.get("id") in expected}
        if valid_hf_evidence(hf_assets, timestamp):
            unresolved = {name for name, item in assets.items() if not classified_hf_asset(item)}
            if not unresolved:
                return plans
            marker = "<!-- szl-estate:hf-lifecycle-triage:v1 -->"
            rows = []
            for name in HF_TRIAGE:
                item = assets["SZLHOLDINGS/" + name]
                if item["id"] not in unresolved:
                    continue
                sha = item["sha"]
                rows.append(f"- [ ] [{name}](https://huggingface.co/{item['id']}/tree/{sha}): "
                            f"confirm artifact type, lifecycle, source authority, and reproducible evidence "
                            f"at revision `{sha}` (observed {item['observed_at']}).")
            plans.append({"repository": "szl-platform", "marker": marker,
                          "title": f"Estate audit: clarify lifecycle for {len(unresolved)} HF assets",
                          "aliases": ["Estate audit: triage 12 unclear zero-download HF models"],
                          "labels": ["housekeeping", "estate-audit"],
                          "body": marker + "\n\nThe operationalization payload requested lifecycle review "
                          "of 12 Hugging Face repositories. The items below still need an explicit "
                          "artifact classification in the supplied fresh audit. Track decisions against "
                          "immutable revisions. A repository in the model namespace can contain kernels, "
                          "scripts, or reference fixtures; download counts do not establish artifact "
                          "quality, training completion, or production readiness.\n\n" + "\n".join(rows) +
                          "\n\nRecord KEEP / MERGE / ARCHIVE / RENAME only with supporting source and "
                          "lifecycle evidence. Record trained weights, evaluation, publication, and live "
                          "runtime separately where applicable. This issue records review work; it does "
                          "not authorize deletion or independently certify these assets.\n"})
    return plans


def classified_hf_asset(item: dict) -> bool:
    return (item.get("classification") in {"software_mirror", "training_code", "untrained_reference", "deprecated_compatibility"}
            and bool(item.get("classification_evidence")))


def valid_hf_evidence(assets: list[dict] | None, timestamp: str) -> bool:
    if not assets:
        return False
    expected = {"SZLHOLDINGS/" + name for name in HF_TRIAGE}
    records = {item.get("id"): item for item in assets if item.get("id") in expected}
    if set(records) != expected:
        return False
    now = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    for item in records.values():
        if not re.fullmatch(r"[a-f0-9]{40}", str(item.get("sha", ""))):
            return False
        try:
            observed = dt.datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00"))
            age = (now - observed).total_seconds()
        except (KeyError, TypeError, ValueError):
            return False
        if age < -60 or age > 3600:
            return False
    return True


def classify_hf_card(content: str) -> tuple[str | None, list[str]]:
    """Identify explicit author scope declarations; never infer quality from downloads."""
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    untrained = [line for line in lines if re.search(r"\b(?:status|roadmap)\b.*\bnot trained\b", line, re.I)]
    if untrained:
        return "untrained_reference", untrained[:4]
    deprecated = [line for line in lines if re.search(r"(?:repository is a \*\*tombstone|deprecated.*superseded|successor is github)", line, re.I)]
    if deprecated:
        return "deprecated_compatibility", deprecated[:4]
    training = [line for line in lines if re.search(r"(?:training (?:code|scripts)|tiny.model training sdk)", line, re.I)]
    if training:
        return "training_code", training[:4]
    mirror = [line for line in lines if re.search(
        r"(?:publish(?: / card)? mirror|hugging face mirror|hub mirror|model-type repo|"
        r"github remains the canonical|compatibility mirror|a python package)", line, re.I)]
    if mirror:
        return "software_mirror", mirror[:4]
    return None, []


def collect_hf_evidence() -> list[dict]:
    """Read only the 12 public targets and exact-revision cards, with bounded fanout.

    No HF credentials are needed for these public cards. No repository code or
    model serialization is imported or executed. HTTP failure remains unavailable.
    """
    def fetch(url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "szl-estate-ops"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise GitHubError("HF_RESPONSE_TOO_LARGE")
                return data
        except urllib.error.HTTPError as error:
            raise GitHubError("HF_EVIDENCE_REQUEST_FAILED", error.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GitHubError("HF_EVIDENCE_UNAVAILABLE") from None

    def inspect(name: str) -> dict:
        repo_id = "SZLHOLDINGS/" + name
        record = {"id": repo_id, "observed_at": dt.datetime.now(dt.timezone.utc).isoformat()}
        try:
            info = json.loads(fetch("https://huggingface.co/api/models/" + repo_id))
            if not isinstance(info, dict) or info.get("id") != repo_id:
                raise GitHubError("HF_TARGET_IDENTITY_MISMATCH")
            sha = info.get("sha")
            if not re.fullmatch(r"[a-f0-9]{40}", str(sha)):
                raise GitHubError("HF_REVISION_UNAVAILABLE")
            url = f"https://huggingface.co/{repo_id}/raw/{sha}/README.md"
            raw = fetch(url)
            content = raw.decode("utf-8")
            classification, evidence = classify_hf_card(content)
            record.update(sha=sha, card_url=url, card_sha256=hashlib.sha256(raw).hexdigest(),
                          classification=classification, classification_evidence=evidence,
                          status="VERIFIED_CARD_SCOPE" if classification else "CLASSIFICATION_UNRESOLVED")
        except GitHubError as error:
            record.update(status="UNAVAILABLE", error=error_record(error))
        except (ValueError, UnicodeError):
            record.update(status="UNAVAILABLE", error={"code": "HF_INVALID_RESPONSE", "http_status": None})
        return record

    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(inspect, HF_TRIAGE))


def run(apply: bool = False, *, client: Client | None = None,
        hf_assets: list[dict] | None = None) -> dict:
    client = client or Client()
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    report: dict[str, Any] = {"provider": "github", "observed_at": timestamp,
                              "mode": "apply" if apply else "audit", "actions": [],
                              "blockers": [], "inventory": [], "governance": {},
                              "transport_diagnostics": getattr(client, "diagnostics", {})}
    try:
        identity = client.request("user")
        report["authentication"] = {"status": "VERIFIED", "login": identity.get("login"),
                                    "transport": getattr(client, "transport", "injected")}
        repos = client.pages(f"orgs/{ORG}/repos?type=all&sort=full_name&direction=asc")
        names = [repo.get("name") for repo in repos]
        if len(set(names)) != len(names):
            raise GitHubError("DUPLICATE_INVENTORY_REPOSITORY")
        report["inventory"] = [compact_repo(repo) for repo in repos]
        report["summary"] = {"total_repos": len(repos),
                             "archived_repos": sum(bool(repo.get("archived")) for repo in repos),
                             "private_repos": sum(bool(repo.get("private")) for repo in repos),
                             "scope": "repositories visible to the authenticated principal"}
    except GitHubError as error:
        report["blockers"].append({"scope": "authentication_or_inventory", **error_record(error)})
        report["status"] = "BLOCKED"
        return report
    # A policy read failure (except genuinely absent AGENTS.md) prevents writes.
    for repo in (".github", *ISSUE_REPOS, "szl-router", *TOPICS):
        try:
            report["governance"][repo] = client.document(repo, "AGENTS.md")
        except GitHubError as error:
            report["blockers"].append({"scope": f"governance/{repo}", **error_record(error)})
    if report["blockers"]:
        report["status"] = "BLOCKED"
        return report
    for repo, desired in TOPICS.items():
        report["actions"].append(topic_action(client, repo, desired, apply))
    try:
        if hf_assets is None:
            hf_assets = collect_hf_evidence()
        report["hf_triage_evidence"] = hf_assets
        # Evidence is observed during this run, so evaluate its age after collection.
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        router = client.request(f"repos/{ORG}/szl-router")
        report["router"] = compact_repo(router)
        report["router_readme"] = client.document("szl-router", "README.md")
        destination = client.document("szl-platform", "README.md")
        report["issue_destination"] = {"repository": "szl-platform", "readme_sha": destination.get("sha"),
                                       "reason": "README declares the estate audit control plane"}
        if "estate control plane" not in destination.get("content", "").lower():
            raise GitHubError("ISSUE_DESTINATION_AUTHORITY_UNVERIFIED")
        plans = build_issue_plans(router, hf_assets, timestamp)
        if not any("router" in plan["marker"] for plan in plans):
            report["actions"].append({"kind": "github_issue", "target": "szl-router",
                                      "status": "NOT_APPLICABLE", "reason": "STALE_ROUTER_CONFLICT_ABSENT"})
        if not any("hf-lifecycle" in plan["marker"] for plan in plans):
            report["actions"].append({"kind": "github_issue", "target": "hf-lifecycle-triage",
                                      "status": "NOT_APPLICABLE" if valid_hf_evidence(hf_assets, timestamp) else "BLOCKED",
                                      "reason": "FRESH_CARDS_ALREADY_CLASSIFY_TARGETS" if valid_hf_evidence(hf_assets, timestamp)
                                      else "FRESH_HF_TARGET_EVIDENCE_REQUIRED"})
        for plan in plans:
            report["actions"].append(reconcile_issue(client, plan, apply))
    except GitHubError as error:
        report["blockers"].append({"scope": "issues", **error_record(error)})
    report["blockers"].extend(action for action in report["actions"]
                               if action["status"] in ("BLOCKED", "UNKNOWN_AFTER_ATTEMPT"))
    report["status"] = "BLOCKED" if report["blockers"] else ("PLANNED" if any(
        action["status"] == "PLANNED" for action in report["actions"]) else "VERIFIED")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("github-result.json"))
    parser.add_argument("--hf-assets", type=Path, help="JSON array with id, sha, observed_at for 12 targets")
    args = parser.parse_args()
    hf_assets = json.loads(args.hf_assets.read_text(encoding="utf-8")) if args.hf_assets else None
    report = run(args.apply, hf_assets=hf_assets)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"provider": "github", "status": report["status"],
                      "summary": report.get("summary"), "actions": [
                          {key: item[key] for key in ("kind", "target", "title", "status", "reason", "url") if key in item}
                          for item in report["actions"]], "blocker_count": len(report["blockers"])}))
    return 2 if report["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
