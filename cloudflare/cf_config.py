#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cloudflare configuration as code: read-only export and drift check.

The committed baseline lives under ``cloudflare/snapshots/<YYYY-MM-DD>/``. This
module turns Cloudflare API responses into the same normalized, secret-free
form, compares the live account with the newest baseline, and reports what
moved.

Subcommands:

  verify-snapshot  Offline. Checks a snapshot's manifest digests, its closed
                   file set and its section shapes, and scans it for secrets.
  export           Live, GET only. Writes the current configuration in snapshot
                   layout, for review before it replaces the baseline.
  drift            Live, GET only. Compares the account with the baseline and
                   writes a JSON report (plus a Markdown step summary under
                   GitHub Actions).

Exit codes: 0 MATCH (or a valid snapshot); 1 DRIFT (or an invalid snapshot);
2 usage error, including a missing token; 3 INCOMPLETE, meaning no drift was
found but at least one section could not be compared (unreadable with this
token, or the baseline marks a value as uncaptured).

The live client can only send GET requests. It sends the token from
``CLOUDFLARE_READ_TOKEN`` in one Authorization header to
https://api.cloudflare.com/client/v4 (or, in the offline tests only, to a
loopback stub), never prints it, and never writes it to a file. Standard
library only.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode, urlsplit

SNAPSHOT_SCHEMA = "szl.cloudflare-config-snapshot/v1"
REPORT_SCHEMA = "szl.cloudflare-drift-report/v1"
API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_ENV = "CLOUDFLARE_READ_TOKEN"
SNAPSHOT_ROOT = Path(__file__).resolve().parent / "snapshots"
ZONE_SECTIONS = (
    "zone",
    "dns",
    "waf_custom",
    "rate_limit",
    "config_rules",
    "bot_management",
    "monetization_rules",
)
ACCOUNT_SECTIONS = ("workers", "tunnels")
PLACEHOLDER = "$uncaptured"
STATE = "_state"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PAGES = 50
MAX_TOKEN_CHARS = 512
MAX_REPORTED_DIFFERENCES = 200
USER_AGENT = "szl-estate-os-cloudflare-drift/1"
RULESET_PHASES = {
    "waf_custom": "http_request_firewall_custom",
    "rate_limit": "http_ratelimit",
    "config_rules": "http_config_settings",
}
QUERY_KEYS = frozenset({"name", "page", "per_page", "is_deleted"})
ZONE_NAME_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
API_PATH_RE = re.compile(r"/(?:zones|accounts)(?:/[A-Za-z0-9._-]{1,128}){0,6}")
SNAPSHOT_DIR_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
VOLATILE_BOT_FIELDS = ("using_latest_model",)
VOLATILE_MONETIZATION_FIELDS = ("created_on", "modified_on", "created_at", "updated_at")
POLICY_TXT_RE = re.compile(r'^"?(?:v=spf1|v=DMARC1)(?:[\s;"]|$)', re.IGNORECASE)


class UsageError(ValueError):
    """Command-line or configuration problem (exit 2)."""


class SnapshotError(ValueError):
    """The committed snapshot is malformed or fails verification."""


class ApiError(RuntimeError):
    """A Cloudflare API read failed. The message never contains the token."""

    def __init__(self, status: int | None, code: Any, message: str) -> None:
        self.status = status
        self.code = code
        super().__init__(f"HTTP {status if status is not None else '-'} code {code}: {message}")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def placeholder(reason: str) -> dict[str, str]:
    """Marks a value the source capture did not record."""
    return {PLACEHOLDER: reason}


def is_placeholder(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {PLACEHOLDER}


# --------------------------------------------------------------------------
# Normalizers: Cloudflare API objects -> secret-free comparable form
# --------------------------------------------------------------------------


def normalize_zone(raw: dict[str, Any]) -> dict[str, Any]:
    plan = raw.get("plan")
    return {
        "name": raw["name"],
        "status": raw.get("status"),
        "type": raw.get("type"),
        "paused": raw.get("paused"),
        "plan": plan.get("name") if isinstance(plan, dict) else plan,
        "name_servers": sorted(raw.get("name_servers") or []),
    }


def normalize_dns_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Keep the record's routing meaning; digest TXT values that are not SPF/DMARC policy.

    Verification strings and DKIM keys are public DNS data, but they are
    token-like, so only their SHA-256 and length are stored.
    """
    record: dict[str, Any] = {"type": raw["type"], "name": raw["name"]}
    content = raw.get("content", "")
    if raw["type"] == "TXT" and not POLICY_TXT_RE.match(content):
        record["content_sha256"] = sha256_text(content)
        record["content_length"] = len(content)
        record["content_kind"] = "dkim" if "v=DKIM1" in content else "other"
    else:
        record["content"] = content
    record["proxied"] = bool(raw.get("proxied"))
    record["ttl"] = raw.get("ttl")
    if raw["type"] == "MX":
        record["priority"] = raw.get("priority")
    return record


def dns_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (record["type"], record["name"], str(record.get("content", record.get("content_sha256", ""))))


def normalize_rule(raw: dict[str, Any]) -> dict[str, Any]:
    """A ruleset rule without ids, versions, refs or timestamps."""
    rule: dict[str, Any] = {
        "description": raw.get("description", ""),
        "expression": raw["expression"],
        "action": raw["action"],
        "enabled": raw.get("enabled", True),
    }
    if raw.get("action_parameters"):
        rule["action_parameters"] = raw["action_parameters"]
    if raw.get("ratelimit"):
        rule["ratelimit"] = raw["ratelimit"]
    return rule


def normalize_bot_management(raw: dict[str, Any]) -> dict[str, Any]:
    settings = {key: value for key, value in raw.items() if key not in VOLATILE_BOT_FIELDS}
    state = {key: raw[key] for key in VOLATILE_BOT_FIELDS if key in raw}
    if state:
        settings[STATE] = state
    return settings


def normalize_monetization_rule(raw: dict[str, Any]) -> dict[str, Any]:
    """Every field except timestamps: a new field (for example a method list) shows as drift."""
    return {key: value for key, value in raw.items() if key not in VOLATILE_MONETIZATION_FIELDS}


def normalize_worker(name: str, settings: dict[str, Any], listing: dict[str, Any]) -> dict[str, Any]:
    bindings = []
    for binding in settings.get("bindings") or []:
        item = {"name": binding["name"], "type": binding["type"]}
        if binding["type"] == "plain_text":
            value = binding.get("text", binding.get("value"))
            if isinstance(value, str):
                item["value_sha256"] = sha256_text(value)
        bindings.append(item)
    worker: dict[str, Any] = {
        "name": name,
        "compatibility_date": settings.get("compatibility_date") or listing.get("compatibility_date"),
        "bindings": sorted(bindings, key=lambda item: (item["name"], item["type"])),
    }
    state = {key: listing[key] for key in ("created_on", "modified_on") if listing.get(key)}
    if state:
        worker[STATE] = state
    return worker


def normalize_tunnel(raw: dict[str, Any]) -> dict[str, Any]:
    connections = raw.get("connections")
    count = len(connections) if isinstance(connections, list) else raw.get("conns")
    return {"id": raw["id"], "name": raw["name"], STATE: {"status": raw.get("status"), "connections": count}}


# --------------------------------------------------------------------------
# Read-only API client
# --------------------------------------------------------------------------


def _validated_token(token: str | None) -> str:
    if not token:
        raise UsageError(f"{TOKEN_ENV} is not set")
    if len(token) > MAX_TOKEN_CHARS or not re.fullmatch(r"[A-Za-z0-9._~+/-]+={0,2}", token):
        raise UsageError(f"{TOKEN_ENV} does not look like a Cloudflare API token")
    return token


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    prefix: str


def parse_api_base(value: str) -> Endpoint:
    """The real API over HTTPS, or (tests only) a loopback stub over HTTP."""
    parts = urlsplit(value)
    if parts.query or parts.fragment or parts.username or parts.password:
        raise UsageError("--api-base must not carry credentials, a query or a fragment")
    host = parts.hostname or ""
    if parts.scheme == "https" and host == "api.cloudflare.com" and parts.port in (None, 443):
        if parts.path.rstrip("/") != "/client/v4":
            raise UsageError("--api-base must be https://api.cloudflare.com/client/v4")
        return Endpoint("https", host, 443, "/client/v4")
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if parts.scheme == "http" and loopback and parts.port:
        return Endpoint("http", host, parts.port, parts.path.rstrip("/"))
    raise UsageError("--api-base must be https://api.cloudflare.com/client/v4 or a loopback http:// test stub")


class ReadOnlyClient:
    """GET-only Cloudflare API client. There is deliberately no other method."""

    def __init__(self, token: str, base: str = API_BASE, timeout: int = 30) -> None:
        self._token = _validated_token(token)
        self._endpoint = parse_api_base(base)
        self._timeout = timeout
        self.requests = 0

    def get(self, path: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
        if not API_PATH_RE.fullmatch(path) or any(segment in (".", "..") for segment in path.split("/")):
            raise ApiError(None, "invalid_path", "refusing an unexpected API path")
        query = query or {}
        if set(query) - QUERY_KEYS:
            raise ApiError(None, "invalid_query", "refusing an unexpected query parameter")
        target = self._endpoint.prefix + path
        if query:
            target += "?" + urlencode(sorted(query.items()))
        if self._endpoint.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                self._endpoint.host, self._endpoint.port, timeout=self._timeout, context=ssl.create_default_context()
            )
        else:
            connection = http.client.HTTPConnection(self._endpoint.host, self._endpoint.port, timeout=self._timeout)
        self.requests += 1
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Authorization": "Bearer " + self._token,
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            raise ApiError(None, "transport", type(exc).__name__) from None
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ApiError(status, "too_large", "response larger than 8 MiB")
        try:
            document = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ApiError(status, "not_json", "response is not JSON") from None
        if not isinstance(document, dict):
            raise ApiError(status, "not_object", "response is not a JSON object")
        if status != 200 or document.get("success") is not True:
            errors = document.get("errors") if isinstance(document.get("errors"), list) else []
            first = errors[0] if errors and isinstance(errors[0], dict) else {}
            message = str(first.get("message", "request failed"))[:200]
            raise ApiError(status, first.get("code"), message)
        return document

    def get_all(self, path: str, query: dict[str, Any] | None = None, per_page: int = 100) -> list[Any]:
        items: list[Any] = []
        page = 1
        while True:
            document = self.get(path, {**(query or {}), "page": page, "per_page": per_page})
            result = document.get("result")
            if not isinstance(result, list):
                raise ApiError(200, "not_list", "paginated result is not a list")
            items.extend(result)
            info = document.get("result_info") if isinstance(document.get("result_info"), dict) else {}
            total_pages = info.get("total_pages")
            total_count = info.get("total_count")
            if isinstance(total_pages, int):
                more = page < total_pages
            elif isinstance(total_count, int):
                more = len(items) < total_count and bool(result)
            else:
                more = False
            if not more:
                return items
            page += 1
            if page > MAX_PAGES:
                raise ApiError(200, "too_many_pages", f"more than {MAX_PAGES} pages")


# --------------------------------------------------------------------------
# Live export
# --------------------------------------------------------------------------


def _zone_record(client: ReadOnlyClient, zone: str) -> dict[str, Any]:
    result = client.get("/zones", {"name": zone}).get("result")
    matches = [item for item in result or [] if isinstance(item, dict) and item.get("name") == zone]
    if len(matches) != 1:
        raise ApiError(200, "zone_not_found", f"{len(matches)} zones named {zone} are visible to this token")
    return matches[0]


def _ruleset_rules(client: ReadOnlyClient, zone_id: str, phase: str) -> list[dict[str, Any]]:
    try:
        document = client.get(f"/zones/{zone_id}/rulesets/phases/{phase}/entrypoint")
    except ApiError as exc:
        if exc.status == 404:
            return []  # no entry point ruleset: the phase has no rules
        raise
    return [normalize_rule(rule) for rule in (document.get("result") or {}).get("rules") or []]


def _monetization_rules(client: ReadOnlyClient, zone_id: str) -> list[dict[str, Any]]:
    try:
        document = client.get(f"/zones/{zone_id}/monetization/rules")
    except ApiError as exc:
        if exc.status == 404 and exc.code == 10005:
            return []  # "payment rule not found": the zone has no rules
        raise
    rules = (document.get("result") or {}).get("rules") or []
    return sorted((normalize_monetization_rule(rule) for rule in rules), key=lambda rule: rule["id"])


def export_live(client: ReadOnlyClient, zones: list[str], account_sections: bool = True) -> dict[str, Any]:
    """Read every section. Each section is {"data": ...} or {"error": "..."}."""
    exported: dict[str, Any] = {}
    account_ids: set[str] = set()
    for zone in zones:
        scope: dict[str, Any] = {}
        exported[f"zone:{zone}"] = scope
        try:
            record = _zone_record(client, zone)
        except ApiError as exc:
            for section in ZONE_SECTIONS:
                scope[section] = {"error": f"zone lookup failed: {exc}"}
            continue
        zone_id = str(record.get("id", ""))
        account = record.get("account") if isinstance(record.get("account"), dict) else {}
        if account.get("id"):
            account_ids.add(str(account["id"]))
        readers: dict[str, Callable[[], Any]] = {
            "zone": lambda: normalize_zone(record),
            "dns": lambda: sorted(
                (normalize_dns_record(item) for item in client.get_all(f"/zones/{zone_id}/dns_records")),
                key=dns_sort_key,
            ),
            "waf_custom": lambda: _ruleset_rules(client, zone_id, RULESET_PHASES["waf_custom"]),
            "rate_limit": lambda: _ruleset_rules(client, zone_id, RULESET_PHASES["rate_limit"]),
            "config_rules": lambda: _ruleset_rules(client, zone_id, RULESET_PHASES["config_rules"]),
            "bot_management": lambda: normalize_bot_management(
                client.get(f"/zones/{zone_id}/bot_management").get("result") or {}
            ),
            "monetization_rules": lambda: _monetization_rules(client, zone_id),
        }
        for section in ZONE_SECTIONS:
            try:
                scope[section] = {"data": readers[section]()}
            except ApiError as exc:
                scope[section] = {"error": str(exc)}
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                scope[section] = {"error": f"unexpected API response shape ({type(exc).__name__})"}
    if not account_sections:
        return exported
    account_scope: dict[str, Any] = {}
    exported["account"] = account_scope
    if len(account_ids) != 1:
        reason = "no zone lookup returned an account id" if not account_ids else "zones belong to different accounts"
        for section in ACCOUNT_SECTIONS:
            account_scope[section] = {"error": reason}
        return exported
    account_id = account_ids.pop()
    try:
        workers = []
        listing = client.get(f"/accounts/{account_id}/workers/scripts").get("result") or []
        for script in listing:
            name = script.get("id")
            if not isinstance(name, str) or not name:
                raise ApiError(200, "bad_listing", "a Worker script has no id")
            settings = client.get(f"/accounts/{account_id}/workers/scripts/{quote(name, safe='')}/settings")
            workers.append(normalize_worker(name, settings.get("result") or {}, script))
        account_scope["workers"] = {"data": sorted(workers, key=lambda item: item["name"])}
    except ApiError as exc:
        account_scope["workers"] = {"error": str(exc)}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        account_scope["workers"] = {"error": f"unexpected API response shape ({type(exc).__name__})"}
    try:
        tunnels = client.get_all(f"/accounts/{account_id}/cfd_tunnel", {"is_deleted": "false"})
        account_scope["tunnels"] = {
            "data": sorted((normalize_tunnel(item) for item in tunnels), key=lambda item: item["name"])
        }
    except ApiError as exc:
        account_scope["tunnels"] = {"error": str(exc)}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        account_scope["tunnels"] = {"error": f"unexpected API response shape ({type(exc).__name__})"}
    return exported


# --------------------------------------------------------------------------
# Snapshot files
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.")
_TOKEN_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]{40}(?![A-Za-z0-9_-]))"
    r"(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{40}"
)
_FORBIDDEN_KEY_RE = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|private[_-]?key|credential)")


def scope_filename(scope: str) -> str:
    if scope == "account":
        return "account.json"
    zone = scope.split(":", 1)[1]
    return f"zones/{zone}.json"


def write_snapshot(directory: Path, scopes: dict[str, dict[str, Any]], manifest_extra: dict[str, Any]) -> dict[str, Any]:
    """Write scope files plus a manifest that binds each file's SHA-256."""
    directory.mkdir(parents=True, exist_ok=True)
    files: dict[str, Any] = {}
    for scope in sorted(scopes):
        relative = scope_filename(scope)
        data = canonical_bytes({"scope": scope, "sections": scopes[scope]})
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(target, data)
        files[relative] = {
            "scope": scope,
            "sha256": hashlib.sha256(data).hexdigest(),
            "sections": sorted(scopes[scope]),
        }
    manifest = {"schema": SNAPSHOT_SCHEMA, "files": files, **manifest_extra}
    _atomic_write(directory / "manifest.json", canonical_bytes(manifest))
    return manifest


def _atomic_write(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _walk(value: Any, path: str = "$"):
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


def secret_findings(document: Any) -> list[str]:
    """Patterns that must never appear in a committed snapshot."""
    findings = []
    for path, value in _walk(document):
        if isinstance(value, dict):
            for key in value:
                if _FORBIDDEN_KEY_RE.search(key):
                    findings.append(f"{path}: forbidden key {key!r}")
            if value.get("type") == "TXT" and "content" in value and not POLICY_TXT_RE.match(str(value["content"])):
                findings.append(f"{path}: TXT content that is not SPF/DMARC policy must be digested")
            if value.get("type") == "plain_text" and ("value" in value or "text" in value):
                findings.append(f"{path}: plain_text binding values must be digested")
        elif isinstance(value, str):
            if "-----BEGIN" in value:
                findings.append(f"{path}: PEM block")
            if re.search(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}", value):
                findings.append(f"{path}: bearer credential")
            if _JWT_RE.search(value):
                findings.append(f"{path}: JWT-like value")
            if _EMAIL_RE.search(value):
                findings.append(f"{path}: e-mail address")
            if _TOKEN_LIKE_RE.search(value):
                findings.append(f"{path}: 40-character token-like value")
    return findings


_REQUIRED_ITEM_KEYS = {
    "dns": ("type", "name"),
    "waf_custom": ("expression", "action"),
    "rate_limit": ("expression", "action"),
    "config_rules": ("expression", "action"),
    "monetization_rules": ("id",),
    "workers": ("name",),
    "tunnels": ("id", "name"),
}


def _check_section_shape(scope: str, section: str, data: Any) -> list[str]:
    if section in ("zone", "bot_management"):
        return [] if isinstance(data, dict) else [f"{scope}/{section}: data must be an object"]
    if not isinstance(data, list):
        return [f"{scope}/{section}: data must be a list"]
    problems = []
    keys = _REQUIRED_ITEM_KEYS[section]
    seen: set[Any] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict) or any(key not in item for key in keys):
            problems.append(f"{scope}/{section}[{index}]: an item needs {', '.join(keys)}")
            continue
        if section in ("monetization_rules", "workers", "tunnels"):
            identity = item[keys[0]]
            if identity in seen:
                problems.append(f"{scope}/{section}: duplicate {keys[0]} {identity!r}")
            seen.add(identity)
    return problems


def load_snapshot(directory: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Verify and load a snapshot. Raises SnapshotError with every problem found."""
    problems: list[str] = []
    manifest_path = directory / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SnapshotError(f"{manifest_path}: unreadable manifest ({type(exc).__name__})") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != SNAPSHOT_SCHEMA:
        raise SnapshotError(f"{manifest_path}: schema must be {SNAPSHOT_SCHEMA}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise SnapshotError(f"{manifest_path}: files must be a non-empty object")
    scopes: dict[str, dict[str, Any]] = {}
    present = {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(present - set(files) - {"manifest.json"})
    if unexpected:
        problems.append(f"files not bound by the manifest: {', '.join(unexpected)}")
    for relative, entry in sorted(files.items()):
        target = directory / relative
        if not isinstance(entry, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            problems.append(f"{relative}: manifest entry needs a sha256")
            continue
        try:
            data = target.read_bytes()
        except OSError:
            problems.append(f"{relative}: missing")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            problems.append(f"{relative}: sha256 {digest} does not match the manifest {entry['sha256']}")
            continue
        try:
            document = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            problems.append(f"{relative}: not JSON")
            continue
        scope = document.get("scope") if isinstance(document, dict) else None
        if scope != entry.get("scope") or relative != scope_filename(str(scope)):
            problems.append(f"{relative}: scope {scope!r} does not match its manifest entry or file name")
            continue
        allowed = ACCOUNT_SECTIONS if scope == "account" else ZONE_SECTIONS
        sections = document.get("sections")
        if not isinstance(sections, dict) or sorted(sections) != sorted(entry.get("sections") or []):
            problems.append(f"{relative}: sections do not match the manifest")
            continue
        loaded: dict[str, Any] = {}
        for section, body in sections.items():
            if section not in allowed:
                problems.append(f"{relative}: unknown section {section!r}")
                continue
            if not isinstance(body, dict) or "data" not in body or "error" in body:
                problems.append(f"{relative}/{section}: a baseline section needs data and no error")
                continue
            if not isinstance(body.get("captured"), dict):
                problems.append(f"{relative}/{section}: captured provenance missing")
            problems.extend(_check_section_shape(scope, section, body["data"]))
            loaded[section] = body["data"]
        for finding in secret_findings(document):
            problems.append(f"{relative}: {finding}")
        scopes[scope] = loaded
    for finding in secret_findings(manifest):
        problems.append(f"manifest.json: {finding}")
    if problems:
        raise SnapshotError("\n".join(problems))
    return manifest, scopes


def latest_snapshot(root: Path = SNAPSHOT_ROOT) -> Path:
    candidates = sorted(path for path in root.iterdir() if path.is_dir() and SNAPSHOT_DIR_RE.fullmatch(path.name))
    if not candidates:
        raise UsageError(f"no dated snapshot directory under {root}")
    return candidates[-1]


# --------------------------------------------------------------------------
# Drift comparison
# --------------------------------------------------------------------------

_MISSING = object()


def _compare(baseline: Any, live: Any, path: str, differences: list, gaps: list) -> None:
    if is_placeholder(baseline):
        gaps.append({"path": path, "reason": baseline[PLACEHOLDER], "live": "<absent>" if live is _MISSING else live})
        return
    if baseline is _MISSING:
        differences.append({"path": path, "change": "added", "live": live})
        return
    if live is _MISSING:
        differences.append({"path": path, "change": "removed", "baseline": baseline})
        return
    if isinstance(baseline, dict) and isinstance(live, dict):
        for key in sorted(set(baseline) | set(live)):
            if key == STATE:
                continue
            _compare(baseline.get(key, _MISSING), live.get(key, _MISSING), f"{path}.{key}", differences, gaps)
        return
    if isinstance(baseline, list) and isinstance(live, list) and len(baseline) == len(live):
        for index, (left, right) in enumerate(zip(baseline, live)):
            _compare(left, right, f"{path}[{index}]", differences, gaps)
        return
    if baseline != live or type(baseline) is not type(live):
        differences.append({"path": path, "change": "changed", "baseline": baseline, "live": live})


def _without_state(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: item for key, item in value.items() if key != STATE}
    return value


def _matches(baseline: Any, live: Any) -> bool:
    differences: list = []
    _compare(baseline, live, "$", differences, [])
    return not differences


def _pair(baseline: list[Any], live: list[Any]) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Pair equal items: exact matches first, then placeholder-tolerant ones."""
    used: set[int] = set()
    pairs: dict[int, int] = {}
    for strict in (True, False):
        for b_index, item in enumerate(baseline):
            if b_index in pairs:
                continue
            for l_index, candidate in enumerate(live):
                if l_index in used:
                    continue
                if (_without_state(item) == _without_state(candidate)) if strict else _matches(item, candidate):
                    pairs[b_index] = l_index
                    used.add(l_index)
                    break
    removed = [index for index in range(len(baseline)) if index not in pairs]
    added = [index for index in range(len(live)) if index not in used]
    return sorted(pairs.items()), removed, added


def _label(section: str, item: Any) -> str:
    if not isinstance(item, dict):
        return json.dumps(item, sort_keys=True)[:120]
    if section == "dns":
        value = item.get("content", f"sha256:{str(item.get('content_sha256', ''))[:12]}")
        return f"{item.get('type')} {item.get('name')} {value}"
    for key in ("description", "name", "id"):
        if item.get(key):
            return str(item[key])[:120]
    return json.dumps(item, sort_keys=True)[:120]


def compare_section(section: str, baseline: Any, live: Any) -> dict[str, Any]:
    differences: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    state_changes: list[dict[str, Any]] = []
    if section in ("zone", "bot_management"):
        _compare(baseline, live, section, differences, gaps)
        if isinstance(baseline, dict) and isinstance(live, dict) and baseline.get(STATE) != live.get(STATE):
            state_changes.append({"path": f"{section}.{STATE}", "baseline": baseline.get(STATE), "live": live.get(STATE)})
    elif section in ("monetization_rules", "workers", "tunnels"):
        key = "name" if section == "workers" else "id"
        old = {item[key]: item for item in baseline}
        new = {item[key]: item for item in live}
        for name in sorted(set(old) | set(new)):
            path = f"{section}[{name}]"
            if name not in new:
                differences.append({"path": path, "change": "removed", "baseline": old[name]})
            elif name not in old:
                differences.append({"path": path, "change": "added", "live": new[name]})
            else:
                _compare(old[name], new[name], path, differences, gaps)
                if old[name].get(STATE) != new[name].get(STATE):
                    state_changes.append(
                        {"path": f"{path}.{STATE}", "baseline": old[name].get(STATE), "live": new[name].get(STATE)}
                    )
    else:  # dns (multiset) and ordered rule lists
        pairs, removed, added = _pair(baseline, live)
        for b_index, l_index in pairs:
            _compare(baseline[b_index], live[l_index], f"{section}[{_label(section, baseline[b_index])}]", [], gaps)
        for index in removed:
            differences.append(
                {"path": f"{section}[{_label(section, baseline[index])}]", "change": "removed", "baseline": baseline[index]}
            )
        for index in added:
            differences.append(
                {"path": f"{section}[{_label(section, live[index])}]", "change": "added", "live": live[index]}
            )
        if section != "dns" and not removed and not added:
            order = [l_index for _, l_index in pairs]
            if order != sorted(order):
                differences.append(
                    {
                        "path": section,
                        "change": "reordered",
                        "baseline": [_label(section, item) for item in baseline],
                        "live": [_label(section, item) for item in live],
                    }
                )
    status = "drift" if differences else ("baseline-gap" if gaps else "match")
    return {
        "status": status,
        "differences": differences[:MAX_REPORTED_DIFFERENCES],
        "differences_total": len(differences),
        "gaps": gaps,
        "state_changes": state_changes,
    }


def drift_report(
    baseline_dir: Path, manifest: dict[str, Any], baseline: dict[str, dict[str, Any]], live: dict[str, Any]
) -> dict[str, Any]:
    sections = []
    for scope in sorted(baseline):
        for section in sorted(baseline[scope]):
            row: dict[str, Any] = {"scope": scope, "section": section}
            observed = live.get(scope, {}).get(section)
            if observed is None:
                row.update({"status": "unverified", "error": "section was not read"})
            elif "error" in observed:
                row.update({"status": "unverified", "error": observed["error"]})
            else:
                row.update(compare_section(section, baseline[scope][section], observed["data"]))
            sections.append(row)
    statuses = [row["status"] for row in sections]
    if "drift" in statuses:
        verdict, code = "DRIFT", 1
    elif "unverified" in statuses or "baseline-gap" in statuses:
        verdict, code = "INCOMPLETE", 3
    else:
        verdict, code = "MATCH", 0
    counts = {name: statuses.count(name) for name in ("match", "drift", "baseline-gap", "unverified")}
    return {
        "schema": REPORT_SCHEMA,
        "verdict": verdict,
        "exit_code": code,
        "baseline": {
            "directory": baseline_dir.as_posix(),
            "snapshot": manifest.get("snapshot"),
            "manifest_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
        },
        "summary": counts,
        "sections": sections,
    }


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        f"## Cloudflare config drift: {report['verdict']}",
        "",
        f"Baseline `{report['baseline']['directory']}`. Sections: "
        + ", ".join(f"{count} {name}" for name, count in report["summary"].items()),
        "",
        "| Scope | Section | Status | Detail |",
        "|---|---|---|---|",
    ]
    for row in report["sections"]:
        if row["status"] == "unverified":
            detail = row.get("error", "")
        else:
            detail = (
                f"{row['differences_total']} difference(s), {len(row['gaps'])} uncaptured, "
                f"{len(row['state_changes'])} state change(s)"
            )
        lines.append(f"| {row['scope']} | {row['section']} | {row['status']} | {str(detail).replace('|', '/')} |")
    details = [
        f"- `{row['scope']}` {item['change']} `{item['path']}`"
        for row in report["sections"]
        for item in row.get("differences", [])[:20]
    ]
    if details:
        lines += ["", "### Differences (first 20 per section)", "", *details]
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _baseline_zones(baseline: dict[str, dict[str, Any]]) -> list[str]:
    zones = sorted(scope.split(":", 1)[1] for scope in baseline if scope.startswith("zone:"))
    for zone in zones:
        if not ZONE_NAME_RE.fullmatch(zone):
            raise UsageError(f"invalid zone name in baseline: {zone!r}")
    return zones


def _client_from_environment(api_base: str) -> ReadOnlyClient:
    return ReadOnlyClient(os.environ.get(TOKEN_ENV, ""), base=api_base)


def _live_scopes(exported: dict[str, Any], captured_at: str) -> dict[str, dict[str, Any]]:
    scopes: dict[str, dict[str, Any]] = {}
    for scope, sections in exported.items():
        scopes[scope] = {}
        for section, body in sections.items():
            entry: dict[str, Any] = {"captured": {"source": "api.cloudflare.com/client/v4 (GET)", "at": captured_at}}
            if "error" in body:
                entry.update({"data": None, "error": body["error"]})
            else:
                entry["data"] = body["data"]
            scopes[scope][section] = entry
    return scopes


def command_verify(args: argparse.Namespace) -> int:
    directory = Path(args.snapshot) if args.snapshot else latest_snapshot()
    try:
        manifest, scopes = load_snapshot(directory)
    except SnapshotError as exc:
        print(f"snapshot {directory} INVALID:\n{exc}", file=sys.stderr)
        return 1
    sections = sum(len(item) for item in scopes.values())
    print(f"snapshot {directory} OK: {len(manifest['files'])} files, {sections} sections, no secret patterns")
    return 0


def command_export(args: argparse.Namespace) -> int:
    zones = args.zone or _baseline_zones(load_snapshot(latest_snapshot())[1])
    client = _client_from_environment(args.api_base)
    started = utc_now()
    exported = export_live(client, zones)
    scopes = _live_scopes(exported, started)
    errors = [f"{scope}/{section}" for scope, sections in exported.items() for section, body in sections.items() if "error" in body]
    write_snapshot(
        Path(args.out),
        scopes,
        {
            "snapshot": Path(args.out).name,
            "generated_by": "cloudflare/cf_config.py export",
            "captured_at": started,
            "unreadable_sections": errors,
        },
    )
    print(f"exported {sum(len(s) for s in scopes.values())} sections to {args.out} with {client.requests} GET requests")
    if errors:
        print("unreadable sections (not a valid baseline until fixed): " + ", ".join(errors), file=sys.stderr)
        return 3
    return 0


def command_drift(args: argparse.Namespace) -> int:
    directory = Path(args.snapshot) if args.snapshot else latest_snapshot()
    try:
        manifest, baseline = load_snapshot(directory)
    except SnapshotError as exc:
        print(f"baseline {directory} INVALID:\n{exc}", file=sys.stderr)
        return 1
    client = _client_from_environment(args.api_base)
    started = utc_now()
    exported = export_live(client, _baseline_zones(baseline), account_sections="account" in baseline)
    report = drift_report(directory, manifest, baseline, exported)
    report["started_at"] = started
    report["completed_at"] = utc_now()
    report["api_requests"] = client.requests
    _atomic_write(Path(args.report), canonical_bytes(report))
    if args.export_dir:
        write_snapshot(
            Path(args.export_dir),
            _live_scopes(exported, started),
            {"snapshot": "live-export", "generated_by": "cloudflare/cf_config.py drift", "captured_at": started},
        )
    for row in report["sections"]:
        detail = row.get("error") or f"{row.get('differences_total', 0)} differences, {len(row.get('gaps', []))} uncaptured"
        print(f"{row['status']:<12} {row['scope']:<24} {row['section']:<20} {detail}")
    print(f"cloudflare drift {report['verdict']} against {directory} ({client.requests} GET requests); report {args.report}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(render_summary(report))
    return report["exit_code"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-snapshot", help="offline integrity and secret check of a snapshot")
    verify.add_argument("--snapshot", help="snapshot directory (default: newest under cloudflare/snapshots)")
    export = sub.add_parser("export", help="write the live configuration in snapshot layout")
    export.add_argument("--out", required=True, help="output directory")
    export.add_argument("--zone", action="append", help="zone to export (default: the baseline's zones)")
    export.add_argument("--api-base", default=API_BASE, help=argparse.SUPPRESS)
    drift = sub.add_parser("drift", help="compare the live configuration with the baseline")
    drift.add_argument("--snapshot", help="baseline directory (default: newest under cloudflare/snapshots)")
    drift.add_argument("--report", default="outputs/cloudflare-drift.json", help="JSON report path")
    drift.add_argument("--export-dir", help="also write the live export here, for a reviewed baseline refresh")
    drift.add_argument("--api-base", default=API_BASE, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    handlers = {"verify-snapshot": command_verify, "export": command_export, "drift": command_drift}
    try:
        return handlers[args.command](args)
    except UsageError as exc:
        print(f"cf_config: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
