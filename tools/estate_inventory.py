"""Read-only registry census; stdlib only. Partial enumeration exits 2.

Visible pagination is not organization access, security, training or readiness.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 20_000_000
MAX_PAGES = 1000
ALLOWED_HOSTS = {"api.github.com", "huggingface.co"}
KNOWN_FLAGSHIPS = {
    "a11oy", "szl-receipt", "governed-receipt-spec", "hatun-mcp",
    "lutar-lean", "killinchu", "szl-khipu", "szl-atelier", "immune",
}


class InventoryError(Exception):
    """Safe machine codes only: never response bodies, URLs or credentials."""


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_url(url, origin=None):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise InventoryError("UNTRUSTED_API_URL") from None
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS
            or parsed.username or parsed.password or port not in (None, 443)
            or parsed.fragment or (origin and parsed.hostname != origin)):
        raise InventoryError("UNTRUSTED_API_URL")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InventoryError("API_REDIRECT_REJECTED")


def request_json(url, token="", timeout=30):
    validate_url(url)
    headers = {"User-Agent": "szl-estate-inventory/2", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            payload = response.read(MAX_BYTES + 1)
            if len(payload) > MAX_BYTES:
                raise InventoryError("RESPONSE_TOO_LARGE")
            return json.loads(payload), {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        raise InventoryError(f"HTTP_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        raise InventoryError("NETWORK_ERROR") from None
    except (ValueError, UnicodeError):
        raise InventoryError("INVALID_JSON") from None


def next_link(header):
    if not isinstance(header, str):
        raise InventoryError("INVALID_PAGINATION_LINK")
    if not header:
        return None
    matches = []
    # Split only between link-values, preserving commas inside URI references.
    for segment in re.split(r',\s*(?=<)', header):
        match = re.fullmatch(r'\s*<([^<>]+)>((?:\s*;\s*[A-Za-z0-9_-]+\s*=\s*(?:"[^"\r\n]*"|[^;\s,"<>]+))*)\s*', segment)
        if not match:
            raise InventoryError("INVALID_PAGINATION_LINK")
        target, parameters = match.groups()
        relations = re.findall(r';\s*rel\s*=\s*(?:"([^"]+)"|([^;\s,]+))', parameters, re.I)
        if len(relations) != 1:
            raise InventoryError("INVALID_PAGINATION_LINK")
        if "next" in (relations[0][0] or relations[0][1]).split():
            matches.append(target)
    if len(matches) > 1:
        raise InventoryError("INVALID_PAGINATION_LINK")
    return matches[0] if matches else None


def collect_pages(url, token, identity="id", fetch=request_json, max_pages=MAX_PAGES):
    """Preserve good pages on error; follow provider cursors with origin checks."""
    items, errors, visited, seen = [], [], set(), set()
    pages, complete = 0, False
    origin = None
    try:
        validate_url(url)
        origin = urllib.parse.urlsplit(url).hostname
        while url:
            validate_url(url, origin)
            if url in visited:
                raise InventoryError("PAGINATION_CYCLE")
            if pages >= max_pages:
                raise InventoryError("PAGE_LIMIT")
            visited.add(url)
            data, headers = fetch(url, token)
            if not isinstance(data, list):
                raise InventoryError("LIST_SHAPE_INVALID")
            pages += 1
            for item in data:
                if (not isinstance(item, dict) or type(item.get(identity)) not in (str, int)
                        or (identity == "slug" and not isinstance(item.get(identity), str))):
                    raise InventoryError("ITEM_ID_INVALID")
                item_id = str(item[identity])
                if not item_id or item_id in seen:
                    raise InventoryError("DUPLICATE_OR_EMPTY_ID")
                seen.add(item_id)
                items.append(item)
            link = next_link(headers.get("link", headers.get("Link", "")))
            try:
                url = urllib.parse.urljoin(url, link) if link else None
            except ValueError:
                raise InventoryError("UNTRUSTED_API_URL") from None
            complete = url is None
    except InventoryError as exc:
        errors.append({"code": str(exc), "page": pages + 1})
    return items, {"status": "COMPLETE_VISIBLE_LISTING" if complete else "PARTIAL",
                   "pages": pages, "observed": len(items), "complete": complete, "errors": errors}


def truth_fields():
    return {"evidence_class": "OBSERVED_METADATA", "runtime_state": "UNVERIFIED",
            "signer_state": "UNVERIFIED", "authorization": "READ_ONLY_INVENTORY",
            "publication_eligibility": "UNVERIFIED"}


def github_record(item):
    if item.get("license") is not None and not isinstance(item["license"], dict):
        raise InventoryError("ITEM_SHAPE_INVALID")
    archived, name = item.get("archived") is True, item.get("name")
    # Canonical links and popularity never establish retirement or readiness.
    status = "ARCHIVED" if archived else "FLAGSHIP" if name in KNOWN_FLAGSHIPS else "UNCLASSIFIED"
    return {
        "name": name, "full_name": item.get("full_name"), "platform": "github",
        "type": "repository", "url": item.get("html_url"), "archived": archived,
        "fork": item.get("fork"), "visibility": item.get("visibility"),
        "default_branch": item.get("default_branch"), "revision": None,
        "pushed_at": item.get("pushed_at"), "updated_at": item.get("updated_at"),
        "language": item.get("language"), "license": (item.get("license") or {}).get("spdx_id"),
        "stargazers_count": item.get("stargazers_count"), "status": status,
        "status_basis": "PROVIDER_ARCHIVED_FLAG" if archived else "LOCAL_TAXONOMY_ONLY",
        "canonical_successor": None, "readme_flags": [],
        "artifact_classification": "SOURCE_REPOSITORY",
        "blockers": ["IMMUTABLE_REVISION_NOT_COLLECTED", "FILE_AUDIT_NOT_PERFORMED"],
        **truth_fields(),
    }


def hf_record(item, kind):
    asset_id = item.get("id")
    prefix = {"model": "", "dataset": "datasets/", "space": "spaces/"}[kind]
    tags, siblings = item.get("tags") or [], item.get("siblings") or []
    runtime = item.get("runtime") or {}
    if not isinstance(tags, list) or not isinstance(siblings, list) or not isinstance(runtime, dict):
        raise InventoryError("ITEM_SHAPE_INVALID")
    return {
        "id": asset_id, "kind": kind, "type": kind, "platform": "huggingface",
        "url": f"https://huggingface.co/{prefix}{asset_id}",
        "visibility": "private" if item.get("private") is True else "public" if item.get("private") is False else "UNKNOWN",
        "revision": item.get("sha"), "last_modified": item.get("lastModified"),
        "downloads": item.get("downloads"), "likes": item.get("likes"),
        "license": [t[8:] for t in tags if isinstance(t, str) and t.startswith("license:")],
        "framework": item.get("sdk") or item.get("library_name"),
        "files": [{"path": s.get("rfilename"), "size": s.get("size")} for s in siblings if isinstance(s, dict)],
        "file_inventory": "LISTING_METADATA_ONLY", "status": "UNCLASSIFIED",
        "artifact_classification": "UNVERIFIED", "provider_runtime_stage": runtime.get("stage"),
        "blockers": ["FILE_AUDIT_NOT_PERFORMED"], **truth_fields(),
    }


def normalize_records(items, coverage, convert):
    records = []
    for item in items:
        try:
            records.append(convert(item))
        except (InventoryError, TypeError, ValueError, AttributeError, KeyError):
            coverage.update(status="PARTIAL", complete=False)
            coverage["errors"].append({"code": "ITEM_SHAPE_INVALID"})
    coverage["normalized"] = len(records)
    return records


def build_inventory(github_org, hf_org, gh_token, hf_token, fetch=request_json, max_pages=MAX_PAGES):
    for owner in (github_org, hf_org):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", owner):
            raise InventoryError("INVALID_ORGANIZATION")
    observed_at = utc_now()
    github, gh_coverage = collect_pages(
        f"https://api.github.com/orgs/{github_org}/repos?type=all&per_page=100&sort=full_name",
        gh_token or "", fetch=fetch, max_pages=max_pages)
    coverage, assets = {"github": gh_coverage}, []
    for plural, kind in (("models", "model"), ("datasets", "dataset"), ("spaces", "space")):
        params = urllib.parse.urlencode({"author": hf_org, "limit": 100, "full": "true"})
        records, coverage[plural] = collect_pages(
            f"https://huggingface.co/api/{plural}?{params}", hf_token or "", fetch=fetch, max_pages=max_pages)
        assets.extend(normalize_records(records, coverage[plural], lambda item: hf_record(item, kind)))
    params = urllib.parse.urlencode({"owner": hf_org, "limit": 100})
    collections, coverage["collections"] = collect_pages(
        f"https://huggingface.co/api/collections?{params}", hf_token or "",
        identity="slug", fetch=fetch, max_pages=max_pages)
    repos = normalize_records(github, gh_coverage, github_record)
    complete = all(item["complete"] for item in coverage.values())
    return {
        "schema": "szl.estate-registry-inventory/v2", "generated_at_utc": observed_at,
        "completed_at_utc": utc_now(), "github_org": github_org, "hf_org": hf_org,
        "status": "COMPLETE_VISIBLE_LISTING" if complete else "PARTIAL",
        "authorization": "READ_ONLY_INVENTORY", "signer_state": "UNSIGNED",
        "scope": {"github": "AUTHENTICATED_VISIBILITY_UNKNOWN" if gh_token else "PUBLIC_ONLY",
                  "huggingface": "AUTHENTICATED_VISIBILITY_UNKNOWN" if hf_token else "PUBLIC_ONLY"},
        "coverage": coverage,
        "limitations": [
            "Visible pagination does not establish full organization access or snapshot stability.",
            "Metadata does not establish runtime readiness, authority, training, security or publication eligibility.",
            "GitHub immutable revisions, branches, file contents and deployment contracts require the deep Estate OS audit.",
            "Partial counts are observed lower bounds, not complete totals.",
        ],
        "summary": {
            "total_repos": len(repos), "archived_repos": sum(r["archived"] for r in repos),
            "retired_repos": 0, "flagship_repos": sum(r["status"] == "FLAGSHIP" for r in repos),
            "total_hf_assets": len(assets), "total_collections": len(collections),
            "zero_download_hf_assets": sum(a["downloads"] == 0 for a in assets if a["kind"] != "space"),
            "download_metric_unavailable": sum(a["downloads"] is None for a in assets if a["kind"] != "space"),
        },
        "github_repos": repos, "hf_assets": assets,
        "collections": [{"slug": c.get("slug"), "title": c.get("title"),
                         "url": "https://huggingface.co/collections/" + c["slug"],
                         "items_count": len(c["items"]) if isinstance(c.get("items"), list) else None}
                        for c in collections],
    }


def atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".inventory-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_inventory(path, value):
    payload = canonical_bytes(value)
    digest = hashlib.sha256(payload).hexdigest()
    atomic_write(path, payload)
    atomic_write(path.with_suffix(path.suffix + ".sha256"), f"{digest}  {path.name}\n".encode("utf-8"))
    return digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-org", default="szl-holdings")
    parser.add_argument("--hf-org", default="SZLHOLDINGS")
    parser.add_argument("--out", type=Path, default=Path("outputs/estate_state.json"))
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
    args = parser.parse_args(argv)
    if not 1 <= args.max_pages <= MAX_PAGES:
        parser.error("--max-pages must be between 1 and 1000")
    try:
        inventory = build_inventory(
            args.github_org, args.hf_org,
            os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),
            os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN"),
            max_pages=args.max_pages)
        digest = write_inventory(args.out, inventory)
    except (InventoryError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAILED", "code": str(exc) if isinstance(exc, InventoryError) else type(exc).__name__}))
        return 2
    print(json.dumps({"status": inventory["status"], "summary": inventory["summary"],
                      "sha256": digest, "signer_state": "UNSIGNED"}, indent=2))
    return 0 if inventory["status"] == "COMPLETE_VISIBLE_LISTING" else 2


if __name__ == "__main__":
    raise SystemExit(main())
