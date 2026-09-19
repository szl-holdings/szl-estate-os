"""Credential-free, public-only housekeeping inventory (standard library).

An observation snapshot, not private inventory or runtime verification. No
environment or cached credentials are read. Only explicitly public rows survive.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20
REQUEST_TIMEOUT = 15
IDENTIFIER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
GITHUB_REPO_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")


class InventoryError(Exception):
    """Contains only a fixed safe error code, never response bodies or URLs."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_public_page(url: str) -> tuple[list, str]:
    # A fresh opener avoids cached authentication, cookies, netrc and ambient
    # proxy credentials. Redirects are denied instead of changing origins.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "szl-estate-public-housekeeping/2",
    })
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            if response.status != 200:
                raise InventoryError("HTTP_STATUS")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise InventoryError("RESPONSE_TOO_LARGE")
            page = json.loads(payload)
            if not isinstance(page, list):
                raise InventoryError("INVALID_PAGE_SHAPE")
            return page, response.headers.get("Link", "")
    except HTTPError as error:
        raise InventoryError(f"HTTP_{error.code}") from None
    except (URLError, OSError, TimeoutError, HTTPException):
        raise InventoryError("NETWORK_ERROR") from None
    except (ValueError, UnicodeError):
        raise InventoryError("INVALID_JSON") from None


def next_page_url(link: str, current_url: str, initial_url: str) -> str | None:
    links = re.findall(r'<([^<>]+)>\s*;\s*rel="next"', link)
    if not links:
        if re.search(r"\bnext\b", link):
            raise InventoryError("INVALID_PAGINATION")
        return None
    if len(links) != 1:
        raise InventoryError("INVALID_PAGINATION")
    if any(ord(character) <= 32 or ord(character) == 127 for character in links[0]):
        raise InventoryError("INVALID_PAGINATION")
    try:
        candidate = urljoin(current_url, links[0])
        initial = urlsplit(initial_url)
        parsed = urlsplit(candidate)
    except ValueError:
        raise InventoryError("INVALID_PAGINATION") from None
    if (
        not candidate.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in candidate)
        or parsed.scheme != "https"
        or parsed.netloc != initial.netloc
        or parsed.path != initial.path
        or parsed.fragment
    ):
        raise InventoryError("INVALID_PAGINATION")
    expected = parse_qs(initial.query)
    actual = parse_qs(parsed.query)
    for name in ("author", "type"):
        if name in expected and actual.get(name) != expected[name]:
            raise InventoryError("INVALID_PAGINATION")
    return candidate


def public_record(raw: object, org: str, kind: str) -> dict | None:
    if not isinstance(raw, dict) or raw.get("private") is not False:
        return None
    identity = raw.get("full_name" if kind == "repo" else "id")
    if not isinstance(identity, str):
        return None
    parts = identity.split("/")
    if (len(parts) != 2 or parts[0].lower() != org.lower()
            or IDENTIFIER.fullmatch(parts[0]) is None
            or (GITHUB_REPO_NAME if kind == "repo" else IDENTIFIER).fullmatch(parts[1]) is None
            or parts[1] in {".", ".."}):
        return None
    record = {"id": identity, "kind": kind, "visibility": "PUBLIC"}
    # Never retain descriptions, README/card bodies, configuration or raw API
    # dictionaries. Missing counters are unknown, never zero.
    counters = ("stargazers_count",) if kind == "repo" else ("downloads", "likes")
    for name in counters:
        value = raw.get(name)
        record[name] = value if type(value) is int and value >= 0 else None
    if kind == "repo":
        for name in ("archived", "fork"):
            record[name] = raw.get(name) if type(raw.get(name)) is bool else None
    return record


def collect_source(org: str, kind: str, *, fetch=get_public_page, max_pages=MAX_PAGES) -> dict:
    if kind == "repo":
        url = f"https://api.github.com/orgs/{org}/repos?" + urlencode({
            "type": "public", "per_page": 100, "sort": "full_name", "direction": "asc",
        })
    else:
        url = f"https://huggingface.co/api/{kind}s?" + urlencode({"author": org, "limit": 100})
    initial_url = url
    records, errors, visited, identities = [], [], set(), set()
    complete = False
    pages = 0
    try:
        for _ in range(max_pages):
            if url in visited:
                raise InventoryError("PAGINATION_CYCLE")
            visited.add(url)
            batch, link = fetch(url)
            pages += 1
            if not isinstance(batch, list):
                raise InventoryError("INVALID_PAGE_SHAPE")
            for raw in batch:
                record = public_record(raw, org, kind)
                if record is None:
                    errors.append("NONPUBLIC_OR_INVALID_RECORD")
                    continue
                identity = record["id"].lower()
                if identity in identities:
                    errors.append("DUPLICATE_RECORD")
                    continue
                identities.add(identity)
                records.append(record)
            # GitHub's Link may use /organizations/<numeric-id>/repos instead
            # of the requested org endpoint. Construct page numbers ourselves
            # to retain the exact public organization scope and origin.
            next_url = (
                initial_url + f"&page={pages + 1}" if len(batch) == 100 else None
            ) if kind == "repo" else next_page_url(link, url, initial_url)
            if next_url is None:
                complete = True
                break
            url = next_url
        if not complete:
            errors.append("PAGE_LIMIT_REACHED")
    except InventoryError as error:
        errors.append(str(error))
    return {
        "source": "github" if kind == "repo" else "huggingface",
        "kind": kind,
        "scope": "PUBLIC_ONLY",
        "status": "MEASURED" if complete and not errors else "PARTIAL",
        "pagination_exhausted": complete,
        "pages_observed": pages,
        "errors": sorted(set(errors)),
        "records": sorted(records, key=lambda record: record["id"].lower()),
    }


def build_inventory(github_org: str, hf_org: str, *, fetch=get_public_page) -> dict:
    if any(IDENTIFIER.fullmatch(org) is None for org in (github_org, hf_org)):
        raise ValueError("Organization must be a single ASCII identifier")
    sources = [collect_source(org, kind, fetch=fetch) for org, kind in (
        (github_org, "repo"), (hf_org, "model"), (hf_org, "dataset"),
    )]
    return {
        "schema": "szl.estate-housekeeping-public/v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "MEASURED" if all(source["status"] == "MEASURED" for source in sources) else "PARTIAL",
        "scope": "PUBLIC_ONLY",
        "private_inventory": "UNAVAILABLE",
        "complete_estate": False,
        "runtime_verified": False,
        "limitations": [
            "Anonymous public listing only; no private inventory or organization-wide completeness claim.",
            "GitHub repositories and Hugging Face models/datasets only; Spaces, collections and domains are not assessed.",
            "No README classification, source-file audit, training verification or deployment authorization.",
            "Pagination is bounded and not an atomic snapshot; rate limits and collection errors remain PARTIAL.",
        ],
        "github_org": github_org,
        "hf_org": hf_org,
        "summary": {source["kind"] + "_count": len(source["records"]) for source in sources},
        "sources": sources,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Public-only, read-only estate housekeeping snapshot")
    parser.add_argument("--github-org", default="szl-holdings")
    parser.add_argument("--hf-org", default="SZLHOLDINGS")
    parser.add_argument("--out", type=Path, default=Path("estate_state.json"))
    args = parser.parse_args(argv)
    inventory = build_inventory(args.github_org, args.hf_org)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": inventory["status"], "scope": inventory["scope"], **inventory["summary"]}))
    return 0 if inventory["status"] == "MEASURED" else 1


if __name__ == "__main__":
    sys.exit(main())
