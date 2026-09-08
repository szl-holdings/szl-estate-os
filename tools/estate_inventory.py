"""
estate_inventory.py

Phase 0 ground-truth inventory for the SZL Holdings estate.
Produces estate_state.json: every GitHub repo and every Hugging Face
model/dataset, classified by status, before consolidation or new builds.

Env vars (recommended to avoid rate limits):
    GITHUB_TOKEN   - GitHub PAT (repo:read)
    HF_TOKEN       - Hugging Face token (read)

Usage:
    python estate_inventory.py --github-org szl-holdings --hf-org SZLHOLDINGS
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

import requests

ARCHIVE_KEYWORDS = re.compile(
    r"\bARCHIVED\b|\bhologram\b|\bduplicate\b|\bcanonical:\s*\S+", re.IGNORECASE
)

STATUS_FLAGSHIP = "FLAGSHIP"
STATUS_COMPONENT = "COMPONENT"
STATUS_REFERENCE = "REFERENCE"
STATUS_EXPERIMENT = "EXPERIMENT"
STATUS_ARCHIVED = "ARCHIVED"
STATUS_RETIRED = "RETIRED"

KNOWN_FLAGSHIPS = {
    "a11oy", "szl-receipt", "governed-receipt-spec", "hatun-mcp",
    "lutar-lean", "killinchu", "szl-khipu", "szl-atelier", "immune",
}


@dataclass
class RepoRecord:
    name: str
    full_name: str
    archived: bool
    fork: bool
    stargazers_count: int
    pushed_at: str | None
    description: str | None
    readme_flags: list = field(default_factory=list)
    canonical_successor: str | None = None
    status: str = STATUS_EXPERIMENT


@dataclass
class HFAssetRecord:
    id: str
    kind: str
    downloads: int
    likes: int
    last_modified: str | None
    status: str = STATUS_EXPERIMENT


def fetch_github_repos(org, token):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    repos, page = [], 1
    while True:
        resp = requests.get(
            f"https://api.github.com/orgs/{org}/repos",
            headers=headers,
            params={"per_page": 100, "page": page, "type": "public"},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"GitHub API error {resp.status_code}", file=sys.stderr)
            break
        batch = resp.json()
        if not batch:
            break
        for r in batch:
            repos.append(RepoRecord(
                r["name"], r["full_name"], r.get("archived", False),
                r.get("fork", False), r.get("stargazers_count", 0),
                r.get("pushed_at"), r.get("description"),
            ))
        page += 1
    return repos


def fetch_readme_flags(org, repo, token):
    headers = {"Accept": "application/vnd.github.raw+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{org}/{repo}/readme",
            headers=headers, timeout=15,
        )
        if resp.status_code != 200:
            return [], None
        text = resp.text
    except requests.RequestException:
        return [], None
    flags = list(set(m.group(0).upper() for m in ARCHIVE_KEYWORDS.finditer(text)))
    successor = None
    m = re.search(
        r"[Cc]anonical(?:\s*(?:GitHub)?)?:?\s*(?:https?://\S+/)?([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)",
        text,
    )
    if m:
        successor = m.group(1)
    return flags, successor


def classify_repo(r):
    if r.archived:
        return STATUS_ARCHIVED
    if r.canonical_successor:
        return STATUS_RETIRED
    if r.name in KNOWN_FLAGSHIPS:
        return STATUS_FLAGSHIP
    if r.readme_flags:
        return STATUS_EXPERIMENT
    if r.stargazers_count > 0 or (r.pushed_at and r.pushed_at > "2026-06-01"):
        return STATUS_COMPONENT
    return STATUS_REFERENCE


def fetch_hf_assets(org, token):
    from huggingface_hub import HfApi
    api = HfApi(token=token)
    assets = []
    try:
        for m in api.list_models(author=org, full=True):
            assets.append(HFAssetRecord(
                m.id, "model", getattr(m, "downloads", 0) or 0,
                getattr(m, "likes", 0) or 0, str(getattr(m, "lastModified", None)),
            ))
    except Exception as e:
        print(f"HF model listing failed: {e}", file=sys.stderr)
    try:
        for d in api.list_datasets(author=org, full=True):
            assets.append(HFAssetRecord(
                d.id, "dataset", getattr(d, "downloads", 0) or 0,
                getattr(d, "likes", 0) or 0, str(getattr(d, "lastModified", None)),
            ))
    except Exception as e:
        print(f"HF dataset listing failed: {e}", file=sys.stderr)
    return assets


def build_inventory(github_org, hf_org, gh_token, hf_token):
    repos = fetch_github_repos(github_org, gh_token)
    for r in repos:
        flags, successor = fetch_readme_flags(github_org, r.name, gh_token)
        r.readme_flags = flags
        r.canonical_successor = successor
        r.status = classify_repo(r)
    hf_assets = fetch_hf_assets(hf_org, hf_token)
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "github_org": github_org,
        "hf_org": hf_org,
        "summary": {
            "total_repos": len(repos),
            "archived_repos": sum(1 for r in repos if r.status == STATUS_ARCHIVED),
            "retired_repos": sum(1 for r in repos if r.status == STATUS_RETIRED),
            "flagship_repos": sum(1 for r in repos if r.status == STATUS_FLAGSHIP),
            "total_hf_assets": len(hf_assets),
            "zero_download_hf_assets": sum(1 for a in hf_assets if a.downloads == 0),
        },
        "github_repos": [asdict(r) for r in repos],
        "hf_assets": [asdict(a) for a in hf_assets],
    }


def main():
    parser = argparse.ArgumentParser(description="SZL Holdings Phase 0 estate inventory")
    parser.add_argument("--github-org", default="szl-holdings")
    parser.add_argument("--hf-org", default="SZLHOLDINGS")
    parser.add_argument("--out", default="estate_state.json")
    args = parser.parse_args()
    inventory = build_inventory(
        args.github_org, args.hf_org,
        os.environ.get("GITHUB_TOKEN"), os.environ.get("HF_TOKEN"),
    )
    with open(args.out, "w") as f:
        json.dump(inventory, f, indent=2)
    print(json.dumps(inventory["summary"], indent=2))


if __name__ == "__main__":
    main()
