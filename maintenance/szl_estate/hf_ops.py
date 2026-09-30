"""Inspect all visible Hub assets; make bounded, revision-bound card repairs.

No model code or weights are downloaded or executed. A model rename requires a
current migration record because moving a repository can invalidate consumers.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from huggingface_hub import HfApi, get_token, hf_hub_download

ORG = "SZLHOLDINGS"
OLD_ID = f"{ORG}/oac-clinical-transport-health-v1"
NEW_ID = f"{ORG}/oac-system-health-v1"
REFERENCE_NAMES = ("MiniEmbed-Nano", "Moons-Nano", "ReceiptAgent-Nano",
                   "TinyKhipu-Nano", "chakana", "qantu", "tinku", "waman")
REFERENCE_NOTE = "> **Status: REFERENCE / TEST FIXTURE.** Not a production model."
SCOPE_NOTE = ("> **Scope note:** Synthetic-data operations/observability logistic "
              "regression for system-health monitoring. Not clinical.")
LEGACY_NOTE = ("> **Deprecated identifier:** The canonical successor is "
               "[SZLHOLDINGS/oac-system-health-v1](https://huggingface.co/SZLHOLDINGS/oac-system-health-v1). "
               "This repository is retained for compatibility and historical reproducibility; "
               "use the successor for new integrations. Both repositories contain synthetic "
               "operational telemetry models, not clinical models.")


def now():
    return datetime.now(timezone.utc).isoformat()


def error_info(exc):
    """Do not serialize exception text, request headers, tokens, or signed URLs."""
    response = getattr(exc, "response", None)
    return {"type": type(exc).__name__, "http_status": getattr(response, "status_code", None)}


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def insert_note(content: str, note: str, marker: str) -> str:
    """Preserve existing front matter and body byte-for-byte except insertion."""
    if content.startswith("\ufeff"):
        raise ValueError("UTF-8 BOM requires explicit card normalization")
    newline = "\r\n" if "\r\n" in content else "\n"
    lines = content.splitlines(keepends=True)
    offset = 0
    if lines and lines[0].strip() == "---":
        for i, line in enumerate(lines[1:], 1):
            if line.strip() in ("---", "..."):
                offset = sum(map(len, lines[:i + 1]))
                break
        else:
            raise ValueError("Unterminated model card metadata")
    # Accept only a real leading body note, not an example in a fence, YAML,
    # HTML comment, or indented code. Ambiguous existing markers need review.
    body_lines = content[offset:].lstrip("\r\n").splitlines()
    if body_lines and body_lines[0] == note:
        return content
    if marker.casefold() in content.casefold():
        raise ValueError("An existing note marker conflicts with the desired leading note")
    prefix = content[:offset]
    if prefix and not prefix.endswith(("\n", "\r")):
        prefix += newline
    return prefix + newline + note + newline + newline + content[offset:]


class Hub:
    def __init__(self, api=None, repo_type="model"):
        if repo_type not in {"model", "dataset"}:
            raise ValueError("Unsupported card repository type")
        self.api = api or HfApi(token=get_token() or False)
        self.repo_type = repo_type

    def info(self, repo_id):
        if self.repo_type == "model":
            return self.api.model_info(repo_id, files_metadata=False)
        return self.api.dataset_info(repo_id, files_metadata=False)

    def card(self, repo_id, revision):
        filename = hf_hub_download(repo_id, "README.md", revision=revision,
                                   token=self.api.token, repo_type=self.repo_type)
        return Path(filename).read_bytes().decode("utf-8")

    def upload(self, repo_id, revision, content):
        return self.api.upload_file(repo_id=repo_id, path_in_repo="README.md",
                                    repo_type=self.repo_type,
                                    path_or_fileobj=content.encode("utf-8"),
                                    parent_commit=revision,
                                    commit_message="Clarify model scope and reference status")


def inventory(hub):
    assets, failures = [], []
    for kind, method in (("model", hub.api.list_models),
                         ("dataset", hub.api.list_datasets),
                         ("space", hub.api.list_spaces)):
        try:
            # SDK handles all pages. A bounded item count avoids unbounded runs.
            rows = method(author=ORG, full=True)
            for index, item in enumerate(rows):
                if index >= 10000:
                    raise RuntimeError("Inventory item limit reached")
                assets.append({"id": item.id, "kind": kind,
                               "revision": getattr(item, "sha", None),
                               "private": getattr(item, "private", None),
                               "downloads": getattr(item, "downloads", None),
                               "tags": getattr(item, "tags", None)})
        except Exception as exc:
            failures.append({"target": kind, "status": "UNAVAILABLE", **error_info(exc)})
    failed_kinds = {item["target"] for item in failures}
    return {"assets": assets, "complete": not failures, "failures": failures,
            "counts": {kind: None if kind in failed_kinds else sum(x["kind"] == kind for x in assets)
                       for kind in ("model", "dataset", "space")},
            "scope": "Repositories visible to the current authenticated identity; downloads do not establish quality"}


def update_card(hub, repo_id, note, marker, apply=False, expected_sha=None, replacement_from=None):
    action = {"operation": "model_card", "target": repo_id}
    attempted = False
    try:
        info = hub.info(repo_id)
        revision = info.sha
        if not revision:
            raise ValueError("Missing immutable revision")
        if expected_sha and revision != expected_sha:
            return {**action, "status": "BLOCKED", "reason": "Source revision changed since review"}
        before = hub.card(repo_id, revision)
        if replacement_from is not None:
            if not replacement_from or before.count(replacement_from) != 1:
                raise ValueError("Reviewed replacement text no longer matches exactly once")
            after = before.replace(replacement_from, note, 1)
        else:
            after = insert_note(before, note, marker)
        action.update(before_revision=revision, before_sha256=digest(before),
                      desired_sha256=digest(after))
        if after == before:
            return {**action, "status": "VERIFIED_NO_CHANGE"}
        if not apply:
            return {**action, "status": "PLANNED", "note": note}
        if hub.info(repo_id).sha != revision:
            return {**action, "status": "BLOCKED", "reason": "Concurrent source update"}
        try:
            attempted = True
            commit = hub.upload(repo_id, revision, after)
        except Exception as exc:
            # A timeout after a successful write is uncertain until readback.
            latest = hub.info(repo_id)
            current = hub.card(repo_id, latest.sha)
            if digest(current) == digest(after):
                return {**action, "status": "VERIFIED_APPLIED", "after_revision": latest.sha,
                        "write_response": "UNKNOWN_READBACK_CONFIRMED"}
            return {**action, "status": "UNKNOWN_AFTER_ATTEMPT", **error_info(exc)}
        latest = hub.info(repo_id)
        current = hub.card(repo_id, latest.sha)
        if digest(current) != digest(after):
            return {**action, "status": "READBACK_FAILED", "after_revision": latest.sha}
        return {**action, "status": "VERIFIED_APPLIED", "after_revision": latest.sha,
                "commit": getattr(commit, "oid", None)}
    except Exception as exc:
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT" if attempted else "BLOCKED" if isinstance(exc, ValueError) else "UNAVAILABLE", **error_info(exc)}


def verify_move(hub, revision):
    """Identical contents in two independent repositories do not prove a move."""
    observed = hub.info(NEW_ID)
    if observed.sha != revision or getattr(observed, "id", None) != NEW_ID:
        return None
    try:
        alias = hub.info(OLD_ID)
    except Exception as exc:
        if error_info(exc)["http_status"] == 404:
            return observed
        raise
    return observed if getattr(alias, "id", None) == NEW_ID else None


def recognize_successor(hub, old, new, migration):
    """Verify an explicitly reviewed migration that retains the legacy repository.

    This never renames, deletes, or overwrites either repository. The old URL may
    remain an active consumer dependency, so report successor migration honestly.
    """
    action = {"operation": "verify_successor", "target": OLD_ID, "destination": NEW_ID}
    if (getattr(old, "id", None) != OLD_ID or getattr(new, "id", None) != NEW_ID
            or migration.get("from_id") != OLD_ID or migration.get("to_id") != NEW_ID
            or migration.get("source_revision") != old.sha
            or migration.get("destination_revision") != new.sha
            or migration.get("canonical_publisher_ready") is not True
            or not re.fullmatch(r"[a-f0-9]{40}", migration.get("publisher_commit", ""))):
        return {**action, "status": "BLOCKED", "reason": "Reviewed successor or publisher state changed"}
    legacy = hub.card(OLD_ID, old.sha)
    canonical = hub.card(NEW_ID, new.sha)
    if (digest(legacy) != migration.get("legacy_card_sha256")
            or digest(canonical) != migration.get("canonical_card_sha256")
            or insert_note(legacy, LEGACY_NOTE, "**Deprecated identifier:**") != legacy):
        return {**action, "status": "BLOCKED", "reason": "Successor cards do not match reviewed source and legacy pointer"}
    return {**action, "status": "VERIFIED_SUCCESSOR", "legacy_retained": True,
            "literal_repository_move": False, "source_revision": old.sha,
            "destination_revision": new.sha, "publisher_commit": migration["publisher_commit"],
            "reason": "Canonical successor verified; old repository retained for existing consumers"}


def rename_model(hub, apply=False, migration=None):
    action = {"operation": "rename_model", "target": OLD_ID, "destination": NEW_ID}
    attempted = False
    try:
        old, new = None, None
        for repo_id in (OLD_ID, NEW_ID):
            try:
                info = hub.info(repo_id)
            except Exception as exc:
                if error_info(exc)["http_status"] != 404:
                    raise
                info = None
            if repo_id == OLD_ID:
                old = info
            else:
                new = info
        if new is not None and getattr(new, "id", None) == NEW_ID and (old is None or getattr(old, "id", None) == NEW_ID):
            return {**action, "status": "VERIFIED_NO_CHANGE", "revision": new.sha}
        if old is None:
            return {**action, "status": "UNAVAILABLE", "reason": "Source and destination missing"}
        if new is not None:
            if migration and migration.get("strategy") == "retain_legacy_pointer":
                return recognize_successor(hub, old, new, migration)
            return {**action, "status": "BLOCKED", "reason": "Destination already exists independently"}
        # Reviewed migration manifest binds consumer/publisher checks to this SHA.
        if (not migration or migration.get("source_revision") != old.sha
                or migration.get("from_id") != OLD_ID or migration.get("to_id") != NEW_ID
                or migration.get("unresolved_consumers") != []
                or migration.get("canonical_publisher_ready") is not True):
            return {**action, "status": "BLOCKED", "revision": old.sha,
                    "reason": "Consumer references and canonical publisher migration have not been resolved at this revision"}
        checked = datetime.fromisoformat(migration["checked_at"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        if not 0 <= age <= 900:
            return {**action, "status": "BLOCKED", "reason": "Migration record must be refreshed within 15 minutes"}
        if not apply:
            return {**action, "status": "PLANNED", "revision": old.sha}
        if hub.info(OLD_ID).sha != old.sha:
            return {**action, "status": "BLOCKED", "reason": "Concurrent source update"}
        try:
            attempted = True
            hub.api.move_repo(from_id=OLD_ID, to_id=NEW_ID, repo_type="model")
        except Exception as exc:
            try:
                observed = verify_move(hub, old.sha)
                if observed is not None:
                    return {**action, "status": "VERIFIED_APPLIED", "revision": observed.sha,
                            "write_response": "UNKNOWN_READBACK_CONFIRMED"}
            except Exception:
                pass
            return {**action, "status": "UNKNOWN_AFTER_ATTEMPT", **error_info(exc)}
        observed = verify_move(hub, old.sha)
        if observed is None:
            return {**action, "status": "READBACK_FAILED", "reason": "Canonical destination or old-name redirect does not match"}
        return {**action, "status": "VERIFIED_APPLIED", "revision": observed.sha}
    except Exception as exc:
        return {**action, "status": "UNKNOWN_AFTER_ATTEMPT" if attempted else "UNAVAILABLE", **error_info(exc)}


def run(apply=False, policy_path=None, hub=None):
    hub = hub or Hub()
    result = {"provider": "huggingface", "checked_at": now(),
              "mode": "apply" if apply else "audit", "actions": [], "blockers": []}
    try:
        identity = hub.api.whoami()
        result["identity"] = identity.get("name")
    except Exception as exc:
        result["authentication"] = {"status": "UNAVAILABLE", **error_info(exc)}
        if apply:
            result["blockers"].append("Hugging Face authenticated identity unavailable")
            return result
    result["inventory"] = inventory(hub)
    result["blockers"].extend(result["inventory"]["failures"])
    policy = json.loads(Path(policy_path).read_text(encoding="utf-8")) if policy_path else {}
    migration = policy.get("migration")
    rename = rename_model(hub, apply=apply, migration=migration)
    result["actions"].append(rename)
    scope_target = NEW_ID if rename["status"] in ("VERIFIED_APPLIED", "VERIFIED_NO_CHANGE", "VERIFIED_SUCCESSOR") else OLD_ID
    reviewed = policy.get("cards", {})
    for repo_id, note, marker in [(scope_target, SCOPE_NOTE, "**Scope note:**")] + [
            (f"{ORG}/{name}", REFERENCE_NOTE, "**Status: REFERENCE / TEST FIXTURE.**")
            for name in REFERENCE_NAMES]:
        entry = reviewed.get(repo_id)
        if not entry:
            # Audit can inspect the proposed repair; applying needs current source review.
            if apply:
                result["actions"].append({"operation": "model_card", "target": repo_id,
                                          "status": "BLOCKED", "reason": "No reviewed card policy"})
                continue
        elif entry.get("disposition") == "preserve":
            try:
                current = hub.info(repo_id)
                status = "VERIFIED_NO_CHANGE" if current.sha == entry.get("revision") else "BLOCKED"
                result["actions"].append({"operation": "model_card", "target": repo_id,
                                          "status": status, "revision": current.sha,
                                          "reason": entry.get("reason") if status != "BLOCKED" else "Reviewed revision changed"})
            except Exception as exc:
                result["actions"].append({"operation": "model_card", "target": repo_id,
                                          "status": "UNAVAILABLE", **error_info(exc)})
            continue
        if apply and (entry.get("disposition") != "patch"
                      or not re.fullmatch(r"[a-f0-9]{40}", entry.get("revision", ""))
                      or entry.get("publisher_ready") is not True):
            result["actions"].append({"operation": "model_card", "target": repo_id,
                                      "status": "BLOCKED", "reason": "Reviewed publisher policy is incomplete"})
            continue
        result["actions"].append(update_card(hub, repo_id, note, marker, apply,
                                              expected_sha=entry.get("revision") if entry else None))
    result["blockers"].extend(a for a in result["actions"] if a["status"] in
                              ("BLOCKED", "UNAVAILABLE", "READBACK_FAILED", "UNKNOWN_AFTER_ATTEMPT"))
    return result
