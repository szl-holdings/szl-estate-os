"""Publish bounded historical coverage; partial controls never become PASS."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from typing import Any

from .inputs import load_hf_summary
from .inventory import InventoryConfiguration, build_frozen_inventory
from .storage import StorageError, atomic_write, canonical_bytes, integrity_bytes
from .worktrees import collect_worktrees

HF_RECEIPT_SHA256 = "31d777345ac57b5eba1c78ce341c8cb513d2f8fdfe021482b6dc99ff82b43ded"


class OutputError(ValueError):
    """Fixed codes; no paths or untrusted exception text."""


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _check_chain(path: Path) -> None:
    if str(path).startswith(("\\\\", "//")) or any(ord(c) < 32 for c in str(path)):
        raise OutputError("UNSAFE_OUTPUT_PATH")
    for node in (*reversed(path.parents), path):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OutputError("REPARSE_OUTPUT_PATH")
        if not stat.S_ISDIR(info.st_mode):
            raise OutputError("OUTPUT_PARENT_NOT_DIRECTORY")


def _reserve_output(path: Path, roots: list[Path], sources: list[Path]) -> Path:
    target = _absolute(path)
    _check_chain(target)
    protected = [_absolute(item) for item in roots]
    protected.append(Path(__file__).resolve().parents[2])
    if any(target.is_relative_to(item) for item in protected):
        raise OutputError("OUTPUT_INSIDE_INSPECTED_CHECKOUT")
    if any(target == _absolute(item) for item in sources):
        raise OutputError("OUTPUT_ALIASES_INPUT")
    if target.exists():
        raise OutputError("OUTPUT_ALREADY_EXISTS_PRESERVED")
    # Only a new owned directory is written. A failed run keeps its partial output.
    target.parent.mkdir(parents=True, exist_ok=True)
    _check_chain(target.parent)
    target.mkdir(exist_ok=False)
    return target


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("utf-8")


def _cell(value: Any) -> str:
    result = "" if value is None else str(value)
    return "'" + result if result.lstrip().startswith(("=", "+", "-", "@")) else result


def repository_csv(rows: list[dict[str, Any]]) -> bytes:
    fields = ("repository_id", "snapshot_sha", "source_observed_at_utc", "private", "archived", "tree_complete", "tracked_paths", "historical_inspected_paths", "unread_or_skipped_paths", "master_designation", "proposed_batch_paths")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(fields)
    for row in rows:
        writer.writerow([_cell(row.get(field)) for field in fields])
    return stream.getvalue().encode("utf-8")


def report_markdown(state: dict[str, Any]) -> bytes:
    github = state["github"]
    local = state["local_worktrees"]
    lines = [
        "# Phase 2 frozen inventory and bounded local metadata", "",
        "Phase 2 exit: INCOMPLETE. This batch validates historical metadata and proposes future reads. It does not establish runtime health, scientific validity, authorization, deployment, or complete semantic review.", "",
        f"Snapshot coverage time: `{github['coverage_observed_at_utc']}`. Local metadata checked at: `{local['observed_at_utc']}`.", "",
        f"Frozen GitHub ledger: {github['repository_count']} repositories ({github['public_repository_count']} public, {github['private_repository_count']} private); {github['source_tracked_paths']} pinned paths; {github['historically_inspected_paths']} historically inspected; {github['unread_or_skipped_paths']} unread, errored or skipped.",
        f"Historical inspected paths without content digests: {github['historical_inspected_content_digest_unknown']}. The older {github['legacy_inspected_paths']}-path baseline is retained separately.", "",
        f"Safe file metadata projected: {github['metadata_index_paths']}. Excluded path counts: `{json.dumps(github['excluded_path_counts'], sort_keys=True)}`. Private repository names and paths are withheld in the frozen projection.",
        f"First proposed batch: {github['batch_selected_paths']} paths. New source reads: 0; unread reduction: 0; remaining source coverage: {github['unread_or_skipped_paths']}. Master designation is unassigned unless explicitly configured by an owner.", "",
        f"Local scope: {local['counts']['roots_requested']} explicit roots, {local['counts']['checkouts_inspected']} checkout observations, {local['counts']['paths_counted']} counted path entries. Dirty state is UNKNOWN. Discovery complete within the requested bounded scope: {local['discovery_complete']}.",
        "betterwithage is the connected computer, not a GitHub organization. Working-file contents, credentials, sessions, dependency trees, weights and dataset rows are excluded. No install, hook, filter, migration, merge or operational change is performed.", "",
        "HF counters are historical and separate from the GitHub ledger. Collections, current visibility, current runtime and behavioral safety remain unknown or not run. Static results do not prove loadability, training eligibility or behavioral safety.", "",
        "## Unmet controls and next actions", "",
        "| Control | Status | Owner / next action |", "| --- | --- | --- |",
    ]
    for item in state["controls"]:
        lines.append(f"| {item['control']} | {item['status']} | {item['next_action']} |")
    lines += ["", "The output file digests establish byte integrity only. Source-read batches are proposals, not execution receipts or quality scores. Existing historical evidence is preserved. No operational weapons, targeting or engagement work is admitted.", ""]
    return "\n".join(lines).encode("utf-8")


def run_inventory(args: Any) -> int:
    sources = [args.backend_bundle] + ([args.hf_inventory] if args.hf_inventory else [])
    try:
        configuration = InventoryConfiguration(batch_size=args.batch_size, priority_repositories=tuple(args.priority_repo), master_repositories=tuple(args.master_repo))
        result = build_frozen_inventory(args.backend_bundle, expected_sha256=args.expected_sha256, configuration=configuration)
        if not result.payload.get("report_ready"):
            status = result.payload.get("status")
            status = status if status in {"FAIL", "INACCESSIBLE"} else "FAIL"
            print(json.dumps({"status": status, "phase2_ready": False, "estate_ready": False, "errors": result.payload.get("errors", ["INVALID_FROZEN_INPUT"])}))
            return 2
        hf = {"status": "NOT_RUN", "current_runtime_status": "NOT_RUN", "collections_status": "UNKNOWN"}
        if args.hf_inventory:
            summary = load_hf_summary(args.hf_inventory)
            if summary.error_code or summary.digest != HF_RECEIPT_SHA256:
                status = "INACCESSIBLE" if summary.error_code == "INPUT_UNREADABLE" else "FAIL"
                print(json.dumps({"status": status, "code": summary.error_code or "HF_RECEIPT_DIGEST_MISMATCH", "phase2_ready": False, "estate_ready": False}))
                return 2
            hf.update({"status": "HISTORICAL_ONLY", "source_sha256": summary.digest, "observed_at_utc": summary.observed_at_utc, "counts": dict(summary.counts), "fresh_heads_verified": False})
        out = _reserve_output(args.out, args.checkout_root, sources)
        local = collect_worktrees(args.checkout_root, git_executable=args.git_executable).to_dict()
        controls = [
            {"control": "frozen_metadata_integrity_and_count_reconciliation", "status": "PASS", "next_action": "Audit owner: retain dated source and member digests"},
            {"control": "current_remote_tree_and_file_coverage", "status": "NOT_RUN", "next_action": "Audit owner: narrowly revalidate designated repositories at exact heads"},
            {"control": "remaining_content_review", "status": "NOT_RUN", "next_action": "Source owners: review proposed bounded batch; no automatic execution"},
            {"control": "private_and_sensitive_path_coverage", "status": "PARTIAL", "next_action": "Owners: establish authorized protected evidence routing"},
            {"control": "local_metadata_scope", "status": "PARTIAL", "next_action": "Audit owner: resolve fixed error codes within explicit known roots"},
            {"control": "local_dirty_state", "status": "UNKNOWN", "next_action": "Checkout owners: provide a separately authorized working-tree receipt"},
            {"control": "hf_current_assets_and_collections", "status": "NOT_RUN", "next_action": "HF owner: bounded exact-revision metadata and collection inventory"},
            {"control": "runtime_and_behavioral_safety", "status": "NOT_RUN", "next_action": "Product and science owners: isolated acceptance checks and human gates"},
            {"control": "disk_stability", "status": "UNKNOWN", "next_action": "Machine owner: repeated bounded resource receipts; one reading is insufficient"},
        ]
        state = {"schema_version": "szl.phase2-inventory-state/v1", "status": "PARTIAL", "report_ready": True, "phase2_ready": False, "estate_ready": False, "proof_scope": "FROZEN_METADATA_AND_EXPLICIT_LOCAL_METADATA_ONLY", "claim_tier": None, "claim_tier_status": "NOT_ESTABLISHED", "github": result.payload, "hf": hf, "local_worktrees": local, "controls": controls}
        outputs = {
            "inventory_summary.json": _json_bytes(result.payload),
            "repository_batch_plan.csv": repository_csv(result.payload["repositories"]),
            "github_files.jsonl": b"".join(canonical_bytes(record) + b"\n" for record in result.file_index_records()),
            "local_worktrees.json": _json_bytes(local),
            "report.md": report_markdown(state),
        }
        state["artifacts"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(outputs.items())}
        for name, data in outputs.items():
            atomic_write(out / name, data, source_paths=sources)
        atomic_write(out / "estate_state.json", integrity_bytes(state), source_paths=sources)
        print(json.dumps({"status": "PARTIAL", "report_ready": True, "phase2_ready": False, "estate_ready": False, "repositories": result.payload["repository_count"], "pinned_paths": result.payload["source_tracked_paths"], "unread_or_skipped_paths": result.payload["unread_or_skipped_paths"], "batch_selected_paths": result.payload["batch_selected_paths"], "new_source_reads": 0, "local_checkouts": local["counts"]["checkouts_inspected"]}, sort_keys=True))
        return 1
    except (OutputError, StorageError, OSError, ValueError, TypeError):
        # Preserve partial outputs and never echo an exception containing a path or secret.
        print(json.dumps({"status": "FAIL", "code": "INVALID_INVENTORY_INPUT_OR_OUTPUT", "phase2_ready": False, "estate_ready": False}, sort_keys=True))
        return 2
