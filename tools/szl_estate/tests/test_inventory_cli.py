"""Synthetic CLI integration: truthful partial exit and preserved output."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pytest

import szl_estate.inventory_cli as cli
from szl_estate.cli import main
from szl_estate.storage import canonical_bytes
from test_inventory import write_bundle


def arguments(tmp_path, **updates):
    source, digest = write_bundle(tmp_path)
    values = dict(backend_bundle=source, expected_sha256=digest, hf_inventory=None,
                  checkout_root=[], git_executable=None, batch_size=64,
                  priority_repo=[], master_repo=[], out=tmp_path / "new-output")
    values.update(updates)
    return argparse.Namespace(**values)


def test_cli_partial_is_not_phase2_or_estate_pass(tmp_path, capsys):
    args = arguments(tmp_path)
    assert cli.run_inventory(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PARTIAL"
    assert result["report_ready"] is True
    assert result["phase2_ready"] is result["estate_ready"] is False
    assert result["new_source_reads"] == 0
    assert result["unread_or_skipped_paths"] == 6
    envelope = json.loads((args.out / "estate_state.json").read_bytes())
    state = envelope["payload"]
    assert envelope["sha256"] == hashlib.sha256(canonical_bytes(state)).hexdigest()
    assert state["claim_tier"] is None
    assert state["hf"]["collections_status"] == "UNKNOWN"
    assert state["local_worktrees"]["counts"]["roots_requested"] == 0
    assert any(c["status"] == "NOT_RUN" for c in state["controls"])
    for name, receipt in state["artifacts"].items():
        raw = (args.out / name).read_bytes()
        assert len(raw) == receipt["bytes"]
        assert hashlib.sha256(raw).hexdigest() == receipt["sha256"]
    index = [json.loads(line) for line in (args.out / "github_files.jsonl").read_text().splitlines()]
    assert len(index) == 4
    assert all(not row["repository_id"].startswith("PRIVATE") for row in index)
    assert "INCOMPLETE" in (args.out / "report.md").read_text()


def test_installed_command_parser_routes_to_inventory(tmp_path, capsys):
    args = arguments(tmp_path)
    assert main(["inventory", "--backend-bundle", str(args.backend_bundle), "--expected-sha256", args.expected_sha256, "--out", str(args.out)]) == 1
    assert json.loads(capsys.readouterr().out)["batch_selected_paths"] == 2


def test_bad_source_pin_has_no_output_or_local_scan(tmp_path, monkeypatch, capsys):
    args = arguments(tmp_path, expected_sha256="0" * 64)
    monkeypatch.setattr(cli, "collect_worktrees", lambda *a, **k: pytest.fail("must not scan rejected source"))
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


def test_missing_bundle_preserves_actual_read_failure_status(tmp_path, monkeypatch, capsys):
    args = arguments(tmp_path, backend_bundle=tmp_path / "missing-source.zip")
    monkeypatch.setattr(cli, "collect_worktrees", lambda *a, **k: pytest.fail("must not scan unreadable source"))
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "INACCESSIBLE"
    assert summary["errors"] == ["FROZEN_INPUT_UNREADABLE"]


def test_existing_output_and_partial_files_are_preserved(tmp_path, capsys):
    args = arguments(tmp_path)
    args.out.mkdir()
    sentinel = args.out / "partially-written.tmp"
    sentinel.write_bytes(b"preserve")
    assert cli.run_inventory(args) == 2
    assert sentinel.read_bytes() == b"preserve"
    assert list(args.out.iterdir()) == [sentinel]
    assert "preserve" not in capsys.readouterr().out


def test_output_inside_requested_checkout_rejected(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    args = arguments(tmp_path, checkout_root=[checkout], out=checkout / "outputs")
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()


def test_output_inside_package_rejected(tmp_path):
    package = Path(cli.__file__).resolve().parents[2]
    args = arguments(tmp_path, out=package / "forbidden-inventory-output")
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()


def test_input_alias_rejected_without_modifying_source(tmp_path):
    args = arguments(tmp_path)
    original = args.backend_bundle.read_bytes()
    args.out = args.backend_bundle
    assert cli.run_inventory(args) == 2
    assert args.backend_bundle.read_bytes() == original


def test_reparse_output_ancestor_rejected(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    original = Path.lstat
    def linked(path):
        info = original(path)
        if path == tmp_path:
            class Reparse:
                st_mode = info.st_mode
                st_file_attributes = 0x400
            return Reparse()
        return info
    monkeypatch.setattr(Path, "lstat", linked)
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()


def test_hf_digest_failure_is_not_historical_pass(tmp_path, monkeypatch, capsys):
    args = arguments(tmp_path, hf_inventory=tmp_path / "hf.json")
    from szl_estate.inputs import InventorySummary
    monkeypatch.setattr(cli, "load_hf_summary", lambda p: InventorySummary("hf_historical_inventory", "2026-09-30T00:00:00Z", "a" * 64, {}, None))
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()
    assert json.loads(capsys.readouterr().out)["code"] == "HF_RECEIPT_DIGEST_MISMATCH"


def test_missing_hf_preserves_inaccessible_and_never_scans(tmp_path, monkeypatch, capsys):
    args = arguments(tmp_path, hf_inventory=tmp_path / "missing-hf.json")
    monkeypatch.setattr(cli, "collect_worktrees", lambda *a, **k: pytest.fail("must not scan with unreadable HF input"))
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "INACCESSIBLE"
    assert summary["code"] == "INPUT_UNREADABLE"


def test_failed_output_write_keeps_completed_file(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    original = cli.atomic_write
    def fail_second(path, raw, **kwargs):
        if path.name == "repository_batch_plan.csv":
            raise OSError("synthetic sensitive error never emitted")
        return original(path, raw, **kwargs)
    monkeypatch.setattr(cli, "atomic_write", fail_second)
    assert cli.run_inventory(args) == 2
    assert (args.out / "inventory_summary.json").is_file()
    assert not (args.out / "estate_state.json").exists()


@pytest.mark.parametrize("value", ["=1+2", " +CMD", "-1", "@SUM"])
def test_csv_formula_cells_are_neutralized(value):
    raw = cli.repository_csv([{"repository_id": value}]).decode()
    assert "'" + value in raw


def test_invalid_batch_size_is_not_ready(tmp_path, capsys):
    args = arguments(tmp_path, batch_size=0)
    assert cli.run_inventory(args) == 2
    assert not args.out.exists()
    assert "PASS" not in capsys.readouterr().out
