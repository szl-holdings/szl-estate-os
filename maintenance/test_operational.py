import json
from argparse import Namespace
from types import SimpleNamespace

import pytest

import szl_operational as runner


def test_nested_failures_and_incomplete_inventory_fail_summary():
    assert runner.has_failure({"a": {"actions": [{"status": "UNKNOWN_AFTER_ATTEMPT"}]}})
    assert runner.has_failure({"inventory": {"complete": False}})
    assert not runner.has_failure({"actions": [{"status": "VERIFIED_NO_CHANGE"}]} )


def test_apply_lock_rejects_second_writer(tmp_path):
    path = tmp_path / "lock"
    with runner.apply_lock(path):
        with pytest.raises(FileExistsError):
            with runner.apply_lock(path):
                pass
    assert not path.exists()


def test_provider_failure_checkpoints_other_provider(tmp_path, monkeypatch):
    def module(name):
        if name.endswith("github_ops"):
            raise RuntimeError("must not serialize secrets")
        return SimpleNamespace(run=lambda **kwargs: {"actions": [{"status": "VERIFIED_NO_CHANGE"}]})
    monkeypatch.setattr(runner.importlib, "import_module", module)
    args = Namespace(apply=False, providers=["github", "cloudflare"], output=tmp_path, hf_policy=None)
    assert runner.execute(args) == 2
    result = json.loads((tmp_path / "estate-state.json").read_text())
    assert result["status"] == "PARTIAL"
    assert "cloudflare" in result["providers"]
    assert "must not serialize secrets" not in (tmp_path / "estate-state.json").read_text()


def test_apply_cannot_report_unexecuted_plan_as_verified(tmp_path, monkeypatch):
    module = SimpleNamespace(run=lambda **kwargs: {"status": "PLANNED", "actions": [{"status": "PLANNED"}]})
    monkeypatch.setattr(runner.importlib, 'import_module', lambda name: module)
    args = Namespace(apply=True, providers=['github'], output=tmp_path, hf_policy=None)
    assert runner.execute(args) == 2
    report = json.loads((tmp_path / 'estate-state.json').read_text())
    assert report['status'] == 'PARTIAL'
    assert 'NEEDS_ATTENTION' in (tmp_path / 'estate-report.md').read_text()
