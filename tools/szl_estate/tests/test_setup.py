"""Offline setup-gate boundaries; no real account, token, or network reads."""
from dataclasses import replace
import hashlib
import json
import re
import importlib.util
import contextlib
import io
from importlib import metadata
from pathlib import Path
import py_compile
import tomllib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from szl_estate.access import AccessError, _observation
from szl_estate.model import EvidenceCode, EvidenceStatus, EvidenceValidationError
from szl_estate.setup import (
    EXPECTED_PYTEST_VERSION, LOCAL_CHECKS, SetupCheck, SetupReport, TestEvidence as OfflineEvidence,
    _check_source, _manifest, _run_tests, not_run_access, run_setup,
)
from szl_estate.cli import main

NOW = "2026-09-30T07:00:00Z"


def live_fixture():
    responses = (
        ("github:user", {"login": "test-user", "id": 1}),
        ("github:org:szl-holdings", {"login": "szl-holdings", "id": 2}),
        ("github:membership:szl-holdings", {"user": {"login": "test-user"}, "organization": {"login": "szl-holdings"}, "state": "active", "role": "admin"}),
        ("hf:whoami:SZLHOLDINGS", {"name": "hf-user", "orgs": [{"name": "SZLHOLDINGS", "roleInOrg": "admin"}]}),
    )
    return tuple(_observation(scope, NOW, (200, body, EvidenceCode.NONE)) for scope, body in responses)


def setup_fixture():
    checks = tuple(SetupCheck(name, EvidenceStatus.PASS, "NONE", NOW) for name in LOCAL_CHECKS)
    tests = OfflineEvidence(2, 2, 3, 0, 0, 0, 0, "a" * 64, "b" * 64)
    return SetupReport(NOW, checks, live_fixture(), tests)


def test_setup_acceptance_is_separate_from_estate_readiness():
    report = setup_fixture()  # synthetic complete Phase 0 conjunction only
    assert report.setup_ready
    assert report.to_dict()["estate_ready"] is False
    assert report.to_dict()["replay_grants_live_readiness"] is False


@pytest.mark.parametrize("name", LOCAL_CHECKS)
def test_phase0_cannot_omit_a_local_requirement(name):
    report = setup_fixture()
    assert not replace(report, checks=tuple(check for check in report.checks if check.name != name)).setup_ready


@pytest.mark.parametrize("status", [EvidenceStatus.NOT_RUN, EvidenceStatus.UNKNOWN, EvidenceStatus.FAIL, EvidenceStatus.INACCESSIBLE])
def test_phase0_nonpassing_local_or_access_evidence_never_promotes(status):
    report = setup_fixture()
    checks = (replace(report.checks[0], status=status), *report.checks[1:])
    assert not replace(report, checks=checks).setup_ready
    row = report.access[0].to_dict()
    row["status"] = status.value
    from szl_estate.storage import sha256_digest
    row["digest"] = sha256_digest({name: value for name, value in row.items() if name not in ("digest", "observed_at_utc")})
    changed = type(report.access[0]).from_dict(row)
    assert not replace(report, access=(changed, *report.access[1:])).setup_ready


@pytest.mark.parametrize("at", ["2026-09-30T05:59:59Z", "2026-09-30T07:00:01Z"])
def test_setup_rejects_stale_or_future_live_evidence(at):
    report = setup_fixture()
    assert not replace(report, access=(replace(report.access[0], observed_at_utc=at), *report.access[1:])).setup_ready
    assert not replace(report, checks=(replace(report.checks[0], checked_at_utc=at), *report.checks[1:])).setup_ready


def test_setup_unmeasured_matrix_is_explicit_and_never_ready():
    rows = not_run_access()
    assert len(rows) == 4
    assert all(row.status is EvidenceStatus.NOT_RUN and row.http_status is None for row in rows)
    assert all(not row.phase0_pass for row in rows)
    assert not replace(setup_fixture(), access=rows).setup_ready


@pytest.mark.parametrize("field,value", [("skips", 1), ("errors", 1), ("failures", 1), ("executed_definitions", 1), ("child_exit_code", 1)])
def test_internal_test_evidence_requires_complete_actual_success(field, value):
    report = setup_fixture()
    assert not replace(report, tests=replace(report.tests, **{field: value})).setup_ready


def test_test_evidence_rejects_boolean_counts():
    with pytest.raises(EvidenceValidationError, match="^INVALID_TEST_EVIDENCE$"):
        replace(setup_fixture().tests, cases=True)


def test_reviewed_source_rejects_forged_hashes_and_extra_test_code(tmp_path):
    source = tmp_path / "src/szl_estate/core.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# reviewed source\n")
    tests = tmp_path / "tests/test_core.py"
    tests.parent.mkdir()
    tests.write_bytes(b"def test_reviewed():\n    pass\n")
    files = {path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, tests)}
    manifest = {"files": files}
    assert len(_check_source(tmp_path, manifest)) == 64
    source.write_bytes(b"# changed source\n")
    with pytest.raises(EvidenceValidationError, match="^SOURCE_FINGERPRINT_MISMATCH$"):
        _check_source(tmp_path, manifest)
    source.write_bytes(b"# reviewed source\n")
    (tests.parent / "conftest.py").write_bytes(b"# unreviewed plugin\n")
    with pytest.raises(EvidenceValidationError, match="^SOURCE_FILE_SET_MISMATCH$"):
        _check_source(tmp_path, manifest)


def test_untrusted_source_blocks_test_execution(tmp_path):
    with patch("szl_estate.setup._manifest", return_value={"files": {}}), \
         patch("szl_estate.setup._check_source", side_effect=EvidenceValidationError("SOURCE_FINGERPRINT_MISMATCH")), \
         patch("szl_estate.setup._run_tests") as runner, \
         patch("szl_estate.setup.collect_access", return_value=not_run_access()):
        report = run_setup(tmp_path, tmp_path / "out")
    runner.assert_not_called()
    assert not report.setup_ready


@pytest.mark.parametrize("version", ["9.2.0", "9.1.1", "9.2.1", "10.0.0", "9.2.0rc1", None])
def test_setup_executes_tests_only_with_the_exact_reviewed_pytest(tmp_path, version):
    for name in ("src/szl_estate", "tests/fixtures", "evidence"):
        (tmp_path / name).mkdir(parents=True)
    manifest = {"files": {}}
    evidence = setup_fixture().tests
    with patch("szl_estate.setup._manifest", return_value=manifest), \
         patch("szl_estate.setup._check_source", return_value="b" * 64), \
         patch("szl_estate.setup.metadata.version", return_value=version,
               side_effect=metadata.PackageNotFoundError("pytest") if version is None else None) as installed_version, \
         patch("szl_estate.setup._run_tests", return_value=evidence) as runner, \
         patch("szl_estate.setup.collect_access", return_value=not_run_access()) as access:
        report = run_setup(tmp_path, tmp_path / "out")
    installed_version.assert_called_once_with("pytest")
    access.assert_called_once_with()
    offline = next(check for check in report.checks if check.name == "offline_tests")
    if version == "9.2.0":
        runner.assert_called_once_with(tmp_path.resolve(), "b" * 64, manifest)
        assert report.tests == evidence and offline.status is EvidenceStatus.PASS
        assert offline.code == "NONE"
    else:
        runner.assert_not_called()
        assert report.tests is None and offline.status is EvidenceStatus.FAIL
        assert offline.code == "TESTS_NOT_RUN_OR_EVIDENCE_INVALID"
    assert all(check.status is EvidenceStatus.PASS for check in report.checks if check.name != "offline_tests")
    assert all(row.status is EvidenceStatus.NOT_RUN for row in report.access)
    assert not report.setup_ready and report.to_dict()["estate_ready"] is False


@pytest.mark.parametrize("filename", ["pyproject.toml", "requirements.txt", "requirements-dev.txt"])
def test_declared_pytest_pins_match_the_strict_runtime_gate(filename):
    root = Path(__file__).resolve().parent.parent
    assert EXPECTED_PYTEST_VERSION == "9.2.0"
    raw = (root / filename).read_text(encoding="utf-8")
    if filename == "pyproject.toml":
        pins = tomllib.loads(raw)["project"]["optional-dependencies"]["test"]
    else:
        pins = [line.strip() for line in raw.splitlines() if line.strip().startswith("pytest")]
    assert pins == [f"pytest=={EXPECTED_PYTEST_VERSION}"]


def test_receipt_failure_blocks_setup_even_with_fresh_access(tmp_path):
    (tmp_path / "src/szl_estate").mkdir(parents=True)
    (tmp_path / "tests/fixtures").mkdir(parents=True)
    (tmp_path / "evidence").mkdir()
    with patch("szl_estate.setup._manifest", return_value={"files": {}}), \
         patch("szl_estate.setup._check_source", return_value="b" * 64), \
         patch("szl_estate.setup._run_tests", return_value=setup_fixture().tests), \
         patch("szl_estate.setup.collect_access", return_value=live_fixture()), \
         patch("szl_estate.setup.now_utc", return_value=NOW), \
         patch("szl_estate.setup.validate_access_receipt", side_effect=AccessError("ACCESS_RECEIPT_MISMATCH")):
        report = run_setup(tmp_path, tmp_path / "out", access_receipt=tmp_path / "forged.json")
    assert report.receipt_status is EvidenceStatus.FAIL
    assert not report.setup_ready


def test_test_runner_sanitizes_environment_and_requires_internal_junit(tmp_path, monkeypatch):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_example.py").write_text("def test_example():\n    pass\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\naddopts="-q"\n', encoding="utf-8")
    files = {path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in (tmp_path / "tests/test_example.py", tmp_path / "pyproject.toml")}
    monkeypatch.setenv("PYTEST_ADDOPTS", "--skip-invented")
    monkeypatch.setenv("PYTEST_PLUGINS", "unreviewed_plugin")
    monkeypatch.setenv("PYTHONPATH", "unreviewed_path")
    def runner(command, **kwargs):
        assert "-I" in command and "--noconftest" in command
        assert "-X" in command
        bytecode = Path(command[command.index("-X") + 1].removeprefix("pycache_prefix="))
        assert bytecode.parent != tmp_path and not bytecode.exists()
        assert kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert all(key not in kwargs["env"] for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH"))
        path = Path(command[command.index("--junitxml") + 1])
        path.write_text('<testsuites><testsuite><testcase classname="tests.test_example" name="test_example" /></testsuite></testsuites>', encoding="utf-8")
        return SimpleNamespace(returncode=0)
    with patch("szl_estate.setup.subprocess.run", side_effect=runner):
        result = _run_tests(tmp_path, "b" * 64, {"files": files})
    assert result.passed and result.executed_definitions == 1


def test_reviewed_runner_bypasses_forged_unchecked_bytecode(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    source = tests / "test_example.py"
    source.write_text("import helper\ndef test_example():\n    assert helper.REVIEWED == 1\n", encoding="utf-8")
    helper = tests / "helper.py"
    helper.write_text("REVIEWED = 1\n", encoding="utf-8")
    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.pytest.ini_options]\naddopts="-q"\n', encoding="utf-8")
    # Compile only; this synthetic hostile fixture is never executed.
    hostile = tmp_path / "hostile.py"
    hostile.write_text('raise RuntimeError("UNREVIEWED_BYTECODE")\n', encoding="utf-8")
    cache = Path(importlib.util.cache_from_source(str(helper)))
    cache.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(hostile), cfile=str(cache), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    manifest = {"files": {path.relative_to(tmp_path).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, helper, config)}}
    result = _run_tests(tmp_path, "b" * 64, manifest)
    assert result.passed and result.cases == 1


def test_cli_attempted_failed_setup_is_fail_and_estate_stays_unmeasured(tmp_path):
    report = SetupReport(NOW, (), not_run_access())
    with patch("szl_estate.cli.run_setup", return_value=report), contextlib.redirect_stdout(io.StringIO()) as captured:
        result = main(["verify", "--check-setup", "--package-root", str(tmp_path / "reviewed"), "--out", str(tmp_path / "out")])
    output = json.loads(captured.getvalue())
    assert result == 1 and output["status"] == "FAIL"
    assert output["setup_ready"] is False and output["estate_ready"] is False
    assert all(row["status"] == "NOT_RUN" for row in output["access_matrix"])


def test_committed_manifest_binds_reviewed_dependency_pin_files():
    # PR #139 rewrote pydantic and playwright pins and left the trust anchor on the previous digests.
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / "src/szl_estate/verification_manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "szl.reviewed-phase0-files/v1"
    unbound = []
    for name in ("pyproject.toml", "requirements.txt"):
        raw = (root / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        recorded = manifest["files"][name]
        if digest != recorded:
            pins = tuple(match.group(0) for match in re.finditer(r"(?:pydantic|playwright)==\d+\.\d+\.\d+", raw.decode("utf-8")))
            unbound.append({"file": name, "recorded": recorded, "checkout": digest, "pins": pins})
    assert unbound == []
    assert len(_check_source(root, manifest)) == 64


def test_pin_binding_runs_when_manifest_json_is_outside_the_reviewed_tree(tmp_path):
    # The setup runner stages only hashed files. verification_manifest.json is not one of them.
    root = Path(__file__).resolve().parent.parent
    manifest = _manifest()
    staged = tmp_path / "reviewed"
    for name, digest in manifest["files"].items():
        raw = (root / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        target = staged / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    assert not (staged / "src/szl_estate/verification_manifest.json").exists()
    spec = importlib.util.spec_from_file_location("staged_phase0_test_setup", staged / "tests/test_setup.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    module.test_committed_manifest_binds_reviewed_dependency_pin_files()


def test_actual_installed_manifest_binds_the_reviewed_checkout():
    root = Path(__file__).resolve().parent.parent
    assert len(_check_source(root, _manifest())) == 64
