"""Phase 0 acceptance: installed foundations plus narrow current account access."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib import metadata, resources
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
import xml.etree.ElementTree as ET

from .access import ACCESS_SPECS, AccessError, AccessObservation, collect_access, validate_access_receipt
from .model import EvidenceCode, EvidenceStatus, EvidenceValidationError, safe_identifier, utc_timestamp
from .storage import StorageError, atomic_write, canonical_bytes, integrity_bytes, sha256_digest

LOCAL_CHECKS = ("python", "installed_package", "reviewed_source", "folders", "offline_tests")
MANIFEST_NAME = "verification_manifest.json"
MAX_SOURCE_FILE = 1024 * 1024
EXPECTED_PYTEST_VERSION = "9.2.0"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class SetupCheck:
    name: str
    status: EvidenceStatus
    code: str
    checked_at_utc: str

    def __post_init__(self) -> None:
        if self.name not in LOCAL_CHECKS or not isinstance(self.status, EvidenceStatus):
            raise EvidenceValidationError("INVALID_SETUP_CHECK")
        safe_identifier(self.code)
        object.__setattr__(self, "checked_at_utc", utc_timestamp(self.checked_at_utc))

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status.value,
                "code": self.code, "checked_at_utc": self.checked_at_utc}


@dataclass(frozen=True, slots=True)
class TestEvidence:
    expected_definitions: int
    executed_definitions: int
    cases: int
    failures: int
    errors: int
    skips: int
    child_exit_code: int
    junit_sha256: str
    source_fingerprint: str

    def __post_init__(self) -> None:
        for name in ("expected_definitions", "executed_definitions", "cases", "failures", "errors", "skips"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 1000000:
                raise EvidenceValidationError("INVALID_TEST_EVIDENCE")
        if type(self.child_exit_code) is not int:
            raise EvidenceValidationError("INVALID_TEST_EVIDENCE")
        for value in (self.junit_sha256, self.source_fingerprint):
            if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise EvidenceValidationError("INVALID_TEST_EVIDENCE")

    @property
    def passed(self) -> bool:
        return (self.expected_definitions > 0 and self.executed_definitions == self.expected_definitions
                and self.cases >= self.expected_definitions and self.child_exit_code == 0
                and self.failures == self.errors == self.skips == 0)

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class SetupReport:
    checked_at_utc: str
    checks: tuple[SetupCheck, ...]
    access: tuple[AccessObservation, ...] = ()
    tests: TestEvidence | None = None
    receipt_status: EvidenceStatus = EvidenceStatus.NOT_RUN

    @property
    def setup_ready(self) -> bool:
        by_name = {check.name: check for check in self.checks}
        if len(by_name) != len(self.checks) or set(by_name) != set(LOCAL_CHECKS):
            return False
        if any(check.status is not EvidenceStatus.PASS or check.code != "NONE" for check in by_name.values()):
            return False
        if self.tests is None or not self.tests.passed:
            return False
        by_scope = {row.scope: row for row in self.access}
        if len(by_scope) != len(self.access) or set(by_scope) != set(ACCESS_SPECS):
            return False
        if by_scope["github:user"].username != by_scope["github:membership:szl-holdings"].username:
            return False
        checked = datetime.fromisoformat(utc_timestamp(self.checked_at_utc).replace("Z", "+00:00"))
        for check in self.checks:
            observed = datetime.fromisoformat(check.checked_at_utc.replace("Z", "+00:00"))
            if not 0 <= (checked - observed).total_seconds() <= 3600:
                return False
        for row in self.access:
            observed = datetime.fromisoformat(row.observed_at_utc.replace("Z", "+00:00"))
            if not row.phase0_pass or not 0 <= (checked - observed).total_seconds() <= 3600:
                return False
        return self.receipt_status in (EvidenceStatus.NOT_RUN, EvidenceStatus.PASS)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "szl.phase0-setup/v1", "checked_at_utc": self.checked_at_utc,
                "setup_ready": self.setup_ready, "estate_ready": False,
                "proof_scope": "PHASE0_SETUP_AND_NARROW_ACCOUNT_ACCESS",
                "checks": [check.to_dict() for check in self.checks],
                "access_matrix": [row.to_dict() for row in self.access],
                "tests": self.tests.to_dict() if self.tests else None,
                "receipt_status": self.receipt_status.value,
                "replay_grants_live_readiness": False}


def _manifest() -> dict[str, Any]:
    import szl_estate
    try:
        distribution = metadata.distribution("szl-estate-audit")
        installed = Path(distribution.locate_file("szl_estate")).resolve()
        if Path(szl_estate.__file__).resolve().parent != installed or distribution.version != "0.1.0":
            raise EvidenceValidationError("PACKAGE_NOT_INSTALLED")
        direct = distribution.read_text("direct_url.json")
        if direct and json.loads(direct).get("dir_info", {}).get("editable") is True:
            raise EvidenceValidationError("EDITABLE_PACKAGE_NOT_TRUST_ANCHOR")
        raw = resources.files("szl_estate").joinpath(MANIFEST_NAME).read_bytes()
        if len(raw) > 64 * 1024:
            raise EvidenceValidationError("INVALID_SOURCE_MANIFEST")
        manifest = json.loads(raw)
    except (metadata.PackageNotFoundError, OSError, ValueError, TypeError):
        raise EvidenceValidationError("PACKAGE_OR_MANIFEST_UNAVAILABLE") from None
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "files"} or manifest["schema"] != "szl.reviewed-phase0-files/v1":
        raise EvidenceValidationError("INVALID_SOURCE_MANIFEST")
    files = manifest["files"]
    if not isinstance(files, dict) or not 10 <= len(files) <= 100:
        raise EvidenceValidationError("INVALID_SOURCE_MANIFEST")
    for name, digest in files.items():
        if not isinstance(name, str):
            raise EvidenceValidationError("INVALID_SOURCE_MANIFEST")
        allowed = (name in {"pyproject.toml", "requirements.txt", "requirements-dev.txt", ".gitattributes"}
                   or name.startswith("src/szl_estate/") and name.endswith(".py")
                   or name.startswith("tests/") and name.endswith((".py", ".json")))
        if (not allowed or ".." in Path(name).parts or "\\" in name
                or not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)):
            raise EvidenceValidationError("INVALID_SOURCE_MANIFEST")
    package_files = {name.removeprefix("src/szl_estate/"): digest for name, digest in files.items() if name.startswith("src/szl_estate/")}
    if {path.relative_to(installed).as_posix() for path in installed.rglob("*.py")} != set(package_files):
        raise EvidenceValidationError("INSTALLED_SOURCE_MISMATCH")
    for name, digest in package_files.items():
        path = installed / name
        if path.is_symlink() or path.stat().st_size > MAX_SOURCE_FILE or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise EvidenceValidationError("INSTALLED_SOURCE_MISMATCH")
    return manifest


def _check_source(root: Path, manifest: dict[str, Any]) -> str:
    files = manifest["files"]
    inputs = {path.relative_to(root).as_posix() for folder in ("src", "tests")
              for path in (root / folder).rglob("*") if path.suffix == ".py" or folder == "tests" and path.suffix == ".json"}
    if inputs != {name for name in files if name.startswith(("src/", "tests/"))}:
        raise EvidenceValidationError("SOURCE_FILE_SET_MISMATCH")
    for name, digest in files.items():
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise EvidenceValidationError("SOURCE_LINK_REJECTED")
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_SOURCE_FILE + 1)
        except OSError:
            raise EvidenceValidationError("SOURCE_UNREADABLE") from None
        if len(raw) > MAX_SOURCE_FILE or hashlib.sha256(raw).hexdigest() != digest:
            raise EvidenceValidationError("SOURCE_FINGERPRINT_MISMATCH")
    return hashlib.sha256(canonical_bytes(files)).hexdigest()


def _expected_tests(root: Path) -> set[tuple[str, str]]:
    expected = set()
    for path in sorted((root / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                key = (path.stem, node.name)
                if key in expected:
                    raise EvidenceValidationError("DUPLICATE_TEST_DEFINITION")
                expected.add(key)
    return expected


def _run_tests(root: Path, fingerprint: str, manifest: dict[str, Any]) -> TestEvidence:
    environment = os.environ.copy()
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONPATH", "GH_TOKEN", "GITHUB_TOKEN", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"):
        environment.pop(name, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    with tempfile.TemporaryDirectory(prefix="szl-phase0-tests-") as directory:
        staged = Path(directory) / "reviewed"
        for name, digest in manifest["files"].items():
            with (root / name).open("rb") as stream:
                raw = stream.read(MAX_SOURCE_FILE + 1)
            if len(raw) > MAX_SOURCE_FILE or hashlib.sha256(raw).hexdigest() != digest:
                raise EvidenceValidationError("SOURCE_CHANGED_BEFORE_TESTING")
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        expected = _expected_tests(staged)
        junit = Path(directory) / "results.xml"
        bytecode = Path(directory) / "fresh-bytecode"
        completed = subprocess.run(
            [sys.executable, "-I", "-X", "pycache_prefix=" + str(bytecode), "-m", "pytest", "--noconftest", "-c", str(staged / "pyproject.toml"),
             str(staged / "tests"), "--junitxml", str(junit)],
            cwd=directory, env=environment, capture_output=True, timeout=60,
        )
        if not junit.is_file() or junit.stat().st_size > 2 * 1024 * 1024:
            raise EvidenceValidationError("TEST_EVIDENCE_MISSING")
        raw = junit.read_bytes()
        if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
            raise EvidenceValidationError("INVALID_TEST_EVIDENCE")
        try:
            suite = ET.fromstring(raw)
        except ET.ParseError:
            raise EvidenceValidationError("INVALID_TEST_EVIDENCE") from None
        cases = suite.findall(".//testcase")
        executed = {(next((part for part in case.get("classname", "").split(".") if part.startswith("test_")), ""),
                     case.get("name", "").split("[", 1)[0]) for case in cases}
        return TestEvidence(len(expected), len(expected & executed), len(cases),
                            len(suite.findall(".//failure")), len(suite.findall(".//error")),
                            len(suite.findall(".//skipped")), completed.returncode,
                            hashlib.sha256(raw).hexdigest(), fingerprint)


def run_setup(root: Path | None, output: Path, *, access_receipt: Path | None = None) -> SetupReport:
    checks: list[SetupCheck] = []
    manifest = None
    fingerprint = ""
    tests = None

    def record(name: str, passed: bool, code: str) -> None:
        checks.append(SetupCheck(name, EvidenceStatus.PASS if passed else EvidenceStatus.FAIL,
                                 "NONE" if passed else code, now_utc()))

    record("python", sys.version_info >= (3, 11), "PYTHON_TOO_OLD")
    try:
        manifest = _manifest()
        record("installed_package", True, "")
    except EvidenceValidationError as error:
        record("installed_package", False, str(error))
    try:
        if root is None or manifest is None:
            raise EvidenceValidationError("REVIEWED_PACKAGE_ROOT_REQUIRED")
        root = root.resolve()
        fingerprint = _check_source(root, manifest)
        record("reviewed_source", True, "")
    except (EvidenceValidationError, OSError) as error:
        record("reviewed_source", False, str(error) if isinstance(error, EvidenceValidationError) else "SOURCE_UNREADABLE")
    try:
        if root is None or not all((root / name).is_dir() for name in ("src/szl_estate", "tests/fixtures", "evidence")):
            raise EvidenceValidationError("REQUIRED_FOLDERS_MISSING")
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".phase0-probe-", dir=output) as directory:
            probe = Path(directory) / "probe"
            atomic_write(probe, b"PHASE0_OUTPUT_PROBE\n")
            if probe.read_bytes() != b"PHASE0_OUTPUT_PROBE\n":
                raise EvidenceValidationError("OUTPUT_PROBE_FAILED")
        record("folders", True, "")
    except (EvidenceValidationError, OSError, StorageError):
        record("folders", False, "REQUIRED_FOLDERS_OR_OUTPUT_UNAVAILABLE")
    try:
        if not fingerprint or root is None or manifest is None:
            raise EvidenceValidationError("TESTS_NOT_RUN_UNTRUSTED_SOURCE")
        if metadata.version("pytest") != EXPECTED_PYTEST_VERSION:
            raise EvidenceValidationError("TEST_RUNNER_VERSION_MISMATCH")
        tests = _run_tests(root, fingerprint, manifest)
        _check_source(root, manifest)
        record("offline_tests", tests.passed, "TEST_SUITE_INCOMPLETE_OR_FAILED")
    except (EvidenceValidationError, metadata.PackageNotFoundError, OSError, subprocess.SubprocessError, SyntaxError):
        record("offline_tests", False, "TESTS_NOT_RUN_OR_EVIDENCE_INVALID")
    try:
        access = collect_access()
    except (AccessError, OSError):
        access = not_run_access()
    receipt_status = EvidenceStatus.NOT_RUN
    if access_receipt is not None:
        try:
            validate_access_receipt(access_receipt, access)
            receipt_status = EvidenceStatus.PASS
        except (AccessError, EvidenceValidationError, StorageError, OSError):
            receipt_status = EvidenceStatus.FAIL
    return SetupReport(now_utc(), tuple(checks), access, tests, receipt_status)


def write_setup_report(path: Path, report: SetupReport) -> None:
    atomic_write(path, integrity_bytes(report.to_dict()))


def not_run_access() -> tuple[AccessObservation, ...]:
    rows = []
    for scope, (source, endpoint) in ACCESS_SPECS.items():
        fields = dict(scope=scope, status=EvidenceStatus.NOT_RUN, source=source, endpoint=endpoint,
                      observed_at_utc="1970-01-01T00:00:00Z", http_status=None, username=None,
                      identity_id=None, org=None, state=None, member_role=None, code=EvidenceCode.OFFLINE_NOT_MEASURED)
        projection = {name: value.value if hasattr(value, "value") else value for name, value in fields.items() if name != "observed_at_utc"}
        rows.append(AccessObservation(**fields, digest=sha256_digest(projection)))
    return tuple(rows)
