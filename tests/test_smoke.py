"""Smoke tests — estate baseline (2026-11-06).

These tests prove the repository's Python sources compile, that every
first-party module declared in pyproject.toml imports, and that each
first-party module those modules import is itself declared (otherwise an
installed copy fails with ModuleNotFoundError). The project declares no
third-party dependencies, so a missing module is a failure, never a skip.
"""
import ast
import compileall
import importlib
import pathlib
import sys
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT
_SETUPTOOLS = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
_DECLARED_TOP_LEVEL = set(_SETUPTOOLS.get("py-modules", [])) | set(_SETUPTOOLS.get("packages", []))
PACKAGES = sorted(
    list(_SETUPTOOLS.get("py-modules", []))
    + [
        f"{package}.{path.stem}"
        for package in _SETUPTOOLS.get("packages", [])
        for path in (ROOT / package).glob("*.py")
        if path.stem != "__init__"
    ]
)
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def test_sources_compile():
    targets = [p for p in ROOT.rglob('*.py') if '.git' not in p.parts and 'node_modules' not in p.parts and '.venv' not in p.parts]
    assert targets, "no Python sources found"
    for t in targets:
        if t.is_dir():
            assert compileall.compile_dir(str(t), quiet=1), f"compile failed under {t}"
        else:
            assert compileall.compile_file(str(t), quiet=1), f"compile failed: {t}"


def test_pyproject_declares_modules():
    assert PACKAGES, "pyproject.toml declares no importable module"


@pytest.mark.parametrize("pkg", PACKAGES)
def test_import_package(pkg):
    importlib.import_module(pkg)


def test_first_party_imports_are_packaged():
    first_party = {path.stem for path in ROOT.glob("*.py")} | {
        path.name for path in ROOT.iterdir() if path.is_dir()
    }
    undeclared = {}
    for module in PACKAGES:
        tree = ast.parse((ROOT / (module.replace(".", "/") + ".py")).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top in first_party and top not in _DECLARED_TOP_LEVEL:
                    undeclared.setdefault(module, set()).add(top)
    assert not undeclared, f"first-party imports missing from pyproject.toml [tool.setuptools]: {undeclared}"
