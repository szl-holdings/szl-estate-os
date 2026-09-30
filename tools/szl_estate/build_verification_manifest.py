"""Refresh the installed-package trust anchor after reviewing Phase 0 file changes.

This hashes reviewed files; it executes no repository code and grants no test or
access PASS. Install the resulting package before checking setup. Exact LF bytes
follow this directory's .gitattributes on Windows and hosted runners.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile


root = Path(__file__).resolve().parent
paths = [root / name for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt", ".gitattributes")]
paths += list((root / "src").rglob("*.py"))
paths += [path for path in (root / "tests").rglob("*") if path.suffix in (".py", ".json")]
files = {}


def replace_bytes(path, raw):
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)  # retain the temporary file on a failed write


for path in sorted(paths):
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise SystemExit("SOURCE_LINK_REJECTED")
    raw = path.read_bytes()
    normalized = raw.replace(b"\r\n", b"\n")
    if raw != normalized:
        replace_bytes(path, normalized)
    files[path.relative_to(root).as_posix()] = hashlib.sha256(normalized).hexdigest()
manifest = {"schema": "szl.reviewed-phase0-files/v1", "files": files}
target = root / "src/szl_estate/verification_manifest.json"
replace_bytes(target, (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8"))
print(json.dumps({"manifest_files": len(files), "status": "HASHED_NOT_TESTED"}, sort_keys=True))
