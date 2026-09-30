# SZL estate audit foundations

An installable Python 3.11+ package inside the existing estate control repository.
Phase 0 consumes local evidence and produces an explicit account of what remains
unknown. It contains no remote write executor or live estate crawler.

From the repository root, use a fresh environment:

```powershell
python -m venv tools/szl_estate/.venv
tools/szl_estate/.venv/Scripts/python -m pip install --no-cache-dir --only-binary=:all: -r tools/szl_estate/requirements-dev.txt
tools/szl_estate/.venv/Scripts/python -m pip install --no-deps --no-build-isolation tools/szl_estate
tools/szl_estate/.venv/Scripts/python -m szl_estate verify
tools/szl_estate/.venv/Scripts/python -m pytest tools/szl_estate/tests
```

On POSIX, use tools/szl_estate/.venv/bin/python. Once installed,
`python -m szl_estate verify` works from any directory in that environment.
The optional requirements.txt records the eight requested exact dependency
versions; none is required to import or run the Phase 0 verifier. Build and
focused test pins are separate. Do not install Playwright browsers.
Optional packages have exact direct pins and official metadata evidence;
their provider/browser dependency closure has not been installed or tested.

Supply locally materialized existing evidence:

```text
python -m szl_estate verify --backend-bundle /path/to/szl-holdings-audit-evidence-2026-09-30.zip --hf-inventory /path/to/SZL_HuggingFace_Audit_2026-09-30.json --out /path/to/new-run
```

The command writes estate_state.json, evidence.csv and report.md. It returns
nonzero while estate scope is inaccessible, unknown, partial or failed; that
is an expected honest result for historical inputs. Without inputs it records
INACCESSIBLE rather than reporting an empty successful audit. Identical inputs
and `--as-of` yield identical bytes. Input digests and source times are retained;
no automatic provider authentication, secret collection or live probing occurs.
Without source times, 1970-01-01 is an explicit unobserved sentinel; it is not
a live observation. Reports show a reference time, not perpetual currentness.
Writes are atomic per file. A failure between files returns an error and can
leave mixed report generations; replay the same inputs before using that run.

The Library GitHub bundle version 2 is a frozen coverage record: 130 repositories,
542 inspected paths, 32,206 unread or skipped paths. Its digest and source identity
are in evidence/source-receipt.json. The HF version 1 inventory is historical.
This package reads only bounded summaries and never extracts or executes archive
members. Full-source review, private completeness, functional estate testing,
scientific validation and deployment verification remain unestablished.

Use [OPERATION_RULES.md](OPERATION_RULES.md) for the seven provenance headings.
[evidence/dependency-evidence.json](evidence/dependency-evidence.json) records
official version metadata and wheel hashes. These pins preserve the existing
maintenance requests/HF/pytest/HTTPX versions. Pydantic, Rich, BeautifulSoup and
Playwright are reserved optional tooling; no new adapters are claimed.
[evidence/access-matrix-20260930.json](evidence/access-matrix-20260930.json) is a
dated, narrow access receipt. Authentication success and root HTTP 200 responses
do not establish full remote scope, service correctness or estate readiness.

Local Python 3.11 validation executed all 122 authored test definitions as
268 parametrized cases: 268 passed, zero failures, errors or skips. The installed
module works from an unrelated directory. Two historical-evidence replays
produced identical JSON, CSV and report bytes and returned exit 1 with
INACCESSIBLE full scope. See [the dated validation receipt](evidence/local-validation-20260930.json).
The [OSV query receipt](evidence/dependency-security-evidence.json) records no
matching advisories returned for the eight installed build/test pins; this
does not certify package security.
