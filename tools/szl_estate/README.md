# SZL estate audit foundations

An installable Python 3.11+ package inside the existing estate control repository.
Phase 0 consumes local evidence and provides a separate setup acceptance gate.
It contains no remote write executor or live estate crawler. Its opt-in access
checks are limited to GitHub identity/org/membership and HF identity/membership.

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
exit 1 when Phase 0 setup has not been checked or its criteria are not satisfied.
The four full estate required scopes are NOT_RUN with OFFLINE_NOT_MEASURED and authorization UNKNOWN.
INACCESSIBLE describes an attempted access failure, not an unexecuted audit.
Full estate readiness is a separate later-phase gate. Identical inputs
and `--as-of` yield identical bytes. Input digests and source times are retained;
no automatic provider authentication, secret collection or live probing occurs.
Without source times, 1970-01-01 is an explicit unobserved sentinel; it is not
a live observation. Reports show a reference time, not perpetual currentness.
Writes are atomic per file. A failure between files returns an error and can
leave mixed report generations; replay the same inputs before using that run.

## Offline scout recommendations

The optional `recommend-scout` command accepts only the bounded numeric JSON
projection produced by the local estate snapshot scout. It prints a deterministic
JSON report to standard output, with source digests and observation times next
to proposal-only recommendations:

```text
python -m szl_estate recommend-scout /path/to/scout-projection.json
```

This command performs no network calls, provider writes, merge actions or model
inference. It rejects duplicate keys, oversized files, inconsistent counts and
claims that an unsigned projection authenticated itself or verified readiness.
Its source hashes are claims carried by that unsigned projection; the command
does not reread the raw GitHub and Hugging Face snapshot files. Keep any raw
private-scope inventory out of public PRs. Default-head CI rollups and Space
stages are historical hints for follow-up probes, never merge authorization,
functional readiness, model qualification or an external witness.

Check the actual Phase 0 contract from the repository root:

```text
python -I -m szl_estate verify --check-setup --package-root tools/szl_estate --out outputs/phase0-setup
```

This opt-in mode prints the access matrix and records phase0_state.json. It exits
0 only when Python 3.11+, the installed package and reviewed source/test/pin
fingerprints, required folders and writable output, the complete offline suite,
GitHub user/org/active membership role, and HF identity/SZLHOLDINGS membership
are all evidenced. It reports setup_ready=true independently of estate_ready=false;
all four full estate scopes remain NOT_RUN. Domains, inventory completeness,
scientific validity and deployment are outside this setup gate.

The verifier loads its manifest from the installed package, rejects changed or
extra executable/test inputs and editable/source-shadowed installs, then
copies verified inputs to a temporary directory and runs those tests once in
isolated Python with plugins and conftest disabled,
using an empty temporary bytecode cache to bypass existing checkout caches.
It checks the fingerprints again after testing. No supplied JUnit/JSON assertion
can grant test PASS. Following reviewed file changes, run
`python tools/szl_estate/build_verification_manifest.py`, then reinstall the
package; this hashes files but does not grant testing or access PASS.

Access reads use existing GitHub CLI authorization and existing HF token state
in process, following [HF's documented token locations](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables).
Only three fixed GitHub GETs and HTTPS HF whoami-v2 are requested. No inventories,
browser downloads, logins, permission changes, tokens or raw responses are saved.
Optional `--access-receipt` context must be complete, fresh, source-bound and
match a fresh narrow read; it cannot independently grant readiness. Unknown
unexposed HTTP remains unknown. Persisted setup reports describe their recorded
time and scope and never grant a fresh live setup pass when loaded later.

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
[The bounded access diagnosis](evidence/access-diagnosis-20260930.json) supersedes
its untested-scope interpretation with NOT_RUN coverage and UNKNOWN authorization,
and records the exact available endpoint/tool statuses and smallest remediation.

Local Python 3.11 validation executed all 122 authored test definitions as
268 parametrized cases: 268 passed, zero failures, errors or skips. The installed
module works from an unrelated directory. Two historical-evidence replays
produced identical JSON, CSV and report bytes and returned exit 1 with
INACCESSIBLE full scope in the original source revision. That recorded output is
preserved in [the dated validation receipt](evidence/local-validation-20260930.json);
the classification correction distinguishes NOT_RUN from attempted denial.
[The correction validation](evidence/classification-validation-20260930.json)
executes all 122 definitions as 271 passing cases, with no failures, errors or
skips. Installed CLI replays remain byte-identical and return NOT_RUN, exit 1:
package validation passes while the full-scope readiness exit remains blocked.
Those dated runs predate the separate Phase 0 setup gate and remain preserved.
The [program-generated Phase 0 setup receipt](evidence/phase0-setup-validation-20260930.json)
records the later actual exit 0 at 2026-09-30T07:33:23Z: all 153 definitions
executed as 333 passing cases, all five local checks and four narrow access
checks PASS, setup_ready=true and estate_ready=false. This is a dated snapshot;
loading it does not grant a fresh setup pass.
The [OSV query receipt](evidence/dependency-security-evidence.json) records no
matching advisories returned for the eight installed build/test pins; this
does not certify package security.
