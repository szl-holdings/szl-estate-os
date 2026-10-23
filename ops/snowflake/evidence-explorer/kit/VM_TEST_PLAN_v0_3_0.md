# VM_TEST_PLAN — kit v0.3.0 DRAFT + bundle v4 DRAFT (2026-10-23)

Nothing below has run. Both packages are **DRAFT_READY, not LOCAL_TESTED**. This round, the only check run on the laptop was `python -I -B -m py_compile`, per the lead's hard limit for this round (the lead reported C: at 10.7 GB free, below Stephen's 15 GB floor). Measured here: 10,150,596,608 bytes free (9.45 GiB) at the start of the round, 2026-10-23, and 16.96 GiB at packaging. The increase came from outside this session (no files were deleted here); the limit was applied as instructed, not re-decided on the later reading. Run these on the VM once Stephen attaches it as a compute target:
- serially;
- with a stdlib-only Python 3.11 or later;
- `-I -B`;
- TEMP/TMP pointing at a scratch folder;
- no Snowflake credentials in the environment.

Record each result raw (stdout/stderr, exit code, UTC, interpreter version, sha256 of every input).

Layout assumed: `<root>/szl_ee_operator_kit/` (kit zip) and `<root>/szl_evidence_explorer_pilot1/` (bundle zip).

| # | what | command (from the directory named) | expected | if it fails |
|---|---|---|---|---|
| 1 | kit unit suite (fake connector) | kit: `SZL_KIT_TEST_TMP=$PWD/tmp python -I -B test_operator_kit.py` | 77 tests, OK (static count of `def test_`) | fix kit; do not edit tests to pass without review |
| 2 | kit mutation sweep | kit: `SZL_KIT_TEST_TMP=$PWD/tmp python -I -B mutation_sweep_kit.py` | 88 mutants, 0 invalid; every survivor needs an EQUIVALENT/REDUNDANT argument plus a test, not suite-passing alone. Writes `mutation_results_kit.json` (absent in the zip by design; v0.1.2 results kept as `mutation_results_kit_v012.json`) | add a killing test or justify |
| 3 | runner suite (runner track's file, unchanged) | kit: `python -I -B test_szl_ee_go.py` | 65 tests (static count). Outcome UNKNOWN: the runner still uses the single-user SYSADMIN contract | report to the runner owner; do not edit here |
| 4 | runner mutation sweep | kit: `python -I -B mutation_sweep_go.py` | as recorded in rc1 evidence; UNKNOWN for v0.3.0 | runner owner |
| 5 | kit dry run against bundle v4 | kit: `python -I -B sf_deploy_pilot.py --dry-run --manifest ../szl_evidence_explorer_pilot1/MANIFEST.json` | exit 0. Plan has no CREATE ROLE, CREATE WAREHOUSE, GRANT ROLE, SYSADMIN or USERADMIN; first kit statement `USE ROLE SZL_EE_SETUP`; owner block printed first | fix schema v4 or kit |
| 6 | bundle unit suite | bundle: `python -I -B test_evidence_core.py -v` | 80 tests (static count), OK; includes the updated v4 schema test | fix schema v4 / test |
| 7 | bundle fixture rebuild | bundle: `python -I -B make_fixture.py <tmp>/fixture_rebuild.json` | byte-identical to `fixture_v1.json` | — |
| 8 | bundle mutation sweep | bundle: `python -I -B mutation_sweep.py <tmp>/mutation_results.json` | as v3 (targets evidence_core.py, unchanged) | — |
| 9 | receipt verifier tamper tests | bundle: `python -I -B test_verify_receipt.py -v` | OK | — |
| 10 | integration (live) | bundle: `python -I -B test_integration_snowflake.py -v` | exit 3, all 11 checks NOT_RUN (no credentials) | must stay NOT_RUN until D0–D6 are approved |
| 11 | emulator check | bundle: `<emulator-python> -I -B test_emulator_fakesnow.py <tmp>/emulator_results.json` | needs a fakesnow interpreter, which is an install: **only with Stephen's approval on the VM**. Role/grant statements are always UNSUPPORTED_BY_EMULATOR | BLOCKED until approved |
| 12 | regenerate bundle receipt | bundle: `python -I -B run_local_evidence.py --out receipt_v4 [--emulator-python <path>]` then `python -I -B verify_receipt.py receipt_v4/local_evidence_receipt.jsonl` | new receipt for v4 inputs. Use `--out receipt_v4` so the STALE v3 receipt is not overwritten; then regenerate MANIFEST.json with the new receipt entry | — |

After steps 1–2 and 5–9 pass, the packages may be labelled LOCAL_TESTED. That label still does not authorize anything live. The eleven live tests stay NOT_RUN until they genuinely execute.

Watch points the tests cannot settle (UNKNOWN until live, after approvals):
- whether `SHOW PARAMETERS … IN WAREHOUSE` is permitted for SZL_EE_SETUP (USAGE via SZL_EE_APP). If not, the preflight refuses (fail-closed) and the owner must decide;
- whether SHOW WAREHOUSES returns cluster-count columns on this edition;
- whether `CURRENT_AVAILABLE_ROLES()` runs without a warehouse;
- whether `DEFAULT_SECONDARY_ROLES = ()` is accepted at CREATE USER;
- how the runtime identity sees tasks and metering.
