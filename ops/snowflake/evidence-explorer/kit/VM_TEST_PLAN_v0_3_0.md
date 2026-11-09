# VM_TEST_PLAN — kit v0.3.0 DRAFT + bundle v4 DRAFT (2026-10-23)

Hosted offline CI has run; both packages remain **DRAFT_READY, not LOCAL_TESTED**, and no live Snowflake result exists. GitHub Actions run `42286104907` on 2026-11-06 UTC checked protected main at `0f1c831479814fa3b4d1b12f5a75b3a81433080b`. The combined core suite completed 146 tests, with 11 credential-gated live tests skipped as NOT_RUN; the job passed. The same run completed 78 kit tests, 67 runner tests and 14 mutation-harness tests. Mutation sweeps killed 48 of 48 core, 88 of 88 kit and 83 of 83 runner mutants. The receipt-verifier mutation sweep killed 17 mutants, with 1 equivalent and no survivors or invalid mutants. This hosted evidence does not authorize deployment, create LOCAL_TESTED evidence or verify any Snowflake account behavior.

The 2026-10-23 local round ran only `python -I -B -m py_compile`, per the lead's hard limit for that round (the lead reported C: at 10.7 GB free, below Stephen's 15 GB floor). Measured then: 10,150,596,608 bytes free (9.45 GiB) at the start and 16.96 GiB at packaging. The increase came from outside that session; no cleanup was attributed to this work. Run the bound sequence below on the VM once Stephen attaches it as a compute target:
- serially;
- with a stdlib-only Python 3.11 or later;
- `-I -B`;
- TEMP/TMP pointing at a scratch folder;
- no Snowflake credentials in the environment.

Record each result raw (stdout/stderr, exit code, UTC, interpreter version, sha256 of every input).

Layout assumed: `<root>/szl_ee_operator_kit/` (kit zip) and `<root>/szl_evidence_explorer_pilot1/` (bundle zip).

| # | what | command (from the directory named) | expected | if it fails |
|---|---|---|---|---|
| 1 | kit unit suite (fake connector) | kit: `SZL_KIT_TEST_TMP=$PWD/tmp python -I -B test_operator_kit.py` | 78 tests, OK in hosted run `42286104907` | fix kit; do not edit tests to pass without review |
| 2 | kit mutation sweep | kit: `SZL_KIT_TEST_TMP=$PWD/tmp python -I -B mutation_sweep_kit.py` | 88 killed, 0 survived, 0 invalid in hosted run `42286104907`; every future survivor needs an EQUIVALENT/REDUNDANT argument plus a test, not suite-passing alone. Writes `mutation_results_kit.json` (absent in the zip by design; v0.1.2 results kept as `mutation_results_kit_v012.json`) | add a killing test or justify |
| 3 | runner suite | kit: `python -I -B test_szl_ee_go.py` | 67 tests, OK in hosted run `42286104907`; current runner requires separate deploy/runtime identities and refuses legacy variables/admin roles | fix runner or tests with review |
| 4 | runner mutation sweep | kit: `python -I -B mutation_sweep_go.py` | 83 killed, 0 survived in hosted run `42286104907` | add a killing test or justify |
| 5 | kit dry run against bundle v4 | kit: `python -I -B sf_deploy_pilot.py --dry-run --manifest ../szl_evidence_explorer_pilot1/MANIFEST.json` | exit 0. Plan has no CREATE ROLE, CREATE WAREHOUSE, GRANT ROLE, SYSADMIN or USERADMIN; first kit statement `USE ROLE SZL_EE_SETUP`; owner block printed first | fix schema v4 or kit |
| 6 | bundle unit suite | bundle: `python -I -B test_evidence_core.py -v` | 93 tests, OK in hosted run `42286104907`; the combined core command completed 146 tests with all 11 live checks skipped as NOT_RUN | fix schema v4 / test |
| 7 | bundle fixture rebuild | bundle: `python -I -B make_fixture.py <tmp>/fixture_rebuild.json` | byte-identical to `fixture_v1.json` | — |
| 8 | bundle mutation sweep | bundle: `python -I -B mutation_sweep.py <tmp>/mutation_results.json` | 48 killed, 0 survived, 0 invalid in hosted run `42286104907` | add a killing test or justify |
| 9 | receipt verifier tamper tests | bundle: `python -I -B test_verify_receipt.py -v` | OK | — |
| 10 | integration (live) | bundle: `python -I -B test_integration_snowflake.py -v` | exit 3, all 11 checks NOT_RUN (no credentials) | must stay NOT_RUN until D0–D6 are approved |
| 11 | emulator check | bundle: `<emulator-python> -I -B test_emulator_fakesnow.py <tmp>/emulator_results.json` | needs a fakesnow interpreter, which is an install: **only with Stephen's approval on the VM**. Role/grant statements are always UNSUPPORTED_BY_EMULATOR | BLOCKED until approved |
| 12 | regenerate bundle receipt | bundle: `python -I -B run_local_evidence.py --out receipt_v4 [--emulator-python <path>]` then `python -I -B verify_receipt.py receipt_v4/local_evidence_receipt.jsonl` | new receipt for v4 inputs. Use `--out receipt_v4` so the STALE v3 receipt is not overwritten; then regenerate MANIFEST.json with the new receipt entry | — |

Hosted CI does not set LOCAL_TESTED because the VM/local receipt sequence above has not been rerun as one bound execution. After steps 1–2 and 5–9 pass in that sequence, the packages may be labelled LOCAL_TESTED. That label still does not authorize anything live. The eleven live tests stay NOT_RUN until they genuinely execute.

Watch points the tests cannot settle (UNKNOWN until live, after approvals):
- whether `SHOW PARAMETERS … IN WAREHOUSE` is permitted for SZL_EE_SETUP (USAGE via SZL_EE_APP). If not, the preflight refuses (fail-closed) and the owner must decide;
- whether SHOW WAREHOUSES returns cluster-count columns on this edition;
- whether `CURRENT_AVAILABLE_ROLES()` runs without a warehouse;
- whether `DEFAULT_SECONDARY_ROLES = ()` is accepted at CREATE USER;
- how the runtime identity sees tasks and metering.
