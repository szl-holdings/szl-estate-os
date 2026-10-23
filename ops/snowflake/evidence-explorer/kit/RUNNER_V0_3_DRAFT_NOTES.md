# szl_ee_go.py v0.3.0 — DRAFT_READY (not LOCAL_TESTED)

Prepared 2026-10-23 (UTC) by the Recoverability track (runner owner). **Nothing here was run except
`python -I -B -m py_compile` on the three source files** (exit 0 for each, 2026-10-23T00:02:12Z).
Reason: the laptop's C: drive is below Stephen's 15 GB floor (7.45 GB free when last read,
MEASURED via `shutil.disk_usage`). No test suite, mutation sweep, emulator, install, Snowflake
connection or credential was used. The 2026-10-22 review brief still governs: nothing here is
approved for deployment, users, keys, grants or upload.

Design basis (REPORTED): PERSISTENT_ACCESS_PROPOSAL.md (version 89654200, NOT APPROVED) plus the
lead's decision D4b: role `SZL_EE_OPERATOR` with OPERATE on `SZL_EE_WH`, granted only to
`SZL_EE_RUNTIME`, also NOT APPROVED. Kit v0.3.0 and schema v4 were not saved when this was
written, so the runner keeps the v0.1.x kit CLI contract (see "Compatibility assumptions").

## What changed from v0.2 (all v0.2 guarantees kept)

| Requirement | v0.3 behaviour | Tests (written) | Mutants |
|---|---|---|---|
| Two identities | Mode A writes two temporary profiles, `szl_ee_setup` (role SZL_EE_SETUP, no warehouse, key `k_setup.p8`) and `szl_ee_runtime` (role SZL_EE_INGEST, warehouse SZL_EE_WH, database SZL_EE_DB, schema EE_DATA, key `k_runtime.p8`). It refuses the same user or the same key for both. Mode B takes `SZL_SF_SETUP_CONNECTION_NAME` and `SZL_SF_RUNTIME_CONNECTION_NAME`, which must differ. The v0.2 single-identity variables are refused, and so is mixing modes. No `role = SYSADMIN` remains anywhere | TestRefusals, TestTwoProfiles | A01, A11–A15 |
| Profile per step | verify / dry run / deploy / object readback use setup. Identity runs on both. RESUME and SUSPEND run on runtime as `USE SECONDARY ROLES SZL_EE_OPERATOR` then the fixed ALTER, all on one connection. Integration tests, the runtime warehouse readback and the shutdown verifier use runtime. Kit children get `SZL_SF_CONNECTION_NAME` set to their profile, and neither connection-name variable leaks to a child | TestTwoProfiles | A07–A10, A14 |
| No admin role at run time | Identity reads `CURRENT_USER()`, `CURRENT_ROLE()` and `CURRENT_AVAILABLE_ROLES()` on both profiles. It refuses: the wrong primary role; any of ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, USERADMIN or ORGADMIN available; setup having INGEST or OPERATOR; runtime having SETUP, OWNER or APP; runtime lacking OPERATOR (so a reliable SUSPEND exists before anything is deployed); the same user on both; different accounts | TestTwoProfiles ×8 | A02–A06, G04 |
| Kit digest pins | New required `--kit-sums-sha256`. `KIT_SHA256SUMS.txt` must hash to it. Every `sf_*.py` in `--kit` must be listed and match, every listed `sf_*.py` must exist, and the four required scripts must be present. Malformed, duplicate or path-escaping lines are refused | TestPins | P01–P05, P12 |
| Bundle digest pins | New required `--manifest-sha256`. `MANIFEST.json` must hash to it, and the three bundle files the runner executes (`test_integration_snowflake.py`, `evidence_core.py`, `make_fixture.py`) must be pinned in it and match | TestPins | P06–P08 |
| Pins re-checked | Before every kit child, again immediately before deploy starts (a change there is REFUSED with nothing deployed), before the integration tests, and before the shutdown verifier. A changed verifier is not run, so the shutdown is unverified and the run FAILs | TestPins ×3 | P09–P11 |
| Live-test prerequisite | Before any credential is read, `sys.executable -I -B -c "import snowflake.snowpark"` runs, with SNOWFLAKE_HOME set to the empty temp dir. If it fails, times out or raises, the run is **BLOCKED (exit 4)** with no connection and no deploy. Nothing is installed. Skipped with `--dry-run-only` | TestPrerequisites, TestRealSnowparkProbe | Q01–Q04 |
| Owner-created objects (narrow design) | Pre-inventory (setup profile) REFUSES if SZL_EE_DB, the app or the stage exist. It REQUIRES SZL_EE_RM exactly once and SZL_EE_WH exactly once (case-insensitive), SUSPENDED, `auto_resume` false, `resource_monitor` SZL_EE_RM and owner ACCOUNTADMIN. Roles are recorded, not required (SHOW ROLES visibility is UNKNOWN) | TestInventory | W01–W05, N05–N08, N28 |
| Shutdown verdict | Verified only if verifier exit is 0/2, W1, W2 and T1 PASS, the runtime readback says SUSPENDED, and the setup readback says SUSPENDED or was unreadable. The billable list now states the warehouse owner and that only ACCOUNTADMIN can act if the runtime role cannot suspend | TestShutdownVerdict ×9 | G02, G15, N16–N18b |

Exit codes: 0 PASS; 2 INCOMPLETE; 1 FAIL; 3 REFUSED; **4 BLOCKED** (no credential, no connector, or no
Snowpark for the live tests); 6 uncertain outcome.

## Known limits (UNKNOWN until a live run)
- Whether `USE SECONDARY ROLES <role>` (a named role rather than ALL/NONE) is accepted, and whether
  OPERATE through a secondary role suffices for ALTER WAREHOUSE … RESUME/SUSPEND. If not, the
  identity checks still pass, but RESUME would be UNKNOWN (exit 6) and SUSPEND would fail. Both
  fail-closed.
- Whether `CURRENT_AVAILABLE_ROLES()` lists inherited roles or only direct grants. If only direct,
  an admin role reached through the hierarchy would not be seen. The privileges track's
  `SHOW GRANTS` readback remains the authoritative check.
- With the runtime profile the shutdown verifier probably cannot see SZL_EE_RM (no MONITOR grant), so
  R1 is expected UNKNOWN. Best case is then exit 2 with the shutdown verified, never PASS.
- Kill of G17 (SNOWFLAKE_HOME before connector import) depends on the connector raising without a
  config directory. That was MEASURED on this Windows host in v0.2; on the VM it is UNKNOWN.

## Compatibility assumptions with kit v0.3.0 / schema v4 (other owner; must be confirmed)
1. The CLI is unchanged: `sf_verify_account_readonly.py --out F`; `sf_deploy_pilot.py --dry-run --manifest M`;
   `sf_deploy_pilot.py --execute --manifest M --approval-file A --out F`; `sf_shutdown_verify.py --out F`.
2. The scripts still read `SZL_SF_CONNECTION_NAME`, and deploy exit codes are still 0/3/4/5 with
   `deploy.json` fields `changes_begun`, `executed`, `failed_step` and a non-empty `post_checks` list.
   If kit v0.3 drops warehouse post_checks because the owner now creates it, the runner will FAIL the
   deploy step, and the post_checks rule needs a joint change.
3. The kit ships a `KIT_SHA256SUMS.txt` that lists every `sf_*.py` with correct hashes. Kit v0.1.1's did
   not (FAILURE_BOUNDARY_MAP.md §0).
4. The v4 MANIFEST pins the three executed bundle files.
5. The kit does not yet put `SZL_EE_RUN_ID` into its QUERY_TAGs.

## Must run on the VM (in this order; nothing below has been run)
Interpreter: the VM's Python with `snowflake-connector-python` (the laptop had 5.1.0). Snowpark
present or absent: both branches of TestRealSnowparkProbe are valid. Installing Snowpark is an
owner decision. Keep TEMP/TMP inside the working dir. No credentials in the environment.

1. Syntax: `python -I -B -m py_compile szl_ee_go.py test_szl_ee_go.py mutation_sweep_go.py`
2. Runner suite (98 tests: 90 use FakeRunner + FakeConnector; 6 TestItestParser tests call the parser only;
   TestRealImportPath and TestRealSnowparkProbe use the real interpreter with no credential). Needs `itest_output_no_env.txt` in the same dir:
   `python -I -B test_szl_ee_go.py 2> RAW_unittest_v0_3.txt; echo exit=$?`
3. Runner mutation sweep (83 mutants: G 17, N 30, P 12, Q 4, A 15, W 5). It gates itself on ≥ 2 GiB RAM
   and ≥ 15 GB free disk, and deletes each mutant dir after use:
   `mkdir -p sweep && python -I -B mutation_sweep_go.py . sweep/mutation_results_go_v0_3.json > sweep/mutation_sweep_stdout.txt`
   Accept only clean = PASS. Any SURVIVED or INVALID is reported with the exact snippet, not explained away.
4. Pin compatibility against the real candidate (no credential; expect exit 4, steps `pins PASS` then
   `credentials BLOCKED`):
   `python -I -B szl_ee_go.py --kit <kit v0.3 dir> --bundle <bundle v4 dir> --approval <kit>/approval.txt --out out --kit-sums-sha256 <sha256 of KIT_SHA256SUMS.txt> --manifest-sha256 <sha256 of MANIFEST.json> --dry-run-only`
5. Other owners' suites, also needed before any readiness claim (commands per their owners):
   kit v0.3 `test_operator_kit.py` and `mutation_sweep_kit.py`; bundle v4 unit, receipt-verifier and
   emulator suites.

## Failure-boundary deltas versus FAILURE_BOUNDARY_MAP.md (v3 design)
Under the narrow design the owner creates SZL_EE_RM, SZL_EE_WH and the six roles (D0) and both users
(D1–D4b) before any runner step. So a failure at the first kit statement leaves **all owner D0–D4b
objects and grants** in place, and nothing from the kit. The kit no longer creates the warehouse or
roles, and there are no `… TO ROLE SYSADMIN` grants. The map's §3c table has to be regenerated from
the kit v0.3 dry run once it exists. That has not been done here.
