SUPERSEDED (v0.1.1 copy, kept for provenance only). Contains stale statements, e.g. test counts (54) and approval status. Authoritative: READINESS_PACKET_2026-10-22.md and the documents it pins.

# OPERATOR_RUNBOOK — SZL Evidence Explorer operator kit (DRAFT, 2026-10-21)

Who runs it: **Stephen, on his own machine, with his own Snowflake login.** Claude Code may help him run it locally if he chooses.
No agent has run any of these steps against Snowflake. The status of every account step is **NOT_RUN**.

"Green light, do whatever you recommend to finish" (2026-10-21) is **not** a scoped spend or deployment approval, and it is not recorded as one.
The only approval this kit accepts is the one-line `approval.txt` described in step 4. That file is written by Stephen and its text must match APPROVAL_TEMPLATE.txt exactly.

Kit version `0.1.0-draft-20261021`. Standard library only, except the Snowflake Python connector, which only the operator installs.

## Files
| File | Purpose |
|---|---|
| `sf_verify_account_readonly.py` | Read-only account facts, exported as sanitized JSON. Moves the mission to ACCOUNT_VERIFIED evidence. |
| `sf_deploy_pilot.py` | Prints the exact ordered statements with `--dry-run` (the default). Executes only when every gate passes. |
| `sf_shutdown_verify.py` | Read-only post-session checks, each reported as PASS/FAIL/UNKNOWN. |
| `sf_kit_common.py` | Shared helpers: allowlist guard, warehouse-wake gate, sanitization. |
| `test_operator_kit.py` | 54 stdlib unit tests using a fake connector. |
| `mutation_sweep_kit.py` | 36-mutant sweep over the guards. |
| `APPROVAL_TEMPLATE.txt` | The exact approval line, with blanks to fill. |
| `DRY_RUN_SYNTHETIC_EXAMPLE.txt`, `COMPAT_DRY_RUN_bundle_b224275f.txt` | Dry-run transcripts. |
| `TEST_LOG_operator_kit.txt`, `mutation_results_kit*.json` | Test and sweep results (MEASURED in the agent sandbox, synthetic data only). |
| `KIT_SHA256SUMS.txt` | Digests of every other file in the kit. |

## Exit codes
| Code | verify | deploy | shutdown |
|---|---|---|---|
| 0 | all checks ran | dry-run printed / execute completed and post-checks recorded | all PASS |
| 1 | — | — | at least one FAIL |
| 2 | partial (some NOT_RUN/ERROR) | — | UNKNOWN present, no FAIL |
| 3 | refused (argv or statement) | refused before any change | refused |
| 4 | connector missing / connection failed | same | same |
| 5 | — | a statement failed **after changes began**: stop, do not re-run, bring the evidence back | — |

## Which statements may need a running warehouse
| Statement | Warehouse | Basis |
|---|---|---|
| `SHOW RESOURCE MONITORS`, `SHOW TASKS` | none | docs: "doesn't require a running warehouse" (fetched 2026-10-21) |
| `SHOW WAREHOUSES`, `SHOW DATABASES`, `SHOW ROLES` | none expected | REPORTED: metadata commands; not stated on the fetched pages |
| `SELECT CURRENT_ACCOUNT()` and other context functions | **UNKNOWN**, so treated as possibly needing one | not established in the fetched docs |
| `ACCOUNT_USAGE` / `ORGANIZATION_USAGE` queries | needs one | they are queries over views |
| DDL and GRANT in deploy (`CREATE ROLE/DATABASE/SCHEMA/TABLE/STAGE/STREAMLIT`), `PUT` | none expected | REPORTED; UNKNOWN for this account |

**Wake gate.** The kit never resumes a warehouse. Before any possibly-compute statement, it reads `SHOW WAREHOUSES` and checks `is_current`. Compute statements run only in two cases:
- the session has no current warehouse, so a compute query would fail instead of resuming anything; or
- the current warehouse is already STARTED.

Otherwise:
- verify and shutdown record those checks as NOT_RUN/UNKNOWN;
- deploy refuses, because the account check is mandatory.

The simplest setup is a named connection **without** a `warehouse` key, and a user with no default warehouse (UNKNOWN for this account).

## Step 0 — prepare (no account access)
1. Create a fresh venv and install the connector: `python -m venv .venv`, then `.venv\Scripts\pip install snowflake-connector-python`. Record the installed version.
2. In `%USERPROFILE%\.snowflake\connections.toml`, define a connection named `szl_ee_pilot`.
   - Use your own auth method (for example SSO/`externalbrowser` or key pair).
   - **Omit `warehouse`.**
   - Never pass credentials on the command line. The kit refuses all argv except `--out` and its documented flags.
   - The kit reads only `SZL_SF_CONNECTION_NAME`, or the connector's own default connection.
3. Check integrity: `Get-FileHash -Algorithm SHA256 *` and compare with `KIT_SHA256SUMS.txt`.
4. Run the tests: `python -I -B test_operator_kit.py`. Expect `Ran 54 tests ... OK`.
   - Optionally run `python -I -B mutation_sweep_kit.py`. Expect `36 mutants: 35 killed, 1 survived`, where M02 is equivalent.

## Step 1 — ACCOUNT_VERIFIED evidence (read-only, no spend)
```powershell
$env:SZL_SF_CONNECTION_NAME = "szl_ee_pilot"
$env:SZL_SF_EXPECTED_ACCOUNT = "<your account identifier>"   # compared only, never printed
.venv\Scripts\python sf_verify_account_readonly.py --out verify_evidence_<UTCdate>.json
```
- Expect exit 0, or exit 2 if a view is unavailable on a trial or a gated check was skipped.
- The JSON contains:
  - warehouses: state, size, auto_suspend, auto_resume, is_current, resource_monitor;
  - database names;
  - resource monitors;
  - redacted account fields plus `account_matches_expected`;
  - region, role and version;
  - 30-day metering, when gated in;
  - `REMAINING_BALANCE_DAILY` (latency up to 72 h; availability on a trial UNKNOWN).
- In Snowsight as ACCOUNTADMIN, the trial balance tile shows the remaining balance (docs). Write down the **balance, expiry date and whether the account is suspended** as text.

## Step 2 — answer the APPROVAL_CHECKLIST (DEPLOYMENT_PLAN.md v2)
Answer groups A–G once. Nothing proceeds on silence.

## Step 3 — manifest and dry run (no account access)
1. Get `MANIFEST.json` from the SQL/app track, or build it yourself from the bundle files you reviewed (`Get-FileHash -Algorithm SHA256`).
   - Format: `{"files": {"schema.sql": {"path": "schema.sql", "sha256": "<hex>"}, "reader_grants.sql": {...}, "streamlit_app.py": {...}, "evidence_core.py": {...}}}`.
   - Paths are relative to the manifest folder.
   - `evidence_core.py` is required in practice: the bundle's app imports it, and the kit refuses an unpinned local import.
2. Leave the `<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>` first lines of `schema.sql` and `reader_grants.sql` as delivered. The kit binds them in memory to your approval's sha256. Alternatively, replace each with `-- DEPLOYMENT_APPROVAL_REF: <approval sha256>` and re-pin the digests.
3. Write `approval.txt` from APPROVAL_TEMPLATE.txt.
   - Use one line.
   - `<N>` is a whole number from 1 to 10 (the kit cap).
   - `<UTC date>` is `YYYY-MM-DD`: later than today and within 31 days.
   - `<locator>` is either `CURRENT_ACCOUNT()` or `ORG-ACCOUNT_NAME`.
4. `.venv\Scripts\python sf_deploy_pilot.py --manifest MANIFEST.json --approval-file approval.txt > dry_run_<UTCdate>.txt`
   - Read every printed statement.
   - The B1 block is the **only** ACCOUNTADMIN step, and the kit never runs it.

## Step 4 — the single ACCOUNTADMIN step (manual, in Snowsight)
1. Run the printed B1 block exactly: `CREATE RESOURCE MONITOR SZL_EE_RM … FREQUENCY = NEVER …` and `GRANT MONITOR … TO ROLE SYSADMIN`.
2. Leave the optional `GRANT MODIFY` commented out unless step 5 fails with a privilege error on the monitor. Whether it is needed is UNKNOWN.
3. Verify with `SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM';`.

## Step 5 — execute (spends nothing by itself)
```powershell
.venv\Scripts\python sf_deploy_pilot.py --execute --manifest MANIFEST.json --approval-file approval.txt --out deploy_evidence_<UTCdate>.json
```
**Preflight.** The kit refuses (exit 3, nothing changed) unless all of these hold:
1. The warehouse gate is open.
2. The connected account equals the approval.
3. `SZL_EE_RM` exists, by exact name, with `CREDIT_QUOTA` = N and `FREQUENCY` = NEVER.
4. `SZL_EE_WH`, `SZL_EE_DB` and the four `SZL_EE_*` roles do not exist.
5. The digests still match.

**Execution order.**
1. Warehouse: `INITIALLY_SUSPENDED`, `AUTO_RESUME = FALSE`, assigned to the monitor.
2. The bundle's `schema.sql`.
3. Warehouse grants.
4. Stage, then `PUT` of the app files.
5. `CREATE STREAMLIT`.
6. The bundle's `reader_grants.sql`.

**Post-checks.** The warehouse must be SUSPENDED, auto_resume false, auto_suspend 60, with monitor `SZL_EE_RM`.

**On exit 5.** Do **not** re-run and do not drop anything. Bring the evidence back; rollback follows DEPLOYMENT_PLAN §2.

## Step 6 — approved session window (separate approval per session, AP-B3)
1. Open the window manually: `ALTER WAREHOUSE SZL_EE_WH SET AUTO_RESUME = TRUE;`. The kit refuses to do this.
2. Run the SQL/app track's fixture loader and integration checks.
3. Open the app. Record the session if approved.
4. Close the window: close app tabs, then `ALTER WAREHOUSE SZL_EE_WH SUSPEND;` and `ALTER WAREHOUSE SZL_EE_WH SET AUTO_RESUME = FALSE;`.

## Step 7 — shutdown verification
`.venv\Scripts\python sf_shutdown_verify.py --out shutdown_<UTCtimestamp>.json`
- Run it right after closing the window, and again 3–6 h later. Metering latency is up to 3 h, or 6 h for cloud services.
- PASS does not promise zero future charges: storage, cloud services and other resources can still cost money.

## Evidence to bring back (sanitized JSON / text only)
1. `verify_evidence_*.json`, plus the trial balance, expiry and suspended status as text.
2. Your APPROVAL_CHECKLIST answers.
3. `dry_run_*.txt`, and the approval sha256 printed in it.
4. The output of `SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM'`.
5. `deploy_evidence_*.json`. It contains query IDs, executed statements and post-checks.
6. Both `shutdown_*.json` files.

**Never bring back:** `connections.toml`, tokens, keys, passwords, screenshots of billing pages or invoices, or user lists.

## Known UNKNOWNs and limits (do not read past these)
- Whether SYSADMIN can assign the monitor inline with only `MONITOR`, or also needs `MODIFY`.
- Whether context functions need a running warehouse.
- The column names of `SHOW RESOURCE MONITORS`. The kit expects `credit_quota`, `used_credits` and `frequency`; if they differ, it refuses or reports UNKNOWN.
- The `END_TIMESTAMP` literal format `'YYYY-MM-DD 23:59:00 +00:00'`. Check it at step 4.
- The `PUT` Windows path form `file://C:/…`.
- SHOW output covers only objects your role can see.
- The kit does not grant `SZL_EE_VIEWER` to any user, load the fixture, or open a window.
- Single-tenant pilot: no isolation is claimed.
