# Bundle v4 DRAFT notes (2026-10-23) — DRAFT_READY, NOT LOCAL_TESTED, NOT APPROVED

What changed from v3 (`szl_evidence_explorer_pilot1_local_v3_20261022.zip`, sha256 `a1b129fde9ca65158c863bce0ba1889a5a6274ec8bb8e76813a5324b4eefc479`):

1. `schema.sql` → v4 (narrow design). This applies `schema_v3_to_v4_PROPOSED.patch` and extends it.
   - §0 creates no roles and grants no role. The three `GRANT ROLE … TO ROLE SYSADMIN` hierarchy grants and the four `CREATE ROLE` statements are removed. The owner creates six roles in kit SNOWSIGHT_SETUP.sql block D0: SZL_EE_SETUP, SZL_EE_OWNER, SZL_EE_INGEST, SZL_EE_APP, SZL_EE_VIEWER and SZL_EE_OPERATOR.
   - §1 creates the database as `SZL_EE_SETUP` (CREATE DATABASE ON ACCOUNT only), no longer as SYSADMIN.
   - §5 is comments only. The owner creates the warehouse, assigns it to the monitor, and runs all warehouse grants (USAGE for APP/INGEST, OPERATE for SZL_EE_OPERATOR only) in D0.
   - Unchanged: §2–§4 (managed-access schemas, 7 tables, exact-object grants), §6, §7, the fail-closed first line.
2. `test_evidence_core.py`: `test_managed_access_and_named_owner` now requires `USE ROLE SZL_EE_SETUP;` before CREATE DATABASE. It also requires that no USERADMIN/SYSADMIN/CREATE ROLE/GRANT ROLE/warehouse grant appears. Written, **not run**.
3. `ADR.md`: banner added. Its role table describes v3 and is superseded for §0/§1/§5.
4. `MANIFEST.json`: regenerated over every file in the bundle (sha256 + bytes), including `receipt/tmp/*`, which v3 omitted. `MANIFEST.json` itself is excluded. The receipt entry is marked STALE.

Evidence status:
- **STALE.** `receipt/local_evidence_receipt.jsonl` and its logs, `TEST_RESULTS.md`, `emulator_results*.json`, `mutation_results*.json`, `verifier_mutation_results.json` and `appstub_smoke_results.json` all describe v3 inputs. They are retained byte-identical as history, not as v4 evidence.
- **BLOCKED.** Receipt regeneration: the emulator env was removed and no installs are allowed; suites were also not run per the lead's hard limit for this round (the lead reported C: at 10.7 GB free, below Stephen's 15 GB floor). Measured here: 10,150,596,608 bytes free (9.45 GiB) at the start of the round, 2026-10-23, and 16.96 GiB at packaging. The increase came from outside this session (no files were deleted here); the limit was applied as instructed, not re-decided on the later reading.
- **NOT_RUN.** Every bundle test against v4. The 11 live integration checks stay NOT_RUN.

Must run on the VM before any LOCAL_TESTED claim: see the kit's `VM_TEST_PLAN_v0_3_0.md`.
