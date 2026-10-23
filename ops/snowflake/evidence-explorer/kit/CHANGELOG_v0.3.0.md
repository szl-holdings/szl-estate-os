# Kit v0.3.0 changelog (2026-10-23) — DRAFT_READY, NOT LOCAL_TESTED, NOT APPROVED
Base: kit v0.2.0-rc1 (szl_ee_operator_kit_v0_2_0_rc1_20261022.zip). Narrow design adopted by the lead.
sf_deploy_pilot.py:
- six owner-created roles (adds SZL_EE_SETUP, SZL_EE_OPERATOR); preflight runs as SZL_EE_SETUP;
- REQUIRES SZL_EE_RM (quota == N, NEVER), SZL_EE_WH (exact properties incl. RESOURCE_MONITOR, AUTO_RESUME FALSE, XSMALL, owner ACCOUNTADMIN, timeouts via SHOW PARAMETERS) and all six roles;
- refuses if CURRENT_AVAILABLE_ROLES() lacks SZL_EE_SETUP or contains any admin/runtime/viewer role;
- never creates roles or warehouses; USE ROLE limited to SZL_EE_SETUP/OWNER/APP;
- ROLE_GRANTS empty (SYSADMIN hierarchy grants dropped); warehouse cells removed from GRANT_MATRIX (31 cells); owner-run grants listed in OWNER_RUN_GRANTS (OPERATE only to SZL_EE_OPERATOR);
- --out deploy.json rewritten (fsync) before and after every statement; pending statement and readback_required recorded;
- QUERY_TAG carries SZL_EE_RUN_ID.
sf_kit_common.py: run_id()/query_tag() (format-validated SZL_EE_RUN_ID), ProgressFile, KIT_VERSION 0.3.0.
sf_verify_account_readonly.py, sf_shutdown_verify.py: refuse a malformed SZL_EE_RUN_ID before connecting; QUERY_TAG carries the run id.
test_operator_kit.py: 77 test methods (was 64), updated for the narrow design — WRITTEN, NOT RUN.
mutation_sweep_kit.py: 88 mutants (M49/M55 retired, M17 retargeted, M62-M92 added; SNOWSIGHT_SETUP.sql copied for tests) — WRITTEN, NOT RUN.
SNOWSIGHT_SETUP.sql: owner sheet D0/D1/D2(commented)/D3/D4/D4b + revocation; fail-closed first line kept.
SNOWFLAKE_ACCESS_SETUP.md: two-user, two-key credential contract.
Privileges-track addition (flag for review): read-only MONITOR on SZL_EE_RM for SZL_EE_INGEST, so the runtime shutdown check can read the monitor.
Unchanged copies (other owners): szl_ee_go.py, test_szl_ee_go.py, mutation_sweep_go.py, docs/*, READINESS_PACKET_2026-10-22.md, rc_evidence/*.
Checks run this round: python -I -B -m py_compile on every touched .py (all exit 0); static string-count validation of all 88 mutants (each matches exactly once). No suites, sweeps, emulator or installs, per the lead's hard limit for this round (the lead reported C: at 10.7 GB free, below Stephen's 15 GB floor). Measured here: 10,150,596,608 bytes free (9.45 GiB) at the start of the round, 2026-10-23, and 16.96 GiB at packaging. The increase came from outside this session (no files were deleted here); the limit was applied as instructed, not re-decided on the later reading.
