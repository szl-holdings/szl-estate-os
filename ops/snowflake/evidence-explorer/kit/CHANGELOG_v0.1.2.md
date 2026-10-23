# Kit v0.1.2 changelog (privileges track, 2026-10-22) - PROPOSAL, NOT APPROVED FOR LIVE USE
Changed: sf_deploy_pilot.py (privilege guard), sf_kit_common.py (KIT_VERSION only), test_operator_kit.py
(+8 tests, 2 tests rewritten, SYN_SCHEMA view removed), mutation_sweep_kit.py (M25/M26 retired, M37-M61 added),
SNOWSIGHT_SETUP.sql (overclaims corrected, parse guard, no inline key, DISABLED user, no MODIFY-on-monitor hint),
SNOWFLAKE_ACCESS_SETUP.md (rewritten as proposal). Unchanged copies: sf_verify_account_readonly.py,
sf_shutdown_verify.py, szl_ee_go.py, test_szl_ee_go.py (owned by the runner track), docs/*, OPERATOR_RUNBOOK.md.
deploy_check v0.1.2: lexical pre-check on raw text (comments, double quotes, backslash, $$, unbalanced quotes,
non-ASCII outside literals); GRANT accepted only as a GRANT_MATRIX cell (33 privilege cells) or one of 3
ROLE_GRANTS pairs or the exact ownership transfer; CREATE ROLE/DATABASE/SCHEMA exact shapes; CREATE TABLE only
SZL_EE_DB.EE_DATA.<t>, no CLUSTER BY/CHANGE_TRACKING/POLICY/TAG, retention 1; CREATE WAREHOUSE/STAGE/STREAMLIT
must equal kit constants; PUT exact shape; CREATE VIEW/SEQUENCE, ALTER TABLE, COMMENT ON no longer accepted.
Adversarial corpus: v0.1.1 accepted 63 of 106 statements that must be refused; v0.1.2 refuses all 106.
KIT_SHA256SUMS.txt regenerated (v0.1.1's was stale for sf_deploy_pilot.py and test_operator_kit.py).
