<<OWNER_REVIEW_REQUIRED_SEE_PERSISTENT_ACCESS_PROPOSAL>>
-- ^ Deliberate fail-closed first line: this worksheet does not parse until the owner removes it.
--   (Whether Snowsight "Run All" stops at the first error is UNKNOWN; run one decision block at a time.)
--
-- SZL Evidence Explorer pilot 1 - OWNER SHEET, kit v0.3.0 DRAFT (2026-10-23), narrow design.
-- STATUS: PROPOSAL - NOT APPROVED. Stephen's 2026-10-22 review authorizes no deployment, spending,
-- credential creation, persistent access, privilege expansion, upload or security-setting change.
-- Each block below is a SEPARATE decision (D0, D1, D2, D3, D4, D4b) and needs its own approval in the
-- wording given in PERSISTENT_ACCESS_PROPOSAL.md. Approving one block approves nothing else.
--
-- Identities: SZL_EE_DEPLOY holds only SZL_EE_SETUP (deploy); SZL_EE_RUNTIME holds only SZL_EE_INGEST
-- and SZL_EE_OPERATOR (runtime). Neither ever holds ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, USERADMIN or
-- ORGADMIN. The kit (sf_deploy_pilot.py v0.3.0) never creates roles or warehouses and refuses to run unless
-- the objects below exist with exactly these properties.
-- Expiry: monitor END_TIMESTAMP 2026-11-21 23:59:00 +00:00 (UTC), a proposed restriction inside the original 2026-11-30
-- window, not a fresh grant. The kit's approval parser refuses on the 'until' date itself.
-- A resource monitor is NOT a hard spending cap: it covers the assigned warehouse (and its cloud services);
-- SUSPEND lets running statements finish, so usage can pass the quota; serverless, storage and other
-- charges are outside it. See COST_AND_SHUTDOWN.md.

-- ======================================================================================= D0
-- Owner foundation objects. ACCOUNTADMIN is genuinely required for the monitor and for assigning the
-- warehouse to it (Snowflake docs). The warehouse stays owned by ACCOUNTADMIN: no pilot role gets MODIFY
-- or OWNERSHIP; only SZL_EE_OPERATOR gets OPERATE (resume/suspend), and AUTO_RESUME stays FALSE.
USE ROLE ACCOUNTADMIN;
SELECT CURRENT_ORGANIZATION_NAME() || '-' || CURRENT_ACCOUNT_NAME() AS ORG_ACCOUNT, CURRENT_REGION() AS REGION;
-- Read-only existence checks: STOP if any exact-name row is returned (never reuse or overwrite).
SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM';
SHOW WAREHOUSES LIKE 'SZL_EE_WH';
SHOW ROLES LIKE 'SZL_EE_%';
SHOW USERS LIKE 'SZL_EE_%';
SHOW DATABASES LIKE 'SZL_EE_DB';

CREATE RESOURCE MONITOR SZL_EE_RM WITH CREDIT_QUOTA = 10 FREQUENCY = NEVER START_TIMESTAMP = IMMEDIATELY
  END_TIMESTAMP = '2026-11-21 23:59:00 +00:00' TRIGGERS ON 50 PERCENT DO NOTIFY ON 75 PERCENT DO NOTIFY
  ON 90 PERCENT DO SUSPEND ON 100 PERCENT DO SUSPEND_IMMEDIATE;
CREATE WAREHOUSE SZL_EE_WH WITH WAREHOUSE_SIZE = XSMALL MAX_CLUSTER_COUNT = 1 MIN_CLUSTER_COUNT = 1
  AUTO_SUSPEND = 60 AUTO_RESUME = FALSE INITIALLY_SUSPENDED = TRUE RESOURCE_MONITOR = SZL_EE_RM
  STATEMENT_TIMEOUT_IN_SECONDS = 120 STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = 60 COMMENT = 'SZL synthetic pilot 1';

USE ROLE USERADMIN;
CREATE ROLE SZL_EE_SETUP COMMENT = 'Deploy-time only: CREATE DATABASE ON ACCOUNT. Revoke after deploy.';
CREATE ROLE SZL_EE_OWNER COMMENT = 'Owns EE schemas and tables. Not used by the app or loader.';
CREATE ROLE SZL_EE_INGEST COMMENT = 'Loader: SELECT and INSERT only on EE_DATA tables.';
CREATE ROLE SZL_EE_APP COMMENT = 'Owns the Streamlit object; owner-rights queries are SELECT-only.';
CREATE ROLE SZL_EE_VIEWER COMMENT = 'View-only audience: USAGE on db, app schema and app object only.';
CREATE ROLE SZL_EE_OPERATOR COMMENT = 'Runtime warehouse control: OPERATE on SZL_EE_WH only (resume/suspend).';

USE ROLE ACCOUNTADMIN;
GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_APP;
GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_INGEST;
GRANT OPERATE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_OPERATOR;
GRANT MONITOR ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_INGEST;   -- read-only; lets the runtime shutdown check read the monitor

-- D0 readback (expect: SUSPENDED, auto_resume false, resource_monitor SZL_EE_RM, owner ACCOUNTADMIN,
-- size X-Small, STATEMENT_TIMEOUT_IN_SECONDS 120, STATEMENT_QUEUED_TIMEOUT_IN_SECONDS 60, six roles).
SHOW WAREHOUSES LIKE 'SZL_EE_WH';
SHOW PARAMETERS LIKE 'STATEMENT%' IN WAREHOUSE SZL_EE_WH;
SHOW GRANTS ON WAREHOUSE SZL_EE_WH;
SHOW GRANTS ON RESOURCE MONITOR SZL_EE_RM;
SHOW ROLES LIKE 'SZL_EE_%';

-- ======================================================================================= D1
-- Two service users, created DISABLED, with no key and no roles. Secondary roles cannot widen a session.
USE ROLE USERADMIN;
CREATE USER SZL_EE_DEPLOY TYPE = SERVICE DEFAULT_ROLE = SZL_EE_SETUP DEFAULT_SECONDARY_ROLES = ()
  DISABLED = TRUE COMMENT = 'SZL EE pilot 1 deploy identity (SZL_EE_SETUP only); disable after deploy';
CREATE USER SZL_EE_RUNTIME TYPE = SERVICE DEFAULT_ROLE = SZL_EE_INGEST DEFAULT_SECONDARY_ROLES = ()
  DISABLED = TRUE COMMENT = 'SZL EE pilot 1 runtime identity (SZL_EE_INGEST, SZL_EE_OPERATOR); disable by 2026-11-21';
DESC USER SZL_EE_DEPLOY;
DESC USER SZL_EE_RUNTIME;

-- ======================================================================================= D2
-- Key registration is done by the owner himself through the approved secure interface, one key per user.
-- Kept as comments so "Run All" can never set a placeholder. Never paste a PRIVATE key anywhere.
-- USE ROLE USERADMIN;
-- ALTER USER SZL_EE_DEPLOY  SET RSA_PUBLIC_KEY = '<deploy public key body, entered by the owner>';
-- ALTER USER SZL_EE_RUNTIME SET RSA_PUBLIC_KEY = '<runtime public key body, entered by the owner>';
-- DESC USER SZL_EE_DEPLOY;  DESC USER SZL_EE_RUNTIME;   (compare RSA_PUBLIC_KEY_FP with the local fingerprints)
-- ALTER USER <user> SET DISABLED = FALSE;   only immediately before an approved run (D5), per user

-- ======================================================================================= D3
-- Setup role for the deploy identity: CREATE DATABASE ON ACCOUNT, read-only MONITOR on the monitor,
-- and the pilot roles SZL_EE_OWNER + SZL_EE_APP (deploy only; revoked after deploy).
USE ROLE SECURITYADMIN;
GRANT CREATE DATABASE ON ACCOUNT TO ROLE SZL_EE_SETUP;
USE ROLE ACCOUNTADMIN;
GRANT MONITOR ON RESOURCE MONITOR SZL_EE_RM TO ROLE SZL_EE_SETUP;
USE ROLE USERADMIN;
GRANT ROLE SZL_EE_OWNER TO ROLE SZL_EE_SETUP;
GRANT ROLE SZL_EE_APP TO ROLE SZL_EE_SETUP;
GRANT ROLE SZL_EE_SETUP TO USER SZL_EE_DEPLOY;
SHOW GRANTS TO ROLE SZL_EE_SETUP;
SHOW GRANTS TO USER SZL_EE_DEPLOY;

-- ======================================================================================= D4
-- Runtime loader role for the runtime identity.
USE ROLE USERADMIN;
GRANT ROLE SZL_EE_INGEST TO USER SZL_EE_RUNTIME;

-- ======================================================================================= D4b
-- Warehouse control for the runtime identity: SZL_EE_OPERATOR = OPERATE on SZL_EE_WH (RESUME/SUSPEND) only. COST EXPOSURE: while SZL_EE_RUNTIME is enabled with this role it
-- can RESUME SZL_EE_WH at any time; spend is then bounded only by SZL_EE_RM (not a hard cap) and by the
-- runner's own timeout/suspend. Separate decision; NOT APPROVED.
USE ROLE USERADMIN;
GRANT ROLE SZL_EE_OPERATOR TO USER SZL_EE_RUNTIME;
SHOW GRANTS TO USER SZL_EE_RUNTIME;     -- expect exactly SZL_EE_INGEST and SZL_EE_OPERATOR

-- ======================================================================================= AFTER / ON ANY DOUBT
-- Non-destructive revocation (nothing is dropped). Disable first; then unset keys; then revoke.
-- USE ROLE USERADMIN;
-- ALTER USER SZL_EE_DEPLOY  SET DISABLED = TRUE;   ALTER USER SZL_EE_RUNTIME SET DISABLED = TRUE;
-- ALTER USER SZL_EE_DEPLOY  UNSET RSA_PUBLIC_KEY;  ALTER USER SZL_EE_RUNTIME UNSET RSA_PUBLIC_KEY;
-- REVOKE ROLE SZL_EE_SETUP FROM USER SZL_EE_DEPLOY;
-- REVOKE ROLE SZL_EE_INGEST FROM USER SZL_EE_RUNTIME;  REVOKE ROLE SZL_EE_OPERATOR FROM USER SZL_EE_RUNTIME;
-- REVOKE ROLE SZL_EE_OWNER FROM ROLE SZL_EE_SETUP;     REVOKE ROLE SZL_EE_APP FROM ROLE SZL_EE_SETUP;
-- USE ROLE SECURITYADMIN;  REVOKE CREATE DATABASE ON ACCOUNT FROM ROLE SZL_EE_SETUP;
-- USE ROLE ACCOUNTADMIN;   ALTER WAREHOUSE SZL_EE_WH SUSPEND;   (errors harmlessly if already suspended)
--                          REVOKE MONITOR ON RESOURCE MONITOR SZL_EE_RM FROM ROLE SZL_EE_SETUP;
-- Independent readback: SHOW WAREHOUSES LIKE 'SZL_EE_WH'; SHOW GRANTS TO USER SZL_EE_DEPLOY;
--                       SHOW GRANTS TO USER SZL_EE_RUNTIME; DESC USER SZL_EE_DEPLOY; DESC USER SZL_EE_RUNTIME;
