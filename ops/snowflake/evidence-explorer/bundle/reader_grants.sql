<<DEPLOYMENT_APPROVAL_REF_REQUIRED>>
-- ^ Deliberate fail-closed guard (see schema.sql).
--
-- SZL Evidence Explorer - least-privilege VIEWER grants DRAFT. NOT EXECUTED.
-- Streamlit in Snowflake apps run with owner's rights by default: queries use
-- SZL_EE_APP's privileges, so the viewer needs no table privilege at all.
-- Snowflake docs (search result read 2026-10-21) list viewer requirements as
-- USAGE on the database, the schema and the Streamlit object. In a
-- managed-access schema the app-object USAGE must be granted explicitly by the
-- schema owner, so it is granted here by SZL_EE_OWNER.
USE ROLE SZL_EE_OWNER;
GRANT USAGE ON DATABASE SZL_EE_DB TO ROLE SZL_EE_VIEWER;
GRANT USAGE ON SCHEMA SZL_EE_DB.EE_APP TO ROLE SZL_EE_VIEWER;
GRANT USAGE ON STREAMLIT SZL_EE_DB.EE_APP.SZL_EVIDENCE_EXPLORER TO ROLE SZL_EE_VIEWER;

-- Deliberately NOT granted to SZL_EE_VIEWER (fixes review flag "reader gets
-- warehouse USAGE"):
--   * USAGE on schema EE_DATA, or SELECT on any EE_DATA table;
--   * USAGE/OPERATE/MODIFY/MONITOR on any warehouse;
--   * EMBED on the Streamlit object (no external embedding in pilot 1);
--   * any FUTURE, ALL, PUBLIC or WITH GRANT OPTION grant.
-- Open item (UNKNOWN): some non-Snowflake guides also grant warehouse USAGE to
-- viewers. If an account test shows the viewer cannot open the app without
-- it, the only permitted fallback is the line below, after spend approval and
-- under the pilot resource monitor:
-- GRANT USAGE ON WAREHOUSE SZL_EE_WH TO ROLE SZL_EE_VIEWER;
--
-- Role-to-user assignment is NOT included; it needs an approval naming users.
--
-- Integration negative checks (run as SZL_EE_VIEWER after approval; each must
-- FAIL with insufficient privileges - see test_integration_snowflake.py):
--   SELECT COUNT(*) FROM SZL_EE_DB.EE_DATA.OBSERVATIONS;
--   INSERT INTO SZL_EE_DB.EE_DATA.EXCLUSIONS SELECT 'x', 'OUT_OF_SCOPE', CURRENT_TIMESTAMP(), 'ALL';
