# Snowflake access for the agent — PROPOSAL, NOT APPROVED (kit v0.3.0 DRAFT, 2026-10-23)

Status: **NOT APPROVED. DRAFT_READY, not LOCAL_TESTED.** Stephen's 2026-10-22 review authorizes no deployment, spending, credential creation, persistent access, privilege expansion, upload or security-setting change. Each owner decision (D0, D1, D2, D3, D4, D4b, D5, D6) needs its own approval in the wording in `PERSISTENT_ACCESS_PROPOSAL.md`. Saying "go" is not an approval.

## Two identities, two keys

| | setup (deploy) | runtime |
|---|---|---|
| Snowflake user | `SZL_EE_DEPLOY` (TYPE SERVICE, created DISABLED) | `SZL_EE_RUNTIME` (TYPE SERVICE, created DISABLED) |
| roles | `SZL_EE_SETUP` only (inherits SZL_EE_OWNER, SZL_EE_APP) | `SZL_EE_INGEST` (primary) + `SZL_EE_OPERATOR` (secondary, for RESUME/SUSPEND only) |
| never | ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, USERADMIN, ORGADMIN, SZL_EE_INGEST, SZL_EE_OPERATOR | ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, USERADMIN, ORGADMIN, SZL_EE_SETUP, SZL_EE_OWNER, SZL_EE_APP |
| key | its own RSA key pair (D2) | its own, different RSA key pair (D2) |
| used for | `sf_verify_account_readonly.py`, `sf_deploy_pilot.py` | fixture load, live read checks, RESUME/SUSPEND of SZL_EE_WH, `sf_shutdown_verify.py` |

The deploy kit refuses to run if the connected identity can reach any admin role, SZL_EE_INGEST, SZL_EE_OPERATOR or SZL_EE_VIEWER (checked with `CURRENT_AVAILABLE_ROLES()`). It also refuses if the D0 objects are missing or differ from spec.

## Credential contract for the runner (`szl_ee_go.py`)

Secrets travel only as environment variables or the owner's own config. They never go on argv, in logs or in artifacts.

**Mode A — environment variables (Claude Science credential store):**
- `SNOWFLAKE_ACCOUNT` — the `ORG-ACCOUNT` identifier.
- `SNOWFLAKE_DEPLOY_USER` = `SZL_EE_DEPLOY`, and `SNOWFLAKE_DEPLOY_PRIVATE_KEY` = the deploy private key (PEM). These become profile `szl_ee_setup`: role `SZL_EE_SETUP`, **no warehouse**.
- `SNOWFLAKE_RUNTIME_USER` = `SZL_EE_RUNTIME`, and `SNOWFLAKE_RUNTIME_PRIVATE_KEY` = the runtime private key (PEM). These become profile `szl_ee_runtime`: role `SZL_EE_INGEST`, secondary role `SZL_EE_OPERATOR` for RESUME/SUSPEND only, warehouse `SZL_EE_WH`, database `SZL_EE_DB`, schema `EE_DATA`.

**Mode B — the owner's own `connections.toml`:** `SZL_SF_SETUP_CONNECTION_NAME` and `SZL_SF_RUNTIME_CONNECTION_NAME` name the two entries, which must carry the same roles as above.

**Kit scripts** read `SZL_SF_CONNECTION_NAME` as before:
- the runner sets it to the setup profile for verify and deploy;
- it sets it to the runtime profile for shutdown-verify.

The runner exports `SZL_EE_RUN_ID` (format `YYYYMMDDTHHMMSSZ-<8 hex>`). Kit v0.3.0 appends it to every QUERY_TAG and refuses a malformed value before connecting.

**Runner status (MEASURED from szl_ee_go.py in kit v0.2.0-rc1, carried unchanged into v0.3.0):** the runner still implements the *old* single-user contract — `SNOWFLAKE_USER` + `SNOWFLAKE_PRIVATE_KEY`, and profile `szl_ee` with `role = "SYSADMIN"`. It must be updated by the runner owner to this two-user contract before any live run. Kit v0.3.0 will refuse a SYSADMIN session at the identity check.

Open questions (UNKNOWN until live):
- whether `USE SECONDARY ROLES SZL_EE_OPERATOR` (a named role list) is accepted, or the runner must `USE ROLE SZL_EE_OPERATOR` around RESUME/SUSPEND;
- what the runtime identity can see in SHOW TASKS / ACCOUNT_USAGE metering. The shutdown verifier's account-wide checks may report ERROR/UNKNOWN as runtime; the owner's independent readback covers them.

## Key handling (owner only)

- The owner generates each key pair on his own machine and registers only the **public** key, through Snowsight (D2, one decision per user).
- The agent never sees, prints, exports or stores a private key.
- The current runner accepts only **unencrypted** PKCS#8 private keys. An unencrypted key file on disk is a residual risk: delete the local `.p8` files after entering them in the credential store, and unset or rotate both keys at the end of the window (`ALTER USER … UNSET RSA_PUBLIC_KEY`).
- Enable each user (`DISABLED = FALSE`) only immediately before an approved run, and disable it afterwards. While `SZL_EE_RUNTIME` is enabled with SZL_EE_OPERATOR, it can start the warehouse (D4b cost exposure).
- Never paste a private key into chat, a worksheet, a project file or a log.

## Owner sheet

`SNOWSIGHT_SETUP.sql` (kit v0.3.0) holds blocks D0, D1, D2 (commented), D3, D4, D4b and the revocation steps. Its first line is a deliberate parse guard. Run one block at a time, after that block is approved.
