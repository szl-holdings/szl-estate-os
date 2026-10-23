# Snowflake Evidence Explorer - readiness packet (2026-10-22)

Scope: local analysis only, with no remote publication. No Snowflake connection, no credential, no SQL against any account, no install, push or upload.
The session did write local files (patches, harnesses, artifacts) and made one environment change earlier: a pip install, recorded in ENV_CHANGE_RECORD.md.
Governing brief: [review brief (governing)]({{artifact:429cb0bd-c661-44d4-902a-6d90db5c088b}}). It authorizes no deployment, spending, credential creation, persistent access, privilege expansion, upload or security-setting change.

**Overall: NOT ready for a live run.** The packaged candidate is locally tested. It still implements the v3 privilege design, which this review found is not least-privilege, and its kit step B3 is expected to fail on Snowflake (see section 2).

## 0. Corrections to earlier lead statements
| Earlier statement | Status | Evidence |
|---|---|---|
| "DEPLOYMENT_APPROVED: APPROVED" | WRONG. The record holds only a 10-credit ceiling (card 3), the funding and entity facts (cards 1-2), "Use your best judgment" (card 4) and one sandbox egress grant. | APPROVAL_SCOPE.md |
| "hard credit cap" (card 3 question, SNOWSIGHT_SETUP v1) | WRONG. The agent wrote this wording. Snowflake documents monitors as imprecise: they cannot suspend cloud services and they exclude serverless, AI and storage. | COST_CONTROL_COVERAGE.md |
| "1 harmless survivor" (runner G12) | WRONG. Not equivalent: the v0.1.1 substring check could refuse a valid unencrypted key whose base64 body contains "ENCRYPTED". Fixed in v0.2 (header-only check, killing tests). | G12_ANALYSIS.txt |
| "Allowlist widened by exactly these strings; admin roles still refused" | INCOMPLETE. The v0.1.1 guard accepted 63 of 106 must-refuse statements, including `GRANT ROLE SYSADMIN TO ROLE SZL_EE_*`. The hole predates the lead patch (a grantee-suffix check); the lead test probed only one direction. v0.1.2: 0 of 106 accepted, 41 of 41 positive controls accepted. | guard_probe_results.json |
| "stops before creating anything" (monitor-privilege failure) | WRONG. By the time kit B3 runs, the manual setup has already created the monitor, the service user and the user's role grants. | FAILURE_BOUNDARY_MAP.md |
| "runs the 11 live tests" | WRONG as stated. The tests need snowflake-snowpark-python, which is not installed, so they would all record NOT_RUN. i07, i09, i10 and i11 always skip, so the best possible result is INCOMPLETE. | FAILURE_BOUNDARY_MAP.md |
| "pip install is purely additive" | WRONG. It added 6 packages and 709 files to the shared base environment, including native cryptography, cffi and protobuf. No conda package was overwritten and pip check is clean (MEASURED). There is no pre-install snapshot. | ENV_CHANGE_RECORD.md |
| approval.txt "passes the parser" | Syntax only, not owner authorization. The kit refuses from 2026-11-21T00:00:00Z (last accepted UTC date 2026-11-20). The monitor END is 2026-11-21T23:59:00Z. The original "2026-11-30" had no time or timezone. | APPROVAL_SCOPE.md |

Stale v0.1.1 docs inside the kit (STATUS, COST_AND_SHUTDOWN, DEPLOYMENT_PLAN, OPERATOR_RUNBOOK, TEST_LOG) were moved to superseded_v0_1_1/ with a header; SNOWFLAKE_WIN_PLAN_2026-10-22.md is superseded by this packet (its mutant attribution and test counts were imprecise).

## 1. Immutable artifact manifest (sha256, computed by the lead 2026-10-22)
| Artifact | sha256 | bytes |
|---|---|---|
| [review brief (governing)]({{artifact:429cb0bd-c661-44d4-902a-6d90db5c088b}}) | `4ebdf9d8662d9881da5fe36f5e3f0dd3941e50c6a9c02c8b84e78888819007e9` | 5539 |
| [v3 bundle zip]({{artifact:79965d8b-c308-45d6-9fb8-738dd01745d5}}) | `a1b129fde9ca65158c863bce0ba1889a5a6274ec8bb8e76813a5324b4eefc479` | 123075 |
| [APPROVAL_SCOPE.md]({{artifact:e5fc1800-4a66-4522-a4f1-196d01cd862b}}) | `dfd827b3293dff5a425e462f8167c3ba43112c17eda1ae4cbe0da119cf55804a` | 19043 |
| [ELIGIBILITY_PROVISIONAL.md]({{artifact:557ccaeb-cd4f-4a7b-bbae-cacc84b8660d}}) | `d3dae43f4dddb2376bf6eb396607c973d0ea6c3ed7c3d3a90bb88ce064091d0e` | 6956 |
| [ENV_CHANGE_RECORD.md]({{artifact:1604243c-9d67-404a-87ab-909a2dfd3c6e}}) | `d747be382d94fc1dc3d9ad9c139f5d82d97b23a0dc13a9885e694cecf5f513ad` | 7481 |
| [COST_CONTROL_COVERAGE.md]({{artifact:4d2ad391-927b-4301-baea-a0108b24b5da}}) | `5d731f6642b7ecc75895d145fd86b3e8a70c0802430c59c5edf9e8d9280d0627` | 29746 |
| [cost_exposure_model.py]({{artifact:64b050f3-96fe-4436-8bfe-501b545b37bc}}) | `2a23705c4079e3efdfaa7e8a729dff5cdd625e025b76e1f962867c77fa9b5297` | 4439 |
| [cost_exposure_model_output.json]({{artifact:d426e298-104c-4f8c-917e-8d9a66f79bc3}}) | `ef59d11981570be3963133c4963ccb44cd8e336236e8ed91d69a2cdee158a1b9` | 1511 |
| [FAILURE_BOUNDARY_MAP.md]({{artifact:3a512cbd-93f5-4d34-b3af-4ad28c1a549b}}) | `2f841f49cb778f4c5e53b6f6796e4a3580ea72da1ffc742a27295fd42b66be2e` | 23852 |
| [G12_ANALYSIS.txt]({{artifact:34713809-2e81-4ab3-9963-f483d93312c0}}) | `bec7e70f131d8226156a0703afc7a5ef51d18021f4c4212ee677170c9a8caa15` | 1725 |
| [PRIVILEGE_OBJECT_DIFF.md]({{artifact:d5a3373c-00d4-4dfd-af7d-68fcb0fc6a11}}) | `cbb95917449868d88b3b93648b7cbc21fed350a15bf62bb62c6942d291794ef5` | 27709 |
| [PERSISTENT_ACCESS_PROPOSAL.md]({{artifact:89654200-9280-4d4c-bfd7-9ac30b92a03a}}) | `6b0854edf403723f136a95a9fa2bd07d21756861d747ba38a5d78b0e88b33747` | 15693 |
| [schema_v3_to_v4_PROPOSED.patch]({{artifact:162d8f5f-19d8-4976-a424-5b64aa72a494}}) | `632a4d6a3436f08d85e9fe79459d0c903cfd556743ae1b00a76957a93e84aa9f` | 3636 |
| [guard_probe_results.json]({{artifact:fc61305c-7871-4227-901f-41de9ba5790f}}) | `e9604c72f2c29c7fe2aec8582031e1de5ca56c0896cc927f966a888cef1a7a7e` | 30906 |
| [m02_analysis.json]({{artifact:ee5a3a16-bcbe-4c10-a1fc-9239a34fd27f}}) | `63bc6e2452f5ac83e0cff81ea17f2a7afaef0e3c7aaf90c2209d177548971ed9` | 1331 |
| [SNOWSIGHT_SETUP.sql v2]({{artifact:7a8c4b4a-9140-40dd-801f-899c5acf221c}}) | `e1ce3e2d8d94cab4cd75ee006a80e01d3c817f7d26c9d343b30f95d3f5f19c49` | 5301 |
| [SNOWFLAKE_ACCESS_SETUP.md v2]({{artifact:179a12e4-b248-402a-a983-67fa7094fdd6}}) | `c9d5841e2ee7f1ca5a8f02155c8510a4426bead4fb52915032d75098ba278a92` | 3911 |
| [kit v0.1.2 zip]({{artifact:db4720a5-4ce6-4d0f-8b4c-73d3354438f4}}) | `8f03e9fc02c947230f3eae6322183b142039f3e35cab70d308ae3f2ec57db6a7` | 91615 |
| [runner v0.2 szl_ee_go.py]({{artifact:b2ad31be-3888-4ccf-9deb-4f87db6bbef0}}) | `696875a062c178c30e9c236446cf548f57d87f5c037ca97c2c16e8bea2d89017` | 37655 |
| [runner tests v0.2]({{artifact:38a85505-7ce2-4cbd-a785-1dc0bb2a3c85}}) | `94b0caaf91b6912d82335c9f4a55600ed0943d0e8a47b9b056dce08687d7a2c6` | 37119 |
| [kit v0.2.0-rc1 zip (lead merge; v2 = stale docs quarantined)]({{artifact:135ad158-d024-40a8-9e7d-531121651501}}) | `52df61759f8defd012e8a5fcff418625bb5fbb95058f408b50f2f12a4282b339` | 132737 |

## 2. Privilege and object diff (summary; full table in PRIVILEGE_OBJECT_DIFF.md)
- v3 design as packaged:
  - SZL_EE_DEPLOY is a key-pair service user holding SYSADMIN and USERADMIN.
  - schema.sql grants SZL_EE_INGEST and SZL_EE_APP to SYSADMIN.
  - That credential could resume or resize any SYSADMIN-owned warehouse outside SZL_EE_RM, create users, and grant roles owned by USERADMIN. It is **not least-privilege**.
- Steps that need ACCOUNTADMIN, per the docs (REPORTED via search snippets): CREATE RESOURCE MONITOR, and assigning a warehouse to a monitor. Kit B3 does the assignment as SYSADMIN, so it is **expected to fail live**. The old "GRANT MODIFY" fallback is not supported by the docs and would let SYSADMIN raise the quota, so it was removed.
- Recommended narrow design (PROPOSAL; documented and patched, not implemented in kit code):
  - **D0 (owner, ACCOUNTADMIN):** create the monitor, the warehouse (suspended, AUTO_RESUME FALSE, monitored) and the roles.
  - **SZL_EE_SETUP** is limited to CREATE DATABASE ON ACCOUNT, MONITOR on SZL_EE_RM, SZL_EE_OWNER and SZL_EE_APP.
  - A separate **SZL_EE_RUNTIME** user holds only SZL_EE_INGEST.
  - No identity holds ACCOUNTADMIN, SECURITYADMIN or SYSADMIN at runtime.
  - Exact SQL: [PERSISTENT_ACCESS_PROPOSAL.md]({{artifact:89654200-9280-4d4c-bfd7-9ac30b92a03a}}). Schema change: [schema_v3_to_v4_PROPOSED.patch]({{artifact:162d8f5f-19d8-4976-a424-5b64aa72a494}}).
- The hierarchy grants were added only because, in the v3 design, the deploy session must `USE ROLE` the pilot roles. Under the narrow design they are replaced by direct grants to SZL_EE_SETUP and SZL_EE_RUNTIME.
- SNOWSIGHT_SETUP.sql v2 ([SNOWSIGHT_SETUP.sql v2]({{artifact:7a8c4b4a-9140-40dd-801f-899c5acf221c}})):
  - A deliberate fail-closed first line: the sheet won't run until you remove it.
  - No inline key.
  - The user is created DISABLED with DEFAULT_SECONDARY_ROLES=().
  - Marked PROPOSAL - NOT APPROVED.

## 3. Cost-control coverage and limits (COST_CONTROL_COVERAGE.md; docs fetched 2026-10-22, 35 HTTP 200)
- **What the monitor counts:** warehouse credits plus the cloud services supporting them.
- **What it does not cover:** storage (stage, Time Travel, Fail-safe), serverless, AI/Cortex, compute pools, data transfer, other warehouses, and cloud services not attributable to the warehouse. It cannot suspend cloud services.
- **Overshoot:**
  - SUSPEND lets running statements finish (bounded by STATEMENT_TIMEOUT 120 s).
  - Monitor latency is undocumented.
  - Each resume bills a 60-second minimum.
- **Streamlit warehouse runtime:** an open viewer session keeps the warehouse up for about 15 minutes after the last activity.
- **Exposure model** (docs-only, assumptions stated in cost_exposure_model.py):

  | Scenario | Credits |
  |---|---|
  | Nominal runner path | 0.0917 |
  | One attempt that hits its own timeouts | 0.5667 |
  | Three attempts | 1.7 |
  | Recording, 2 takes | 1.05 |
  | Unattended app or AUTO_RESUME left on | 9.0333-11.0333 (latency-dependent) |
- **A strict 10-credit maximum cannot be guaranteed** (MEASURED against the docs). Residual exposure needs your decision.
- **UNKNOWN:**
  - account trial or paid status, balance, expiry, edition and region;
  - the Enterprise credit price for AWS ca-central-1 (the official pricing pages returned 403/1010; USD 3.00-4.65 is REPORTED from secondary sources);
  - whether an app visit honours AUTO_RESUME=FALSE.

## 4. Mutation and cleanup sequence (FAILURE_BOUNDARY_MAP.md)
- **Execution order:** 6 manual setup statements, then 57 kit statements (8 of them USE ROLE), then the runner's RESUME and SUSPEND, then the integration-test inserts.
- **Each failure point** records what already exists, whether compute can still bill, and the recovery step. The recovery step is always the same: read back first, never DROP, REPLACE or overwrite, never auto-retry.
- **Likeliest live failure:** the PUT upload (D50-D51), because its storage host is UNKNOWN and not allowlisted. By then the warehouse, 4 roles, the hierarchy grants, the database, 2 schemas, 7 empty tables, the grants and the stage all exist.
- **A partial deploy cannot be finished by rerunning.** The kit refuses existing objects. The options are to leave it suspended, run a cleanup you approve, or use a new reviewed kit.
- **Runner v0.2 adds:**
  - a unique run id;
  - a read-only exact-name inventory before the run, which refuses on any existing object;
  - a global deadline with 600 s reserved for shutdown;
  - exit code 6 for uncertain outcomes;
  - per-step fsync'd receipt and logs, STARTED intent lines and an atomic run_state.json.
- **A failed or unverified shutdown fails the whole run** and writes a list of potentially billable resources.
- **Open kit-side gaps (not yet fixed):**
  - the kit's own QUERY_TAGs don't carry the run id;
  - a killed deploy writes no deploy.json;
  - i03 reloads the fixture even if i02 failed.

## 5. Local test evidence: lead rerun of the merged candidate, kit v0.1.2 + runner v0.2 (Python 3.11.16, `-I -B`, RAM 5.8 GiB free)
| Suite | Result | Kind |
|---|---|---|
| test_operator_kit.py | Ran 64, OK | fake connector |
| test_szl_ee_go.py | Ran 65, OK (the first merge run had 2 errors: a missing captured fixture, fixed by including it) | 58 fake runner/connector, 6 parser-only, 1 real connector import with no credential |
| test_evidence_core.py (v3 bundle) | Ran 80, OK | stdlib, synthetic fixture |
| test_verify_receipt.py | Ran 24, OK | stdlib |
| verify_receipt.py on the v3 receipt | VALID (unsigned) | the receipt includes an EMULATOR step (fakesnow 0.11.22, environment since removed) |
| kit mutation sweep | 59 of 59 killed | M02 resolved as REDUNDANT (0 decision differences over 210 inputs; reason-pin test added) |
| runner mutation sweep | 46 of 46 killed | runner sha256 696875a062c178c3... |
| deploy dry run against v3 MANIFEST | exit 0, nothing executed | |

Raw outputs are in rc_evidence/ inside the rc1 zip. None of these establish authentication, SQL permissions, uploads, billing controls or shutdown on Snowflake. **The 11 live tests are NOT_RUN.**

## 6. Eligibility (ELIGIBILITY_PROVISIONAL.md): PROVISIONAL
- The official rules pages returned 403/1010, and no official rules for the current cycle were found.
- Your stated facts: "SAFE or convertible note" (you didn't say which) and "United States (e.g. Delaware C-corp)" (that was the option label; the state isn't confirmed).
- Whether a SAFE or note counts as an equity security, and whether a valuation cap counts as a valuation, is UNKNOWN until the official rules are read.

## 7. Outstanding decisions (each separate; none granted)
1. **Design:** adopt the narrow setup/runtime design (recommended), or keep v3. The narrow design needs schema v4 and kit and runner changes. Regenerating the bundle's emulator receipt is BLOCKED: the emulator environment is gone and installs aren't authorized.
2. **D0:** you create the monitor, warehouse and roles as ACCOUNTADMIN.
3. **D1:** create service users SZL_EE_DEPLOY and SZL_EE_RUNTIME (DISABLED, no key, no roles).
4. **D2:** you register each public key through the secure interface and enable the user for a named run only.
5. **D3 and D4:** grant SZL_EE_SETUP to SZL_EE_DEPLOY, and SZL_EE_INGEST to SZL_EE_RUNTIME.
6. **D5:** a deploy run with pinned kit, manifest and approval digests plus a run id.
7. **D6:** upload exactly the two pinned app files, plus allowlisting the specific storage host (UNKNOWN until observed).
8. **Environment:** install snowflake-snowpark-python, or accept that the live tests stay NOT_RUN.
9. **Residual cost:** accept or reject the exposure in section 3.
10. **Window:** confirm the ceiling and the exact window: last run start 2026-11-20T23:59:59Z, monitor END 2026-11-21T23:59:00Z.
11. **Not in scope:** recording and hosting, Cortex, real GitHub/Hugging Face ingestion, design-partner access. GitHub stays the source of truth.
