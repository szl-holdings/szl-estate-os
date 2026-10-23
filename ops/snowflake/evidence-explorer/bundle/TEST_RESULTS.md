# TEST_RESULTS v2: SZL Evidence Explorer pilot 1 (local + emulator)

- Date: 2026-10-21 (UTC). Host: native Windows.
- Interpreters: stdlib suite on Python 3.11.16. Separate env `snowflake-emu` (fakesnow 0.11.22, snowflake-connector-python 3.12.4, duckdb 1.5.6, sqlglot 30.22.0) for the emulator check only. Separate env `streamlit-smoke` (Streamlit 1.66.0, Python 3.11.17) for the stub smoke only.
- Labels:
  - **MEASURED** means run in this session.
  - **EMULATOR** means run inside fakesnow/DuckDB. It is NOT a Snowflake result.
- Static review, local tests and emulator runs do not establish live access, performance, availability, production readiness or challenge eligibility.
- A general "green light, do whatever you recommend" was relayed on 2026-10-21. It is not a scoped spend or deployment approval and is not recorded as one.

## Evidence receipt (hash-chained, unsigned)

- `python -I -B run_local_evidence.py --emulator-python <snowflake-emu python>` ran every step below fresh and wrote `receipt/local_evidence_receipt.jsonl` (sha256 `a7a4c9155d05d9841dc265a4fce8506fc4ae5fee5585216f06ede7fa5cb1d498`, chain head `b7911c4d5040b6491cdd35a797d99ec508a5ca2af61114a8e707e2bd75db7694`) plus `receipt/logs/*`. A built-in hygiene gate confirmed that no home or workspace path appears in any log.
- `python -I -B verify_receipt.py receipt/local_evidence_receipt.jsonl --logs receipt/logs --inputs .` returned exit 0: **VALID (unsigned; signature NOT_RUN; integrity only, not authorship)**. MEASURED.

| Step | Command | Exit | Status | Evidence label | Summary |
|---|---|---|---|---|---|
| fixture_rebuild | `<python> -I -B make_fixture.py <tmp>/fixture_rebuild.json` | 0 | PASS | MEASURED_LOCAL | matches_committed=True |
| unit_tests | `<python> -I -B test_evidence_core.py -v` | 0 | PASS | MEASURED_LOCAL | ran=80, result=OK, failures=0, errors=0, skipped=0, not_run=0 |
| integration_snowflake | `<python> -I -B test_integration_snowflake.py -v` | 3 | NOT_RUN | MEASURED_LOCAL | ran=11, result=OK, failures=0, errors=0, skipped=11, not_run=11 |
| mutation_sweep | `<python> -I -B mutation_sweep.py <tmp>/mutation_results.json` | 0 | PASS | MEASURED_LOCAL | KILLED=48, SURVIVED=0, INVALID=0 |
| verifier_tamper_tests | `<python> -I -B test_verify_receipt.py -v` | 0 | PASS | MEASURED_LOCAL | ran=24, result=OK, failures=0, errors=0, skipped=0, not_run=0 |
| emulator_check | `<emulator-python> -I -B test_emulator_fakesnow.py <tmp>/emulator_results.json` | 0 | PASS | EMULATOR (fakesnow 0.11.22) | PASS=40, FAIL=0, UNSUPPORTED_BY_EMULATOR=44 |

Signature: `NOT_RUN (signing requires owner approval)`. The chain is unkeyed, so anyone can rewrite the file and recompute every hash. The verifier detects partial or accidental tampering and semantic overclaims (for example, NOT_RUN reported as PASS at stage LOCAL_TESTED). It cannot prove authorship.

### Tamper detection

- Synthetic receipts: `test_verify_receipt.py` has 24 tests, all passing (MEASURED). T00 is the untampered control and must be VALID. The tamper classes are: edit without rehash; edit with that entry rehashed; raw reorder; re-chained reorder; re-chained missing step; raw missing step; NOT_RUN reported as PASS (re-chained), disguised as exit 0 (caught by the stage policy) and caught by its log; re-chained duplicated step; truncation (no end entry); partial last line; claimed signature; edited log; input drift; duplicate key or non-canonical line; mutation survivors reported as PASS; time going backwards; emulator result relabelled as MEASURED; skipped unit tests reported as PASS; integration NOT_RUN mislabelled FAIL at a later stage; CLI fail-closed on a missing file and on a garbage or truncated file, without echoing local paths.
- Real receipt tampered (MEASURED; each must be INVALID):

| Tamper on the real receipt | Verifier exit | First reason |
|---|---|---|
| edit_no_rehash | 1 | - entry 2 (integration_snowflake): entry_sha256 mismatch (edited) |
| not_run_as_pass_full_rewrite | 1 | - entry 2: integration must be NOT_RUN at stage LOCAL_TESTED, got PASS |
| missing_step_rechained | 1 | - step sequence ['fixture_rebuild', 'unit_tests', 'integration_snowflake', 'verifier_tamper_tests', 'emulator_ |
| reorder | 1 | - step sequence ['fixture_rebuild', 'integration_snowflake', 'unit_tests', 'mutation_sweep', 'verifier_tamper_ |
| signature_claimed_rechained | 1 | - receipt_end: signature field 'SIGNED' is not the unsigned marker; no signing has been approved |

- Verifier mutation sweep (`verifier_mutation_sweep.py`): **18 mutants, 17 killed, 0 survived, 1 equivalent**. V10 (duplicate-key guard off) is EQUIVALENT: such a line can never equal its canonical form, so the canonical-form guard rejects it first. In the first sweep V05 survived; adding T17 now kills it.

## Section-8 local checks (unit suite: 80 run, 0 failed, 0 skipped)

| Check | Description | Test class | Tests | Status | Label |
|---|---|---|---|---|---|
| S8.01 | Fixture determinism and expected row counts | `S8_01_FixtureDeterminismAndCounts` | 6 | PASS | MEASURED |
| S8.02 | Required fields and enum validation | `S8_02_RequiredFieldsAndEnums` | 8 | PASS | MEASURED |
| S8.03 | Malformed timestamp/revision rejection | `S8_03_MalformedTimestampAndRevision` | 5 | PASS | MEASURED |
| S8.04 | Content-digest mismatch detection | `S8_04_ContentDigest` | 4 | PASS | MEASURED |
| S8.05 | Duplicate-batch behavior | `S8_05_DuplicateBatch` | 9 | PASS | MEASURED |
| S8.06 | Exclusion enforcement | `S8_06_ExclusionEnforcement` | 8 | PASS | MEASURED |
| S8.07 | Synthetic-label preservation | `S8_07_SyntheticLabel` | 6 | PASS | MEASURED |
| S8.08 | No secret-bearing fields | `S8_08_NoSecretBearingFields` | 6 | PASS | MEASURED |
| S8.09 | Parameterized query construction | `S8_09_ParameterizedQueries` | 4 | PASS | MEASURED |
| S8.10 | Bounded result limits | `S8_10_BoundedResultLimits` | 3 | PASS | MEASURED |
| S8.10b | Reference ordering mirrors SQL ORDER BY (added in v2; found by emulator) | `S8_10b_ReferenceOrderingMatchesSql` | 6 | PASS | MEASURED |
| S8.11 | Truthful empty/error states | `S8_11_TruthfulEmptyErrorStates` | 8 | PASS | MEASURED |
| (support) | SQL static checks | `X_SqlStaticChecks` | 7 | PASS | MEASURED |

## Core mutation sweep: 48 mutants, 48 killed, 0 survived

- History:
  - v1 initial run: 42 of 43 killed (M41 survived). Fixed with two tests.
  - v1 final run: 43 of 43 killed.
  - v2 adds M43–M47 for the ordering and timestamp bugs found through the emulator. The final run kills all 48 (MEASURED inside the receipt).
- These mutants are hand-chosen, one per guard. Killing all of them does not prove there are no other gaps.

| ID | Mutant | Final |
|---|---|---|
| M00 | BROKEN BASELINE: validate_row accepts everything | KILLED |
| M01 | secret field-name guard disabled | KILLED |
| M02 | secret value guard disabled | KILLED |
| M03 | unknown-field (closed schema) guard disabled | KILLED |
| M04 | missing-field guard disabled | KILLED |
| M05 | enum membership guard disabled | KILLED |
| M06 | future-timestamp guard disabled | KILLED |
| M07 | UTC-only: timestamp offsets accepted | KILLED |
| M08 | calendar-invalid date swallowed | KILLED |
| M09 | mutable revision refs accepted | KILLED |
| M10 | revision/provider consistency guard disabled | KILLED |
| M11 | content-digest comparison disabled | KILLED |
| M12 | digest check skipped when content absent | KILLED |
| M13 | batch-level manifest idempotency disabled | KILLED |
| M14 | identical duplicate row appended instead of skipped | KILLED |
| M15 | conflicting duplicate id accepted (overwrite risk) | KILLED |
| M16 | ingestion-time exclusion disabled | KILLED |
| M17 | exclusion prefix-strip disabled (git-sha1:<blob> slips through) | KILLED |
| M18 | display-scope exclusion disabled | KILLED |
| M19 | synthetic label text check disabled | KILLED |
| M20 | is_synthetic=TRUE check disabled | KILLED |
| M21 | secret rejections store a row digest | KILLED |
| M22 | upper LIMIT bound removed | KILLED |
| M23 | LIMIT exact-int check weakened to isinstance (bool accepted) | KILLED |
| M24 | provider filter string-concatenated instead of bound | KILLED |
| M25 | identifier parameter validation disabled | KILLED |
| M26 | ERROR state carries rows | KILLED |
| M27 | EMPTY reported as OK | KILLED |
| M28 | restricted-rights display guard disabled | KILLED |
| M29 | internal-only rights operand dropped | KILLED |
| M30 | training_allowed evidence guard disabled | KILLED |
| M31 | explicit-missing value consistency disabled | KILLED |
| M32 | rights NONE ingestion guard disabled | KILLED |
| M33 | row-count bound disabled | KILLED |
| M34 | request-size bound disabled | KILLED |
| M35 | cost screen accepts unsourced measurement | KILLED |
| M36 | stale threshold widened | KILLED |
| M37 | MERGE gains WHEN MATCHED UPDATE | KILLED |
| M38 | rejected rows not retained | KILLED |
| M39 | value grammar allows markup | KILLED |
| M40 | locator traversal guard disabled | KILLED |
| M41 | orphan-reference guard for revisions disabled | KILLED |
| M42 | bool exact-type check weakened | KILLED |
| M43 | all_observations reference order differs from SQL ORDER BY | KILLED |
| M44 | revision order compares timestamp text, not instants | KILLED |
| M45 | ingestion batches returned in insertion order | KILLED |
| M46 | latest-revision tie-break reversed vs SQL | KILLED |
| M47 | latest rights compares timestamp text | KILLED |

## Emulator check: EMULATOR (fakesnow 0.11.22), not Snowflake

`test_emulator_fakesnow.py` runs:
- schema.sql, with the approval guard line dropped from an in-memory copy only;
- fixture ingestion through `evidence_core.build_merge` with qmark binds;
- the rerun-is-idempotent check;
- 13 screen queries compared row-for-row and in order with `local_execute`;
- the presentation layer;
- 8 CHECK probes in a separate `PROBE_DB`.

Final pass: **40 PASS, 0 FAIL, 44 UNSUPPORTED_BY_EMULATOR**.

| Category | PASS | UNSUPPORTED_BY_EMULATOR | FAIL |
|---|---|---|---|
| CHECK_PROBE | 7 | 1 | 0 |
| DDL | 0 | 10 | 0 |
| DDL_CORE | 8 | 0 | 0 |
| IDEMPOTENT_RERUN | 1 | 0 | 0 |
| INGEST_MERGE | 8 | 0 | 0 |
| PRESENTATION | 3 | 0 | 0 |
| ROLE_OR_PRIVILEGE | 0 | 33 | 0 |
| SCREEN_QUERY | 13 | 0 | 0 |

Notes:
- **ROLE_OR_PRIVILEGE** (USE ROLE, CREATE ROLE, every GRANT, plus reader_grants.sql) is always UNSUPPORTED_BY_EMULATOR, even where fakesnow accepted the statement as a no-op. Access control is not emulated.
- **DDL UNSUPPORTED** covers `WITH MANAGED ACCESS` (a parser error; the run used a substitute without the property) and `DATA_RETENTION_TIME_IN_DAYS`/`COMMENT`, which are ignored. The statement cores (DDL_CORE) PASS.
- **CK03** (the UTC-offset CHECK) is UNSUPPORTED_BY_EMULATOR. DuckDB TIMESTAMPTZ drops the input offset: MEASURED, `DATE_PART('timezone_hour', ...)` follows the session time zone. Snowflake behaviour is UNKNOWN.
- **The first emulator pass had 7 FAIL** (emulator_results_pass1_before_fixes.json):
  - 4 came from a harness bug: probe rows were written into the fixture tables. Probes now use a separate database.
  - 1 was CK03, reclassified as above.
  - 2 were genuine reference-model ordering mismatches (`all_observations` truncated at LIMIT; `ingestion_batches`).
- **Review of the ordering fix found two more latent bugs:** timestamps sorted as text, and the latest-revision tie-break reversed relative to the SQL. All are fixed and pinned by 7 tests and M43–M47.
- **One emulator overclaim was corrected** before the final receipt: `CREATE DATABASE … DATA_RETENTION_TIME_IN_DAYS … COMMENT` had been PASS only because no warning was emitted. Every statement with object properties is now UNSUPPORTED for the property part.

## Local Streamlit stub smoke (NOT a Snowflake test; re-run after the v2 core changes)

| Check | Status | Label |
|---|---|---|
| A_dependency_absent_visible_failure | PASS | MEASURED (local stub) |
| B_no_active_session_visible_failure | PASS | MEASURED (local stub) |
| C_stub_session_six_screens_render | PASS | MEASURED (local stub) |
| C_stub_every_issued_query_parameterized | PASS | MEASURED (local stub) |
| D_query_failure_shows_error_no_rows | PASS | MEASURED (local stub) |

## Snowflake integration checks: all NOT_RUN / BLOCKED

`test_integration_snowflake.py` ran inside the receipt: exit 3, 11 of 11 skipped, NOT_RUN. Emulator analogues do not satisfy these checks.

| Check | Description | Status | Blocker |
|---|---|---|---|
| I.01 | Exact account/database/schema/warehouse identity | BLOCKED (test reports NOT_RUN) | No Snowflake credential or approved connection |
| I.02 | Expected inserted rows and deterministic query results | BLOCKED (test reports NOT_RUN) | No credential; no spend authorization (emulator analogue: ING_*, Q_*, EMULATOR only) |
| I.03 | Duplicate-safe rerun without uncontrolled row growth | BLOCKED (test reports NOT_RUN) | No credential (emulator analogue: RERUN, EMULATOR only) |
| I.04 | Correct filters and revision comparison | BLOCKED (test reports NOT_RUN) | No credential (emulator analogue: Q_*, PRES_COMPARISON, EMULATOR only) |
| I.05 | Rejected invalid inputs retained as reported failures | BLOCKED (test reports NOT_RUN) | No credential |
| I.06 | Least-privilege reader access | BLOCKED (test reports NOT_RUN) | Roles and grants not emulated (UNSUPPORTED_BY_EMULATOR); DDL not approved |
| I.07 | Unauthorized user/role denied | BLOCKED (test reports NOT_RUN) | Access control not emulated; needs a live viewer session |
| I.08 | No unintended data sharing | BLOCKED (test reports NOT_RUN) | No credential |
| I.09 | Observed query IDs and sanitized execution evidence | BLOCKED (test reports NOT_RUN) | Manual evidence after an approved run |
| I.10 | Measured warehouse activity and suspension after demo | BLOCKED (test reports NOT_RUN) | No warehouse; cost plan owned by another track |
| I.11 | App fails visibly when real Snowflake dependency unavailable (live) | BLOCKED (test reports NOT_RUN) | Not deployed (the local stub smoke passes, but that is not the live check) |

## File digests

Every deliverable's sha256 and size is in **MANIFEST.json**, which lists this file too. The files pinned as receipt inputs are listed below. Each was re-hashed by `verify_receipt.py --inputs .` after the run and matched.

| File | sha256 |
|---|---|
| evidence_core.py | `843ab2fdd2061b2a2421a1f354fe80c862f4ab9dc782560730ececa043d1fdac` |
| fixture_v1.json | `be43d225497b1f48d445c9c5b53130041889fec614740778cc1b14de406dac72` |
| make_fixture.py | `e3bc01868c7d4b280a06142762406f329fb6e9bf473b73e36fd3232c3b606ce1` |
| mutation_sweep.py | `2a75347c656c3b8184013d169f3a006b50690189f33818e5651c107a5f8e8676` |
| reader_grants.sql | `91461dff708e40b5c9be3c47e7e460630569cfc8a568034919a798a738a3b343` |
| run_local_evidence.py | `dd5da9e8d7ceb22e41777e00e41c0b33982c6641dc4faa11be99488d11eb596f` |
| schema.sql | `8775f3cad3b1de97ebfd42ddd5ef21dafe8b271e046c2a5e5338f53a71c20b61` |
| streamlit_app.py | `ca5c25e271fb3fd1b91fdbff86c9d414a145481c25f00832d4b4dbe43c659160` |
| test_emulator_fakesnow.py | `2efd26d3320790fb3cdbfc184b83ba6fe03909037a47bec45c491b1557d51a80` |
| test_evidence_core.py | `46d116a9b4f2ea4976a57c9ac7091ce918c57df2ad1a3f58569d979b1bc4e23b` |
| test_integration_snowflake.py | `17ded3673c20e67031c71a075799d5cbac2f0cea302b69b51bd6a37d885b7374` |
| test_verify_receipt.py | `b80fb7eb28e0fbe4e94af2b42c572931cb263eacde6f4dc1bf9c7de8455211f3` |
| verify_receipt.py | `3839ea1f0b876af87b5faf12d83a269748285221ff6e03b0b531a73538954834` |
