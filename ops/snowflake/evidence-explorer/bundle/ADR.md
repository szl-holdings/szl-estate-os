> **v4 DRAFT banner (2026-10-23):** sections on roles (§0), database executor (§1) and compute (§5) are superseded by schema.sql v4 and the kit v0.3.0 owner sheet. Roles and warehouse are owner-created (D0), the database is created by SZL_EE_SETUP, and no pilot role joins SYSADMIN. See V4_DRAFT_NOTES.md. Everything below describes v3.

# ADR-001: SZL Evidence Explorer pilot 1 (Snowflake-backed vertical slice)

- Date: 2026-10-21 (UTC)
- Status: **DRAFT_READY, LOCAL_TESTED (local checks only)**. Not account-verified, not deployed.
- Governing spec: "Snowflake implementation mission", sections 3, 5, 6, 8 and 14. Pasted copy sha256 `3b933462f45f5497fe6c69edd79d5f1e0bc64f36c5c234bb20bf08378ea422f9`, 23,122 bytes (MEASURED).
- Labels: **MEASURED** means run or read in this session on 2026-10-21. **REPORTED** means taken from a document or prior artifact and not re-checked. **UNKNOWN** means it cannot be determined offline.

## 1. Context

A reviewer must be able to:
- select an AI artifact;
- see its exact source revision and its evaluation observations;
- tell stale or incomplete evidence apart from current evidence;
- trace each displayed value back to its source locator.

The mission requires Snowflake to do real persistence and querying. A logo on a static page does not count.

Prior project inputs are reused, not redone (REPORTED):
- the metadata proposal packet (37 synthetic tests) and its review, which raised least-privilege (LP) flags;
- the fit matrix (the 2026 challenge closed on 2026-02-18; 2027 rules are UNKNOWN).

## 2. Decision: canonical role of each platform

| Platform | Canonical responsibility | Role in pilot 1 |
|---|---|---|
| GitHub | Source code, review, issues, CI, release history | Unchanged. Code for this slice is a local review directory, not pushed. Snowflake Git sync does not replace CI or review. |
| Hugging Face | Model weights, model and dataset cards, dataset distribution, Spaces | Unchanged. No weights or dataset bodies are copied into Snowflake. |
| **Snowflake** | **Persistence and query backend for approved asset metadata, provenance references and evaluation observations, plus the demo's governed query layer (Streamlit in Snowflake).** | Seven tables in `SZL_EE_DB.EE_DATA`: the six from mission §6 plus `REJECTED_ROWS`. The app issues every screen's data as a live, parameterized query. |
| Cloudflare | DNS, TLS, public edge, existing domain routing | Unchanged. No route, DNS or email record is touched. a-11-oy.com and a11oy.net are not repointed. |
| SZL runtime (Hatun, RAG/DAG, Second Brain, Living Anatomy, Forge, router) | Existing contracts and boundaries | Not integrated in pilot 1. Later integration only through reviewed read-only contracts. |

Only rows that pass `evidence_core.validate_row` and the batch rules may reach Snowflake. In pilot 1 these are synthetic rows only: `is_synthetic` must be TRUE and the exact label must be present, so real data is refused by construction.

The following never cross into Snowflake:
- source bodies, weights or private repository content;
- forum posts or scraped content;
- personal or clinical data;
- secrets;
- raw values of rejected rows.

## 3. Per-asset disposition enum

This is `ASSETS.DISPOSITION`, enforced in Python and by a SQL CHECK.

| Value | Meaning |
|---|---|
| KEEP_CANONICAL | The asset stays where it is. Snowflake holds at most a reference. |
| INGEST_APPROVED_METADATA | Approved metadata and observations may be stored in Snowflake. |
| PILOT_ADAPTER | Ingested through the pilot adapter (this slice) under the fixture contract. |
| MIGRATE_AFTER_REVIEW | A candidate for later migration. No action until a review is approved. |
| EXCLUDED | Must not be fetched, ingested or displayed. An exclusion record exists. |
| BLOCKED | Cannot proceed because of a rights, access or approval blocker. |
| UNKNOWN | Not yet assessed. This is the default for anything not inspected. |

The fixture assigns dispositions to **mock** assets only. No real SZL asset is given a disposition here; the real coverage ledger belongs to the inventory track.

## 4. Tenancy

**Pilot 1 is single-tenant:** one private synthetic dataset and one intended audience (`SZL_EE_VIEWER`).

No multi-tenant isolation is claimed, implemented or tested. No client-side filter is presented as isolation.

## 5. Out of scope for pilot 1

- Cortex or any AI service call
- Model inference, embeddings, training or fine-tuning
- External network access integrations
- Live scraping
- Snowflake Git repository sync
- External embedding (`EMBED`), Native App packaging and public sharing
- Tasks, streams, pipes and serverless features
- Ingestion of real (non-synthetic) data, which needs the content-digest decision in §7
- Changes to protected qualification fields (publication_eligible, LIVE, MEASURED) or to doctrine or honesty gates

## 6. Security model and least-privilege (LP) fixes

Streamlit in Snowflake apps run with **owner's rights** by default. Queries use the app owner's privileges, and viewers need USAGE only on the database, the schema and the app. This is MEASURED from Snowflake documentation search results read on 2026-10-21; it has not been verified on the account.

| Role | Created by | Privileges (schema.sql, reader_grants.sql) |
|---|---|---|
| SZL_EE_OWNER | USERADMIN; granted to SYSADMIN | Owns `SZL_EE_DB` and the managed-access schemas `EE_DATA` and `EE_APP`, and all tables. Not used by the app or the loader. |
| SZL_EE_INGEST | USERADMIN | USAGE on db and `EE_DATA`; SELECT and INSERT on the seven tables. No UPDATE, DELETE or TRUNCATE. |
| SZL_EE_APP | USERADMIN | Owns the Streamlit object; SELECT only on the seven tables; CREATE STREAMLIT on `EE_APP`. |
| SZL_EE_VIEWER | USERADMIN | USAGE on db, on `EE_APP` and on the Streamlit object only. No table privilege and no warehouse grant. |

| Prior review flag (REPORTED) | Disposition in this draft |
|---|---|
| Reader gets warehouse USAGE | **Fixed.** The viewer has no warehouse grant. Whether viewers need one is UNKNOWN (documentation and third-party guides disagree); a single commented fallback limited to the pilot warehouse needs approval. |
| One shared warehouse | **Partial.** One dedicated `SZL_EE_WH`, never shared with other workloads. App and loader share it; the loader is a one-off controlled load. Its DDL is commented out pending spend approval, and its values belong to the cost plan. |
| Unnamed DDL owner (ACCOUNTADMIN risk) | **Fixed.** Roles are created by USERADMIN, the database by SYSADMIN, and ownership is then moved to `SZL_EE_OWNER`. No active statement uses ACCOUNTADMIN (test-enforced). Resource monitors and `PREVENT_UNLOAD_TO_INTERNAL_STAGES` need ACCOUNTADMIN; they are listed as separate, approval-gated recommendations. |
| No managed-access schema | **Fixed.** Both schemas use `WITH MANAGED ACCESS`, so app-object USAGE is granted explicitly by the schema owner. |
| Raw sha256 allows content confirmation | **Contained for pilot 1.** Only synthetic content is digested. Ingesting real private sources is **BLOCKED** until the owner chooses a keyed HMAC held outside Snowflake or git object IDs only. |
| Account identifier embedded in files | **Fixed.** No account identifier, host name or URL appears in any deliverable. A test scans every file against the identifier's sha256, so the literal is never written. |
| `DEFAULT_SECONDARY_ROLES`, `PREVENT_UNLOAD`, `ERROR_LOGGING` | Recommended for service users and at account level (not executed). `ERROR_LOGGING` stays off; rejected rows are stored as reason code plus digest only. |

Residual risk (REPORTED and carried forward): `SZL_EE_OWNER` can still alter or drop objects. "Append-only" binds the loader and the app, not the owner.

## 7. Data integrity

- **Constraint enforcement.** CHECK and NOT NULL serve as defence in depth. Per the prior review of Snowflake docs (REPORTED), Snowflake enforces CHECK and NOT NULL on standard tables but does **not** enforce PRIMARY KEY, UNIQUE or FOREIGN KEY, so none are declared.
- **Deduplication** is enforced in `ingest_batch` in four ways:
  - batch idempotency by `input_manifest_digest`;
  - a key pre-check against stored plus staged rows;
  - identical rows are skipped and counted;
  - a conflicting row under an existing key is rejected (`CONFLICTING_DUPLICATE_ID`) and never overwrites.

  `build_merge` emits insert-only `MERGE … WHEN NOT MATCHED THEN INSERT` with bind variables.
- **Reruns** never delete or reset anything. The local store has no delete or update API (test-enforced).
- **Concurrency.** Writes are serialized per process by a lock, and six concurrent identical batches ingest once (MEASURED). Across processes, pilot 1 assumes **one writer**. Multi-writer ingestion needs a batch-claim protocol before it is enabled.
- **Content digest.** `sha256` over the local content bytes is checked before acceptance; missing content is rejected as `DIGEST_UNVERIFIABLE`. Hashes show content integrity only. They do not show authorship, signature validity or operational truth.
- **Timestamps** must be UTC (`…Z`) and calendar-valid, and must not be later than `as_of`. They are stored as `TIMESTAMP_TZ(6)` with a UTC-offset CHECK. Whether `DATE_PART` is accepted inside a CHECK is UNKNOWN; if it is not, `CREATE TABLE` fails closed.
- **Explicit missing values.** `VALUE_STATE` takes PRESENT, MISSING or NOT_MEASURED. `SUMMARIZED_VALUE` is NULL exactly when the state is not PRESENT.
- **Rights.** Metadata rights and training rights are separate. `TRAINING_ALLOWED` defaults to FALSE and requires `TRAINING_EVIDENCE_REF` when TRUE. A value is shown only when `ALLOWED_USE = METADATA_DISPLAY` and redistribution is not PROHIBITED. Otherwise it is withheld with a visible reason.

## 8. Consequences and open items

- No SQL in this directory has been executed on any account; each file starts with an unparseable approval guard line. (MEASURED)
- UNKNOWN items:
  - whether `session.sql(query, params=[...])` qmark binding is supported in the account's Streamlit runtime;
  - whether a viewer needs warehouse USAGE;
  - whether CHECK with `DATE_PART` is accepted;
  - whether the account's release enforces CHECK.
- Each of these is an integration check and is NOT_RUN.
- Freshness is descriptive (stale after more than 90 days). No colour or threshold is a promotion decision.

## 8a. Emulator evidence (v2, 2026-10-21)

These are **EMULATOR (fakesnow 0.11.22, DuckDB 1.5.6, sqlglot 30.22.0) results, not Snowflake results.** They are in emulator_results.json; all are MEASURED in the emulator.

- **Works in the emulator:** the seven CREATE TABLE cores (columns, types, NOT NULL, DEFAULT, CHECK), qmark-bound insert-only MERGE for every fixture row, row counts equal to the reference model, a rerun that inserts 0 rows, all 13 screen queries (rows and order equal to `local_execute`), the revision comparison, the gap classification and display exclusions.
- **CHECK probes:** 7 of 8 violating rows were refused.
- **UNSUPPORTED_BY_EMULATOR:**
  - every role or privilege statement (access control is not emulated);
  - `WITH MANAGED ACCESS`;
  - table, database and schema properties (`DATA_RETENTION_TIME_IN_DAYS`, `COMMENT`), which fakesnow ignores with a warning;
  - the UTC-offset CHECK. DuckDB TIMESTAMPTZ drops the input offset, so `DATE_PART(timezone_hour)` reflects the session time zone (MEASURED in DuckDB) and that CHECK cannot be exercised. Snowflake behaviour is UNKNOWN, and Python rejects non-`Z` timestamps first.
- **Genuine bugs the emulator found, now fixed:** the reference model (`local_execute`) did not mirror the SQL ORDER BY for `all_observations` and `ingestion_batches`, so LIMIT-truncated results would differ from live results. Review then found two more:
  - timestamps were sorted as text (`…00.25Z` before `…00Z`);
  - the latest-revision tie-break was the reverse of the SQL's.

  The revision-comparison SQL also gained an `OBSERVATION_ID` tie-break. Seven regression tests and five mutants (M43–M47) pin these fixes.

## 9. Stage status

| Stage | Status | Label |
|---|---|---|
| DRAFT_READY | DONE | MEASURED |
| LOCAL_TESTED | PASS: local stdlib suite, mutation sweep, local Streamlit stub smoke, fakesnow emulator check, and a hash-chained local evidence receipt (unsigned). See TEST_RESULTS.md. | MEASURED (emulator part labelled EMULATOR) |
| ACCOUNT_VERIFIED | BLOCKED: no Snowflake credential in this environment; account state must be re-checked by the owner | MEASURED (absence) |
| DEPLOYMENT_APPROVED | BLOCKED: no deployment or spending authorization (mission §1: "NOT YET SPECIFIED"). A general "green light, do whatever you recommend" relayed on 2026-10-21 is not a scoped spend or deployment approval and is not recorded as one. | REPORTED |
| PRIVATE_DEMO_VERIFIED and every later stage | NOT_RUN, blocked by the stages above | MEASURED |

## 10. Sources

| Source | Observed | Label |
|---|---|---|
| docs.snowflake.com Streamlit security overview and privileges pages (search snippets: owner's rights; viewer needs USAGE on db, schema and app; managed-access schemas need explicit USAGE grants) | 2026-10-21, via web search snippets, not full-page fetch | MEASURED (snippet) |
| CHECK and NOT NULL enforced, PK/UNIQUE/FK not enforced, ERROR_LOGGING option | Prior review report, 2026-10-21 | REPORTED |
| Account edition, region, credits, warehouses | Mission §1, historical observation | REPORTED, must be re-checked |
