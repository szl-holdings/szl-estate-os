# DATA_FLOW_MANIFEST: SZL Evidence Explorer pilot 1

- Date: 2026-10-21 (UTC).
- Scope: the local review directory only. Nothing here has been deployed, uploaded or sent to any account.
- Labels: **MEASURED** means run or read in this session. **REPORTED** means taken from a document. **UNKNOWN** means it cannot be determined offline.

## 1. Flows

| # | From | To | What moves | Status | Label |
|---|---|---|---|---|---|
| F1 | `make_fixture.py` (seed 20261021, no clock, no network) | `fixture_v1.json` | Synthetic rows; synthetic `local_content` strings for digest checks | Runs locally; byte-identical across processes | MEASURED |
| F2 | `fixture_v1.json` | `evidence_core.ingest_batch`, then `LocalStore` (in memory) | Validated rows; rejected rows as reason code + digest; batch records | Local only | MEASURED |
| F3 | `local_content` | `ingest_batch` digest check | Bytes, hashed and then discarded; never stored and never part of the manifest digest | Local only | MEASURED |
| F4 | Accepted rows (F2) | `SZL_EE_DB.EE_DATA` through `build_merge` (insert-only, bound) as `SZL_EE_INGEST` | The same rows as F2 | **NOT_RUN**: no credential, no approval | MEASURED (not run) |
| F5 | `EE_DATA` tables | Streamlit app (owner's rights `SZL_EE_APP`), then the viewer's Snowsight session | Bounded SELECT results (LIMIT ≤ 200) rendered as text or tables | **NOT_RUN**: not deployed | MEASURED (not run) |
| F5e | Accepted rows (F2) plus schema.sql (guard line dropped from an in-memory copy) | fakesnow/DuckDB **in-memory** emulator in a separate local env (`SNOWFLAKE_HOME` = empty temp folder; no network, no credentials) | Synthetic rows through `build_merge` with qmark binds; screen queries | **EMULATOR (fakesnow 0.11.22)**, local only; not Snowflake | MEASURED |
| F6 | Integration test results | `TEST_RESULTS.md` | Pass/fail plus sanitized query IDs only | **NOT_RUN** | MEASURED (not run) |

## 2. What never flows

- Secrets, tokens, keys or passwords. Secret-named fields and token-shaped values are refused, and their rejected-row digest is NULL (test-enforced).
- Raw values of any rejected row. Only the reason code, the field name and a sha256 of the canonical row are kept.
- Source bodies, model weights, dataset bodies, private repository content, forum posts, personal or clinical data.
- Account identifiers or host names (test-enforced scan against the identifier's sha256).
- Anything non-synthetic. Pilot 1 refuses a row unless `is_synthetic = TRUE` and the exact label is present.

## 3. Rights model

| Field | Rule |
|---|---|
| `allowed_use` | Takes METADATA_DISPLAY, METADATA_INTERNAL, NONE or UNKNOWN. Only METADATA_DISPLAY values are shown. NONE blocks ingestion of the asset's observations (`RIGHTS_DENIED`). |
| `redistribution_status` | Takes ALLOWED, RESTRICTED, PROHIBITED or UNKNOWN. PROHIBITED values are withheld from display. |
| `training_allowed` | Defaults to FALSE. TRUE requires `training_evidence_ref`; no fixture row sets TRUE validly. Metadata rights never imply training rights. |
| Missing rights record | The value is withheld and shown as `WITHHELD: RIGHTS_UNKNOWN`. |

## 4. Exclusion register

| ID | source_identifier | Reason | Scope | Effective (fixture) | Provenance | Enforcement evidence |
|---|---|---|---|---|---|---|
| E1 | `f75070d94bc3683a7aa18e3d111cb0dd112638c1` | OWNER_EXCLUSION | ALL | 2026-10-01T00:00:00Z (**placeholder**; real effective date UNKNOWN) | REPORTED: mission §2 says "Preserve excluded Studio blob and copies". The v5 handoff records the blob as `studio.py` in `szl-holdings/agents-studio` at head `e51779dc3cd3320e7455e0b73878bb1c92f8463e`, rule EXCLUDED_DO_NOT_FETCH, which covers identical-blob copies. The body was never read. | MEASURED: a revision carrying `git-sha1:<blob>` is rejected as EXCLUDED; the blob never appears in any stored data row; mutants M16 and M17 are killed. |
| E2 | `mock://github/demo-org/scraped-forum-demo` | OUT_OF_SCOPE | ALL | 2026-10-01T00:00:00Z | Synthetic | MEASURED: that asset is rejected as EXCLUDED. |
| E3 | `demo-obs-adv-card` | OWNER_EXCLUSION | DISPLAY | 2026-10-20T00:00:00Z | Synthetic | MEASURED: the row is kept in storage, hidden from screens, and the app shows a "1 row hidden by display exclusions" count. |

How exclusion matching works:
- Matching uses exact identifiers on asset_id, revision_id, observation_id, the locators, `immutable_source_revision` (also with its `scheme:` prefix stripped) and `content_digest`.
- An identical-blob copy recorded under the same git blob ID is therefore caught.
- A re-encoded or modified copy has a different hash and **cannot** be detected by identifier. Whether such copies exist is UNKNOWN.
- Exclusions are append-only. No exclusion can be removed through this code.

## 5. Retention

- Every table is append-only: the loader is granted INSERT and SELECT only, and the app SELECT only. Owner-level DDL remains possible (REPORTED limitation).
- Historical revisions and exclusion records are kept.
- Time Travel is 1 day (`DATA_RETENTION_TIME_IN_DAYS = 1`); the cost plan owns the final choice.
- A rerun never deletes, resets or overwrites anything.

## 6. Preserved, unrelated work

- The v5 unified handoff (`pasted-text-2026-10-21T11-39-06.txt`, 84,744 bytes, sha256 `991cbeccd861e99a38071f32f445a4e6d3463a6f62f370697ac70e27fdd1bca6`) was read only for the exclusion context (MEASURED hash).
- It was not modified, and nothing in it is marked complete by this slice.
