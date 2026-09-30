# Bounded witness/census/pin source review: batch 4

12 pinned objects acquired/hash-verified; 11 byte-credited and 1 withheld. Static review: 10 COMPLETE / 1 PARTIAL / 1 SKIPPED. Runtime NOT_RUN; Phase 2/estate readiness false.

## 1. Authority and stack

Reports-only branch `codex/estate-witness-source-batch4`, stacked on draft 56 / `codex/estate-receipt-source-batch3` at `10407794b36a3f5df1a0793c78ffd57f47a1a691`. Ordinary read-only source auditing was authorized. Existing owners retain repairs and all merges; no candidate source/registry/payload/card edits.

## 2. Scope and evidence

Two generic repositories: `szl-holdings/szl-ci-witness` at `f8102adf6e0e3214f5879dc16bea852394215d32` and `szl-holdings/szl-pin` at `8906cb2e995b720a096df814a15a1555093f0664`. 69,187 frozen bytes, largest 25,105; 12 distinct blobs. Same frozen index and unchanged reviewed reader; no new framework. At 14:42:11/19UTC both repositories returned HTTP200/public. The run completed14:42:22UTC using 26 GETs and 10 nonrecursive tree reads. Exact commit/tree membership, regular leaf modes, blob sizes, Git-framed SHA1 and SHA256 were verified before screening.

`tools/source_census.py` was wholly withheld by secret-marker screening with code CREDENTIAL_BLOCK_WITHHELD. No body/cache was reviewed and its line count/behavior remain UNKNOWN. The screening result does not prove an actual credential leak. No guard bypass or refetch occurred. Four lines of `tests/test_source_census.py` were masked: 129, 136, 144-145.

## 3. Coverage and explicit unknowns

All 147 prior selected identities (including skipped paths) and their blobs were excluded. Historical 685 + 11 newly credited paths = **696 / 32,748**; **32,052 remain unread/skipped**. This dated denominator is not a current estate census. All 12 objects were acquired/hash-verified, but the wholly withheld file gets zero read/review credit. 906 known physical lines comprise 902 visible reviewed lines plus 4 masks; withheld implementation line count is UNKNOWN.

At 14:33:06UTC terminal page1/per_page100 open-PR metadata contained 0 entries for each repository; unpublished writers remain UNKNOWN. At 14:51:34UTC authorized JSON-only head reads matched both review pins; HTTP was unexposed. Every repair still requires a fresh head/blob comparison. Source bodies and caches remain outside Git.

## 4. Findings and proposed owner handoff

10 bounded findings follow. Facts describe visible source; consequences are inferences; synthetic owner fixtures are proposals NOT_RUN. Tests/docs cannot establish withheld implementation behavior. Owner roles remain PROPOSED_NOT_ASSIGNED, repairs NOT_ATTEMPTED.

### R4-WITNESS-001: Hash-valid records can yield green summaries with contradictory test evidence

HIGH / FACT; [pinned source src/szl_ci_witness/witness.py:77-104](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/src/szl_ci_witness/witness.py#L77-L104).

The verifier requires field presence and a tests dictionary but validates neither test counters nor their consistency with conclusion. The summary counts conclusion=success as green. The separate record-junit producer rejects success with failed tests at lines 154-155, but the verifier and ordinary record path do not enforce that rule.

Consequence (INFERENCE): A hash-consistent success record with a positive failed count can reach a green/MEASURED summary. This is an inferred source branch, not an observed CI result or release bypass; origin authentication remains separate.

Proposed acceptance (NOT_RUN): Owner uses synthetic records with success plus failed>0, missing, boolean, noninteger or negative counters, and unbound commit/date fields. Require invalid or explicitly unverified semantic evidence, preserving legitimate unavailable counts for failed runs without promotion.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-WITNESS-002: Summary command returns success status for an INVALID chain

MEDIUM / FACT; [pinned source src/szl_ci_witness/witness.py:168-174](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/src/szl_ci_witness/witness.py#L168-L174).

The summary branch prints witness_summary and unconditionally returns 0. witness_summary returns state INVALID for an empty or invalid chain at lines 95-97. The verify command instead returns 1 for invalid chains.

Consequence (INFERENCE): An exit-status-only caller can treat an invalid summary as successful execution; its printed INVALID state remains visible. No caller behavior was tested.

Proposed acceptance (NOT_RUN): Owner runs a disposable empty or tampered-chain summary fixture; require an explicit nonzero error exit while a valid summary remains successful.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-WITNESS-003: Predecessor validation and append are not serialized

MEDIUM / FACT; [pinned source src/szl_ci_witness/witness.py:54-69](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/src/szl_ci_witness/witness.py#L54-L69).

append_record loads and verifies the chain, validates the new predecessor/hash, then separately opens append mode and fsyncs. No lock spans those operations.

Consequence (INFERENCE): Concurrent writers can validate the same predecessor and append competing successors; later chain verification would detect the resulting broken linkage. No concurrent incident or data loss was observed.

Proposed acceptance (NOT_RUN): Owner uses two disposable synthetic appenders with a controlled interleaving after predecessor validation. Require serialized valid extension or an explicit refusal; preserve prior bytes and report both outcomes.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-WITNESS-004: Conflicting JUnit outcomes can produce negative passed counts

MEDIUM / FACT; [pinned source src/szl_ci_witness/witness.py:118-121](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/src/szl_ci_witness/witness.py#L118-L121).

Failures/errors and skipped cases are counted independently; passed is total minus both counters. No mutual-exclusion check precedes the MEASURED result.

Consequence (INFERENCE): One malformed synthetic testcase containing both failure and skipped outcomes contributes twice and can produce passed=-1. This describes the visible arithmetic; no XML fixture was executed.

Proposed acceptance (NOT_RUN): Owner supplies a synthetic single testcase with conflicting outcomes; reject ambiguous reports or use an explicit deterministic classification while enforcing nonnegative disjoint counts.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-WITNESS-005: MEASURED summary is scoped to recomputed declared fields

INFO / FACT; [pinned source src/szl_ci_witness/witness.py:94-107](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/src/szl_ci_witness/witness.py#L94-L107).

After hash/link validation the summary emits state MEASURED and derives green/red/fix counts from supplied conclusion fields. This function fetches no native CI status or authenticated source receipt. The module explicitly documents external anchors and the record-junit path labels signatures UNSIGNED_HONEST.

Consequence (INFERENCE): Consumers must interpret this as recomputed declared-chain statistics; signature authorization, native CI truth, complete-history freshness and estate readiness remain unestablished. No authentication flaw beyond this scope distinction is claimed.

Proposed acceptance (NOT_RUN): An inert consumer-envelope fixture keeps chain integrity true while native CI truth, signer authorization, freshness and complete-history scope remain UNKNOWN; do not promote MEASURED to shipping or release authorization.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-CENSUS-001: Declared-oversize regression does not observe body-read calls

LOW / FACT; [pinned source tests/test_census_streaming.py:39-41](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/tests/test_census_streaming.py#L39-L41).

The declared-oversize fixture supplies an empty body and asserts an exception. It never asserts zero body-read calls despite its name.

Consequence (INFERENCE): A premature read followed by rejection could satisfy this visible test. The withheld source-census implementation remains UNKNOWN.

Proposed acceptance (NOT_RUN): Use an instrumented synthetic response; assert zero body reads when the declared size exceeds the cap.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-CENSUS-002: Inventory identity regressions omit provider-ID-only drift

LOW / FACT; [pinned source tests/test_inventory_identity.py:15-44](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/tests/test_inventory_identity.py#L15-L44).

Visible fixtures retain provider ID 7 while separately changing branch, archived state, canonical name and timestamps. They do not exercise a provider-ID-only change.

Consequence (INFERENCE): Regression coverage for the documented provider-identity dimension is not established; actual implementation handling is unknown.

Proposed acceptance (NOT_RUN): Change only the numeric repository ID in synthetic metadata; require identity to change while preserving the existing timestamp-invariance case.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-CENSUS-003: Nonexecution regression lacks an independent side-effect observer

LOW / FACT; [pinned source tests/test_source_census.py:49-53](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/tests/test_source_census.py#L49-L53).

The fixture contains a raising statement and asserts normal parse results; it has no independent observation of execution or side effects.

Consequence (INFERENCE): Exception suppression could conceal execution from those assertions. No candidate execution occurred and the implementation is withheld.

Proposed acceptance (NOT_RUN): Use an inert execution-boundary observer or disposable sentinel fixture and assert it remains untouched during static inspection.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

### R4-PIN-001: Diff-detail regression asserts only eight-character revision displays

LOW / FACT; [pinned source tests/test_pin.py:27-33](https://github.com/szl-holdings/szl-pin/blob/8906cb2e995b720a096df814a15a1555093f0664/tests/test_pin.py#L27-L33).

The visible moved-detail fixture expects eight-character from/to revisions. No visible same-prefix collision case or full-revision detail binding is tested here. The pin implementation was historically inspected and deliberately excluded from this deduplicated batch.

Consequence (INFERENCE): These assertions do not establish that full immutable from/to identities survive the consumer handoff. Short displays may be legitimate if full entries remain available; no actual truncation defect in the unseen implementation is asserted.

Proposed acceptance (NOT_RUN): Use two synthetic forty-character revisions sharing eight characters; require distinguishable full from/to evidence, while retaining any clearly labeled abbreviated display.

Proposed owner route: existing pin-package maintainer; revalidate exact current head/blob first.

### R4-CLAIM-001: Embedded green-test statement is an unverified historical source claim

INFO / FACT; [pinned source tests/test_witness.py:1-1](https://github.com/szl-holdings/szl-ci-witness/blob/f8102adf6e0e3214f5879dc16bea852394215d32/tests/test_witness.py#L1-L1).

The file header says every assertion executed green before it was pushed. This batch read test definitions without fetching an exact historical run receipt or executing them.

Consequence (INFERENCE): Source presence does not validate that claim or current runtime readiness. It remains dated to the reviewed source revision.

Proposed acceptance (NOT_RUN): An inert evidence classifier preserves this as an unverified historical declaration until an exact-head run receipt establishes real counts and outcomes.

Proposed owner route: existing CI-witness maintainer; revalidate exact current head/blob first.

## 5. Artifacts and privacy

evidence.json retains exact file/revision/blob identities, original/screened digests, timestamps, statuses, line exclusions and 10 source-bound findings. files.csv projects the 12 file records. check_report.py validates report metadata using stdlib only. No candidate bodies, credentials, personal/profile/room/tool identifiers, private inventories or execution outputs are committed.

| ID | Path | Byte | Static | Known lines |
|---|---|---|---|---|
| R4-001 | `szl-holdings/szl-ci-witness/docs/SOURCE_CENSUS.md` | COMPLETE | COMPLETE | 55 |
| R4-002 | `szl-holdings/szl-ci-witness/src/szl_ci_witness/__init__.py` | COMPLETE | COMPLETE | 6 |
| R4-003 | `szl-holdings/szl-ci-witness/src/szl_ci_witness/witness.py` | COMPLETE | COMPLETE | 177 |
| R4-004 | `szl-holdings/szl-ci-witness/tests/test_archive_canonical_fallback.py` | COMPLETE | COMPLETE | 69 |
| R4-005 | `szl-holdings/szl-ci-witness/tests/test_census_streaming.py` | COMPLETE | COMPLETE | 70 |
| R4-006 | `szl-holdings/szl-ci-witness/tests/test_inventory_identity.py` | COMPLETE | COMPLETE | 48 |
| R4-007 | `szl-holdings/szl-ci-witness/tests/test_persistence.py` | COMPLETE | COMPLETE | 160 |
| R4-008 | `szl-holdings/szl-ci-witness/tests/test_source_census.py` | COMPLETE | PARTIAL | 170 |
| R4-009 | `szl-holdings/szl-ci-witness/tests/test_witness.py` | COMPLETE | COMPLETE | 45 |
| R4-010 | `szl-holdings/szl-ci-witness/tools/source_census.py` | SKIPPED | SKIPPED | UNKNOWN |
| R4-011 | `szl-holdings/szl-pin/src/szl_pin/__init__.py` | COMPLETE | COMPLETE | 6 |
| R4-012 | `szl-holdings/szl-pin/tests/test_pin.py` | COMPLETE | COMPLETE | 100 |

## 6. Validation and proof limits

All 16 report consistency checks passed on Python 3.11, with zero failures, errors or skips. Report metadata validation is separate from candidate fixtures; all candidate tests and proposed regressions remain NOT_RUN. Candidate code was read as data, never imported, parsed into executable form, built or run. Static COMPLETE covers the selected visible file only. Hash integrity does not establish authenticated origin, CI truth, scientific validity, measured performance, rights, training/loadability, deployment or release authorization. Novelty remains NOT_ESTABLISHED; human biosafety/clinical/custom-license/security gates remain required.

## 7. Remaining acceptance and next three actions

1. Existing CI-witness/pin owners revalidate current affected blobs and review the listed inert regression proposals; preserve the withheld implementation and its unknown status.

2. Continue another deduplicated generic source batch from existing evidence, excluding all 159 selected identities and active-owner source paths.

3. Existing platform/HF/science/queue owners resolve their bounded access/runtime/release receipts; queue owner alone handles eligible normal green merges.

Full Phase 2 remains incomplete: current/private repo/file coverage, HF models/datasets/Spaces/collections/kernels, domain/mobile/benign-tab behavior, measured accessibility, research/registry parity, current PR controls and sustained disk stability. No repair, payload execution, deployment, settings/key change, publication, merge or history rewrite occurred.
