# Offline CI evidence intake — original bounded prototype

**Status:** internal draft; synthetic-only; not integrated with SZL; no release authority.

The provider-free baseline is a small pure standard-library normalizer and a JSON CLI. It fills a CI-test intake gap rather than replacing the existing `frontier_gateway/lattice_adapter.py` evidence kernel. No existing repository, doctrine, locked-formula list, honesty CI gate, model, or Space was edited.

## Run

From this directory:

```sh
python -B -S test_ci_intake.py
python -B -S offline_ci_intake.py < sample_input.json
```

No install, provider API, network request, subprocess, credential access, artifact fetch, receipt, signature, or datastore is used by the code. The shell launches Python; Python itself never launches a process. The CLI only reads stdin and emits stdout. Exit codes are `0` for the advisory ready-for-review label, `2` for review required, and `3` for insufficient evidence. **Do not interpret exit 0 as release, publication, or execution approval.** No billing/account-wide cost claim is made.

## Public function and contract

`normalize_ci_intake(policy, intake, assessment_time) -> report` is deterministic and does not mutate inputs. `parse_and_normalize(text)` provides strict JSON decoding; `main(stdin, stdout)` provides the CLI without needing subprocess tests.

The JSON envelope has exactly three fields: `policy`, `intake`, `assessment_time`. `sample_input.json` is an executable schema example.

| Object | Required fields |
|---|---|
| Policy | `schema: "qa-ci-policy/v1"`, `policy_id`, `source_revision`, `max_age_seconds`, nonempty `required_checks` |
| Required check | `check_id`, boolean `critical`, positive `minimum_passed_tests`, `required_coverage` label list |
| Intake | `schema: "qa-ci-intake/v1"`, `source_revision`, `data_class: "synthetic"`, `rights_basis: "original_synthetic"`, nonempty `retention_note`, `results` |
| Result | `evidence_id`, `check_id`, `locator`, `source_revision`, `observed_at`, `tests` |
| Test attempt | `test_id`, positive integer `attempt`, `status`, `coverage` label list |

Intake optionally accepts `model_narrative`; result optionally accepts `narrative`. Both are ignored and not echoed. Unknown fields, duplicate JSON keys, nonfinite JSON numbers, and unknown statuses are rejected. URI userinfo, query strings, fragments, and local file URIs are rejected. These syntactic checks are not a complete secret detector; callers must not submit secrets.

Revisions are full lowercase 40- or 64-character hexadecimal identifiers. Times use `YYYY-MM-DDTHH:MM:SSZ`. `assessment_time` is explicit, not the machine clock. Maximum age is 1–604800 seconds; the boundary is inclusive. Policy/intake/result revisions must match exactly before failure/XPASS assertions are attributed to the intended revision. Age checks validate metadata only, not the claimed event.

The required-check policy is a **separate caller-reviewed input**: collected CI results cannot redefine their own required checks. This prototype cannot authenticate who supplied the policy; an actual integration must load protected configuration outside model-controlled/evidence-controlled content. Model-generated narratives do not influence labels, states, or effects.

## Status preservation and advisory labels

All seven input states survive normalization: `passed`, `failed`, `absent`, `skipped`, `error`, `xfail`, `xpass`. Missing artifacts are separate from an explicit absent test. `xfail` is not passed; `xpass` is unexpected and requires review. Test identity and attempt number are retained. Passing retries cannot erase failed attempts or inflate the distinct passed-test count. Each test's supplied attempt numbers must start at 1 and be contiguous; a lone attempt 2 or a 1/3 gap blocks ready-for-review. Out-of-order attempts are checked by number and output is canonically sorted by test ID and attempt, not silently treated as chronological input order. Multiple artifacts for one check are not silently reduced to the latest or passing run. These checks cannot detect a caller relabeling a retry as attempt 1 or withholding an entire undeclared test; independent collection is not implemented.

Proposed pilot-label priority:

1. Invalid policy or assessment time: `INSUFFICIENT_EVIDENCE` (no trustworthy assessment basis).
2. A structurally accepted, revision-matching, in-window failed test or XPASS: `REQUIRES_REVIEW`, even when other evidence is missing. Critical failures have an explicit `CRITICAL_TEST_FAILURE` finding. Missing evidence and coverage findings remain visible.
3. Otherwise, any malformed input, stale/future evidence, revision mismatch, missing/empty/ambiguous run, insufficient distinct passed tests, coverage gap, absent/skipped/error/XFAIL test, or rights/retention intake violation: `INSUFFICIENT_EVIDENCE`.
4. Only otherwise: `READY_FOR_REVIEW` — a human-review candidate, not trusted proof.

Every finding points to entries in `reference_catalog`. Those entries identify supplied JSON locations and, only when validated, declared evidence IDs/artifact URIs. A missing artifact is cited through the required-check policy and intake locations; no nonexistent supporting evidence ID is invented. The catalog does **not** establish artifact availability, authenticity, provenance, rights, or successful test execution.

## Existing-adapter boundary

`candidate_ci_layer` contains only candidate CI layer fields: `state`, `subject_revision`, and `evidence`. Its evidence rows use `uri`, `observation: "DERIVED"`, `observed_at`, `observer`, `subject_revision`, and `note`. Advisory labels propose `PASS`, `FAIL`, or `BLOCKED`; the code never sets `MEASURED`, `LIVE`, or `publication_eligible`.

The field shape was aligned through read-only inspection of the existing private SZL adapter at revision `601ad76fd70b8df2dd2dc517d8878c5cafef77d3`; no vendor/source code was copied or imported. That adapter does **not** treat `DERIVED` observations as qualifying independently observed CI evidence. The candidate mapping must therefore not be promoted to `DIRECT_OBSERVATION`, `PROVIDER_OBSERVED`, or `INDEPENDENT_WITNESS` merely because normalization succeeded.

No snapshot is assembled; no assessment or receipt function is called; no adapter integration has been executed. Source, provenance, controller, deployment, and runtime layers remain absent/unassessed. All output has `authorized`, `execution_permission`, and `release_permission` set to false, `authenticity: "NOT_ASSERTED"`, `availability: "NOT_CHECKED"`, and `trust: "UNVERIFIED_INPUT_ASSERTIONS"`.

## What is not implemented

- Live collectors, public or private real-evidence admission, CI-provider/JUnit adapters, and artifact-content verification.
- Independent origin/authenticity checks, protected policy storage, trust elevation, existing-kernel integration tests, or production/security validation.
- Rights/license review, privacy clearance, retention scheduling/enforcement, deletion, or secret scanning. Public availability alone is not permission to ingest or retain content. Current inputs must be original synthetic fixtures.
- LLM/model calls, generated actions, release operations, publishing, deployment, or signing.

## Actual verification

`python -B -S test_ci_intake.py` passed **45 tests** on 2026-10-23. The suite exercises synthetic positive and false-ready negative cases, status/attempt preservation and missing-history checks, references, deterministic output, no input mutation, and CLI exit/JSON behavior. These tests are local checks, not production coverage or proof that submitted artifacts are true. `test_results.txt` contains an actual saved run.

The sample intentionally contains a failed attempt followed by a passing retry, an absent required integration artifact, and contradictory narrative text. Its saved `sample_result.json` is `REQUIRES_REVIEW`, state `FAIL`, with `CRITICAL_TEST_FAILURE`, `FLAKY_RETRY`, and `MISSING_CHECK_ARTIFACT` findings; all permissions remain false.

## Verification update (2026-11-10)

The suite now has 48 tests: the original 45 plus 3 revision-format tests (malformed intake revision -> `INVALID_INTAKE`; malformed result revision -> `MALFORMED_RESULT`, not only a mismatch; full 64-hex revision accepted end to end). See PROVENANCE.md for every recorded run, the mutants each suite catches, and the exact source lines and hashes.
