# Phase 0 operation rules

## 1. Authority and source

Canonical destination: szl-holdings/szl-estate-os, tools/szl_estate.
Python 3.11+ and a standard-library core follow existing estate tooling.
This package consumes evidence; importing it performs no network access.
The existing maintenance runner, registry tools, product PRs and root
estate_state.json have separate owners and contracts.

## 2. Scope and boundaries

Phase 0 provides setup, typed evidence, offline verification, bounded cache,
parsers, classifier fixtures and reports. It has no write executor, provider
credential handling, migrations, deployment or operational integration.
No operational weapons enhancement or finance, legal or defense imports into
science. Existing research is separate; novelty remains NOT_ESTABLISHED.

## 3. Evidence and provenance

Every record identifies source, reference, observation UTC, scope, digest,
freshness and proof origin. A snapshot includes checked_at_utc and retains its
original observation time on replay. Missing access and auth failures are
INACCESSIBLE. Hash equality establishes byte consistency only; it establishes
neither signed origin nor truth. Historical inventory is never current runtime
proof. All unknowns and partial failures remain visible.

## 4. Claims and independent dimensions

SHIPPING, DEMONSTRATED, INTERNALLY_TESTED and ROADMAP describe claim maturity.
FACT, INFERENCE and PROPOSAL describe claim basis. Neither axis confers
cryptographic integrity, scientific validity, authorization, proof scope or
deployment readiness. These dimensions remain separately typed. A passing
offline fixture proves only its exercised contract; no benchmark is invented,
and no report overrides a promotion gate.

## 5. Access, cache and resumability

Consume the existing GitHub Library bundle version 2 and historical HF inventory
version 1. Use consumer-local materialization and verify readable bytes.
Bound cache/input size; allowlist public structured projections; withhold private
or unknown response bodies. Never record tokens, authorization/cookie headers,
signed URLs or arbitrary private response text. Cache keys are opaque and
hash-based. Replay retains source time and is not a fresh live probe.
Handle list/object pages, totalCount/comment variants, limits, backoff,
cursor loops and partial errors without emitting successful collection states.

## 6. Validation and release evidence

Install the independent src package before running python -m szl_estate verify.
Verify uses local inputs only. Outputs are deterministic for the same inputs and
reference time, with explicit INACCESSIBLE estate scopes. Each output file is
replaced atomically; preserve its old bytes on an interrupted write and retain
incomplete temporary files for recovery. A failure between report writes can
leave mixed generations; the command fails and the whole run must be replayed.
Run only reviewed Phase 0 tests in the scheduled focused lane; do not execute
bundled scripts or unknown repository code. Never install Playwright browsers
in this phase. Pin dependencies from official package evidence and record actual
environment/test results separately from metadata compatibility.

## 7. Ownership, decisions and limits

Classifier results are recommendations only: MERGE_NOW_GREEN, WAIT_CHECKS,
FIX_CHECKS, CONFLICT_REBASE, DOCS_ONLY, DRAFT_PRESERVE, HOLD_PRESERVE and
NEEDS_OWNER_DECISION. The existing queue owner owns all merges.
No red, pending, draft or HOLD merges; no force push or history rewrite.
Keep new work isolated; push only a tested draft after environment/test readiness.
Verify remote SHA and CI; never claim whole-estate readiness from Phase 0.
