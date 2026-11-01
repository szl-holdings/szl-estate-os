# SZL Evidence Explorer on Snowflake - pilot 1, v0.3 DRAFT

Status: OFFLINE_REGRESSION_TESTED; live deployment remains unqualified. A green
offline CI job is not evidence of account access, a live deployment, or successful
live integration tests.

- kit/: operator kit v0.3.0 (narrow privilege design: owner-created monitor, warehouse and roles; SZL_EE_SETUP deploy identity; SZL_EE_RUNTIME runtime identity) plus runner szl_ee_go.py v0.3.0.
- bundle/: Evidence Explorer bundle v4 (schema v4 without SYSADMIN hierarchy grants). The bundle receipt predates schema v4 and is marked STALE.
- READINESS_PACKET_2026-10-22.md: approval scope, privilege diff, cost-control limits, failure map, test evidence, open decisions. Artifact links inside it resolve only in the originating workspace.

Current offline checks (Python 3.12, 2026-11-01): the exact bundle CI command
runs 140 tests, with 129 passed and 11 live tests skipped (including 11
mutation-gate and 8 integration-boundary regressions in that total); operator kit 78 passed; reconstructed
runner contracts 29 passed; shared kit/runner evidence and output-isolation
regressions 10 passed. Total: 246 passed, 11 skipped. The repaired core
mutation sweep has 48 behavioral kills, 0 survivors, and 0 invalid results.
The operator-kit sweep now includes the runner module its clean baseline imports,
and has 88 behavioral kills, 0 survivors, and 0 invalid results.
Its clean baseline runs before the mutants; input SHA-256 digests and per-mutant
test counts are recorded in the result artifact. Syntax/import failures,
timeouts, signals, incomplete suites, and error-only crashes are INVALID, never
counted as behavioral kills. M07 and M37 now exercise valid code instead of
syntax/string-formatting failures.

The `snowflake-evidence-explorer` CI job runs all those checks and preserves the
new core and kit mutation result artifacts, including baseline-failure diagnostics. A survivor or invalid result exits
nonzero. Kit and runner sweeps refuse to overwrite an existing report, and the
runner sweep uses a unique temporary directory so concurrent runs do not share
or delete one another's working files.
Run locally from this directory:

```bash
(cd bundle && python -B -m unittest -v test_evidence_core test_verify_receipt test_integration_snowflake test_mutation_sweep)
(cd kit && python -B -m unittest -v test_operator_kit && python -I -B test_szl_ee_go.py -v)
(cd kit && python -I -B test_mutation_support.py -v)
(cd bundle && python -I -B mutation_sweep.py /tmp/ee-mutation-results.json)
(cd kit && python -I -B mutation_sweep_kit.py /tmp/ee-kit-mutation-results.json)
```

The real `szl_ee_go.py --dry-run-only` path also completed its file-pin check,
plan generation, receipt-chain validation, and temporary-directory cleanup in
an isolated environment with a synthetic approval account. Its exit code is 2
(INCOMPLETE), as intended: an offline plan must never claim a live success.

Remaining qualification gaps: the reconstructed runner suite is not the
withheld historical 65/98-test harness and does not establish the full live
deploy/shutdown state machine. Full runner mutation qualification,
v4 emulator/receipt regeneration, and all eleven live integration tests still
need separate current evidence. The current reconstructed runner sweep exits 1:
25 behavioral kills, 52 survivors, and 6 invalid results across 83 mutations.
These are coverage/fixture gaps, not a successful qualification; the runner
sweep is deliberately not advertised as passing in the offline CI job.
Timed-out operations now keep shutdown
unverified and the warehouse potentially billable, even after a SUSPENDED
readback; the delayed-completion regression covers this. Automatic cancellation
and final-state reconciliation are not implemented. Historical package checksums and
receipts remain historical. The bundle manifest hashes and byte sizes match all 41 current entries;
that integrity check does not refresh historical receipts or establish deployment authorization.

Last measured suites (v0.2.0-rc1 + v3 bundle, 2026-10-22): kit 64 OK, runner 65 OK, mutants 59/59 and 46/46 killed, bundle 80 OK, verifier 24 OK.

The original approval.txt, APPROVAL_PROVENANCE.md and runner harness were
withheld because they contained the Snowflake account identifier; two local
logs were also withheld. `kit/test_szl_ee_go.py` is a new synthetic-only suite,
not a recovery of that original file. KIT_SHA256SUMS.txt remains the historical
package inventory and does not attest this new test file.
Synthetic demonstration data only. Not clinical; must never receive patient data.

Fixture writes require the SZL_EE_INGEST primary role, readable available roles,
and no available admin/setup/owner/app roles. Each load rechecks identity; failed
identity stays refused. The duplicate-load check is skipped if the initial
fixture load or deterministic validation fails, so a failed load is not retried.
