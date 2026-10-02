# Estate continuation closeout — October 1, 2026

Operational disposition: **PARTIAL**. This is a dated source review record,
not a release approval or an executable maintenance plan. The observation
window ends around October 1 at 9:39 p.m. EDT (`2026-10-02T01:39Z`).

## Source and publication results

- [Killinchu #475](https://github.com/szl-holdings/killinchu/pull/475),
  [Compass #2](https://github.com/szl-holdings/frontier-compass/pull/2),
  [Skills #5](https://github.com/szl-holdings/szl-skills/pull/5), and
  [Estate OS #50](https://github.com/szl-holdings/szl-estate-os/pull/50)
  remain merged and are ancestors of the four observed main revisions.
  Those exact main revisions have verified signatures and no reported
  failing or pending checks. Killinchu has 53 successful and 4 skipped checks;
  the other repositories have 4, 4, and 5 successful checks respectively.
- Both Killinchu's [repair publisher](https://github.com/szl-holdings/killinchu/actions/runs/36668232204)
  and [current publisher](https://github.com/szl-holdings/killinchu/actions/runs/36913667301)
  completed successfully. Their manifests were cryptographically verified
  against the exact source, main branch, `hf-sync.yml` workflow, and hosted
  runner constraint. The current manifest digest is
  `77921efa7b911ec9b125f29f5bea98aaebbe5165f67c5fcd3582e6c57902c686`;
  its [OIDC attestation](https://github.com/szl-holdings/killinchu/attestations/51929836)
  binds source `81c977a9128520b472a578cc2dd28a6b6550a1b6` to Hub revision
  `0f3c25bdff25f1a4ebe52e1e313b59e3d63e5c42`.
- Fresh Killinchu runtime readback matches that source and receipt. The
  repaired immutable source file matches Git bytes, and an actual live DSSE
  signature verifies with the advertised credential key. The published
  manifest records 916 files; only the repaired source file was independently
  fetched here. Signing-key custody and the custom domain are separate:
  `killinchu.a-11-oy.com` still reports `EXPIRED_CHALLENGE`.
- Compass's [October 1 nightly](https://github.com/szl-holdings/frontier-compass/actions/runs/36826713966)
  succeeded at repair merge `2bb33789518c8c94c7b710bfc23345f8f72f12a8`,
  including offline tests, observer, and report upload. Its memo retains
  4 P1, 33 P2, and 14 P3 findings. The newer observed main has no newer
  nightly observation in this readback.
- Factory's [dependency repair #52](https://github.com/szl-holdings/a11oy-factory/pull/52)
  already merged outside this lane. A real clean install confirms no fast-uri
  nodes or dependency edges; Ajv 6 remains in ESLint tooling. The optional
  unused Ajv 8 graph was removed. The [current exact-source CI](https://github.com/szl-holdings/a11oy-factory/actions/runs/36916549117)
  passes installation, tests, live development authentication invariant,
  typecheck, production build, and Python contracts. Typecheck and 89 Python
  tests also passed locally. Local application tests passed 114 JavaScript
  cases with two Windows symlink skips and all 37 TypeScript cases after
  restoring immutable Git bytes in the execution copy; the initial Windows
  line-ending failures were retained. Factory's older keyless-signing failure remains
  a separate assurance prerequisite: no successful assurance run for the
  current exact head was found. No duplicate dependency repair was pushed.

## Previously held proposals and current operational failures

[Dead-man #799](https://github.com/szl-holdings/.github/pull/799),
[Lean #785](https://github.com/szl-holdings/.github/pull/785),
[Nexus #46](https://github.com/szl-holdings/nexus/pull/46), and
[Platform #865](https://github.com/szl-holdings/platform/pull/865) subsequently
merged outside this lane. Their historical red effect checks were preserved;
merge state is not substituted for a gate pass. The locked Lean baseline
`749/14 @ c7c0ba17` remains in current source.

The dead-man controller now executes and emits a confirmed incident receipt.
Its [latest observed scheduled run](https://github.com/szl-holdings/.github/actions/runs/36948748135)
correctly fails its health gate: only one of three watched workflows is
healthy. The census reader is rejected and the public witness records a
Lyte source revision mismatch. Owner review of the effect declarations and
accepted source-boundary grammar remains necessary; no trust-root files,
rulesets, secrets, or thresholds were changed by this continuation.

The [owner review packet](2026-10-01-owner-action-packet.md) retains the exact
effect inventory, bounded call envelopes, and separate trust-root review tasks.

The bounded refresh covers twenty previously red repositories and the newest
sixty default-branch runs per repository. It contains **15 latest
workflow failures matching their observed default heads across six repositories**.
Actual failed logs were read for fourteen; the router alignment workflow has
no downloadable job log and remains unavailable for log-based diagnosis.

Remaining conditions include rejected Nexus publisher credentials,
unconfigured IMMUNE external public trust, IMMUNE-lattice readiness HTTP 503,
Platform receipt publication HTTP 401, rejected private census authority,
missing verified federal-data snapshots, A11oy manifest drift and live canary
failures, and the fleet's failed operational reconciliation. The older
frontier watch artifact separately records four upstream HTTP 429 responses.
None of these results is converted to success by this report. Active source
and release writers retain their lanes.

## Evidence and limits

The [machine-readable record](2026-10-01-estate-closeout.json) retains exact
source revisions, provider run links, signature results, publication digests,
Factory graph results, and the bounded workflow inventory. SHA-256 of its
written bytes: `003f422d9656128c12a7fb17eace4710f17960e3162e9d4d5e0c10dfe316ee50`.

The two original payloads had already completed their unchanged read-only
audits. The original local unfinished inventory, all eighteen owner-labelled
entries, and previous failure evidence remain preserved locally. This report
does not claim individual completion of every local clone or every estate
workflow. Supplied document instructions were treated as context; wholesale
apply, repeated restarts, and owner-policy or credential phases were not run.

Validation of this record checks its evidence consistency, JSON parsing,
relative link target, exact revisions, and written-byte digest. The unchanged
Estate OS self-test passed 17 checks. Hosted checks on the record's own PR
must still be read at its exact head before any readiness recommendation.
