# SZL estate production readiness

Status: `PARTIAL`
Control-plane mode: `READ_ONLY`
Evidence date: `2026-08-01`

## Measured baseline

From a controlled clean checkout of then-current main
`bbf9099b80d9740daad14997093b6adf1d49ddd4`, the local run completed the
deterministic suite, audit `audit-2e42589df4114cc58245bb4e90aa735e`, baseline
verification, and bounded stress on 2026-08-01. The current audit and stress
schemas do not embed the Git revision or a worktree digest, so these are
human-observed local measurements, not immutable source-bound attestations.

| Evidence | Observed result |
|---|---|
| Deterministic checks | 17/17 passed; readiness verifier 33/33 passed |
| GitHub | 63 assets: 1 organization plus 62 repositories (58 public, 4 private); the then-current collector labeled authenticated completeness unknown |
| Hugging Face | 81 public assets: 16 models, 27 datasets, 26 Spaces, 12 collections |
| Domains | 26 routes across `a-11-oy.com` and `a11oy.net`; 0 broken |
| Estate total | 170 assets, 25 duplicate clusters, 155 gated proposals |
| Receipts | Chain valid, unsigned |
| Hugging Face alignment | 5 `EXACT_RUNTIME_HEAD`, 4 `EXACT_HEAD`, 10 `PINNED_NON_HEAD`, 48 `MANAGED_UNBOUND`, 2 `RUNTIME_SOURCE_UNRESOLVED` |
| Baseline verifier | `FAIL`: the only failing check was the four required response headers on `a11oy.net/` |
| Bounded stress | 1,000/1,000 HTTP 200, zero errors, p95 254.80 ms, 198.89 requests/second; service ready afterward |

These measurements prove only the named local checks and observation window.
They do not establish production promotion, authenticated estate completeness,
independent signing authority, deployment equivalence, or an immutable binding
to the cited checkout. Successor diagnostics remain `PARTIAL` until committed,
rerun on the exact reviewed head, and independently witnessed where required.

## Production blockers

| Priority | Blocker | Required closure evidence |
|---|---|---|
| P0 | Authenticated estate completeness is not established across providers | Authorized inventory reconciling private/protected assets and modeled asset classes for GitHub, Hugging Face, and every other in-scope provider |
| P0 | Hugging Face source/runtime binding is unresolved | Immutable GitHub revision and running Space revision match for every critical Space |
| P0 | Credential-backed deployments are not mapped estate-wide | Repo, reviewed commit, artifact digest, environment, URL, owner, and deployment receipt graph |
| P1 | `www.a-11-oy.com` did not resolve in the bounded DNS probe | Correct DNS, redirect/canonical behavior, TLS, and post-change probe |
| P1 | `a11oy.net` omits CSP, Referrer-Policy, HSTS, and nosniff response headers | Activate the compatible edge from [a11oy-net PR #8](https://github.com/szl-holdings/a11oy-net/pull/8), then pass exact live header readback on the reviewed source |
| P1 | `a-11-oy.com` enforces framing policy but leaves resource restrictions report-only | Refactor inline resources, enforce a fail-closed CSP, run application E2E, and read back the deployed header |
| P1 | Audit receipt is unsigned and local HMAC is not independent authority | Approved asymmetric signer, key ID, rotation/revocation, detached verification, and independent witness |
| P1 | Browser evidence is unavailable | Desktop/mobile interaction, console/network, keyboard, screen-reader, zoom, contrast, and WCAG 2.2 AA report |
| P1 | Restore and failure-domain proof is unavailable | Witnessed backup restore, dependency-loss drill, RTO/RPO measurement, and corrective-action closure |

## Promotion gates

`baseline` requires all public sources to be measured, known critical public
assets to exist, critical routes and Spaces to be live, required web security
headers to be present with semantically fail-closed values, and no directly
observed `BROKEN` asset.

`production` additionally requires authenticated scope, private critical assets,
exact critical Space source/runtime alignment, independent asymmetric evidence,
zero active P0/P1 gaps, credential-backed deployment proof, browser/accessibility
evidence, and recovery evidence. The production profile is expected to fail
until those artifacts exist.

Deployment evidence covers the complete manifest-declared critical deployment
set, not one selected target. Each witness, browser packet, and restore packet
uses a signed evidence index keyed by the exact critical domain-route or Space
asset ID; missing or extra targets fail before artifact evaluation. Each witness
is an exact graph edge, not a status assertion. Its repository and deployment
asset IDs must exist in the signed audit; the repository must be operationally
`ACTIVE`; its source revision must equal the audited protected repository head;
and its HTTPS URL, canonical owner, environment, deployed artifact digest, and
nested deployment receipt must agree byte-for-byte with an independently
observed repository-to-deployment edge in the audit inventory. Missing,
unrelated, malformed, or internally inconsistent references fail the production
profile.
The receipt is not trusted because it says `VERIFIED`: its canonical bytes must
verify under a provider identity and RSA key pinned separately in
`deployment_provider_trusted_keys`.

Critical Hugging Face Spaces require `EXACT_RUNTIME_HEAD`, a GitHub-verified and
reachable exact source commit, a recomputed artifact-provenance `PASS`, and an
independent runtime-currency `CURRENT` result. Source-head equality without both
artifact and running-revision evidence is not promotable. The declared source
repository must belong to the canonical GitHub organization while its source,
default-branch, artifact, and runtime revisions all agree. A Space deployment
witness must name that same verified source repository and exact revision;
independently valid but divergent alignment and deployment edges fail closed.
Browser evidence binds the exact audited deployment revision, artifact digest,
receipt identity, and deployment time to named desktop and mobile runs, console/network,
keyboard, screen-reader, zoom, contrast, and WCAG 2.2 AA results plus a report
path whose loaded bytes must match the report digest. Recovery evidence uses a
typed machine measurement whose exact bytes are digest-bound inside a
provider-signed `szl.estate-restore-drill/v2` wrapper. The wrapper binds the
same deployment target, URL, revision, artifact digest, receipt, and environment
selected by the provider-authenticated witness. The measurement must prove a
read-only unchanged source database and SQLite sidecars, an ephemeral isolated
restore target, zero production writes, cleanup, schema/content/row
equivalence, integrity and foreign-key checks, structural receipt-chain
validity, and corrupt/missing backup rejection. Measured RTO and RPO must equal their recorded intervals and
stay below the manifest policy ceilings. Future or stale evidence, unknown
restore-provider keys, duplicate asset IDs, and minimal
status-only JSON fail closed. Audit completion is bounded against the verifier's
current time, so an internally consistent but expired signed packet cannot be
replayed. The production requirements object must contain every known gate with
literal Boolean `true`, except the alignment gate's exact nonempty state list.

## Execution order

1. Close DNS and exact source/runtime binding gaps without changing truth labels.
2. Reconcile repository, build, artifact, deployment, domain, telemetry, owner, risk, and cost into one evidence graph.
3. Apply organization-wide secure software factory controls through protected reusable workflows.
4. Run browser, API, accessibility, security, restore, and failure-domain tests against approved environments.
5. Generate the investor data-room index from immutable operating evidence.

No live broker authority, regulatory approval, multi-region availability, SOC 2
report, ISO certification, or production deployment is claimed by this document.
