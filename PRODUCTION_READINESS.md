# SZL estate production readiness

Status: `PARTIAL`  
Control-plane mode: `READ_ONLY`  
Evidence date: `2026-08-01`

## Measured baseline

The local exact-main checkout at `f51aab466e7856b8145184d1b9bde702bb01fdca`
completed the deterministic Estate OS suite and a live deep public audit.

| Evidence | Observed result |
|---|---|
| Deterministic checks | 13 passed before this hardening wave |
| GitHub | 59 public organization assets; privileged/private scope unavailable |
| Hugging Face | 81 public assets: 16 models, 27 datasets, 26 Spaces, 12 collections |
| Domains | 26 routes across `a-11-oy.com` and `a11oy.net`; 0 broken |
| Estate total | 166 assets, 25 duplicate clusters, 152 gated proposals |
| Receipts | Chain valid, unsigned |
| Hugging Face alignment | 48 `MANAGED_UNBOUND`, 14 `SOURCE_HEAD_UNAVAILABLE`, 7 `RUNTIME_SOURCE_UNRESOLVED` |

The first 1,000-request local stress profile at concurrency 32 observed 929
HTTP 200 responses and 71 connection refusals. The service remained ready after
the run. That result is a measured pre-hardening failure, not a production
capacity claim; this wave increases the HTTP accept backlog and turns the same
profile into a repeatable CI gate.

## Production blockers

| Priority | Blocker | Required closure evidence |
|---|---|---|
| P0 | Authenticated estate completeness is not established | Authorized inventory proving organization scope and reconciling all private/protected assets |
| P0 | Hugging Face source/runtime binding is unresolved | Immutable GitHub revision and running Space revision match for every critical Space |
| P0 | Credential-backed deployments are not mapped estate-wide | Repo, reviewed commit, artifact digest, environment, URL, owner, and deployment receipt graph |
| P1 | `www.a-11-oy.com` did not resolve in the bounded DNS probe | Correct DNS, redirect/canonical behavior, TLS, and post-change probe |
| P1 | Audit receipt is unsigned and local HMAC is not independent authority | Approved asymmetric signer, key ID, rotation/revocation, detached verification, and independent witness |
| P1 | Browser evidence is unavailable | Desktop/mobile interaction, console/network, keyboard, screen-reader, zoom, contrast, and WCAG 2.2 AA report |
| P1 | Restore and failure-domain proof is unavailable | Witnessed backup restore, dependency-loss drill, RTO/RPO measurement, and corrective-action closure |

## Promotion gates

`baseline` requires all public sources to be measured, known critical public
assets to exist, critical routes and Spaces to be live, required web security
headers to be present, and no directly observed `BROKEN` asset.

`production` additionally requires authenticated scope, private critical assets,
exact critical Space source/runtime alignment, independent asymmetric evidence,
zero active P0/P1 gaps, credential-backed deployment proof, browser/accessibility
evidence, and recovery evidence. The production profile is expected to fail
until those artifacts exist.

## Execution order

1. Close DNS and exact source/runtime binding gaps without changing truth labels.
2. Reconcile repository, build, artifact, deployment, domain, telemetry, owner, risk, and cost into one evidence graph.
3. Apply organization-wide secure software factory controls through protected reusable workflows.
4. Run browser, API, accessibility, security, restore, and failure-domain tests against approved environments.
5. Generate the investor data-room index from immutable operating evidence.

No live broker authority, regulatory approval, multi-region availability, SOC 2
report, ISO certification, or production deployment is claimed by this document.
