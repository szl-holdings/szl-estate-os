# SZL One-of-One Estate OS

This turns the supplied `SZL_ONE_OF_ONE_ESTATE_OS` model into an operational,
dependency-free control plane. It inventories the live public estate, applies
evidence-aware scores, clusters probable duplicates, records gated fate
proposals, maintains SQLite history, emits hash-chained receipts, and serves a
local dashboard/API.

Each audit also runs the One-of-One Operating Fabric: an evidence-bound
defensive control evaluation across cybersecurity, product, engineering,
data/AI, operations, people, and governance. It persists lane assessments,
control findings, and a prioritized action queue. Every action is
`PROPOSE_ONLY`, requires approval, and contains no exploit or autonomous
mutation path.

The implementation is deliberately read-only. It does not archive repositories,
merge assets, alter branch protections, modify Hugging Face resources, update
DNS, or deploy domains. Those are high-risk governance actions; this system
creates measured proposals for them instead of treating strategy as approval.

## Quick start

From this directory:

```powershell
$python = "C:\Users\steph\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py self-test
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py audit
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py operating-report
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py serve
```

Open `http://127.0.0.1:8787`.

The default data files are:

- `.\outputs\estate.db`
- `.\outputs\latest_audit.json`

## Credentials and scope

No credential is required for a public audit. Without credentials, private or
protected inventory is labeled `UNAVAILABLE`, not counted as zero.

Set credentials in the local process environment when deeper access is needed:

```powershell
$env:GH_TOKEN = "<fine-grained GitHub token>"
$env:HF_TOKEN = "<Hugging Face token>"
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py audit --deep
```

Do not place tokens in this repository or pass them as command-line arguments.
The program reads:

- `GH_TOKEN` or `GITHUB_TOKEN`
- `HF_TOKEN` or `HUGGING_FACE_HUB_TOKEN`
- `SZL_RECEIPT_SIGNING_KEY` for HMAC-authenticated receipts
- `SZL_CONTROL_TOKEN` when explicitly serving beyond loopback

An authenticated inventory can see more assets, but token presence alone does
not prove complete organization scope. `AUTHENTICATED_COMPLETE` is emitted only
when the API-reported public and private repository totals each exactly
reconcile with the observed visibility composition of one stable, fully
exhausted, unique inventory and collection reports no error.
Count mismatches, pagination uncertainty, or partial visibility remain
`PARTIAL` with `AUTHENTICATED_VISIBILITY_UNKNOWN`. The scheduled public baseline
deliberately supplies no GitHub or Hugging Face credential; authenticated
production inventory requires a separately approved evidence packet.

## Commands

```text
self-test          Deterministic local checks; no network
audit              Live read-only GitHub, Hugging Face, and domain audit
status             Latest audit and receipt-chain status
export             Export the latest SQLite projection to JSON
verify-receipts    Verify payload hashes, chain links, and available signatures
operating-report   Seven-lane controls, evidence, blockers, and action queue
evidence-template  Template for current external-only control evidence
serve              Dashboard, JSON API, health, readiness, and metrics
```

Useful audit options:

```powershell
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py audit `
  --github-org szl-holdings `
  --hf-org SZLHOLDINGS `
  --domain a-11-oy.com `
  --domain a11oy.net `
  --deep `
  --timeout 15
```

### Seven-lane operating fabric

The fabric evaluates controls from the same observed audit snapshot. Examples
include organization MFA, repository secret scanning and branch protection,
web security headers, live customer trust routes, Hub-to-source provenance,
source availability, proposal gating, and receipt integrity. Lane scores never
convert missing evidence into a pass. `readiness_to_claim_fully_operational`
stays `BLOCKED` until every critical control is directly measured and passing.

Filter the latest projection without rerunning the network audit:

```powershell
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py operating-report --lane cybersecurity
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py operating-report --state FAIL `
  --output .\outputs\failed-controls.json
```

Restore drills, security training, and on-call ownership cannot be inferred
from repository or website metadata. Generate a bounded evidence template,
replace its examples with real references and current expiry times, then admit
it during an audit:

```powershell
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py evidence-template `
  --output .\outputs\operating-evidence.json
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py audit --deep `
  --evidence .\outputs\operating-evidence.json
```

The isolated SQLite restore runner is a raw measurement producer, not a
promotion authority. It opens the source database read-only with `query_only`,
restores only inside a fresh temporary directory, verifies integrity, schema,
content, row counts, foreign keys, receipt-chain structure, corrupt/missing
backup rejection, preserves the main database plus any WAL, SHM, and journal
sidecars byte-for-byte, rejects report-output aliases to those source files,
and verifies cleanup before emitting an unsigned
`szl.sqlite-restore-measurement/v2` measurement:

```powershell
& $python .\ci\run_restore_drill.py `
  --database .\outputs\estate.db `
  --output .\outputs\restore-measurement.json `
  --max-rto-seconds 900 `
  --max-rpo-seconds 300
```

That file cannot satisfy production by itself. An approved provider must bind
its exact digest and the promoted deployment into a signed
`szl.estate-restore-drill/v2` wrapper. The production evidence index must then
cover every manifest-critical deployment, and the verifier must recognize the
provider key from `restore_provider_trusted_keys`. The committed manifest keeps
that key map empty, so promotion deliberately remains blocked.

External assertions are labeled `ATTESTED`, not `MEASURED`, and therefore do
not make a lane green by themselves. Only the three external-only control IDs
are accepted; the evidence bundle cannot override directly observed cyber,
product, engineering, data/AI, or governance findings.

Repository governance is evaluated from directly observed applicable rules.
A protected default branch passes the minimum rule only when non-fast-forward
updates are blocked, pull requests are required, at least one approval is
required, review-thread resolution is required, and a nonempty set of status
checks is enforced. A web-commit signoff setting is reported separately and
cannot satisfy the full change-signoff control unless signed-commit enforcement
is also measured. Control output lists the exact failed and unassessed asset IDs
instead of collapsing missing coverage into a single Boolean.

Deep GitHub checks require a token and query default-branch protection plus the
repository community profile. They also retrieve the exact default-branch Git
commit and preserve GitHub's signature-verification result as a separate commit
fact; reachability, SHA syntax, and runtime equality alone never count as a
verified artifact. Public mode intentionally does not burn the
unauthenticated rate limit pretending to have privileged governance evidence.
Deep Hugging Face checks query every Space detail endpoint and record its exact
revision, runtime stage, hardware request, and served-domain state. A sleeping
Space is `UNAVAILABLE`, a running Space is `LIVE`, and a build/runtime/config
error is `BROKEN`; a published card alone is only `OBSERVED`.

Deep mode also queries exact model, dataset, and Space revisions and reads only
the supported source-binding documents present at those immutable revisions:
`hf-deploy-manifest.json`, `SPACE_PROVENANCE.json`, and
`DATASET_PROVENANCE.json`, `SZL_ESTATE_MANAGED.json`, plus the
repository-owned publication contracts
`a11oy-metadata.json`, `publication.json`, and `publication-manifest.json`.
Management markers remain management-only and cannot establish artifact
equivalence. Each Hub repository receives a
`metadata.github_alignment` result. `EXACT_HEAD` requires an exact 40-character
source revision that equals the GitHub repository's observed default-branch
revision. `PINNED_NON_HEAD`, `REPOSITORY_ONLY`, `MANAGED_UNBOUND`,
`NOT_DECLARED`, conflicts, and unavailable evidence remain distinct; a managed
marker alone is never treated as source alignment.

`estate/provenance_policy.py` provides the dependency-free decision boundary
for immutable artifact provenance versus live runtime currency. An artifact
source revision passes only when separately retrieved commit evidence marks the
exact 40-character SHA `VERIFIED_REACHABLE`; a syntactically valid or merely
reachable SHA is insufficient. A verified historical artifact can remain valid
as `PINNED_NON_HEAD` while runtime currency is evaluated independently, and a
current runtime observation can never manufacture missing artifact provenance.

For running non-static Spaces, deep mode also attempts the conventional
same-host read-only `/api/build-info` route on a Hugging Face-provided
`*.hf.space` domain. `EXACT_RUNTIME_HEAD` requires `build.state=OBSERVED` and an
exact runtime revision that uniquely equals one observed GitHub default-branch
revision. The audit never infers a repository from a service name, and it keeps
`receipt_minted` separate from source alignment.

The conventional read-only `/.well-known/szl-source.json` route is also
inspected on running Spaces. Unsigned structural declarations and explicit
reference relationships are reported as `SOURCE_REFERENCE_ONLY`; they are
never promoted to source parity or a reproducible-build claim.

When no supported JSON provenance document exists, one strict card fallback is
allowed: `README.md` must contain exactly one SZL Holdings GitHub repository and
exactly one 40-character Git revision. Cards with multiple repositories or
revisions remain unbound rather than relying on editorial guesswork.

Domain audits start from the configured root and discover a bounded set of
same-origin navigation routes from the live HTML. Fragments collapse to their
real server path, static assets are excluded, and discovery failures fall back
to the declared root. This keeps route evidence aligned with the deployed site
instead of treating retired, guessed paths as current contracts.

The audit preserves raw required security-header values as well as presence.
Web hardening fails closed on a wildcard or unsafe-script CSP, a short or zero
HSTS max-age, non-`nosniff` content-type policy, or a leaking referrer policy.
Unsafe sources are checked independently in `script-src`, `script-src-elem`,
and `script-src-attr`; header names alone cannot turn the control green.

## API

The local server exposes:

```text
GET /                         Embedded estate dashboard
GET /healthz                  Process health
GET /readyz                   Database and latest-audit readiness
GET /api/v1/status            Latest audit, source scopes, counts, receipt state
GET /api/v1/assets            Latest assets; filters: type, status, limit
GET /api/v1/proposals         Gated proposals; filters: status, limit
GET /api/v1/operating-fabric  Lanes, controls, and proposal-only action queue;
                              filters: lane, state
GET /api/v1/receipts          Receipt metadata and chain verification
GET /metrics                  Prometheus text exposition
```

Loopback is the safe default. A non-loopback bind requires both
`--allow-remote` and `SZL_CONTROL_TOKEN`; read-only API requests then require
`Authorization: Bearer <token>`.

## Truth model

- `MEASURED`: retrieved and evaluated during the audit.
- `PARTIAL`: useful evidence was retrieved, but at least one source or scope is
  incomplete.
- `ATTESTED`: a current operator assertion was admitted with source, reference,
  owner, expiry, and bundle hash; it was not directly measured by Estate OS.
- `OBSERVED`: the asset exists in a live inventory, but runtime availability was
  not proved.
- `LIVE`: the specific route or runtime state was directly observed live.
- `MODELED`: placeholder, thin, or not yet operational content.
- `BROKEN`: the probe directly observed a failed state.
- `UNAVAILABLE`: access or runtime evidence could not be retrieved.
- `ARCHIVED`: the source reports that the asset is archived.

Scores are nullable. Missing branch protection, security, governance, or card
evidence remains `UNAVAILABLE`; it is never silently converted to a failing or
passing score.

## Receipts

Every audit writes a canonical payload hash and links it to the prior receipt.
Without `SZL_RECEIPT_SIGNING_KEY`, the chain can detect local modification but
is reported as `CHAIN_VALID_UNSIGNED`, not cryptographically verified.

With a signing key set before the first audit:

```powershell
$env:SZL_RECEIPT_SIGNING_KEY = "<locally managed high-entropy key>"
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py audit
& $python .\SZL_ONE_OF_ONE_ESTATE_OS.py verify-receipts
```

The same key is required to verify HMAC signatures later. Use an approved local
secret store for durable operation.

## Operational boundary

This is the audit, score, replay, proposal, and evidence layer. Estate-wide
mutation still requires:

- Exact authenticated inventory and authorized organization scope
- An approved canonical repository/product map
- Independent review for high-risk merge/archive/kill proposals
- Protected normal merges for code changes
- Deployment acknowledgements and post-change probes
- Signed receipts if cryptographic authenticity is required

The current source contracts follow the official
[GitHub organization repository API](https://docs.github.com/en/rest/repos/repos#list-organization-repositories),
[GitHub branch API](https://docs.github.com/en/rest/branches/branches),
and [Hugging Face Hub API](https://huggingface.co/docs/hub/en/api).

## Continuous readiness

The critical-surface contract lives in `estate/manifest.json`. It separates
public baseline evidence from authenticated and production evidence so a public
scan cannot silently become a production claim.

The scheduled `Estate readiness evidence` workflow performs deterministic
checks, a live audit, baseline verification, receipt-chain verification, and a
bounded read-only API stress profile as independent steps. A final aggregate
gate fails if any step fails, while the evidence packet is still uploaded for
diagnosis. Production evidence additionally requires provider-authenticated
deployment receipts, exact report-file digests, canonical source ownership,
an explicit `szl.estate-audit/v1` payload, exact `ASYMMETRIC_VERIFIED` signature
state plus RSA verification, fresh source/critical-asset observations, and
restore results within manifest RTO/RPO ceilings. Production also requires an
exact `MEASURED` aggregate audit status and observations captured inside the
recorded audit interval. Signed
evidence indexes must cover every manifest-critical domain route and Space for
the witness, browser, and restore gates; a single selected deployment cannot
certify the estate. `production_deployment_sources` binds each target to its
expected critical GitHub repository; `null` keeps an unresolved source
explicitly unpromotable. Browser and recovery report bytes use typed schemas and
must repeat the wrapper bindings exactly. Recovery RTO is measured from failure
onset to service restoration, while RPO is measured from the durable recovery
point to failure onset. Its JSON, Markdown, and stress reports are retained as
workflow artifacts rather than committed as mutable snapshots.

Run the same gates locally after an audit:

```powershell
& $python .\ci\verify_estate_readiness.py `
  --audit .\outputs\latest_audit.json `
  --manifest .\estate\manifest.json `
  --profile baseline

& $python .\ci\stress_estate_os.py `
  --database .\outputs\estate.db `
  --requests 1000 `
  --concurrency 32 `
  --max-error-rate 0 `
  --max-p95-ms 2500
```

`--profile production` intentionally fails closed until authenticated inventory,
exact Hugging Face source/runtime binding, signed independent evidence, and all
active critical gaps in the manifest are closed. See `PRODUCTION_READINESS.md`.
