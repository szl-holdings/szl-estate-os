# SZL One-of-One Estate OS

This turns the supplied `SZL_ONE_OF_ONE_ESTATE_OS` model into an operational,
dependency-free control plane. It inventories the live public estate, applies
evidence-aware scores, clusters probable duplicates, records gated fate
proposals, maintains SQLite history, emits hash-chained receipts, and serves a
local dashboard/API.

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
not prove complete organization scope. The report therefore uses
`AUTHENTICATED_VISIBILITY_UNKNOWN` unless completeness is independently
established.

## Commands

```text
self-test          Deterministic local checks; no network
audit              Live read-only GitHub, Hugging Face, and domain audit
status             Latest audit and receipt-chain status
export             Export the latest SQLite projection to JSON
verify-receipts    Verify payload hashes, chain links, and available signatures
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

Deep GitHub checks require a token and query default-branch protection plus the
repository community profile. Public mode intentionally does not burn the
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

## API

The local server exposes:

```text
GET /                         Embedded estate dashboard
GET /healthz                  Process health
GET /readyz                   Database and latest-audit readiness
GET /api/v1/status            Latest audit, source scopes, counts, receipt state
GET /api/v1/assets            Latest assets; filters: type, status, limit
GET /api/v1/proposals         Gated proposals; filters: status, limit
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

The scheduled `Estate readiness evidence` workflow performs a live audit,
checks the baseline contract, verifies the local receipt chain, and exercises
the read-only API under bounded concurrent load. Its JSON, Markdown, and stress
reports are retained as workflow artifacts rather than committed as mutable
snapshots.

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
