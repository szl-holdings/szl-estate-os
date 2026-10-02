# Frontier Steward: operational boundary and runbook

The Steward is a Python proposal compiler in the existing Estate OS. It does
not replace a foundation model, train weights, qualify biological systems, or
gain authority by producing a convincing answer. It never merges code,
publishes a model, deploys a Space, changes DNS, or approves its own work.
Unsupported claims stay unsupported.

## Run it

Python 3.11+ and the standard library are sufficient. From the repository root:

```powershell
python SZL_ONE_OF_ONE_ESTATE_OS.py self-test
python -m unittest discover -s ci -p 'test*.py' -v
python SZL_ONE_OF_ONE_ESTATE_OS.py audit --deep
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-plan --provider deterministic
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-status
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-verify
python SZL_ONE_OF_ONE_ESTATE_OS.py serve
```

The live audit uses only credentials available in the process. Never paste a
token into a prompt, source file, command argument, public output, or model
context. A public or visibility-limited observation is not a complete private
estate audit. The dashboard is local at `http://127.0.0.1:8787` and includes
recorded Steward state and proposals. Its GET endpoints never mint plans or
receipts. Binding beyond loopback still requires the existing explicit opt-in
and control token.

Custom database/plan wiring is explicit:

```powershell
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-plan --provider deterministic --db outputs/custom.db --output outputs/custom-plan.json
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-status --db outputs/custom.db --plan outputs/custom-plan.json
python SZL_ONE_OF_ONE_ESTATE_OS.py serve --db outputs/custom.db --steward-plan outputs/custom-plan.json
```

Run an audit into that database first. Missing, naive, future-dated, or stale
audit times and invalid receipt chains prevent model planning. Partial audit
status also prevents model planning. A measured snapshot can still contain
failed controls, broken routes, or incomplete provider visibility; those
findings remain blockers, not a release approval.
The audit row must also match an actual `ESTATE_AUDIT` receipt in the verified
chain, including its ID, timestamp, status, counts, scope, and source reports.
A syntactically valid hash beside an empty chain cannot satisfy this gate.

## Daybreak access and isolation

The default provider is `responses`, selected model
`gpt-daybreak-blue-latest`. Configure `OPENAI_API_KEY` privately in the process
or deployment secret manager for an API project provisioned for Daybreak Blue,
then run:

```powershell
python SZL_ONE_OF_ONE_ESTATE_OS.py steward-plan --provider responses --model gpt-daybreak-blue-latest
```

This adapter sends one bounded request to the official Responses endpoint,
with no tools, no conversation storage, and a strict closed JSON schema. It
does not launch a workspace-reading agent, expose repository credentials, or
accept model-produced tool calls. HTTP redirects are rejected. Outbound input
is the prepared estate snapshot, which may contain private asset names; use
only an approved account/data-processing arrangement for that information.

Daybreak selection includes the explicit access-program request and requires
the response to confirm the requested program. No alternative model is
silently selected. Missing credentials, denied access, refused/incomplete
responses, schema errors, or provider errors become blocked/refused recorded
outcomes. Error bodies and credential values are not copied into plans.
An alias or provider-reported model name is not an independently pinned model
identity. `production_allowed` stays false; successful inference alone cannot
change that.

The optional CLI adapter requires both `--provider codex-cli` and
`--allow-local-agent`. It uses fresh temporary working/config directories and
an allowlisted child environment. This is a development diagnostic, not a
claim of hostile-code or secret-read isolation. Its sandbox is read-only, not
read-denied. Ambient CLI authentication/configuration is deliberately not
forwarded; access may therefore fail. Do not loosen these controls to make a
model invocation pass.

Official references: [Daybreak access](https://developers.openai.com/api/docs/guides/daybreak),
[structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs),
and [Responses migration/storage controls](https://developers.openai.com/api/docs/guides/migrate-to-responses).

## Evidence and failure recovery

Each plan has a closed envelope schema, immutable content digest, bounded
evidence snapshot, explicit model/access state, absorbing refusal policy,
release order, and eight distinct proof layers. Proposals require a hypothesis,
tests, success measures, stop conditions, and constrained effects. Neither
schema validity nor heuristic refusal matching is a complete semantic safety
proof. Human review and deterministic downstream release controls remain
required. Operational harmful biology, offensive malware, evidence
fabrication, credential theft, and safety/control bypasses are denied.

Each accepted proposal must cite the exact audit ID, audit receipt hash, and
bounded context digest captured in its plan. The validator rejects invented
handles and moving aliases such as `receipt:latest`, even if a plan's overall
content digest is recomputed. A deterministic draft built without eligible
evidence carries only `evidence:UNAVAILABLE` and remains `BLOCKED`. These
handles bind the draft to an observation; they do not independently establish
the truth of a proposal's hypothesis or an external provider's state. Older
plans containing unbound aliases remain historical artifacts and fail current
validation until regenerated from a fresh governed audit.

Writes follow this order:

1. Exclusively create and flush `outputs/steward-plans/<plan_id>.json`.
2. Acquire SQLite's immediate write transaction, verify the existing receipt
   chain, append a receipt binding the exact bytes/digest/paths/state, and commit.
3. Atomically publish the convenience latest-plan JSON.
4. Read back the recorded state against the immutable artifact and receipt.

A database failure cannot replace the previous latest projection. An orphan
immutable file is evidence of an incomplete write, not a recorded plan. A
publication failure after commit leaves a recoverable immutable artifact and
receipt. Concurrent writers serialize their chain append; an out-of-order
latest projection is labeled `STALE_PROJECTION`, not silently accepted as
latest. Readback hides proposals from blocked plans and whenever the bound
audit is superseded or stale, while retaining the plan status and receipt.
Unsigned receipts prove local byte/chain consistency, not external identity or
independent witness. Preserve outputs and the database for incident analysis;
do not erase retained failures to restore a green label.

## Public A11oy integration boundary

`steward-export-public --source-revision <exact-current-Git-SHA>` creates the
dedicated `outputs/steward-public.json` projection only from recorded,
receipt-bound deterministic observations whose GitHub and Hugging Face scope
is `PUBLIC_ONLY` and whose domain scope is `PUBLIC_NETWORK`. Authenticated,
partial, unknown, model-produced, and unrecorded inputs are refused. The
exporter compares its committed source bytes, retains an immutable artifact,
and commits an export receipt before publishing the convenience projection.

The standalone `steward_public.py` reader admits only the closed public schema,
exact source revision and exact-byte SHA-256. Freshness is limited to two hours
from the original audit, not the time of export; stale views hide proposals.
This is unsigned integrity evidence and never a production-readiness witness.
The manually dispatched observation workflow does not refresh the deployed
projection. Until an authenticated producer and sole canonical publisher can
deliver and read back a fresh bounded projection, an expired live endpoint is
expected to remain unavailable rather than extend its validity window.
Only this public projection and its pinned reader may be admitted into A11oy's
existing protected source and sole canonical publisher. The private database,
full plan, local dashboard, inventories, paths and credentials are not part of
that public deployment. Public requests neither export nor sign, invoke a
model, execute tools, or mutate state. Approved live inference is a separate
operator-controlled integration, not a public read side effect.

`steward-verify` checks only schema, digest, and internal policy. Use
`steward-status` for artifact/receipt/database binding. `PROPOSED` means a
valid proposal, not authorization or operational readiness. Exit codes are
0 for proposed, 3 for blocked, 4 for denied/invalid, and 1 for execution failure.

## Canonical release chain

Canonical Python source lives in `github:szl-holdings`. Changes must pass
exact-head CI, signed-commit verification, applicable protected review/merge
rules, and retained merge evidence. Do not force-push, self-approve, or bypass
required checks. A draft PR or local test pass is not a merged release.

Only after merge may a governed publisher map the immutable Git SHA and exact
file bytes to the approved `huggingface:SZLHOLDINGS` destination. Models,
datasets, kernels, and Spaces are different artifact types; metadata presence
or a RUNNING Space does not establish training, inference, data rights,
correctness, or qualification. Do not invent a destination or upload the
private estate snapshot as a dataset. Retain publication receipts and read back
exact revisions/file parity.

Then deploy/verify `a-11-oy.com` and `a11oy.net` against that release. Separately
retain source, exact-head CI, protected merge, provider publication, deployment,
application readiness, functional probe, and independent witness. Broken
routes and failed controls cannot be hidden by successful hosting or metadata.
The Steward carries this order in every plan but has no mutating transport.

## CI and scope

The normal Estate OS CI runs deterministic policy/provider/storage/API tests
without real credentials. The manually dispatched Steward observation workflow
collects a credential-free public audit and stores its deterministic plan and
receipts as workflow artifacts governed by repository access, retaining blocked status when scope
is limited. It performs no model call, publication, training, or deployment.
Do not describe these synthetic tests as live Daybreak inference or production
runtime evidence. The local generated dashboard inherits the inventory's
privacy; do not publish authenticated outputs.

Rollback removes the additive Steward module, tests, dashboard section,
commands, and dedicated workflow. There is no schema migration, model upload,
DNS change, or autonomous deployment to undo. Preserve recorded artifacts and
receipts even if the feature is disabled.
