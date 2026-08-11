# Action Assurance in Estate OS

## Status

**Executable local contract and CI evidence lane.** This integration does not
claim that an external action was authorized, executed, cryptographically
signed, deployed, or independently certified merely because a JSON document
exists.

The implementation translates the useful parts of the supplied master payload
into the existing Estate OS control plane instead of introducing a second,
weaker estate crawler. Estate OS remains the source for live GitHub, Hugging
Face, domain, provenance, receipt-chain, and operating-fabric observations.
This lane adds a strict contract around an individual governed action.

## Counterfactual Action Passport

A passport records:

- **Identity** — agent, principal, session, and delegation chain.
- **Authority** — parent scopes, child scopes, tool, resource, and constraints.
- **Evidence** — exact ordered claims bound by `SHA3-256`.
- **Policy decision** — `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `THROTTLE`, or
  `WARN`.
- **Human oversight** — approval state and approval-receipt reference.
- **Counterfactual closure** — expected result if acted (`C1`) and if withheld
  (`C0`), recorded before the action request.
- **Action, outcome, and rollback** — attempted state, measured result, and
  compensating-action readiness.
- **Signature boundary** — `ECDSA-P256` / `SHA3-256` metadata with an exact
  signing-payload digest.

The Action Assurance package, principally
`estate/action_assurance_passport.py`, enforces cross-field invariants that
JSON Schema cannot express safely:

1. `child_scopes` must be a subset of `parent_scopes` unless the parent
   explicitly delegates `*`.
2. Counterfactuals must exist before `action.requested_at`.
3. `REQUIRE_APPROVAL` cannot execute without approval, and approval must precede
   execution.
4. `BLOCK` must produce a refusal, with a refusal outcome.
5. The evidence graph must bind the exact ordered claim list.
6. Action, outcome, rollback, and timestamp states must be mutually consistent.
7. The signing digest must bind the exact passport payload.

## Honest signature boundary

The dependency-free verifier deliberately supports only:

- `UNSIGNED`
- `SIGNED_UNVERIFIED`

It does **not** promote a signature to verified. The interoperability projection
contains:

- an unsigned DSSE envelope (`signatures: []`), and
- a proofless W3C Verifiable Credential-shaped document.

Those files are useful integration targets, not signed receipts. Production
promotion requires a separately reviewed signing/verifying component, trusted
key registry, canonicalization contract, key-rotation policy, and negative
forgery tests.

## External claim drift

`szl.external-claim-ledger/v1` replaces static marketing claims with an exact
local contract containing retrieval, last-verification, and next-review times.
The verifier performs no network requests. It fails when a claim is stale,
divergent, unavailable, malformed, or when its declared state disagrees with
the state derived from the review deadline.

The committed citation ledger is synthetic test data. It is not production
research and must not be copied into investor or compliance collateral.

## Trust Factor

The Trust Factor is a recency-weighted, per-agent summary derived only from
valid passports. It is always labeled `MODELED` and includes its sample size,
confidence proxy, event counts, and limitations. It is not:

- an identity credential,
- an authorization decision,
- a compliance certification,
- a substitute for the underlying passports, or
- permission to expand delegated authority.

Operator-supplied `trust_factor_delta` is preserved as passport metadata but is
not allowed to control the computed score.

## Local verification

From the repository root:

```bash
python -m py_compile \
  estate/action_assurance.py \
  estate/action_assurance_contract.py \
  estate/action_assurance_passport.py \
  estate/action_assurance_reporting.py \
  ci/verify_action_assurance.py \
  ci/test_action_assurance.py

python -m unittest discover \
  -s ci \
  -p 'test_action_assurance.py' \
  -v

python ci/verify_action_assurance.py
```

The verifier writes:

```text
outputs/action-assurance/verification-report.json
outputs/action-assurance/citation-drift-report.json
outputs/action-assurance/trust-factor-report.json
outputs/action-assurance/interop/<passport-id>.json
```

CI runs without application secrets or network-dependent claim verification.
The workflow uploads the evidence packet even when the verification job fails.

## Files

| Path | Purpose |
| --- | --- |
| `estate/action_assurance.py` | Stable public API facade. |
| `estate/action_assurance_contract.py` | Shared constants, deterministic JSON, digests, timestamps, and exact-shape helpers. |
| `estate/action_assurance_passport.py` | Passport semantic validator and unsigned interoperability projection. |
| `estate/action_assurance_reporting.py` | Claim drift evaluation, Trust Factor computation, and JSON loading. |
| `ci/verify_action_assurance.py` | Evidence-packet generator and fail-closed command-line gate. |
| `ci/test_action_assurance.py` | Adversarial tests for escalation, tampering, timing, approval, refusal, drift, and scoring. |
| `schemas/action-assurance/*.schema.json` | Strict structural schemas; semantic validation remains authoritative. |
| `fixtures/action_assurance/` | Synthetic execution, refusal, and citation fixtures. |
| `.github/workflows/action-assurance.yml` | Pull-request and main-branch verification workflow. |

## Production wiring sequence

1. Emit passports from the real policy gate before and after each governed
   action; do not reconstruct counterfactuals after execution.
2. Resolve `source_refs` to immutable Estate OS evidence and bind the retrieved
   bytes, not editorial labels.
3. Add an isolated signer/verifier behind managed key custody. Keep signing
   authority outside application code and reject unknown or retired keys.
4. Bind DSSE and W3C VC artifacts to the exact passport payload and verify them
   independently before any `VERIFIED` label is permitted.
5. Replace synthetic citation fixtures with a separately re-verified claim
   ledger and retain source snapshots where licensing permits.
6. Expose Trust Factor in the dashboard only with its `MODELED` label, sample
   size, and underlying event links visible.
7. Add live API/dashboard routes only after the storage, migration, access
   control, retention, and receipt-chain contracts are reviewed together.

## Non-goals of this change

- No GitHub merge, repository archive, Hugging Face mutation, DNS change, or
  production deployment is authorized by a passport fixture.
- No ECDSA key is generated or read.
- No external source is declared current because CI can reach a URL.
- No claim is upgraded from `MODELED` or `REPORTED` to `VERIFIED` automatically.
- No Trust Factor result overrides the non-increasing authority lattice.
