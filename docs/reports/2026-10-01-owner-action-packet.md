# Dead-man effect onboarding and current source readback

Read-only packet prepared October 1, 2026, approximately 21:40 EDT. No repository source, protection setting, provider state, secret, PR comment or review was changed by this lane. Proposed review tasks are not authorization or a deployable policy patch.

## Current facts replace the September 30 holds

| Previously held item | Fresh provider result | Qualification retained |
|---|---|---|
| `.github#799` | Merged September 30 at 17:45:07 EDT; head `26adc09175aedff9ea774fa9632d0f67f6003b01`; merge `5d24867411f01142cf0b9773460fcffebf0d0dd9` | Historical candidate has 25 SUCCESS, 3 SKIPPED and 1 FAILURE. The failure remains the effect gate. This lane did not merge it and does not infer how the provider admitted it. |
| `.github#785` | Merged September 30 at 21:44:16 EDT; head `5212fd8eda60f64ab22fa79e756d507c524a8f2d`; merge `b18cc89d46eb54e15d45b66d3b9b6145e8875bc9` | Historical candidate has 24 SUCCESS, 3 SKIPPED and 1 FAILURE. It adds a candidate recount only. Immutable current `.github/data/lean_numbers.json` still locks `749 declarations / 14 unique axioms @ c7c0ba17`. |
| `nexus#46` | Merged September 30 at 16:40:24 EDT; head `1e0cc4369bef861af7033981a05aff2b9601723b`; merge `4a400d07fe9b27bb00b58394b30f6a26e0216513` | Six successful candidate checks. The unchanged PR body explicitly says `AUTH_RUNTIME_UNQUALIFIED`; merging does not supply broker callbacks, real account/session probes, schema evidence or publication evidence. |
| `platform#865` | Merged September 30 at 16:07:07 EDT; final head `d808b1a23b51dc97343e73e86606ea10e293c4a4`; merge `3d3b0a29ba2388e3324aefa647c77d9f657c25d2` | Final reported candidate has 49 SUCCESS and 2 SKIPPED, including actual hosted Typecheck, Runtime Audit, frozen lock integrity and blocking security checks. Earlier candidate/local results are not substituted for this head. No deployment claim. |

These are PR-head check results, not a claim that every current-main workflow is green. Complete readbacks retain timestamps, heads, bodies, reviews and checks. All four returned no latest reviews and no comments at capture; that does not establish the absence of other approval or merge evidence.

The fresh `.github` main snapshot is `55455ddf685c755084b73d50506e974a2a8d674b`, with GitHub verification `verified=true`, `reason=valid`. Classic branch protection returns 404 `Branch not protected`; active rulesets are present. Active `forge9-main` ruleset 19755620 requires eight `gate/*` contexts and `deploy/staging`, signed commits, PRs, linear history and merge queue. Its required-status list does not include `Static control-plane effect boundary`. An active organization integrity ruleset is also listed. The effective full union was not inferred from this one ruleset; no merge bypass is asserted and no protection setting was changed.

## Dead-man source repair is running; estate health is still red

Actual scheduled run [36948748135](https://github.com/szl-holdings/.github/actions/runs/36948748135), October 1 at 20:59–21:01 EDT, ran at the immutable current-main snapshot above. Contract reproof, restricted QILLQAQ observer mint, observation, receipt upload and incident reconciliation succeeded. The final health requirement failed correctly.

Downloaded provider artifact `estate-deadman-36948748135-1` contains an actual terminal receipt. Its exact file SHA-256 is `6011ba80dce28abee1332e480a782f893f473033282296360396d6fff79d5da6`, matching the retained sidecar. Its policy digest matches the immutable governance policy bytes. The receipt reports two samples, `controller_tip_reverified=true`, `CONFIRMED_FAILURE`, 1/3 healthy targets and incident 684 successfully refreshed. No synthetic runtime execution was used to create this receipt.

| Target | Actual source of failure or success | Remaining task |
|---|---|---|
| Autonomic public-estate SRE | Successful run 36948629753, inside the receipt's 30-minute freshness budget | Retain successful evidence; no repair inferred. |
| Scheduled estate census | Run 36908047896 fails `github-reader source=DOCS_AUTOMATION_TEAM_READ_TOKEN state=REJECTED reason=HTTP_401` | Owner supplies a valid, least-privilege organization census reader with the required private inventory scope through the existing credential binding. Validate identity/scope without printing values; let an actual scheduled run produce a complete authoritative census receipt. No broader token fallback, fake inventory or waived completeness. |
| Public estate live witness | Run 36909923230's downloaded report is `complete=false`; Lyte expected default tip `e5c0c7f4bc796d6bf38510058658de42321c4fe7`, observed `02064f9aa2135c4d8f764d623bc203a0c871c68b` | Reconcile Lyte's canonical protected source and central immutable publication path, then obtain a fresh actual witness receipt. This is that run's observation, not a fresh claim that Lyte still differs now. |

## Concrete effect inventory for owner review

The current policy still has no declaration for either dead-man workflow. Historical effect receipt at PR799 preserved `WORKFLOW_DECLARATION_MISSING` and `UNBOUND_EXECUTABLE_CHANGE`. Re-running the current analyzer's source functions on immutable current bytes also finds hard, non-reviewable limitations:

- Both workflows: `CHECKOUT_SOURCE_BOUNDARY_UNSUPPORTED` on explicit `${{ github.sha }}` checkout; `ACTION_RESOURCE_OVERRIDE_UNSUPPORTED` on their distinct artifact names.
- Scheduled workflow: `UNCLASSIFIED_EXTERNAL_ACTION` for exact `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`; `bind_declaration` unconditionally denies `issues:write` as `GITHUB_WRITE_PERMISSION_PRESENT`.
- Python/shell source also has enumerated reviewed-source unknowns. `snapshot-analysis.json` retains every actual unknown and location. No blanket unknown acceptance is proposed.

Consequently, adding JSON declarations or populating `reviewed_unknowns` cannot qualify the present workflows. Keep the existing denied result honest until a separately owned trust-root review determines whether to support these exact semantics. No gate, policy, gate test or Lean script was edited in this lane.

| Effect | Exact resource/scope | Proposed review `max_calls` per workflow attempt | Meaning and limit |
|---|---|---:|---|
| Runner guard configuration | `runner:guard:egress` | 1 each workflow | One pinned action invocation; telemetry/network details need the action review. |
| Checkout | Contents of `szl-holdings/.github` at exact scheduled/change revision | 1 each workflow | One action invocation. Contract workflow also admits PR and merge-group events; review fork/current-event boundaries explicitly. |
| Python setup | `runner:toolchain:python`, version 3.12 | 1 each workflow | One pinned action invocation; no claim of one HTTP request. |
| Artifact publication | Contract `estate-deadman-contract-<run>-<attempt>`; scheduled `estate-deadman-<run>-<attempt>` | 1 each workflow | One upload action invocation. Scope requires exact run/attempt/name binding. Chunk upload/finalization HTTP calls are not currently budgeted by the gate. |
| Read-only observer token mint/revoke | Existing QILLQAQ App, exactly `.github`, `szl-org-health`, `a11oy`; actions/contents read | 1 mint invocation and 1 cleanup invocation | Review the exact pinned third-party action and its internal endpoint/request bounds before classifying. `QILLQAQ_PRIVATE_KEY`, `QILLQAQ_CLIENT_ID` and generated tokens are names/bindings, not recorded values. |
| Target metadata reads | Each of three exact policy workflow identities: workflow definition, scheduled run list (`per_page=20`), workflow-changing commit (`per_page=1`) | 2 per endpoint/target; 18 GETs total | At most two samples, three requests per target per sample. Errors shorten the path; there is no request retry loop. |
| Controller authority reads | `.github/main` verified branch tip | 4 GETs | Initial, post-observation, before comment and before close; other paths use fewer. Any revision drift stops the mutation. |
| Incident discovery | `.github` open issues matching the exact reserved title, Actions bot and valid marker | 1 GET | One search, `per_page=100`; truncated/incomplete results reject. |
| Authenticate prior marker | `.github` scheduled dead-man run/attempt from the exact validated marker | 1 on a successful unique-incident path; 100 exhaustive denial-path envelope | Current code authenticates matching rows before rejecting multiple matches. An owner may propose detecting duplicates before authentication in a separate source repair, with meaningful regression evidence; a budget of 1 is not currently true of all denial paths. |
| Incident creation | One `.github` issue with exact reserved title/current run marker | 1 POST | Used only for confirmed failure when no valid current incident exists. |
| Incident refresh or close | That one structurally validated `.github` incident | 1 PATCH | Refresh current evidence on confirmed failure, or close only after healthy evidence and a second authority check. |
| Recovery comment | That same validated incident | 1 POST | Healthy recovery path only. Combined incident-write maximum is 2, not 3: create, refresh and close branches are exclusive. |
| Incident readback | Same issue number/title/body/state | 1 GET | Readback follows creation/refresh/close and rejects drift. |

The source-derived controller successful-path envelope is at most 25 GETs and 2 incident writes. A duplicate-search denial path can authenticate up to 100 matching markers before refusing all incident writes; its conservative controller-read envelope is 121 GETs. These are source-review bounds for the current fixed policy, not enforced CP-eBOM runtime budgets and not bounds on third-party action internals. No publication/write budget is falsely set to zero for the contract workflow: it uploads an artifact.

## Bounded owner review tasks

1. Keep the runtime failure and exact receipts intact. Remediate the census credential binding and qualify Lyte publication using their existing owner lanes. The dead-man remains red until both targets pass their actual scheduled contracts.
2. Choose the owner-maintained effect onboarding scope: offline contract first, or separately scoped live observer/incident lifecycle. Pin both workflow bytes, controller, validator, tests and policy. Do not place ordinary dead-man Python in `trusted_transitives`, whose current schema admits only the fixed gate and its tests.
3. If the owner chooses to extend the trust root, review exact changes supporting event-bound checkout, run-bound artifact identity, the pinned read-only App action and the one-incident write grammar. Test wrong repository/title/bot/marker, duplicate incidents, budget excess, unbounded resource/input, new action SHA, changed dependency bytes, expired intent and authority drift. No wildcard resources, broader secrets, write-all permissions or blanket unknown list.
4. Keep the trust-root proposal separate from ordinary executable changes so unrelated DENY is not laundered into `REVIEW_REQUIRED`. Capture exact reviewed head/digests and the actual transition verdict; the candidate must not certify its own authority.
5. After a reviewed root is on the governed base, obtain an ordinary exact-head analysis and retained hosted receipt, then a real provider-scheduled runtime receipt. Static boundary, merge admission, observation, incident effect and health are separate qualifications.

No approval, independent witness, all-green current main, deployment, auth activation or estate closure is inferred from this packet.
