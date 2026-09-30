# Hatun bounded source review: batch 2

48 pinned paths: **47 byte-complete / 1 withheld**; static review **28 COMPLETE / 18 PARTIAL / 2 SKIPPED**. Candidate runtime **NOT_RUN**; Phase 2 and estate readiness remain false. No candidate source was changed or executed.

## 1. Authority and stack

Reports-only draft on `codex/estate-hatun-source-batch2`, based on draft 54 / `codex/estate-content-review-batch1` at `5352659a023c20a34eacdb48e168064ea571e836`. GitHub szl-holdings remains source of truth. Existing source owners retain repairs; the queue owner retains merges. The truncated operator is outside this batch.

## 2. Scope and evidence

Reviewed public `szl-holdings/hatun-mcp` at `482edd750f3354569ed417a5f443c43a1271ac91`. Published proposal and normalized execution-plan hashes are separate input roles in `evidence.json`. Collection completed 2026-09-30T12:04:06+00:00: 55 API GETs, 5 nonrecursive tree reads, 48 blob fetches and 354,807 bytes. Selected canonical tree membership, regular file modes, blob size, Git-framed SHA1 and original SHA256 were checked before bounded screening. The visibility endpoint returned HTTP 200 at 12:03:44 UTC. These observations establish only this read scope.

## 3. Coverage and explicit unknowns

Historical baseline 603 + 47 new unique byte-covered paths = **650 / 32,748**; **32,098 remain unread/skipped**. There is no overlap with the prior 64 records. The historical denominator covers 130 repositories, 120 public and 10 private at its dated snapshot. This is frozen coverage, not a current estate census.

7,960 cached lines include blanks; 37 privacy-filtered lines and 368 operational-scope lines are unavailable to semantic review, leaving 7,555 eligible unmasked lines. COMPLETE means available selected static text was reviewed, not that its assertions passed. `.gitleaks.toml` was withheld by the scanner; this is not proof of an actual key. H2-008 is byte-accounted but entirely SKIPPED for operational scope. Five shared source/test files also have operational exclusions. Original acquisition evidence remains immutable and earns no extra credit from rescreening.

## 4. Findings and proposed owner handoff

25 pinned findings below. Facts describe visible source; consequences are inferences and regression tests are proposals, all **NOT_RUN**. Repairs are **NOT_ATTEMPTED**; owner routing is **PROPOSED_NOT_ASSIGNED**. The narrow default-branch read at 2026-09-30T12:38:35.602205+00:00 observed `482edd750f3354569ed417a5f443c43a1271ac91`; its JSON-only CLI did not expose an HTTP status, so that remains UNKNOWN. Every repair still requires a fresh exact-head/blob check.

### H2-CORE-001: Default local BLS derivation does not establish independent signer identity

HIGH / FACT; [pinned source hatun_mcp/dsse.py:113-128](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/dsse.py#L113-L128).

Without an explicitly provided or environment-provided seed, the aggregator uses a fixed source default. It deterministically derives each organ key pair from that seed and organ name. Verification reconstructs the same local keys. The optional BLS implementation can provide genuine signature mathematics, but no independent external signer ownership or trust binding is established by this derivation.

Consequence (INFERENCE): A successful local aggregate round trip could be misinterpreted as independent organ attestation if a consumer promotes cryptographic validity into identity or release authority. Current operational quorum remains explicitly false elsewhere in the reviewed source.

Proposed acceptance (NOT_RUN): Use two isolated default aggregator instances and synthetic organ labels to demonstrate identical public identities. Assert that this local round trip cannot establish independent-attestation or release-authorization status without separately verified external trust evidence. Do not print seed, scalar or private-key values.

### H2-CORE-002: Unknown signer mode can produce READY state

MEDIUM / FACT; [pinned source hatun_mcp/state.py:186-210](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/state.py#L186-L210).

Signer readiness is defined by mode differing from the placeholder label. The missing-mode default and other unrecognized modes therefore satisfy signer readiness when local chain verification succeeds. The signed flag separately requires the recognized ECDSA mode, so readiness and demonstrated signing can disagree.

Consequence (INFERENCE): A process-observed READY label can exceed the available signer evidence and should not be treated as demonstrated signing or release readiness.

Proposed acceptance (NOT_RUN): Construct synthetic state dependencies with a valid local chain and a signer with no mode, an unrecognized mode, and a placeholder mode. Require each to retain explicit unknown or unavailable signer readiness and prevent a READY conclusion from absent evidence.

### H2-CORE-003: New receipt declares chain verified without validating its existing prefix

HIGH / FACT; [pinned source hatun_mcp/governance.py:260-281](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/governance.py#L260-L281).

Emission hashes and signs a new packet, sets its chain_verified field true unconditionally, appends it and updates the head. It does not call prefix verification before making that assertion. The separate verifier can detect prior receipt tampering, and a supplied test definition asserts such detection.

Consequence (INFERENCE): After a prefix becomes invalid, a subsequent receipt can carry a positive integrity assertion while full local chain verification is false. This assertion is also distinct from DSSE signature verification.

Proposed acceptance (NOT_RUN): Create a synthetic local chain, modify an earlier receipt detail, then request another local receipt. Assert that the result cannot declare the entire chain verified when prefix verification fails. Keep signature validity, hash continuity and authorization assertions separate.

### H2-CORE-004: Caller and returned dictionaries can mutate stored receipt evidence

MEDIUM / FACT; [pinned source hatun_mcp/governance.py:257-277](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/governance.py#L257-L277).

Emission retains the caller's detail dictionary in the packet and stored receipt. Receipt serialization is shallow, and recent returns those shallow dictionaries. Nested detail and DSSE structures can therefore remain shared with mutable caller or returned objects after hashing.

Consequence (INFERENCE): Evidence presented as append-only can change after emission through ordinary reference mutation, invalidating stored hash continuity or separating displayed payload from its signed bytes.

Proposed acceptance (NOT_RUN): Emit a synthetic receipt containing nested dictionaries, mutate the original input and a value obtained through recent, and assert that stored receipt content, signed payload and chain verification remain unchanged. Test only local in-memory data.

### H2-CORE-005: Iteration budget does not bound a nonreturning awaited step

MEDIUM / FACT; [pinned source hatun_mcp/loop.py:143-166](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/loop.py#L143-L166).

The runner enforces a finite iteration count, but each step is awaited without a deadline in the reviewed implementation. A single step that never returns prevents the iteration budget from reaching a terminal trace.

Consequence (INFERENCE): The local finite-step mechanism alone does not demonstrate wall-clock termination or service reliability. External cancellation behavior is unknown in this assigned scope.

Proposed acceptance (NOT_RUN): Use a synthetic read-only coroutine that waits indefinitely and a one-step budget. Under a separately declared small wall-clock bound, assert bounded cancellation and an explicit terminal reason without leaving a task running.

### H2-CORE-006: Loop exception paths are incomplete and expose raw exception messages

MEDIUM / FACT; [pinned source hatun_mcp/loop.py:163-174](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/loop.py#L163-L174).

The step exception handler places exception type and message into the returned trace. The convergence predicate is invoked after that handler, so its exception escapes instead of producing the runner's error trace.

Consequence (INFERENCE): A callback failure can break the declared terminal-trace contract, and a step failure can disclose private callback text through an otherwise structured result.

Proposed acceptance (NOT_RUN): Use synthetic read-only step and predicate callbacks that each raise a message containing a synthetic private marker. Assert a fixed bounded error reason, a terminal error trace in both cases, and absence of that marker in the returned result.

### H2-CORE-007: Scientific bound helper accepts inputs outside its stated numeric domain

MEDIUM / FACT; [pinned source hatun_mcp/tools/governance_tools.py:32-47](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/tools/governance_tools.py#L32-L47).

The bound helper checks positive sample count, confidence interval and nonnegative complexity, but does not require an exact nonboolean integer sample count, finite complexity/risk, or risk within its unit interval. A nonfinite complexity value bypasses its negative-value check. The tool subsequently emits a success receipt for the calculation.

Consequence (INFERENCE): Malformed caller inputs can yield a nonfinite or out-of-domain value with a successful arithmetic receipt. Such a receipt is not empirical or generalization evidence.

Proposed acceptance (NOT_RUN): Use synthetic NaN and infinity complexity/risk values, risk outside the unit interval, and boolean or fractional sample counts. Require explicit bounded invalid-input results without a successful scientific receipt. Keep a valid finite arithmetic example separately; assert no empirical-evidence promotion.

### H2-CORE-008: Non-string input truncation is not carried into gate evidence

MEDIUM / FACT; [pinned source hatun_mcp/puriq.py:206-211](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/puriq.py#L206-L211).

Non-string input is serialized and sliced to a fixed maximum before gating. The gate's oversized-input heuristic uses a strict greater-than comparison against that same size. The reviewed path does not attach a truncation indicator to the gate evidence, so the original oversized extent is absent from the gate decision.

Consequence (INFERENCE): A heuristic result can appear to cover the supplied object even though it covers only a truncated representation. Operational quorum still fails closed; this finding does not establish authorization bypass.

Proposed acceptance (NOT_RUN): Supply a synthetic read-only object whose serialized representation exceeds the limit. Assert explicit truncated or partial input coverage and prevent a complete-input gate assertion; retain declined operational authorization without independent quorum.

### H2-CORE-009: Direct governance test runner does not signal failures through its exit status

LOW / FACT; [pinned source tests/test_governance.py:237-249](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/tests/test_governance.py#L237-L249).

The direct-script runner calls discovered test functions, catches their exceptions and prints failure text, then finishes without a failing exit. Some test functions require fixture arguments, which this direct runner does not provide. The normal pytest route is a separate contract; its current CI use and outcome were not established here.

Consequence (INFERENCE): If a developer or CI invokes this file directly, failed or incorrectly invoked tests can be mistaken for a successful command based only on its exit status.

Proposed acceptance (NOT_RUN): In an isolated source-owner test, inject a synthetic failing test into the direct-runner harness and require a nonzero exit, or formally retire that invocation and test the documented pytest command instead. No candidate tests were run during this review.

### H2-T01: Dependency upper-bound regex admits an incompatible-major range

MEDIUM / INFERENCE; [pinned source tests/test_dependency_contract.py:21-32](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/tests/test_dependency_contract.py#L21-L32).

The textual upper-bound regex at line 23 accepts a bound such as <2.1. That declared range admits version 2.0, while the remaining assertions may be satisfied by a currently installed 1.x package and available import. The visible test definition therefore does not establish that the declared dependency range excludes every incompatible major version. No test was executed and the actual requirements file was not read in this lane.

Proposed acceptance (NOT_RUN): PROPOSAL: Offline requirement fixtures should accept an appropriate <2 cap and reject <2.1 or an absent major cap; validate parsed dependency semantics independently of the installed package.

### H2-T02: Withheld fixture field prevents complete semantic review

INFO / FACT; [pinned source tests/test_github_estate_snapshot.py:25-36](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/tests/test_github_estate_snapshot.py#L25-L36).

The repository-fixture field at line 29 is redacted. The complete original fixture schema cannot be established from this projection, so static review remains PARTIAL without reproducing a withheld value.

Proposed acceptance (NOT_RUN): PROPOSAL: Preserve a non-identifying fixture-schema projection and redaction receipt; withheld fields must remain explicit and cannot inherit complete semantic-review status.

### H2-T03: Digest fixture does not establish concurrent complete-snapshot repeatability

LOW / INFERENCE; [pinned source tests/test_github_estate_snapshot.py:446-461](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/tests/test_github_estate_snapshot.py#L446-L461).

The canonical-digest repeatability definition uses the default single-PR fixture. A separately interleaved large-queue fixture reaches a request cap and asserts partial coverage. These visible definitions do not establish repeatable complete-snapshot digests across different concurrent response-completion orders. No actual nondeterminism is claimed.

Proposed acceptance (NOT_RUN): PROPOSAL: If complete-snapshot repeatability is required, use an offline multi-PR fixture with a fixed observation clock and reversed completion orders; compare canonical outputs and digests.

### H2-C01: Pinned documents disagree on the static tool count

LOW / FACT; [pinned source STATUS.md:12-15](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/STATUS.md#L12-L15).

STATUS.md declares 25 static tools, while ARCHITECTURE.md at the same snapshot declares 26. Neither count was checked against an executed catalog. The status file's June update header also contains later June/July declarations, so its dating does not establish fresh runtime observation.

Proposed acceptance (NOT_RUN): PROPOSAL: A static documentation consistency fixture should bind declared catalog counts and observation dates to a named source revision, preserving UNKNOWN runtime count when no runtime receipt exists.

### H2-C02: Canonical binding contract URL is mutable

LOW / FACT; [pinned source SZL_ESTATE_BINDING.json:5-12](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/SZL_ESTATE_BINDING.json#L5-L12).

The binding points to a main-branch contract URL without an immutable revision or digest in this file. Veto-only authority, default deny, approval precedence and proof/receipt requirements are declared metadata; enforcement and the contract's exact bytes were not evaluated.

Proposed acceptance (NOT_RUN): PROPOSAL: An inert binding fixture should retain an immutable canonical-contract revision/digest; a changed contract must produce distinct evidence identity, and missing policy-proof/receipt evaluation must remain UNKNOWN.

### H2-C03: Historical endpoint and signing assertions lack current runtime evidence

INFO / FACT; [pinned source DEPRECATED.md:7-9](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/DEPRECATED.md#L7-L9).

The dated migration document asserts prior HTTP 200/404 observations. STATUS.md separately declares live signing and sink behavior. This source-read batch establishes document bytes, not those backend statuses or signatures; placeholder/transparency boundaries remain separately disclosed source claims.

Proposed acceptance (NOT_RUN): PROPOSAL: Offline evidence-classification fixtures must keep dated endpoint/signing declarations separate from fresh provider/runtime receipts; absent runtime evidence cannot become PASS or a scientific-readiness claim.

### H2-C04: Release security declarations are not verified release receipts

INFO / FACT; [pinned source SECURITY.md:23-34](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/SECURITY.md#L23-L34).

The policy declares keyless release signatures and published SBOMs and gives a verification example. No artifact, certificate, signature, SBOM or release-provenance receipt was validated. Line 15 separately says encrypted-report key provisioning is pending; reporting-contact coverage is withheld. No current compliance or legal conclusion is made.

Proposed acceptance (NOT_RUN): PROPOSAL: An offline artifact fixture with missing or mismatched signature/SBOM evidence must preserve release verification as UNVERIFIED; pending provisioning remains ROADMAP and cannot inherit demonstrated status.

### H2-C05: Architecture records operational-domain scope outside scientific proof

INFO / FACT; [pinned source ARCHITECTURE.md:6-9](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/ARCHITECTURE.md#L6-L9).

The document identifies drone/vessel backend context and later mentions state-changing operational tools. Weapons/targeting intent is not established by this document. This review records domain context only and proposes no operational cue/control implementation or tests. Those declarations do not establish scientific validity or authorize operational enhancement.

Proposed acceptance (NOT_RUN): PROPOSAL: An offline report-classification fixture should preserve operational domain as an explicit scope label and prevent unrelated science, training or deployment readiness from inheriting these source declarations. No operational behavior is exercised.

### H2-SURFACE-001: Credential shape is accepted without authoritative key validation

HIGH / FACT; [pinned source hatun_mcp/server_http.py:75-99](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/server_http.py#L75-L99).

The visible resolver checks the expected textual prefix, derives a client fingerprint, and grants a default read scope without checking the authoritative credential store named by its documentation. Middleware places that returned identity into request context, while the generic tool wrapper treats a nonempty identity as authenticated. Current upstream restrictions, deployed configuration, and actual credential provisioning remain UNKNOWN.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: in a hermetic benign read-only echo fixture, an unknown but correctly shaped synthetic credential must remain unauthenticated and must not invoke the echo callback.

### H2-SURFACE-002: Generic wrapper can mark a backend error as success

HIGH / FACT; [pinned source hatun_mcp/server.py:232-238](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/server.py#L232-L238).

For the ordinary backend path, a dictionary containing a truthy error is classified as success whenever deployed is true or absent. This source rule can issue a success receipt for an error-bearing result. The separate estate evidence-contract branch requires COMPLETE evidence and is not included in this finding; its dedicated stricter checks are visible at lines 202-217 and 235-236.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: a benign read-only echo stub returns deployed=true with a synthetic HTTP-error result; require failure status and a failure receipt, with no successful observation claim.

### H2-SURFACE-003: Generic latency budget is checked only after completion

MEDIUM / FACT; [pinned source hatun_mcp/server.py:196-229](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/server.py#L196-L229).

The generic wrapper awaits the supplied coroutine directly and calculates latency and the budget tripwire after it returns. No wrapper deadline or cancellation boundary is applied around that await. Individual backend timeout behavior and effective deployment limits were not established by this review.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: an isolated benign read-only listing coroutine exceeds a short synthetic budget; verify a bounded deadline and an explicit incomplete or failure outcome rather than an unbounded wait.

### H2-SURFACE-004: Registration accepts quorum metadata without enforcement wiring

HIGH / FACT; [pinned source hatun_mcp/adapters/base.py:308-350](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/adapters/base.py#L308-L350).

The registration helper accepts a quorum decider but does not invoke it. The governance-critical marker affects documentation, while neither that marker nor the decider is forwarded to the governed wrapper. This establishes a missing enforcement connection in the visible generic registration layer; no operational component-specific behavior is assessed.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: register a benign synthetic read-only audit_echo callback with recording governance and decider stubs; verify that advertised critical-governance metadata produces an explicit enforceable decision before the callback.

### H2-SURFACE-005: Registration discards advertised per-tool input schemas

MEDIUM / FACT; [pinned source hatun_mcp/adapters/base.py:320-350](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/adapters/base.py#L320-L350).

Every dynamically registered tool uses the same optional arguments-dictionary signature. The per-tool catalog schema stored by the adapter is not used by registration. Exact schema exposed by a running MCP SDK remains UNKNOWN because no candidate import or protocol session was run.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: register a benign read-only echo tool whose synthetic catalog requires a top-level message string; inspect the resulting schema and require preservation of that constraint and its value.

### H2-SURFACE-006: Fixed catalogs claim current reachability without a probe

MEDIUM / FACT; [pinned source hatun_mcp/adapters/companion.py:42-58](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/adapters/companion.py#L42-L58).

The catalog method makes no endpoint request and unconditionally returns reachable=true and HTTP status 200 with a fixed catalog. The LLM catalog does the same. Historical verification comments do not establish present reachability. Actual live endpoint state is UNKNOWN.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: represent a benign unavailable synthetic service; require its catalog to distinguish unverified declarations from observed successful reachability.

### H2-SURFACE-007: Smoke script announces pass without checking rejection outcome

MEDIUM / FACT; [pinned source tests/smoke_mcp_client.py:47-53](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/tests/smoke_mcp_client.py#L47-L53).

The injection-check segment parses and prints the returned status and reason, then prints an all-checks-passed message without asserting that rejection occurred. This is a static defect in the success claim, not evidence that any smoke execution passed. Operational-context fixtures elsewhere in the file are excluded from this review.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: use only a benign synthetic read-only scoring response; substitute an accepted response for the rejection case and require the smoke check to fail without printing its pass marker.

### H2-SURFACE-008: Connect descriptor selects an unpinned install helper

MEDIUM / FACT; [pinned source hatun_mcp/server_http.py:407-411](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/hatun_mcp/server_http.py#L407-L411).

The desktop-client descriptor selects npx with automatic confirmation and a bare mcp-remote package name, without an exact helper version in the visible package argument. The helper version that would resolve, package provenance, installation readiness, and any surrounding omitted credential fields remain UNKNOWN. No npm command was run.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: inspect a sanitized descriptor fixture and require an exact reviewed helper version with an official package-evidence reference; perform no installation or credential handling.

## 5. Per-file receipt matrix

The full matrix, original/cache digests and exact excluded line ranges are in `evidence.json`; `files.csv` is the bounded spreadsheet projection. Source bodies and private raw evidence are outside Git. H2 IDs alias the unchanged collector B1 IDs by plan position; identities are keyed by repository, revision, path and blob.

| ID | Path | Byte | Static | Eligible lines |
|---|---|---|---|---:|

| H2-001 | `hatun_mcp/__init__.py` | COMPLETE | COMPLETE | 11 |

| H2-002 | `hatun_mcp/adapters/__init__.py` | COMPLETE | PARTIAL | 61 |

| H2-003 | `hatun_mcp/adapters/a11oy.py` | COMPLETE | COMPLETE | 42 |

| H2-004 | `hatun_mcp/adapters/anatomy.py` | COMPLETE | COMPLETE | 85 |

| H2-005 | `hatun_mcp/adapters/base.py` | COMPLETE | COMPLETE | 392 |

| H2-006 | `hatun_mcp/adapters/companion.py` | COMPLETE | COMPLETE | 66 |

| H2-007 | `hatun_mcp/adapters/immune.py` | COMPLETE | COMPLETE | 97 |

| H2-008 | `hatun_mcp/adapters/killinchu.py` | COMPLETE | SKIPPED | 0 |

| H2-009 | `hatun_mcp/adapters/llm.py` | COMPLETE | COMPLETE | 85 |

| H2-010 | `hatun_mcp/adapters/second_brain.py` | COMPLETE | COMPLETE | 80 |

| H2-011 | `hatun_mcp/console.py` | COMPLETE | COMPLETE | 13 |

| H2-012 | `hatun_mcp/console_v2.py` | COMPLETE | PARTIAL | 223 |

| H2-013 | `hatun_mcp/dsse.py` | COMPLETE | PARTIAL | 183 |

| H2-014 | `hatun_mcp/governance.py` | COMPLETE | PARTIAL | 524 |

| H2-015 | `hatun_mcp/loop.py` | COMPLETE | COMPLETE | 181 |

| H2-016 | `hatun_mcp/puriq.py` | COMPLETE | PARTIAL | 210 |

| H2-017 | `hatun_mcp/quorum.py` | COMPLETE | PARTIAL | 384 |

| H2-018 | `hatun_mcp/server.py` | COMPLETE | PARTIAL | 636 |

| H2-019 | `hatun_mcp/server_http.py` | COMPLETE | PARTIAL | 596 |

| H2-020 | `hatun_mcp/state.py` | COMPLETE | COMPLETE | 264 |

| H2-021 | `hatun_mcp/tools/__init__.py` | COMPLETE | PARTIAL | 26 |

| H2-022 | `hatun_mcp/tools/governance_tools.py` | COMPLETE | PARTIAL | 201 |

| H2-023 | `tests/proof_inmemory.py` | COMPLETE | COMPLETE | 104 |

| H2-024 | `tests/smoke_mcp_client.py` | COMPLETE | PARTIAL | 42 |

| H2-025 | `tests/test_adapters.py` | COMPLETE | PARTIAL | 106 |

| H2-026 | `tests/test_console_state.py` | COMPLETE | COMPLETE | 166 |

| H2-027 | `tests/test_dependency_contract.py` | COMPLETE | COMPLETE | 47 |

| H2-028 | `tests/test_github_estate_snapshot.py` | COMPLETE | PARTIAL | 646 |

| H2-029 | `tests/test_governance.py` | COMPLETE | COMPLETE | 249 |

| H2-030 | `tests/test_http_routes.py` | COMPLETE | COMPLETE | 328 |

| H2-031 | `tests/test_ledger_forward.py` | COMPLETE | COMPLETE | 47 |

| H2-032 | `tests/test_loop.py` | COMPLETE | COMPLETE | 154 |

| H2-033 | `tests/test_no_mock.py` | COMPLETE | COMPLETE | 49 |

| H2-034 | `tests/test_puriq_real.py` | COMPLETE | COMPLETE | 117 |

| H2-035 | `tests/test_quorum.py` | COMPLETE | COMPLETE | 326 |

| H2-036 | `tests/test_second_brain_anatomy.py` | COMPLETE | COMPLETE | 27 |

| H2-037 | `tests/test_server.py` | COMPLETE | PARTIAL | 266 |

| H2-038 | `.gitignore` | COMPLETE | COMPLETE | 8 |

| H2-039 | `.gitleaks.toml` | SKIPPED | SKIPPED | 0 |

| H2-040 | `ARCHITECTURE.md` | COMPLETE | PARTIAL | 103 |

| H2-041 | `CITATION.cff` | COMPLETE | COMPLETE | 16 |

| H2-042 | `CONTRIBUTING.md` | COMPLETE | COMPLETE | 31 |

| H2-043 | `DEPRECATED.md` | COMPLETE | COMPLETE | 48 |

| H2-044 | `LICENSE` | COMPLETE | PARTIAL | 185 |

| H2-045 | `renovate.json` | COMPLETE | COMPLETE | 22 |

| H2-046 | `SECURITY.md` | COMPLETE | PARTIAL | 37 |

| H2-047 | `STATUS.md` | COMPLETE | PARTIAL | 58 |

| H2-048 | `SZL_ESTATE_BINDING.json` | COMPLETE | COMPLETE | 13 |


## 6. Validation and proof limits

All 15 report consistency checks passed on Python 3.11: zero failures, errors or skips. These data checks inspect only this report and its metadata. Candidate acceptance tests were read as definitions and remain NOT_RUN. Unchanged collector/package validation is historical PR54 evidence: 564 package cases plus 18 subtests on Python 3.11/3.12, zero failures/errors/skips; it was not rerun for this reports-only batch.

Scope rescreening creates a new local cache projection without overwriting raw evidence, refetching source or granting fresh proof. No source bodies, signature seeds/scalars, key values, personal profile paths or room/tool IDs are published. Byte integrity establishes neither independent signer ownership nor scientific validity, authorization, loadability, rights, behavior, safety or deployment. Historical document claims remain dated/unverified; novelty is NOT_ESTABLISHED. Human biosafety/clinical/custom-license/security gates remain required.

## 7. Remaining acceptance and next three actions

1. Existing Hatun/platform owners revalidate exact current-head blobs, accept the proposed generic provenance/authentication handoff and run minimal hermetic regressions before repairs

2. Audit owner proposes the next bounded metadata-selected generic source batch after deduplicating all prior identities; excluded operational paths remain excluded

3. Owners supply current behavior/science/deployment receipts for the remaining estate requirements; queue owner alone handles eligible normal green merges


32,098 historical pinned paths remain unread/skipped; current/private repo and file coverage incomplete; HF models, datasets, Spaces, collections and kernels need current governed evidence; Product/proof domains, mobile/benign tabs and measured accessibility/performance remain open; Research novelty, registry/science validity, source/runtime parity and human release gates remain open; PR queue exact-head controls and sustained disk stability require current independent receipts. Full Phase 2 remains incomplete.
