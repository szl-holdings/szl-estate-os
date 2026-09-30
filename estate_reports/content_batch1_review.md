# Pinned source review: first bounded batch

Checked at 2026-09-30T11:39:11+00:00; source reads completed 2026-09-30T11:09:08+00:00.

Batch exit: **INCOMPLETE**. The collector returned **exit 1 / PARTIAL**. Runtime is **NOT_RUN**; `phase2_ready=false`, `estate_ready=false`. Source was read as data; no candidate code, install, test, browser, payload or deployment ran. No source repairs or merges were performed.

## 1. Authority and stack

This additive draft targets `codex/estate-inventory-phase2` at `668bd10d4d126ca74c9899470ce4045d6879bd69` (draft 53), above Phase 1 draft 52 and Phase 0 draft 51. GitHub szl-holdings remains source of truth. Existing backend/HF/science/platform owners retain repairs; the queue owner retains all merges. Findings require fresh exact-head revalidation and may already have been repaired elsewhere.

## 2. Scope and evidence

The frozen proposal selected 48 frontier-bench files at `f39456789019af3fbfec3e832c730401ee8ba1cc` and 16 hatun-mcp files at `482edd750f3354569ed417a5f443c43a1271ac91`: 480,647 declared bytes, largest 145,903. All 64 were regular blobs in the frozen ledger and verified selected live trees. Both repository metadata endpoints returned 200 and public visibility at the recorded read times; this establishes these bounded reads only.

The successful run used 84 API GETs (19 nonrecursive tree calls), 61 unique blob fetches and 452,155 fetched bytes. Canonical Git tree hashes, selected path/mode/size/blob membership, Git-framed blob hashes and original SHA256s were checked before caching. Runtime receipt SHA256: `c5ff036b386f354b23167090e92d56eabe06caad95e87d5da3b8bb835e01952e`. Exact source/test/tool and input digests are retained in the JSON report. Source bodies, arbitrary headers/error responses, private file inventories and personal room/tool IDs are absent from this repository report.

## 3. Coverage and explicit unknowns

The full historical denominator remains 32,748 pinned paths across 130 repositories (120 public/10 private at the frozen snapshot). Historical inspected 542 + 61 new unique verified identities = 603; **32,145 remain unread/skipped**. There is zero historical overlap in this batch. Mirror paths remain distinct file identities while shared objects are fetched once. The failed first attempt and successful retry are unioned, not added.

Byte statuses: 61 COMPLETE, 3 SKIPPED, 0 PARTIAL, 0 ERROR. Static statuses: `{'COMPLETE': 41, 'PARTIAL': 20, 'SKIPPED': 3}`. COMPLETE static assessment means the available unredacted file was read for selected contracts; it grants no runtime or whole-repository completion. Every file with redactions remains PARTIAL. The selected controller and publisher/publisher-test files are conservatively withheld for ambiguous multiline credential-block patterns; this is not an assertion of an actual credential. They are outside further source review in this batch.

The first attempt saved 64 progress records / 61 cache files before final accounting rejected `.github` and unsupported unselected path grammar. Its shell reported exit 1 with the fixed FAIL code; the reviewed module failure contract is exit 2. Those partial files remain intact outside Git and earn no second coverage credit. The eligibility fix was independently reviewed and tested. Of 28,718 projected safe metadata rows, this strict reader accepts 28,226; 37 policy-excluded, 449 oversized and 6 unsupported-name rows remain unread. The prior 4,030 metadata exclusions and full denominator remain preserved.

## 4. Findings and owner handoff

The following are pinned static observations and derived risks. Candidate acceptance tests are proposals marked NOT_RUN. Owner roles are proposed handoff routes, not evidence that a repair task was assigned. Generic verifier/aggregation repairs remain UNASSIGNED and NOT_ATTEMPTED. No benchmark values are invented, no claim is promoted, and no source owner lane is edited.

Default-branch metadata at 2026-09-30T11:34:17Z still matched both reviewed pins. The CLI JSON interface exposed exit 0 but no HTTP code; that code stays UNKNOWN. Before repair, resolve the exact current head again, compare the affected path/blob and test contracts, and bind all regression receipts to that new head. Matching metadata at this earlier snapshot is not continuing validation.

### B1-BACKEND-001: Receipt value validation is weaker than the declared admission schema

HIGH / FACT; source [verify/verifier.py:32–47](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/verify/verifier.py#L32-L47). Owner route: backend/science source owner; handoff proposed.

Visible admission checks require keys and allowed labels, machine-key presence, truthy measured metrics, and a self-consistent hash. They do not enforce an object of finite numeric metrics, a valid UTC observation time, string machine/method fields, or nonnegative numeric RAM. Default JSON decoding and digest encoding also permit non-finite values. A correctly self-hashed malformed value can therefore pass these checks. Non-object JSON or unhashable labels can escape as exceptions outside the file-read handler. This is a frozen source finding, not a claim that a deployed invalid receipt exists.

Proposed acceptance (NOT_RUN): parameterize one correctly hashed measured fixture with a string metrics value, a non-finite metric, an invalid UTC time, and negative RAM. Each must return fixed validation errors and no publishable paths. A list-shaped JSON receipt and a list-shaped plane value must fail through the same bounded error interface rather than escape.

### B1-BACKEND-002: Sync exports bytes reopened after receipt verification

HIGH / FACT; source [tools/sync_results.py:24–59](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/tools/sync_results.py#L24-L59). Owner route: backend/science source owner; handoff proposed.

The chain is verified first, then the same mutable paths are reopened to check plane/time values, and measured paths are reopened again to construct output rows. A replacement between verification and either read can supply exported metrics and a receipt hash that were not the bytes admitted by the verifier. The existing initial abort-on-verifier-errors gate is a useful safeguard but does not bind these later reads.

Proposed acceptance (NOT_RUN): replace a fixture receipt after the verification call and before export. Require either an explicit integrity failure with no replacement output, or export from the exact immutable bytes already verified. The altered metrics must never be published as admitted data.

### B1-BACKEND-003: Merge truth flag assumes rather than proves verified measured inputs

MEDIUM / FACT; source [tools/merge_results.py:89–130](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/tools/merge_results.py#L89-L130). Owner route: backend/science source owner; handoff proposed.

The merge input check establishes object/list shape, count, a nonempty timestamp, expected plane, and digest-shaped unique receipt labels. It does not recompute receipt admission or require an independently authenticated expected input digest. Nevertheless the deployment payload unconditionally labels its rows measured-only. Source revisions are caller-provided syntax-valid labels. The module documents already-verified inputs as a precondition, but the enforcement of that precondition and the active publisher route remain outside this reviewed source.

Proposed acceptance (NOT_RUN): supply a shape-valid synthetic input containing a digest-shaped receipt label without the expected upstream admission attestation. Require rejection or an explicit unverified truth state. A changed input must also fail when its bytes no longer match the separately supplied expected verified-input digest and source pin.

### B1-BACKEND-004: Zero-request runs can still receive the MEASURED label

MEDIUM / FACT; source [harness/runner.py:37–51](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/harness/runner.py#L37-L51). Owner route: backend/science source owner; handoff proposed.

After a successful health gate, empty prompts or zero/negative repeat counts produce an empty nested loop and an empty summary, followed by an unconditional MEASURED label. The visible CLI accepts arbitrary integer repeats and the prompt loader does not validate a nonempty prompt collection. The file contains two redacted lines, so the full request/accounting contract remains partial; these visible loop and label paths are sufficient to identify the zero-request case.

Proposed acceptance (NOT_RUN): parameterize zero repeats, negative repeats, and an empty prompt list with injected health/client fixtures. Require rejection or an explicit non-measured state before issuing generation requests. No zero-request run may emit a measured result.

### B1-BACKEND-005: Endpoint and exception text reach result or console output

HIGH / FACT; source [harness/runner.py:28–35](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/harness/runner.py#L28-L35). Owner route: backend/science source owner; handoff proposed.

Endpoint strings are resolved directly from environment configuration, included in a blocked reason, and printed before a run. The client returns stringified or repr-form exception text, which metrics retains as errors. If configured endpoint or exception text contains credential-bearing URL components or private response data, these visible paths can disclose them. No environment values or actual credential text were read during this review; the client/runner review remains partial because accounting lines are redacted.

Proposed acceptance (NOT_RUN): use a synthetic endpoint with credential-bearing URL components and injected transport exceptions containing synthetic private text. Capture result JSON, stdout, and stderr. Require fixed safe error codes and no disclosure of those components or exception contents; do not make live requests.

### B1-BACKEND-006: Malformed SSE events are discarded without a partial-stream state

MEDIUM / FACT; source [harness/client.py:48–58](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/harness/client.py#L48-L58). Owner route: backend/science source owner; handoff proposed.

Malformed JSON data events are silently skipped. A stream containing some valid text can then reach the visible successful-result path even if another data event was malformed. No explicit completed-versus-truncated stream state is visible. Existing usage-event tests intentionally allow streams without a final end marker, so completion policy needs an owner decision rather than an assumption that all providers have the same trailer contract. Redacted request/result fields make this a partial file review.

Proposed acceptance (NOT_RUN): first define the supported provider completion contract. Add a stream fixture with valid text followed by malformed JSON and an abruptly ended stream. Require an explicit invalid/partial admission state when completion is not established, while preserving the declared usage-only event compatibility.

### B1-BACKEND-007: Latency aggregation has no finite nonnegative value admission

MEDIUM / FACT; source [harness/metrics.py:49–73](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/harness/metrics.py#L49-L73). Owner route: backend/science source owner; handoff proposed.

Successful samples are selected by their truthy success flag, and every non-null TTFT/total value is converted into percentile inputs without finite or nonnegative checks. The visible sample dataclass does not validate these timing fields. Invalid numeric samples can therefore produce invalid latency summaries. The accounting field is redacted, so no complete token-throughput type claim is made.

Proposed acceptance (NOT_RUN): parameterize a successful sample with negative, non-finite, and boolean timing values. Require fixed rejection or explicit invalid-sample exclusion before percentile aggregation; absent valid measurements must remain unknown rather than become numeric benchmark results.

### B1-BACKEND-008: Sync output truncates the existing artifact before writing completes

MEDIUM / FACT; source [tools/sync_results.py:60–68](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/tools/sync_results.py#L60-L68). Owner route: backend/science source owner; handoff proposed.

The sync tool writes directly to the destination in truncating write mode. An interrupted write or storage error can destroy a previously valid result artifact and leave a partial output. The reviewed merge tool already has a per-file atomic replacement pattern, but the sync writer does not use it. This is a source-level preservation concern, not a claim that an actual output was corrupted.

Proposed acceptance (NOT_RUN): preserve a known destination artifact, inject a write or flush failure while producing the replacement, and require an explicit failure with the original artifact bytes unchanged. A successful write should replace the destination only after the staged bytes are complete.

### B1-C001: Initial cache screen retained identifying local-path fields

Audit cache screening gap remediated; ten synthetic privacy cases passed. Original private evidence is preserved.

MEDIUM / FACT; source [evidence/eclipse-native-repaired-20260905.json:78–80](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/evidence/eclipse-native-repaired-20260905.json#L78-L80). Owner: platform.

Historical error strings retained local user-profile paths despite an initial receipt declaring zero redacted lines. Identifying values are excluded here. This is a cache-screening gap, not a claim of a source vulnerability; static coverage remains PARTIAL. Additional affected lines are 93 and 177.

Proposed acceptance (NOT_RUN): Synthetic JSON-escaped and plain Windows profile-path fixtures must withhold identifying spans, preserve line correspondence, refresh cache provenance and retain PARTIAL coverage for withheld content.

### B1-C002: Mock startup depends on a fixed sleep

LOW / INFERENCE; source [.github/workflows/ci.yml:25–27](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/.github/workflows/ci.yml#L25-L27). Owner: platform.

The declared workflow backgrounds a mock server and sleeps for one second before the runner. Startup readiness is not established by that delay alone; no observed workflow failure is claimed.

Proposed acceptance (NOT_RUN): Delayed and failed mock startup fixtures must use bounded readiness checks and fail explicitly without producing successful measurement evidence.

### B1-C003: Inline mock assertion proves aggregate statuses only

LOW / FACT; source [.github/workflows/ci.yml:27–28](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/.github/workflows/ci.yml#L27-L28). Owner: science.

The visible inline assertion checks one MEASURED and five BLOCKED engine statuses. That assertion alone does not establish positive successful-sample counts, valid metrics or answer quality. Other invoked tests may cover additional behavior; their results are not part of this review.

Proposed acceptance (NOT_RUN): Zero-success, malformed-output and valid-positive-sample fixtures must distinguish measurement eligibility from status labels, with no success claim on errors.

### B1-C004: Prompt configuration lacks scientific corpus and model-revision binding

MEDIUM / FACT; source [configs/prompts.json:2–16](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/configs/prompts.json#L2-L16). Owner: science.

The file declares five general prompts spanning technical, literary, economics and health topics, plus engine/model identifiers. It supplies no prompt IDs, corpus digest, domain manifest, expected answers, scoring criteria or immutable model revisions. Distinct quantized/native model identifiers do not establish equivalent loaded model identity. This is a smoke/performance input declaration, not validated scientific or training evidence.

Proposed acceptance (NOT_RUN): Bind stable prompt IDs, domain labels, configuration/corpus digests and immutable model/quantization revisions to receipts; economics, health and literary inputs must not inherit a science-readiness claim. Missing quality evidence remains UNKNOWN.

### B1-C005: Historical fixture report is not a current runtime attestation

MEDIUM / FACT; source [evidence/eclipse-native-repaired-20260905.json:188–200](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/evidence/eclipse-native-repaired-20260905.json#L188-L200). Owner: science.

The artifact declares local fixture-verifier controls, ten caught mutation cases and a source commit different from the reviewed snapshot. Its golden records identify fixture-control hardware and synthetic dates. These are dated source claims; no control, hash, verifier digest or result was independently rerun. They do not establish live benchmark measurements or scientific sensitivity at this snapshot.

Proposed acceptance (NOT_RUN): Consumers must preserve FIXTURE scope, bind artifact source commit and verifier digest, and keep historical or unmatched evidence distinct from current measurements. A separately scheduled reproduction of the ten mutation controls would need new dated receipts.

### B1-H001: Initial cache screen retained personal attribution

Audit cache screening gap remediated; ten synthetic privacy cases passed. Original private evidence is preserved.

MEDIUM / FACT; source [.github/workflows/gitleaks.yml:7–7](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/gitleaks.yml#L7-L7). Owner: platform.

Personal attribution survived the initial screen although its receipt reports zero redacted lines. Identifying values are withheld from this report; review remains PARTIAL. This concerns the cache screen rather than source behavior.

Proposed acceptance (NOT_RUN): Synthetic personal-attribution fixtures must withhold identifying spans, retain line correspondence, refresh the cache digest and preserve PARTIAL review status.

### B1-H002: Scanner archive installation lacks visible integrity verification

MEDIUM / FACT; source [.github/workflows/gitleaks.yml:31–37](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/gitleaks.yml#L31-L37). Owner: platform.

The visible workflow downloads a version-addressed scanner archive, extracts it and installs the binary without a visible checksum or signature verification step. No download or installation was performed during review.

Proposed acceptance (NOT_RUN): An altered archive must be rejected against independently retained expected integrity evidence before extraction or installation.

### B1-H003: Scanner invocation does not establish historical cleanliness

INFO / FACT; source [.github/workflows/gitleaks.yml:38–51](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/gitleaks.yml#L38-L51). Owner: platform.

The visible command scans the current tree only. Comments about historical-patch cleanliness are not established by this invocation or by the static review.

Proposed acceptance (NOT_RUN): Separate synthetic current-tree and history-only markers; report each measured scope independently and keep unscanned historical scope UNKNOWN.

### B1-H004: HF witness checks HTML surface markers only

INFO / FACT; source [.github/workflows/hf-drift-check.yml:58–66](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/hf-drift-check.yml#L58-L66). Owner: HF.

The checks inspect HTML marker presence and asset-marker counts. They do not request the referenced mesh API or establish endpoint semantics, authorization, source/deployment equality or scientific validity. The declared workflow was not run and no live HF validation was performed.

Proposed acceptance (NOT_RUN): A synthetic HTML response containing all expected markers while its API is unavailable may satisfy surface-presence checks, but runtime/API evidence must remain UNKNOWN.

### B1-H005: HF parity policy has an unestablished active consumer

LOW / INFERENCE; source [.github/hf-module-drift-allow.json:2–25](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/hf-module-drift-allow.json#L2-L25). Owner: HF.

The policy describes a source-bound Space/deployer and excludes several behavior-capable asset formats. The inspected witness workflow instead declares the standalone publisher retired. Active policy consumption and full deployment parity remain unestablished; no deployment mismatch is claimed.

Proposed acceptance (NOT_RUN): Establish whether this policy has an active consumer or is historical configuration. If active, changed excluded assets must remain outside text-parity proof rather than inherit a full-parity claim.

### B1-H006: Contract dependency setup is not exactly versioned

LOW / FACT; source [.github/workflows/hf-deploy-contract.yml:66–72](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/hf-deploy-contract.yml#L66-L72). Owner: platform.

The visible setup installs pytest without an exact version, while the actual contract invocation is withheld. Runner reproducibility and exercised test scope cannot be established from the visible definition.

Proposed acceptance (NOT_RUN): Retain a sanitized contract identifier and resolved dependency manifest; a controlled dependency change must not silently retain identical environment provenance.

### B1-H007: Caller has no declared merge-group trigger

LOW / FACT; source [.github/workflows/overclaim-guard.yml:8–20](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/overclaim-guard.yml#L8-L20). Owner: platform.

The caller declares manual, PR and push events but no merge_group event. Whether it is required for merge-queue admission is UNKNOWN; the pinned reusable implementation was not inspected.

Proposed acceptance (NOT_RUN): For a synthetic merge-group event, establish either that the required guard is scheduled or that it is explicitly outside required queue checks; absence must not be reported as PASS.

### B1-H008: SAST definition does not substantiate its maturity comment

INFO / FACT; source [.github/workflows/codeql.yml:9–9](https://github.com/szl-holdings/hatun-mcp/blob/482edd750f3354569ed417a5f443c43a1271ac91/.github/workflows/codeql.yml#L9-L9). Owner: science.

A comment asserts SLSA maturity. The inspected SAST definition supplies no build-provenance or attestation verification evidence sufficient to establish that assertion. Scientific validity and novelty remain independent and unestablished.

Proposed acceptance (NOT_RUN): Passing SAST with missing builder/attestation evidence must preserve the asserted maturity as UNVERIFIED, without inferring scientific validity or novelty.

### B1-PLATFORM-001: Docker smoke safety gate runs after controller import

MEDIUM / FACT; source [deploy/bench-plane/test_bench_docker.py:22–28](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/deploy/bench-plane/test_bench_docker.py#L22-L28). Owner: platform.

The module executes the packaged controller during import. The Linux/GitHub-hosted-runner and no-credential checks are defined later and invoked only from main. Therefore those checks do not guard controller import when the smoke-test module is imported or started outside its intended runner. Controller import side effects remain UNKNOWN because its bytes are withheld; this finding does not assert that any side effect actually occurred.

Proposed acceptance (NOT_RUN): In an owner-reviewed isolated harness, use a harmless sentinel controller and verify that a non-disposable runner or credential-bearing environment is rejected before controller import or Docker access. NOT_RUN.

### B1-PLATFORM-002: Historical site can label structurally consistent assertions as verified

MEDIUM / INFERENCE; source [site/app.js:49–79](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/site/app.js#L49-L79). Owner: platform.

The historical validator compares the two publication documents' declared source records, accepts any well-formed 40-character source revision, and checks only source equality plus a 64-character receipt shape for rows. It does not independently bind raw result bytes to an externally fixed digest, require an admitted measured status, or validate per-plane metrics/authentication metadata. The renderer then labels the publication verified and renders arbitrary row metrics. This is a conditional historical-source concern: active publisher selection and production exposure are UNKNOWN because publisher/controller source is withheld. The operations guide says site files are historical; that statement is not independently proven by this review.

Proposed acceptance (NOT_RUN): If this route is retained as an eligible publication surface, submit self-consistent fabricated, BLOCKED, or malformed-metric fixtures and require UNAVAILABLE/no measured claim; document the trusted publisher and admission boundary. Otherwise prove that the canonical export excludes this route. NOT_RUN.

### B1-PLATFORM-003: Historical site fetch has no bounded terminal failure deadline

LOW / FACT; source [site/app.js:180–195](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/site/app.js#L180-L195). Owner: platform.

The historical boot path waits for two fetches and parses both bodies with response.json without an explicit abort deadline or response-size bound. A stalled response can keep the displayed loading state unresolved; a large JSON response is buffered before validation. The reviewed deploy template separately supplies a 10-second abort deadline and a 4 MiB streamed-body cap. Historical-route selection and production exposure remain UNKNOWN.

Proposed acceptance (NOT_RUN): If the historical route can be selected, use stalled and oversized mocked responses and require a bounded transition to unavailable with no result rendering. NOT_RUN.

### B1-PLATFORM-004: Legacy Compose port omits an explicit loopback bind

MEDIUM / INFERENCE; source [deploy/docker-compose.yml:3–8](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/deploy/docker-compose.yml#L3-L8). Owner: platform.

The legacy Compose service publishes host port 7861 without a host-IP component. Under ordinary Compose/Docker defaults this permits a wider bind than loopback, while the maintained-controller documentation describes node-local loopback services. This file is explicitly an older path in the runbook. Current use, Docker daemon defaults, firewall policy, and production exposure are UNKNOWN; no port was contacted.

Proposed acceptance (NOT_RUN): If the legacy path remains supported, inspect its owner-resolved Compose configuration and require an explicit loopback host bind unless a reviewed external-access requirement exists. Verify actual socket exposure only in an authorized disposable environment. NOT_RUN.

### B1-PLATFORM-005: Maintained controller assurance is blocked by withheld source

HIGH / FACT; source [deploy/bench-plane/BENCH_PLANE_OPERATIONS.md:5–47](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/deploy/bench-plane/BENCH_PLANE_OPERATIONS.md#L5-L47). Owner: platform.

The operations guide describes receipt/HMAC admission, Docker staging/cutover, immutable publication readback, conditional commits, and compensating rollback. The exact maintained controller is classified CREDENTIAL_BLOCK_WITHHELD and has no readable cache. These operational/security claims cannot be verified from that controller's source in this review. The screening classification is a review limitation, not a finding that a live credential leaked. Redacted controller tests also cannot establish implementation behavior or current test results.

Proposed acceptance (NOT_RUN): Obtain an owner-approved secret-free review representation bound to the pinned or deliberately re-reviewed fresh revision, then complete controller source review before assigning a verified deployment/security claim. Preserve withheld original material privately. NOT_RUN.

### B1-PLATFORM-006: Publication environment reproducibility is not established by its direct pin

LOW / FACT; source [deploy/bench-plane/requirements-publish.txt:1–1](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/deploy/bench-plane/requirements-publish.txt#L1-L1). Owner: HF.

The reviewed requirement file pins only huggingface_hub 1.30.0. The guide installs that file into a virtual environment and requires Python 3.11 or newer plus system Git, Docker/BuildKit, and NVIDIA tooling. A transitive lock, artifact-hash policy, resolver result, exact interpreter/tool versions, and provider compatibility proof are not present in the assigned installation material. Such context elsewhere is UNKNOWN. No claim is made that the pin is unavailable or incompatible, and no provider dependency was installed or queried.

Proposed acceptance (NOT_RUN): The publication owner supplies a reviewed environment receipt with the direct/transitive versions, interpreter/system-tool identity, artifact provenance, and an isolated resolver/compatibility result for the exact publication path. NOT_RUN.

### B1-PLATFORM-007: Dated runtime and CI observations are not fresh runtime proof

INFO / FACT; source [deploy/bench-plane/BENCH_PLANE_OPERATIONS.md:248–264](https://github.com/szl-holdings/frontier-bench/blob/f39456789019af3fbfec3e832c730401ee8ba1cc/deploy/bench-plane/BENCH_PLANE_OPERATIONS.md#L248-L264). Owner: platform.

The guide explicitly identifies its runtime, CI, branch-protection, receipt-producer, and harness observations as a 2026-09-05 inventory. Its later organization-publication section preserves those historical observations. The source was fetched at a fresh pinned snapshot, but a fresh source fetch does not refresh the truth of embedded historical observations. Current CI/provider/hardware/measurement state remains UNKNOWN in this static review.

Proposed acceptance (NOT_RUN): Before a SHIPPING or DEMONSTRATED assertion, attach fresh owner-collected CI, provider/runtime, source-identity, and admitted-receipt evidence; retain dated observations as historical and keep fixture/internally-tested claims separate. NOT_RUN.

## 5. Per-file dispositions

Original byte hashes and selected membership proofs are in `content_batch1_review.json`; CSV provides the64-row completion matrix. Withheld files have zero reviewed cache lines. Redaction preserves line numbering.

| File | Repository/path at pinned revision | Byte | Static | Read cache lines | Blocker |
| --- | --- | --- | --- | --- | --- |
| B1-001 | `szl-holdings/frontier-bench/.gitattributes` | COMPLETE | COMPLETE | 14 | None in available static text |
| B1-002 | `szl-holdings/frontier-bench/.github/CODEOWNERS` | COMPLETE | PARTIAL | 2 | REDACTED_OWNER_MAPPING_LINE_2 |
| B1-003 | `szl-holdings/frontier-bench/.github/dependabot.yml` | COMPLETE | COMPLETE | 46 | None in available static text |
| B1-004 | `szl-holdings/frontier-bench/.github/workflows/ci.yml` | COMPLETE | COMPLETE | 65 | None in available static text |
| B1-005 | `szl-holdings/frontier-bench/.github/workflows/codeql.yml` | COMPLETE | COMPLETE | 20 | None in available static text |
| B1-006 | `szl-holdings/frontier-bench/.gitignore` | COMPLETE | COMPLETE | 10 | None in available static text |
| B1-007 | `szl-holdings/frontier-bench/LICENSE` | COMPLETE | PARTIAL | 202 | PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-008 | `szl-holdings/frontier-bench/configs/prompts.json` | COMPLETE | COMPLETE | 17 | None in available static text |
| B1-009 | `szl-holdings/frontier-bench/deploy/RUNBOOK.md` | COMPLETE | COMPLETE | 40 | None in available static text |
| B1-010 | `szl-holdings/frontier-bench/deploy/bench-plane/.gitignore` | COMPLETE | COMPLETE | 5 | None in available static text |
| B1-011 | `szl-holdings/frontier-bench/deploy/bench-plane/BENCH_PLANE_OPERATIONS.md` | COMPLETE | PARTIAL | 331 | One source line redacted; controller and actual publisher source withheld.; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-012 | `szl-holdings/frontier-bench/deploy/bench-plane/finish_bench_plane.py` | SKIPPED | SKIPPED | 0 | CREDENTIAL_BLOCK_WITHHELD; no cache text and no inferred source line count. |
| B1-013 | `szl-holdings/frontier-bench/deploy/bench-plane/requirements-publish.txt` | COMPLETE | COMPLETE | 1 | None in available static text |
| B1-014 | `szl-holdings/frontier-bench/deploy/bench-plane/szl-bench-suite.README.md` | COMPLETE | COMPLETE | 45 | None in available static text |
| B1-015 | `szl-holdings/frontier-bench/deploy/bench-plane/szl-bench-suite.index.html` | COMPLETE | COMPLETE | 408 | None in available static text |
| B1-016 | `szl-holdings/frontier-bench/deploy/bench-plane/szl/SOURCE.json` | COMPLETE | COMPLETE | 27 | None in available static text |
| B1-017 | `szl-holdings/frontier-bench/deploy/bench-plane/szl/logos/szl_favicon.svg` | COMPLETE | COMPLETE | 20 | None in available static text |
| B1-018 | `szl-holdings/frontier-bench/deploy/bench-plane/szl/szl-design-system.css` | COMPLETE | PARTIAL | 427 | Attribution privacy masking removes two source lines from the safe review representation; post-rescreen digest verification is root-owned.; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-019 | `szl-holdings/frontier-bench/deploy/bench-plane/test_bench_docker.py` | COMPLETE | COMPLETE | 175 | None in available static text |
| B1-020 | `szl-holdings/frontier-bench/deploy/bench-plane/test_bench_surface.mjs` | COMPLETE | COMPLETE | 226 | None in available static text |
| B1-021 | `szl-holdings/frontier-bench/deploy/bench-plane/test_finish_bench_plane.py` | COMPLETE | PARTIAL | 1067 | Twenty source lines redacted; the imported controller is withheld. Redaction-induced syntax is not treated as an original parse defect. |
| B1-022 | `szl-holdings/frontier-bench/deploy/docker-compose.yml` | COMPLETE | COMPLETE | 14 | None in available static text |
| B1-023 | `szl-holdings/frontier-bench/evidence/eclipse-native-repaired-20260905.json` | COMPLETE | PARTIAL | 201 | INITIAL_V2_SCREEN_PRIVACY_GAP_LINES_78_80_93_177; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-024 | `szl-holdings/frontier-bench/harness/__init__.py` | COMPLETE | COMPLETE | 0 | None in available static text |
| B1-025 | `szl-holdings/frontier-bench/harness/client.py` | COMPLETE | PARTIAL | 122 | REDACTED_LINES_8 |
| B1-026 | `szl-holdings/frontier-bench/harness/engine_registry.py` | COMPLETE | COMPLETE | 77 | None in available static text |
| B1-027 | `szl-holdings/frontier-bench/harness/metrics.py` | COMPLETE | PARTIAL | 75 | REDACTED_LINES_1 |
| B1-028 | `szl-holdings/frontier-bench/harness/runner.py` | COMPLETE | PARTIAL | 83 | REDACTED_LINES_2 |
| B1-029 | `szl-holdings/frontier-bench/receipts/000-genesis.json` | COMPLETE | COMPLETE | 14 | None in available static text |
| B1-030 | `szl-holdings/frontier-bench/site/README.md` | COMPLETE | COMPLETE | 17 | None in available static text |
| B1-031 | `szl-holdings/frontier-bench/site/app.js` | COMPLETE | COMPLETE | 199 | None in available static text |
| B1-032 | `szl-holdings/frontier-bench/site/index.html` | COMPLETE | COMPLETE | 85 | None in available static text |
| B1-033 | `szl-holdings/frontier-bench/site/style.css` | COMPLETE | PARTIAL | 175 | Attribution privacy masking removes one source line from the safe review representation; post-rescreen digest verification is root-owned.; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-034 | `szl-holdings/frontier-bench/site/szl/SOURCE.json` | COMPLETE | COMPLETE | 27 | None in available static text |
| B1-035 | `szl-holdings/frontier-bench/site/szl/logos/szl_favicon.svg` | COMPLETE | COMPLETE | 20 | None in available static text |
| B1-036 | `szl-holdings/frontier-bench/site/szl/szl-design-system.css` | COMPLETE | PARTIAL | 427 | Attribution privacy masking removes two source lines from the safe review representation; post-rescreen digest verification is root-owned.; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-037 | `szl-holdings/frontier-bench/tests/mock_server.py` | COMPLETE | PARTIAL | 39 | REDACTED_LINES_1 |
| B1-038 | `szl-holdings/frontier-bench/tests/test_client.py` | COMPLETE | PARTIAL | 170 | REDACTED_LINES_6 |
| B1-039 | `szl-holdings/frontier-bench/tests/test_merge_results.py` | COMPLETE | COMPLETE | 87 | None in available static text |
| B1-040 | `szl-holdings/frontier-bench/tests/test_metrics.py` | COMPLETE | PARTIAL | 45 | REDACTED_LINES_5 |
| B1-041 | `szl-holdings/frontier-bench/tests/test_publish_space.py` | SKIPPED | SKIPPED | 0 | CREDENTIAL_BLOCK_WITHHELD |
| B1-042 | `szl-holdings/frontier-bench/tests/test_space_bundle.py` | COMPLETE | COMPLETE | 111 | None in available static text |
| B1-043 | `szl-holdings/frontier-bench/tests/test_sync_results.py` | COMPLETE | COMPLETE | 67 | None in available static text |
| B1-044 | `szl-holdings/frontier-bench/tests/test_verifier.py` | COMPLETE | COMPLETE | 55 | None in available static text |
| B1-045 | `szl-holdings/frontier-bench/tools/merge_results.py` | COMPLETE | COMPLETE | 190 | None in available static text |
| B1-046 | `szl-holdings/frontier-bench/tools/publish_space.py` | SKIPPED | SKIPPED | 0 | CREDENTIAL_BLOCK_WITHHELD |
| B1-047 | `szl-holdings/frontier-bench/tools/sync_results.py` | COMPLETE | COMPLETE | 73 | None in available static text |
| B1-048 | `szl-holdings/frontier-bench/verify/verifier.py` | COMPLETE | COMPLETE | 83 | None in available static text |
| B1-049 | `szl-holdings/hatun-mcp/.dockerignore` | COMPLETE | COMPLETE | 5 | None in available static text |
| B1-050 | `szl-holdings/hatun-mcp/.gitattributes` | COMPLETE | COMPLETE | 35 | None in available static text |
| B1-051 | `szl-holdings/hatun-mcp/.github/CODEOWNERS` | COMPLETE | PARTIAL | 2 | REDACTED_OWNER_MAPPING_LINE_2 |
| B1-052 | `szl-holdings/hatun-mcp/.github/CODE_OF_CONDUCT.md` | COMPLETE | PARTIAL | 20 | REDACTED_REPORTING_CONTACT_LINE_10 |
| B1-053 | `szl-holdings/hatun-mcp/.github/CONTRIBUTING.md` | COMPLETE | COMPLETE | 19 | None in available static text |
| B1-054 | `szl-holdings/hatun-mcp/.github/ISSUE_TEMPLATE/bug_report.md` | COMPLETE | COMPLETE | 14 | None in available static text |
| B1-055 | `szl-holdings/hatun-mcp/.github/ISSUE_TEMPLATE/config.yml` | COMPLETE | COMPLETE | 5 | None in available static text |
| B1-056 | `szl-holdings/hatun-mcp/.github/ISSUE_TEMPLATE/feature_request.md` | COMPLETE | COMPLETE | 12 | None in available static text |
| B1-057 | `szl-holdings/hatun-mcp/.github/dependabot.yml` | COMPLETE | COMPLETE | 97 | None in available static text |
| B1-058 | `szl-holdings/hatun-mcp/.github/hf-module-drift-allow.json` | COMPLETE | COMPLETE | 26 | None in available static text |
| B1-059 | `szl-holdings/hatun-mcp/.github/pull_request_template.md` | COMPLETE | COMPLETE | 14 | None in available static text |
| B1-060 | `szl-holdings/hatun-mcp/.github/workflows/codeql.yml` | COMPLETE | PARTIAL | 57 | REDACTED_LINES_56_57 |
| B1-061 | `szl-holdings/hatun-mcp/.github/workflows/gitleaks.yml` | COMPLETE | PARTIAL | 52 | INITIAL_V2_SCREEN_PERSONAL_ATTRIBUTION_GAP_LINE_7; PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-062 | `szl-holdings/hatun-mcp/.github/workflows/hf-deploy-contract.yml` | COMPLETE | PARTIAL | 72 | REDACTED_TRIGGER_LINES_19_37_AND_INVOCATION_LINE_71 |
| B1-063 | `szl-holdings/hatun-mcp/.github/workflows/hf-drift-check.yml` | COMPLETE | PARTIAL | 75 | PRIVACY_RESCREEN_WITHHELD_ATTRIBUTION_OR_PROFILE_LINES |
| B1-064 | `szl-holdings/hatun-mcp/.github/workflows/overclaim-guard.yml` | COMPLETE | COMPLETE | 20 | None in available static text |

## 6. Validation and proof limits

Python 3.11.9 ran all 289 authored package test definitions as 564 cases plus 18 subtests: zero failures/errors/skips. The collection source was separately validated as 554 cases plus 18 subtests; its original manifest stays bound to the actual execution receipt. The final privacy fix adds ten synthetic cases. Installed isolated module help and pip consistency checks passed. Fixtures cover forged/mismatched pins, cache replay, privacy/withholding, historical overlap, metadata names, tree shape/truncation, exact plan/index binding, rate/backoff and preservation of partial outputs. Candidate tests are read only and were not run. Static report consistency validation is recorded separately at publication.

Privacy review found attribution/profile-path lines missed by the first screen. A new hash-verified projection masks 32 additional lines across 8 files, retaining line numbering and PARTIAL review. Original evidence and all progress/collection receipts remain private outside Git; no raw or screened source bodies are committed. Old/new cache hashes and the new sanitizer digest are bound in the privacy receipt. Rescreening is CACHE evidence and grants no fresh-source credit. These audit-tool privacy defects were corrected; candidate source repairs remain unattempted.

Byte integrity does not establish signed origin, scientific validity, authorization beyond the recorded GET scope, license/training eligibility, safety or deployment. Scientific novelty remains NOT_ESTABLISHED. Model 11/12 and asset/runtime historical claims remain unverified unless their owners supply fresh exact receipts. No red/pending/draft/HOLD merges, permission bypass or history rewrite are admitted. Human biosafety/clinical/custom-license/security release gates remain required. Operational weapons/targeting/engagement and finance/legal/defense imports into science remain excluded.

## 7. Remaining acceptance and next three actions

1. Source owners accept the unassigned generic verifier/aggregation handoff, revalidate exact current heads and run the listed minimal regression fixtures before any repairs
2. Audit owner schedules the separate 48-path/354,807-byte Hatun architecture batch with fresh visibility/hash/privacy bounds
3. Owners supply current behavior/science/deployment receipts within their governed lanes; queue owner alone handles eligible normal green merges, while withheld controller/publisher paths stay excluded here

The next proposal is 48 Hatun MCP architecture/install/contract source paths, 354,807 declared bytes, at the existing pinned revision. It excludes prior 64 identities (including withheld files), historical inspected paths, protected/oversized/unsupported names, binding configs and transcripts. It is metadata only: **PROPOSAL / NOT_RUN**. Do not reduce unread coverage until actual verified reads occur.

Full Phase 2 and Phase 1 acceptance remains open: current GitHub/tree/file/private coverage; HF models/datasets/Spaces/collections/kernels; a-11-oy.com product versus a11oy.net proof origin; accessible mobile/benign tabs with measured performance; research/science/registry validity; source/runtime parity; normal green PR controls; and sustained disk stability. Snapshot metadata and static archive consistency establish none of those runtime outcomes.
