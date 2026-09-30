# Bounded receipts/provenance source review: batch 3

**35 byte-complete records**:34 generic package files plus1 requested domain CNAME. Static review:22 COMPLETE / 13 PARTIAL. Candidate runtime NOT_RUN; Phase 2/estate readiness false.

## 1. Authority and stack

Reports-only branch `codex/estate-receipt-source-batch3`, stacked on draft 55 / `codex/estate-hatun-source-batch2` at `1422dc8a7898aa7f4c8c7b873439a4c58469b3c4`. Hatun/frontier-bench repair and HF card/motion/publication lanes are excluded. Existing owners retain source fixes and all merges.

## 2. Scope and evidence

Two generic packages were selected from the existing hash-bound frozen index: governed-receipt-spec14 paths and szl-receipt20 paths,174,539 bytes. Both public metadata endpoints returned HTTP 200 at the recorded collection times. The main run completed13:07:04 UTC with54 GETs / 16 nonrecursive tree reads. Selected regular leaves, exact tree membership, blob size, Git-framed SHA1 and SHA256 were verified before screening. The separate requested CNAME run completed13:16:48 UTC,4 GETs / 1 tree / 21 bytes. Separate input/execution/cache digests are retained in evidence.json.

## 3. Coverage and explicit unknowns

Historical baseline 650 + 35 new unique byte-accounted paths=**685 / 32,748**; **32,063 remain unread/skipped**. All 112 prior selected identities are excluded; the original historical denominator remains dated130 repository coverage, not a current estate census. 4,217 available lines include blanks:17 privacy masks + 279 scope exclusions leave3,921 eligible lines. Static COMPLETE grants no behavioral/safety/scientific or whole-repository validation. Original acquisition receipts are immutable; cache scope rescreening grants no fresh credit.

Open-PR filename metadata was paginated for the two package repositories and reported no open PRs at its timestamp. Unpublished writer paths remain UNKNOWN. Current-head JSON-only observations preserve unexposed HTTP as UNKNOWN and require fresh revalidation before every repair. All proposed candidate regressions are NOT_RUN; repairs NOT_ATTEMPTED.

At 2026-09-30 13:54:49 UTC, both package main branches had advanced: governed-receipt-spec to `e2f94bd507e0d19bce87eb13015745b9f3831876`, and szl-receipt to `52e85bc8568d11c5eadc7fa9a396dc8415c8a15b`. These findings describe the reviewed historical revisions and may already be repaired; owners must compare affected blobs at current heads before acting.

## 4. Findings and proposed owner handoff

24 pinned findings follow. Facts describe source; consequences are inferences, and benign tests/owner routes are proposals. Full source keys include repository/revision/path/blob; the context finding is uniquely aliased to avoid cross-repository ID collision.

### R3-CORE-001: Manifest verdicts coerce malformed evidence into positive declarations

HIGH / FACT; [pinned source scripts/emit_run_manifest.py:70-93](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/scripts/emit_run_manifest.py#L70-L93).

Input validation requires three evidence fields to exist but does not validate their value types or domains. Two verdict fields are converted using truthiness, and the numeric field is copied unchanged. A nonempty false-like string therefore becomes a positive declared verdict.

Consequence (INFERENCE): Malformed upstream evidence can produce an overstated manifest declaration. Current downstream publication enforcement and any actual scientific or runtime outcome remain unknown.

Proposed acceptance (NOT_RUN): With only synthetic metadata, require exact JSON booleans for verdicts and finite bounded numeric evidence in the declared schema. Nonboolean verdicts and invalid numeric values must fail before output; valid negative verdicts must remain negative.

### R3-CORE-002: Statement digest membership can pass without structural validity

HIGH / FACT; [pinned source src/szl_receipt/attest.py:312-328](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/src/szl_receipt/attest.py#L312-L328).

The verifier checks the statement type, optionally checks predicate type, then accepts matching subject-digest membership. It does not invoke maintained structural validation or require a subject name and nonempty predicate. Those fields are required in the reviewed construction path.

Consequence (INFERENCE): The result described as a valid statement can exceed a digest-membership observation. Digest equality remains separate from cryptographic validity, signer trust and release authorization.

Proposed acceptance (NOT_RUN): Use a synthetic matching digest in an incomplete statement with no subject name or predicate. Require an explicit structural-validation failure while keeping a complete benign statement as a separate valid case; do not promote either case into authorization.

### R3-CORE-003: Malformed subject digest breaks the statement verifier's fail-soft contract

MEDIUM / FACT; [pinned source src/szl_receipt/attest.py:318-325](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/src/szl_receipt/attest.py#L318-L325).

For each dictionary subject, the verifier calls a mapping method on its digest value without checking that value's type. A present null or other nonmapping digest can therefore raise instead of returning the documented graceful failure.

Consequence (INFERENCE): A malformed input can interrupt a receipt consumer that relies on the stated never-raises validation contract. No live service failure was observed.

Proposed acceptance (NOT_RUN): Supply only synthetic subjects with null, list and scalar digest values. Each must return a fixed false result without an exception or echoed input value.

### R3-CORE-004: Receipt representation is mutable despite its immutable-record contract

MEDIUM / FACT; [pinned source src/szl_receipt/receipt.py:38-60](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/src/szl_receipt/receipt.py#L38-L60).

The documented immutable record is an unfrozen dataclass retaining a mutable body dictionary. Digest computation reads that live dictionary. Signing separately reads the body for the digest, envelope payload and signature rather than using one captured byte snapshot.

Consequence (INFERENCE): Caller or concurrent mutation can change a receipt's evidence after construction or make signing steps describe different snapshots. The reviewed exact-byte verifier may reject such inconsistencies; no false cryptographic PASS or live failure is asserted.

Proposed acceptance (NOT_RUN): Construct a synthetic receipt from nested caller-owned data and mutate the original and exposed body. Require a documented immutable snapshot or explicit mutable contract; when signing is tested by its owner, all advertised digest, payload and signature must derive from the same captured bytes.

### R3-CORE-005: Conformance PAE representation contradicts the reviewed fixed-format tests

MEDIUM / FACT; [pinned source conformance/run_vectors.py:45-52](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/conformance/run_vectors.py#L45-L52).

The runner length-prefixes the context as well as payload type and payload. The reviewed fixed-format tests assert a literal context prefix instead. The V02 check builds and reparses the runner's own representation, so it does not independently resolve this cross-file contradiction.

Consequence (INFERENCE): V02 can establish local self-consistency while leaving the incompatible fixed-format assertions unresolved. External-spec correctness, the referenced canonical implementation and deployed interoperability remain unverified.

Proposed acceptance (NOT_RUN): Compare both representations against the existing benign fixed-byte format fixture. Require exact byte agreement and a failed conformance result for the conflicting representation. Do not treat self-parsing as independent interoperability proof.

### R3-CORE-006: Malformed expectations and incomplete vector sets can produce an all-pass declaration

MEDIUM / FACT; [pinned source conformance/run_vectors.py:226-256](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/conformance/run_vectors.py#L226-L256).

The runner requires a nonempty vector directory but does not enforce the documented five-vector identity set or unique IDs. It does not validate the expectation enum; any unrecognized expectation is handled as a negative expectation, allowing a failed check to be reported as a passed vector.

Consequence (INFERENCE): Malformed vector metadata can cause a false vector PASS, and a successful incomplete run does not establish complete five-vector coverage. Any separate caller coverage enforcement remains outside this scope.

Proposed acceptance (NOT_RUN): Use benign synthetic vector metadata. Reject unrecognized expectations before checks run, reject duplicate IDs, and reject an incomplete set when claiming the full documented suite. Report observed versus required coverage explicitly.

### R3-CORE-007: Genesis handling bypasses a supplied predecessor requirement

MEDIUM / FACT; [pinned source conformance/run_vectors.py:159-175](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/conformance/run_vectors.py#L159-L175).

The linkage check accepts the genesis sentinel before comparing an explicitly supplied predecessor. The vector's declared purpose requires comparison when a predecessor is supplied. The timestamp check reads predecessor time only when its path exists.

Consequence (INFERENCE): The suite can accept incomplete predecessor evidence in this branch. This does not establish a deployed chain bypass or release authorization failure.

Proposed acceptance (NOT_RUN): With synthetic local receipt metadata, combine a supplied predecessor with a genesis sentinel and require an explicit linkage failure or separately documented genesis-only result. A missing required predecessor must fail required conformance.

### R3-CORE-008: Predecessor digest and timestamp use separate local reads

MEDIUM / FACT; [pinned source conformance/run_vectors.py:168-185](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/conformance/run_vectors.py#L168-L185).

The linkage check hashes one read of the predecessor file, while the timestamp check independently rereads the same path. The checks do not share a captured predecessor byte snapshot in the reviewed implementation.

Consequence (INFERENCE): If the local file changes between checks, the combined result can refer to different predecessor evidence. No changing-file incident was observed.

Proposed acceptance (NOT_RUN): Use a benign synthetic predecessor fixture whose path replacement is controlled by the test harness. Require both checks to consume one bounded captured byte snapshot with one recorded digest, or explicitly fail a detected replacement.

### R3-A01: Fallback note can be counted as a required authorship marker

MEDIUM / INFERENCE; [pinned source attribution/attribution.py:54-55](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/attribution/attribution.py#L54-L55).

The visible fallback creates an authorship note from an unmarked AI mention. With review and merge markers, dictionary-entry counting can reach the branch describing all three vocabulary markers as present. The taxonomy requires all three explicit markers. Existing visible tests supply all three markers and do not establish fallback behavior. No parser was executed.

Proposed acceptance (NOT_RUN): PROPOSAL: Use synthetic review/merge markers and a generic AI mention without an authorship marker; the result must not describe all three explicit markers as present and must retain missing authorship evidence.

### R3-A02: Substring classification does not distinguish negated approval language

MEDIUM / INFERENCE; [pinned source attribution/attribution.py:34-38](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/attribution/attribution.py#L34-L38).

Visible approval detection uses substring matching. A synthetic negative-evidence statement containing a negated approval phrase may still reach the UNSAFE attribution branch. This is a parser-category observation, not an admission or operational safety verdict; no result was executed.

Proposed acceptance (NOT_RUN): PROPOSAL: Use a generic unavailable-review statement explicitly denying approval; establish the intended diagnostic behavior and ensure denial alone is not reported as an affirmative approval claim.

### R3-A03: Extracted review scope is an unverified opaque declaration

MEDIUM / FACT; [pinned source attribution/attribution.py:57-59](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/attribution/attribution.py#L57-L59).

The visible extraction captures a nonempty scope string; it does not validate a head/date/verdict or establish that a review ran. Masked regions and independent consumers are outside complete semantic review. Verification implications remain INFERENCE, and actual runtime provenance remains UNKNOWN.

Proposed acceptance (NOT_RUN): PROPOSAL: Use an opaque synthetic scope lacking head/date/verdict; consuming evidence must preserve those fields as UNKNOWN and classify the marker as an unverified source declaration.

### R3-A04: Attribution category is separate from evidence basis and maturity

INFO / FACT; [pinned source attribution/attribution.py:82-85](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/attribution/attribution.py#L82-L85).

The visible result fields and taxonomy attribution states do not provide explicit FACT/INFERENCE/PROPOSAL or SHIPPING/DEMONSTRATED/INTERNALLY_TESTED/ROADMAP evidence axes. MEASURED attribution cannot establish verified provenance, correctness, runtime behavior or shipping status.

Proposed acceptance (NOT_RUN): PROPOSAL: A generic consumer-envelope fixture must not automatically map MEASURED attribution to FACT or SHIPPING/DEMONSTRATED maturity.

### R3-A05: Complete source-byte binding is not established by the visible digest path

INFO / INFERENCE; [pinned source attribution/attribution.py:82-85](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/attribution/attribution.py#L82-L85).

The visible digest path serializes an assessment object, and the visible repeatability fixture uses the same input twice. Two nearby assessment-field lines are masked, so this review cannot establish whether complete original claim bytes are retained or bound. Assessment-summary integrity must remain distinct from authenticated source provenance until that scope is established.

Proposed acceptance (NOT_RUN): PROPOSAL: After complete field-scope validation, use synthetic inputs and independently computed full-source-byte receipts to establish exactly which bytes the assessment digest covers; consumers must preserve UNKNOWN binding where fields remain withheld.

### R3-C01: Output-production wording exceeds the admitted self-attestation boundary

MEDIUM / INFERENCE; [pinned source docs/NON_GOALS.md:13-14](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/docs/NON_GOALS.md#L13-L14).

The document says a receipt proves that an input/model/parameter set produced an output, while its own visible self-attestation disclosure permits a dishonest runtime to sign a false record. Record integrity alone cannot establish execution truth. The stronger production wording is a source claim, not observed runtime proof.

Proposed acceptance (NOT_RUN): PROPOSAL: An inert evidence fixture with a valid-statement-integrity flag and self-asserted production claim must preserve execution truth as UNKNOWN without promoting correctness or scientific validity.

### R3-C02: Source existence is presented as SHIPPING without runtime evidence here

LOW / FACT; [pinned source docs/LANDSCAPE.md:22-24](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/docs/LANDSCAPE.md#L22-L24).

The document labels source/verifier presence as live working SHIPPING evidence and makes external positioning assertions. This source-only review validates cached text, not those runtime or comparative claims. External primary sources were not fetched; excluded legal/formal-proof regions provide no scientific or novelty qualification.

Proposed acceptance (NOT_RUN): PROPOSAL: A source-maturity classification fixture must retain the SHIPPING wording as an unverified source claim when only source bytes are available; no comparative or novelty result may be inferred.

### R3-C03: Completeness semantics are prose beyond visible schema shape

LOW / FACT; [pinned source schema/governed-action.v1.schema.json:62-75](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/schema/governed-action.v1.schema.json#L62-L75).

The visible schema defines obligation booleans and a COMPLETE/INCOMPLETE enum, while its description says completeness is derived and forbids PASS for incomplete evidence. The inspected subtree does not encode that relationship. Masked fields and the independent semantic verifier were not validated, so no integrated verifier defect or admission bypass is claimed.

Proposed acceptance (NOT_RUN): PROPOSAL: A role-free inert record with an unsatisfied obligation and asserted COMPLETE must distinguish schema-shape validation from semantic completeness; shape status cannot become runtime PASS.

### R3-C04: DSSE prose requirements are not visible signature-verification evidence

MEDIUM / FACT; [pinned source schema/governed-receipt.schema.json:146-160](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/schema/governed-receipt.schema.json#L146-L160).

The visible DSSE definition says signed=true requires nonempty signatures, but its array has no visible minItems/conditional constraint and entry fields have no required keyid/sig list. Top-level envelope fields are also outside the receipt's required list. These are shape-contract observations; signature verification behavior remains UNKNOWN.

Proposed acceptance (NOT_RUN): PROPOSAL: Use inert data with signed=true and an empty signatures array or an empty entry; a shape-only result must not become verified-signature or admissible-evidence status.

### R3-C05: Policy reference shape does not establish immutable policy bytes

LOW / FACT; [pinned source schema/governed-action.v1.schema.json:35-40](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/schema/governed-action.v1.schema.json#L35-L40).

The visible policy reference is a string described as a digest or URI without an encoded immutable revision/digest requirement in that property. This lane did not resolve or validate policy bytes. A referenced name or URI therefore remains a declaration, not reproducible policy evidence.

Proposed acceptance (NOT_RUN): PROPOSAL: An inert policy-reference fixture containing only a mutable URI must preserve exact policy-byte identity as UNKNOWN rather than claiming reproducible evaluation.

### R3-VERIFIER-001: Skipped signature verification is formatted as PASS

HIGH / FACT; [pinned source verify.py:674-677](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/verify.py#L674-L677).

When signatures are present but no verify key is supplied, check_signatures returns a successful boolean with a SKIP explanation. The report formatter consequently prefixes this check with PASS. Aggregate file and overall results can also remain PASS. The source documentation says skipped signature checks must never be reported as a pass. A reader or status parser can treat PASS as successful cryptographic verification even though the key was absent. The explanation discloses the skip, but the leading status conflicts with that explanation. No live invocation or consumer behavior was observed.

Consequence (INFERENCE): A reader or status parser can treat PASS as successful cryptographic verification even though the key was absent. The explanation discloses the skip, but the leading status conflicts with that explanation. No live invocation or consumer behavior was observed.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: use a benign synthetic signed read-only listing receipt without a supplied trust key; require an explicit signature SKIPPED or UNVERIFIED state and keep structural validity separately labeled.

### R3-VERIFIER-002: A second declared content digest is not checked

MEDIUM / FACT; [pinned source verify.py:427-446](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/verify.py#L427-L446).

The content-hash checker returns immediately after validating a declared PAE digest. A simultaneously declared raw-payload digest is therefore not compared. Both digest names are accepted by the envelope metadata allowlist. A receipt carrying a correct PAE digest and a contradictory raw-payload digest can avoid rejection of the second declared digest by this source control flow. This is a conditional static result; no fixture was executed.

Consequence (INFERENCE): A receipt carrying a correct PAE digest and a contradictory raw-payload digest can avoid rejection of the second declared digest by this source control flow. This is a conditional static result; no fixture was executed.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: a benign synthetic read-only listing receipt declares both digest formats; alter only the raw-payload digest and require an explicit contradictory-digest failure.

### R3-CI-001: Scanner failures can reach the successful policy-gate branch

HIGH / INFERENCE; [pinned source .github/workflows/forbidden-domain.yml:46-54](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/.github/workflows/forbidden-domain.yml#L46-L54).

Both search stages suppress every nonzero exit status with an unconditional successful fallback. The final success branch checks only whether filtered stdout is empty. A missing scanner, search failure, or read error with no matching stdout can take the same success path as an ordinary no-match result. No scanner failure was observed at runtime.

Consequence (INFERENCE): A missing scanner, search failure, or read error with no matching stdout can take the same success path as an ordinary no-match result. No scanner failure was observed at runtime.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: an inert read-only scanner fixture emits no stdout and an error exit status; require an explicit gate error. Separately preserve success for the ordinary no-match exit status.

### R3-CI-002: Filename guard wording can exempt unrelated matching content

MEDIUM / INFERENCE; [pinned source .github/workflows/forbidden-domain.yml:46-47](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/.github/workflows/forbidden-domain.yml#L46-L47).

The first search emits filename and line-number prefixes. The exemption search filters the entire emitted line rather than only the source content. A filename containing an exemption term can suppress matching content that contains no guard or prohibition context, exceeding the same-source-line exemption described by the workflow. No live match was observed.

Consequence (INFERENCE): A filename containing an exemption term can suppress matching content that contains no guard or prohibition context, exceeding the same-source-line exemption described by the workflow. No live match was observed.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: put identical inert matching text without guard wording in two synthetic files, changing only whether the filename contains a guard term; require identical violation results.

### R3-CI-003: Source-binding regression checks do not prove active relationships

MEDIUM / INFERENCE; [pinned source tests/test_pr_source_binding.py:21-29](https://github.com/szl-holdings/governed-receipt-spec/blob/19a625bfc0f72fc7635babc4bda97beaebe75af5/tests/test_pr_source_binding.py#L21-L29).

The regression checks for five required substrings anywhere in each workflow text. It does not bind them to active job environment values, checkout inputs, or executable proof steps. Required text confined to comments or disconnected steps can satisfy these assertions while active binding differs. The three reviewed workflow files currently contain visibly connected source-binding steps; this finding concerns future regression strength.

Consequence (INFERENCE): Required text confined to comments or disconnected steps can satisfy these assertions while active binding differs. The three reviewed workflow files currently contain visibly connected source-binding steps; this finding concerns future regression strength.

Proposed acceptance (NOT_RUN): NOT_RUN proposal: use inert synthetic workflow text with required binding strings confined to comments and an active read-only listing job using a different source reference; require the contract check to reject it.

### R3-CONTEXT-001: CI source does not bind the runner image or resolved install environment

LOW / FACT; [pinned source .github/workflows/ci.yml:21-35](https://github.com/szl-holdings/szl-receipt/blob/2dca7158dd1069dee533beea31120fcb4334bda8/.github/workflows/ci.yml#L21-L35).

The visible workflow selects ubuntu-latest, minor Python labels and an editable dev install. Its action references are full commit pins, but these workflow statements do not supply an immutable runner-image digest or an observed resolved dependency receipt. Packaging/lock contents are outside this batch, so dependency compatibility and installation behavior remain UNKNOWN.

Consequence (INFERENCE): A successful run label alone cannot establish exact-environment reproducibility without separately bound runtime/environment evidence.

Proposed acceptance (NOT_RUN): PROPOSAL, NOT_RUN: an inert environment-receipt fixture with absent image/version/dependency provenance must remain incomplete; only an exact-head receipt identifying actual runtime and resolved versions can support an exact-environment claim. No workflow settings or builds are changed by this audit.

## 5. Domain lookup, receipt matrix and backlog

The pinned [CNAME:1](https://github.com/szl-holdings/szl-holdings.github.io/blob/7ba4c683ced57bf8e0b255e867ed3cacdd51b72d/CNAME#L1) declares holdings.a-11-oy.com. Source binding for szlholdings.com remainsUNKNOWN. The supplied 13:02–13:03 UTC browser/text-reader observation reported a displayed 502 Bad Gateway/connection-closed error. Raw HTTP status, DNS, current ownership/hosting/configuration and error cause remain UNKNOWN; no universal-outage diagnosis is made. The first lookup plan lacked an explicit PROPOSAL field and failed before output/network; that plan is preserved, corrected metadata used a new path, and only the successful read earns one credit.

files.csv and evidence.json retain35 exact source identities, original/cache digests, timestamps, static statuses and excluded ranges. Source bodies, credentials, private inventories and personal profile/room/tool identifiers remain outside Git. requirements_delta.json/.md add 20 backlog/constraint rows after source review, linked to existing requirement IDs. Overhaul V2/V6 and Frontier 1 summaries grant no source coverage or implementation credit; original attachment bytes were not reviewed here.

| ID | Repository/path | Byte | Static | Eligible lines |
|---|---|---|---|---:|
| R3-001 | `szl-holdings/governed-receipt-spec/.github/workflows/codeql.yml` | COMPLETE | COMPLETE | 69 |
| R3-002 | `szl-holdings/governed-receipt-spec/.github/workflows/forbidden-domain.yml` | COMPLETE | COMPLETE | 54 |
| R3-003 | `szl-holdings/governed-receipt-spec/.github/workflows/verify.yml` | COMPLETE | COMPLETE | 52 |
| R3-004 | `szl-holdings/governed-receipt-spec/attribution/attribution.py` | COMPLETE | PARTIAL | 81 |
| R3-005 | `szl-holdings/governed-receipt-spec/attribution/CLAIM-TAXONOMY-v1.md` | COMPLETE | PARTIAL | 27 |
| R3-006 | `szl-holdings/governed-receipt-spec/attribution/test_attribution.py` | COMPLETE | PARTIAL | 41 |
| R3-007 | `szl-holdings/governed-receipt-spec/docs/LANDSCAPE.md` | COMPLETE | PARTIAL | 39 |
| R3-008 | `szl-holdings/governed-receipt-spec/docs/NON_GOALS.md` | COMPLETE | PARTIAL | 56 |
| R3-009 | `szl-holdings/governed-receipt-spec/schema/governed-action.v1.schema.json` | COMPLETE | PARTIAL | 112 |
| R3-010 | `szl-holdings/governed-receipt-spec/schema/governed-receipt.schema.json` | COMPLETE | PARTIAL | 126 |
| R3-011 | `szl-holdings/governed-receipt-spec/tests/test_codeql_lockstep.py` | COMPLETE | COMPLETE | 89 |
| R3-012 | `szl-holdings/governed-receipt-spec/tests/test_pr_source_binding.py` | COMPLETE | COMPLETE | 33 |
| R3-013 | `szl-holdings/governed-receipt-spec/tests/test_verify.py` | COMPLETE | COMPLETE | 614 |
| R3-014 | `szl-holdings/governed-receipt-spec/verify.py` | COMPLETE | COMPLETE | 775 |
| R3-015 | `szl-holdings/szl-receipt/.github/workflows/ci.yml` | COMPLETE | COMPLETE | 38 |
| R3-016 | `szl-holdings/szl-receipt/.github/workflows/pin-check.yml` | COMPLETE | COMPLETE | 20 |
| R3-017 | `szl-holdings/szl-receipt/.github/workflows/sbom.yml` | COMPLETE | PARTIAL | 19 |
| R3-018 | `szl-holdings/szl-receipt/conformance/README.md` | COMPLETE | COMPLETE | 13 |
| R3-019 | `szl-holdings/szl-receipt/conformance/run_vectors.py` | COMPLETE | COMPLETE | 260 |
| R3-020 | `szl-holdings/szl-receipt/conformance/vectors/V01-canonicalization.json` | COMPLETE | COMPLETE | 6 |
| R3-021 | `szl-holdings/szl-receipt/conformance/vectors/V02-pae-byte-length.json` | COMPLETE | COMPLETE | 6 |
| R3-022 | `szl-holdings/szl-receipt/conformance/vectors/V03-der-parse.json` | COMPLETE | COMPLETE | 6 |
| R3-023 | `szl-holdings/szl-receipt/conformance/vectors/V04-prev-hash-linkage.json` | COMPLETE | COMPLETE | 6 |
| R3-024 | `szl-holdings/szl-receipt/conformance/vectors/V05-ts-monotonic.json` | COMPLETE | COMPLETE | 6 |
| R3-025 | `szl-holdings/szl-receipt/scripts/assert_digest.py` | COMPLETE | COMPLETE | 63 |
| R3-026 | `szl-holdings/szl-receipt/scripts/emit_run_manifest.py` | COMPLETE | COMPLETE | 111 |
| R3-027 | `szl-holdings/szl-receipt/src/szl_receipt/_intoto.py` | COMPLETE | PARTIAL | 126 |
| R3-028 | `szl-holdings/szl-receipt/src/szl_receipt/_sign.py` | COMPLETE | PARTIAL | 155 |
| R3-029 | `szl-holdings/szl-receipt/src/szl_receipt/attest.py` | COMPLETE | PARTIAL | 173 |
| R3-030 | `szl-holdings/szl-receipt/src/szl_receipt/receipt.py` | COMPLETE | PARTIAL | 223 |
| R3-031 | `szl-holdings/szl-receipt/tests/test_attest.py` | COMPLETE | PARTIAL | 71 |
| R3-032 | `szl-holdings/szl-receipt/tests/test_pae_rule.py` | COMPLETE | COMPLETE | 221 |
| R3-033 | `szl-holdings/szl-receipt/tests/test_sign.py` | COMPLETE | COMPLETE | 145 |
| R3-034 | `szl-holdings/szl-receipt/tests/test_vectors.py` | COMPLETE | COMPLETE | 84 |
| R3-D01 | `szl-holdings/szl-holdings.github.io/CNAME` | COMPLETE | COMPLETE | 1 |


## 6. Validation and proof limits

All 18 report consistency checks passed on Python 3.11, with zero failures, errors or skips, including the additive Frontier 1 checkpoint/history/status check. Candidate test definitions and proposed regressions remain NOT_RUN. Historical unchanged-tool validation at 5352659a023c20a34eacdb48e168064ea571e836 passed 564 package cases plus 18 subtests on Python 3.11/3.12, with zero failures/errors/skips; it was not rerun in this reports-only batch. Source acquisition and static reading establish neither authorized signer identity nor execution truth/completeness, scientific validity, measured performance, rights, training/loadability or deployment. Novelty remains NOT_ESTABLISHED. Human biosafety/clinical/custom-license/security gates remain required.

## 7. Remaining acceptance and next three actions

1. Existing package owners revalidate exact current heads/blobs and run the listed minimal benign regressions before any separately scoped repairs

2. Audit owner selects another deduplicated generic source batch from the frozen index while preserving active-owner exclusions

3. Domain/platform and HF owners resolve current deployment/access/rights and backlog receipts through their existing lanes; queue owner alone handles eligible normal green merges


Full Phase 2 remains incomplete:current/private repo/file coverage; HF models/datasets/Spaces/collections/kernels; product/proof domains/mobile/benign tabs/measured accessibility; research/science/registry/source-runtime parity; PR current-head controls and sustained disk stability. No source repair, payload execution, publisher, settings change, deployment, schedule, issue creation, merge or history rewrite occurred.
