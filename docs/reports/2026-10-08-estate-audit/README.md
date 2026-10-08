# SZL estate source audit recovery

**Internal review packet, prepared 2026-10-08.** This records dated observations and pinned source findings. It is a proposal for review, not a release approval or a claim that the ecosystem is fully wired. No repository source, tests, model, training job, or live service was executed for this packet.

**October 8 update:** A later authenticated census found **141 visible repositories** (128 public, 13 private, 29 archived). See the [dated census and current-head wiring addendum](october-8-refresh.md), [complete inventory](repository-census-2026-10-08.csv), and [head delta](head-delta-2026-10-08.csv). The October 3 inventory and October 7 path ledger below remain historical snapshots.

## Inventory and exact coverage boundary

The earlier complete authorized organization census was **2026-10-03 15:06 UTC**: **139 repositories** (127 public, 12 private, 29 archived). Authenticated GraphQL pagination reached its terminal page and an independent REST name listing agreed. [Repository pins](repository-pins-2026-10-03.csv) provide every name, GitHub ID, visibility, archive state, and then-default-head commit. This is a historical inventory, not a fresh October 8 count.

A frozen consolidation of the ten original per-file ledgers at about **2026-10-07 20:03 UTC** matched all 139 assigned repositories and 35,095 saved tree paths to pinned commits. Every saved recursive tree was untruncated. No repository ledger, path key, or assigned commit pin was missing or duplicated. One A11oy gitlink pointer lacked its target OID in the ledger; the saved tree had it. [Bucket coverage](bucket-coverage-2026-10-07.csv) records the frozen states:

| Ledger label | Paths | Meaning |
| --- | ---: | --- |
| Full | 8,460 | Lane-specific label, often exact byte acquisition; **not** 8,460 full semantic reviews. |
| Partial | 2,871 | Selective review or other partial state. |
| Unread | 17,337 | No semantic review or selected acquisition as defined by the original lane. |
| Binary | 1,786 | Outside selected text review. |
| Excluded | 4,641 | Deliberate scope boundary, including protected content. |

These labels are heterogeneous. The bucket 2 total uses its kernel **semantic-review** overlay (55 full, 12 partial, 98 unread among 177 kernel paths) rather than treating 165 byte-acquired files as full reviews. Later owner reports advanced some states after the freeze. In particular, later semantic ledgers for buckets 1, 7, and 8 identify acquired files still partly or wholly unreviewed; they are not merged into the frozen CSV.

## Frontend ownership at the pinned inventory

The exact Hugging Face organization-card source is `.github` (linked below). [`a11oy@f291a53`](https://github.com/szl-holdings/a11oy/tree/f291a53fb78b492b74059c3e21cc354af5c117d8) owns the product frontend and Python governance API; [`a11oy-net@185e689`](https://github.com/szl-holdings/a11oy-net/tree/185e68961cab45aedc3ecddf281893c04f6d9c19) is a static proof registry. Private [`szl-command-center@fbc619f`](https://github.com/szl-holdings/szl-command-center/tree/fbc619fd66e881fd93278c97b1d130bf05c88eb7) has a Python-served UI that fetches `/api/estate` and `/api/verticals`, with deployment unverified. Private [`szl-showcase@fab1043`](https://github.com/szl-holdings/szl-showcase/tree/fab10436a7935632ef281898640c529127fe5e5e) is a generated static catalog whose October 1 count of 132 predates the 139-repository census. [`holographic-unify@eb96e9c`](https://github.com/szl-holdings/holographic-unify/tree/eb96e9c06f9ec7597049c51e1524cc17b19906ff) is a separate hologram, [`szl-constellation@b3b094f`](https://github.com/szl-holdings/szl-constellation/tree/b3b094f913cc550ef137037187aea3195365d2a0) is a WebGL/FastAPI demo, and archived [`a-11-oy.github.io@683acd1`](https://github.com/szl-holdings/a-11-oy.github.io/tree/683acd11d6ef47c49b8099c0cd5c63c489b19f5e) has deliberately blank live trust/router settings. These distinct surfaces should not be treated as interchangeable deployments.

## Prioritized wiring map

| Priority | Boundary | Pinned source, tested, and live distinction |
| --- | --- | --- |
| P0 | A11oy to governed SZL Router | [A11oy's Python client at `f291a53`](https://github.com/szl-holdings/a11oy/blob/f291a53fb78b492b74059c3e21cc354af5c117d8/szl_router_client.py) has an opt-in path to [router control at `8b402e3`](https://github.com/szl-holdings/szl-router/blob/8b402e3da5af9646a249468e222944a7e476f67b/router_control/app.py). The consumer's completion timeout is 45 seconds against a 660-second router budget. A passing consumer CI run used an older router peer; the October 3 public governed health readback said `UNAVAILABLE`, `LOCAL_CONFIGURATION_ONLY`, 0/3 engines. No current authorized completion, receipt, or provider binding was checked here. |
| P0 | Caller admission and receipt integrity | Pinned static reviews found A11oy write paths outside the reviewed operator gate, [Ayllu Counsel](https://github.com/szl-holdings/ayllu/blob/55178e2edc6dc11edfe40065f88d4c9cda33b004/ayllu/counsel.py) able to mark unavailable inference `ALLOW`, and [Immune](https://github.com/szl-holdings/immune/blob/2654fc9db126e30b3f06d49bfe1156b9748c45ae/server/routes/immune/infer-answer.ts) able to return an answer after a failed answer seal. [Energy proxy receipts](https://github.com/szl-holdings/szl-energy-attest/blob/1520b4b50ef957e58628a64a205edb46cdc6348e/szl_energy_attest/meter_proxy/proxy.py) can carry an Authorization-header prefix. These are code-path findings, not verified live exposure or executed failures. The existing energy privacy PR has a separate owner. |
| P0 | Frontend visual and truthful status | The exact Hugging Face organization-card source was [`.github@add2ca1e`](https://github.com/szl-holdings/.github/blob/add2ca1e8fbea40f52564f9d505547c91ec0006e/huggingface/org-card/index.html), with an October 3 served Hub revision bound to that source. A colorful [September 29 revision](https://github.com/szl-holdings/.github/blob/56198271fd5bf135a34049ea1a42ad49f3525144/huggingface/org-card/index.html) is a visual comparison candidate, not proof of a broad degradation cause. A11oy's two health routes disagreed about signer state in an October 3 read window. The homepage design owner works separately; no frontend was edited here. |
| P1 | Python product services | [Vertical Services FastAPI at `1f2f691`](https://github.com/szl-holdings/vertical-services/blob/1f2f6919c2959225209cb2fe3a391e4a46bf2555/deploy/app.py) had a same-source October 3 live build readback and six structural ready verticals, with operator/model binding still required. [David Leads at `a357667`](https://github.com/szl-holdings/david-leads/blob/a35766748c3c1fcf4c83543ac8c1589f02cf2819/app/server.py) had a same-source public readback but an operator-blocked workspace; its automatic Space deploy filter omits backend-only changes. [Hatun MCP at `d1e82c9`](https://github.com/szl-holdings/hatun-mcp/blob/d1e82c98c583192dd201f6a501babca22c91a395/hatun_mcp/server_http.py) has transport source, but its former standalone host returned 404 in the October 3 check. No new live probes were made. |
| P1 | Model stack | Forge has specific Unsloth Qwen training recipes and candidate manifests. A ReceiptAgent v2 local serving loader does not pin the same training base/loader contract; v3 is source-ready, not trained. LiteLLM appears as optional callback/proxy recipes, while the governed SZL Router is an independent gateway. Bonsai 2/Prism remains on production hold pending its custom loader and model-bound evaluation. No Unsloth–LiteLLM–Bonsai operating pipeline or current A11oy model turn was verified. |

## Remaining review work and owners

- **Original partition owners** continue permitted per-file review at the October 3 pins. The frozen unread counts are concentrated in bucket 0 (**6,389**), bucket 2 (**10,188** using semantic kernel status), and bucket 5 (**682**). Bucket 4 has **2,518** partial/selective rows at its 20:01 freeze. These are timestamped counts; later owner reports advanced some statuses.
- Buckets 3, 6, and 9 satisfied their limited byte-accounting and focused-report handoffs. They did **not** establish all-permitted-file semantic completion. Bucket 3 needs semantic classification of **526** byte-surveyed texts by its original `task-11` owner. Bucket 6 needs triage of **78 acquisition-unread** paths and reconciliation of an outdated semantic overlay by `task-17`. Bucket 9 needs semantic classification of **2,012** byte-acquired texts by `task-13`. These are classification queues, not assertions that every acquired file has never been read.
- Bucket 6's 78 unread are **57 Killinchu, 15 Frontier, 3 NEXUS**, and one each in Khipu Lab, Lyte Lattice, and Command Lab. Five lockfiles and one CSS file are ordinary text candidates; cookbook/JSON/large vendor paths need scope triage before opening. Its **861 excluded** and **271 binary** paths are separate from the 78.
- Bucket 4's frozen ledger had two selected UTF-8 byte-size mismatches and 67 acquired query paths without response-outcome rows. The A11oy gitlink OID gap is ledger bookkeeping. The original owners should reconcile these before a final coverage claim.
- Five bucket 2 file reads were rejected by automatic approval review because excluded dataset/evaluation, mixed generated payload, or operational content could not be ruled out. They remained unread. Datasets, held-out or per-case evaluation, weights, credentials, keys, and operational biological material remain excluded throughout the estate.

No October 8 current-head census, current CI/run, provider/model call, or end-to-end live connection is established by this packet. The next implementation phase should choose one frontend and Python route at a time, bind the exact deployed source and caller/receipt contract, then obtain separate authorized test and live evidence before marking it wired.

## Evidence provenance

The full original ledgers, exclusion lists, and detailed source reports remain in the local audit workspace. This branch contains the concise review packet and repository-pin/coverage summaries; it deliberately omits raw source, per-case data, secrets, weights, copied workflow responses, and the 26,635-row non-full-path index. The following SHA-256 digests identify the retained inputs:

| Retained evidence | SHA-256 |
| --- | --- |
| October 3 complete repository inventory JSONL | `1a10c24d658bab446d7a1f58394cdc798b9466970d1f64d6da2674881de773b1` |
| [October 3 repository pins](repository-pins-2026-10-03.csv) | `a0745ecf783458889875f87e55bb0894674dceb2a4ab2184a5b5c1aa1df81534` |
| October 7 ledger QA report | `c13adf16601132e9e5460d94ab9f826e14a3ed63af56913bf24341e5ba0d345b` |
| October 7 non-full-path index (retained locally) | `e6a51f17361ba95a8138a4646e4e0fd3458150f40a2e791c09c73be34a2fe58a` |
| Terminal bucket 3/6/9 scope check | `12ac6d62a4581e26bc0dbda7057a78f362e423b79001bde957cb18db4fbcc3f2` |
| [Frozen bucket coverage](bucket-coverage-2026-10-07.csv) | `78dd18f6045fffd2405e9d06d9083f27c564f36e2afab6bf995599d8b54e5ce1` |
