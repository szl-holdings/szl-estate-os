# Anatomy gate — evaluate_body_gate

**Surface:** private `szl-holdings/szl-estate-os`  
**Kind:** admission-gated kernel spec of an existing estate, not a new public product  
**Public freeze:** still in force. This PR does not mint a GitHub public repo, Hugging Face Space, model, dataset, kernel, collection, or product name.

## Distinct from szl-khipu

| Kernel | Question | Not |
|---|---|---|
| `szl_khipu.anatomy.evaluate_anatomy` | Are the five organs LIVE? | Commercial authorization |
| `estate.anatomy_gate.evaluate_body_gate` | May this commercial action pass the body? | Live BFT, ATO, ROI |

Do not collapse the two. Do not brand this as a second Anatomy kernel on a new public surface.

## No bandages

The body is not a UI warning. The ledger calls `evaluate_body_gate` / `body_blocks_action` **before** status can become APPROVED or OVERRIDDEN.

- Blocked APPROVE/OVERRIDE writes `anatomy.block` (SHA-256 receipt) and **leaves status QUEUED**
- HOLD and ROLLBACK are never blocked
- Golden vectors in `fixtures/anatomy_gate_vectors.json` are the shared truth with the Estate OS demo

## What it gates

- `lyte.approve` — blocked unless body ALLOW
- `lyte.override` — WILLAY vetoes override-without-reason (≥8 char written reason)
- `estate.admit` — DENY while Wave 0 unsigned (no new public surface)
- `wave.unlock` — DENY while skeleton abstains

## Quorum (Conjecture 2, MODELED)

Witnesses: HEART, WILLAY, CIRCULATORY, SKELETON.

- 3-of-4 ALLOW required
- WILLAY veto is absolute
- SKELETON abstains while Wave 0 is unsigned
- BRAIN and NERVOUS observe during perfusion; they do not vote

This is **not** a live multi-party consensus network.

## Perfusion

A case travels WILLAY → BRAIN → HEART → CIRCULATORY → NERVOUS → SKELETON as blood. Each organ votes or observes. The body verdict is receipted and stamped on the case overlay. MODELED.

## Inca decimal

Standing DENY fixture: LYT-1041, LYT-1042, LYT-1044, LYT-1045 → **$76,500 MODELED held**.

## Files

- `estate/anatomy_gate.py`
- `estate/khipu_number.py`
- `estate/anatomy_gate.json`
- `fixtures/anatomy_gate_vectors.json`
- `ci/test_anatomy_gate.py`

## Hugging Face

Consolidate into existing [`SZLHOLDINGS/anatomy`](https://huggingface.co/spaces/SZLHOLDINGS/anatomy). Do not mint a second Space. This sandbox has no HF writer.

## Do not

- Invent 9000 live nodes
- Claim ATO, paid pilot, ROI, or live BFT
- Dump a Grok sandbox onto GitHub
- Treat nexus or szl-khipu as new front doors
- Lead investors with repository, Space, formula, or 9000-node counts

Public terminal outcome remains `NO_MUTATION_READ_ONLY_STRATEGY` until Wave 0 is signed.
