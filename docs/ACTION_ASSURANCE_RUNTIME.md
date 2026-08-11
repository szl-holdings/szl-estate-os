# Action Assurance Runtime

The Action Assurance Runtime turns the Counterfactual Action Passport contract into a durable, queryable Estate OS subsystem without weakening the estate's read-only external boundary.

## What is operational

- Valid passports persist in the same SQLite database used by Estate OS by default: `outputs/estate.db`.
- Passport IDs are immutable. Exact re-ingest is idempotent; the same ID with different canonical bytes is rejected as a conflict.
- Every ingest persists its own result, citation-drift report, and modeled Trust Factor report.
- Trust Factor reporting is recomputed from the complete persisted valid-passport set.
- The runtime provides a local read-only dashboard and JSON API.
- Non-loopback serving requires both `--allow-remote` and `SZL_ACTION_CONTROL_TOKEN`.
- The HTTP surface exposes no write method. `POST`, `PUT`, `PATCH`, and `DELETE` return `405`.

## Commands

```bash
python ACTION_ASSURANCE_RUNTIME.py ingest \
  --passports fixtures/action_assurance/passports \
  --citations fixtures/action_assurance/citations.current.json \
  --source-label local

python ACTION_ASSURANCE_RUNTIME.py status
python ACTION_ASSURANCE_RUNTIME.py report
python ACTION_ASSURANCE_RUNTIME.py serve
```

Default server: `http://127.0.0.1:8788`

## API

```text
GET /healthz
GET /readyz
GET /api/v1/action-assurance/status
GET /api/v1/action-assurance/passports
GET /api/v1/action-assurance/passports?agent_id=<id>&decision=<decision>&limit=100
GET /api/v1/action-assurance/trust-factors
GET /api/v1/action-assurance/citations
```

## Persistence contract

Two tables are added idempotently to the existing SQLite database:

- `action_assurance_passports`
- `action_assurance_ingests`

A passport stores both the signed-payload digest declared by the contract and a SHA-256 digest of the complete canonical passport JSON. The complete digest is used for immutable-ID conflict detection.

An ingest with invalid passports, stale/divergent citation evidence, or immutable-ID conflicts records `FAIL`; it is not silently upgraded. A failed ingest can still persist valid, nonconflicting passports from that batch so the ledger preserves what was actually accepted. The failure record remains visible as the latest ingest until a later ingest supersedes it.

## Security boundary

This runtime does **not**:

- execute governed actions;
- mutate GitHub, Hugging Face, DNS, deployments, or production databases;
- generate or read ECDSA private keys;
- claim that `SIGNED_UNVERIFIED` inputs are cryptographically verified;
- convert a modeled Trust Factor into authority;
- make external citations true merely because they were locally well formed.

Managed signing and independent signature verification belong at the key-provider boundary. Estate OS continues to fail closed until that provider is explicitly configured and independently verified.

## CI gate

`.github/workflows/action-assurance-runtime.yml` compiles the runtime, runs the persistence regressions, performs a deterministic fixture ingest, and reads the durable status/report. The workflow has blocked egress except for pinned GitHub Actions infrastructure.
