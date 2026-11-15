# Cloudflare configuration as code

This directory keeps a **read-only, secret-free snapshot** of the estate's
Cloudflare configuration and a scheduled **drift check** that compares the
live account against it (THREAD_AUDIT C-29 / B-38). Nothing here changes
Cloudflare. Any change to the live account still goes through the owner's
approval. After a change lands, the baseline is refreshed by a reviewed pull
request.

| Path | What it is |
|---|---|
| `snapshots/2026-11-06/` | The first baseline: `manifest.json`, `zones/<zone>.json`, `account.json` |
| `cf_config.py` | Standard-library exporter, normalizer, snapshot verifier and drift check (`verify-snapshot`, `export`, `drift`) |
| `build_snapshot_20261106.py` | The provenance script that built the first baseline from the coordinator's captures |
| `test_cf_config.py` | Offline contracts against a local API stub (`python -I -B cloudflare/test_cf_config.py -v`) |
| `../.github/workflows/cloudflare-config-ci.yml` | Runs the offline contracts on every PR that touches this directory |
| `../.github/workflows/cloudflare-config-drift.yml` | Every 6 hours and on dispatch: offline contracts, then the live drift check when the token is configured |

This repository is private, and the snapshot belongs here only. Do not copy it
to a public repository.

## What the snapshot covers

Per zone (`a-11-oy.com`, `a11oy.net`, `szlholdings.com`):

- zone status, plan and name servers;
- DNS records;
- WAF custom rules and rate-limit rules, in order;
- configuration rules;
- bot-management settings;
- Monetization Gateway rules.

Per account:

- Workers: name, compatibility date and binding names and types;
- tunnels: name and id, with status and connection count kept as operational state.

Sizes in the 2026-11-06 baseline:

| Section | a-11-oy.com | a11oy.net | szlholdings.com |
|---|---|---|---|
| DNS records | 27 | 13 | 15 |
| WAF custom rules | 7 | 1 | 0 |
| Rate-limit rules | 1 | 0 | 0 |
| Configuration rules | 1 | 0 | 0 |
| Monetization rules (enabled) | 15 (4) | 2 (0) | 0 |

The account has 5 Workers and 9 tunnels: 3 down and 1 inactive at 16:11Z.

What the snapshot never contains:

- API tokens or token metadata;
- the audit log;
- account names, members, billing, and e-mail routing and destination addresses;
- Worker secret values;
- raw TXT values other than SPF and DMARC policy. Verification strings and DKIM keys are stored as SHA-256 plus length;
- raw `plain_text` binding values, which are stored as SHA-256.

`verify-snapshot` enforces this. It refuses e-mail addresses, bearer
credentials, PEM blocks, JWT-like and 40-character token-like strings, keys
named like `token` or `secret`, and undigested TXT or `plain_text` values. It
also checks every file's SHA-256 against `manifest.json` and refuses any file
the manifest does not bind.

### How the 2026-11-06 baseline was built

The coordinator's read-only captures were normalized with the same functions
the live check uses. The manifest records each source file's SHA-256 and write
time.

| Section | Source (file written, UTC) |
|---|---|
| zone, DNS (a-11-oy.com, a11oy.net) | `_cf/cf_audit.json` (15:06:12Z) |
| zone, DNS (szlholdings.com) | `_cf/szlholdings_zone.json` (15:25:25Z), `_cf/szlholdings_dns_after.json` (15:31:55Z), after the owner-approved onboarding |
| WAF, rate-limit and configuration rules | `_cf/inspect_1610.json` (16:11:23Z) for the rule list, order and enabled flags; `action_parameters` from `cf_audit.json` where description, expression and action are unchanged |
| bot management, Workers, tunnels | `_cf/inspect_1610.json` (16:11:23Z) |
| Monetization rules | `_cf/monetization_rules_1650.json` (16:26:29Z), with the three disables of `_cf/monetization_changes_1655.json` (16:27:21-25Z, HTTP 200 each) applied |

Ten values were not in any capture. Each is stored as
`{"$uncaptured": "<reason>"}`, and the drift check reports it as a
*baseline gap* rather than a match:

- 6 MX priorities;
- `action_parameters` of the 2 WAF rules added after 15:06Z;
- the rate-limit rule's thresholds;
- 1 `plain_text` Worker binding value.

Changes known to postdate a capture are listed under
`known_changes_after_capture` in the manifest. In particular, the 15:08:20Z DNS
record creation in a-11-oy.com (CLOUDFLARE_REPORT CF-8, `showcase.`) is not in
the baseline.

## Verdicts and exit codes

`python -I -B cloudflare/cf_config.py drift` compares every baseline section
with the live account:

| Section status | Meaning |
|---|---|
| `match` | Equal after normalization. Operational state (tunnel status and connections, Worker deploy timestamps, `using_latest_model`) is reported under `state_changes` and is never drift. |
| `drift` | Something was added, removed, changed or reordered. Rule order matters; DNS is compared as a set; Monetization rules, Workers and tunnels are compared by id or name. |
| `baseline-gap` | No drift, but the baseline marks a compared value as uncaptured. The live value is in the report. |
| `unverified` | The section could not be read, for example HTTP 403 because the token lacks a permission, or the zone is not visible. |

The run verdict is `DRIFT` (exit 1) if any section drifted. Otherwise it is
`INCOMPLETE` (exit 3) if any section is a gap or unverified, and `MATCH`
(exit 0) only when every section matches. A missing or malformed token is a
usage error (exit 2). The report (`outputs/cloudflare-drift.json`, gitignored; schema
`szl.cloudflare-drift-report/v1`) and a live export in snapshot layout are
uploaded as the `cloudflare-config-drift` artifact. A summary table is written
to the job summary.

## The live client is read-only

- `ReadOnlyClient` has one network method, `get`. It refuses API paths outside
  `/zones/...` and `/accounts/...`, path segments `.` and `..`, and query
  parameters other than `name`, `page`, `per_page` and `is_deleted`.
- The token is read from `CLOUDFLARE_READ_TOKEN`. It is sent only in the
  `Authorization` header to `https://api.cloudflare.com/client/v4`, with TLS
  verification. The tests use a loopback stub instead. The token is never
  printed, logged or written. The tests assert this for stdout, the report and
  the export.
- In the workflow, `harden-runner` blocks egress from the drift job except to
  `api.cloudflare.com` and the GitHub endpoints that checkout, Python setup
  and artifact upload need.
- The token is used only for runs of `refs/heads/main`.

This module is deliberately separate from
`maintenance/szl_estate/cloudflare_ops.py`, which can PATCH TLS settings. The
drift job's code path has no mutation capability. Only the token's own scope,
which Cloudflare enforces, can guarantee read-only access. Create it read-only,
as below.

## Owner steps

Until these are done, every scheduled run shows the drift job as **skipped**,
with the notice "Cloudflare drift check skipped". **No drift verdict is
produced.** The offline contracts still run.

1. **Create a read-only API token.** In the Cloudflare dashboard, go to
   Manage Account, then Account API Tokens (or My Profile, then API Tokens),
   then Create Token, then Custom token.
   - Permissions. All of them are **Read**:
     - Zone: Zone Read
     - Zone: DNS Read
     - Zone: Firewall Services Read
     - Account: Workers Scripts Read
     - Account: Account Rulesets Read
     - Payments Gateway Read (Monetization Gateway rules)
   - Zone resources: include the zones `a-11-oy.com`, `a11oy.net` and
     `szlholdings.com`.
   - Account resources: the estate account only.
   - TTL: set an expiry, for example 90 days. All 11 existing account tokens
     have none (THREAD_AUDIT C-31).

   The tunnel, bot-management and configuration-rule reads may need further
   read groups, likely *Cloudflare Tunnel Read*, *Bot Management Read* and
   *Config Settings Read*. This session did not call the Cloudflare API, so
   neither those names nor the list above were checked against the dashboard.
   A missing grant is never silent: the first run reports the section
   `unverified` with `HTTP 403`. Add the read permission Cloudflare names for
   it. Never grant an Edit permission.
2. **Add it to this repository.** In GitHub, open szl-holdings/szl-estate-os,
   then Settings, then Secrets and variables, then Actions, then New
   repository secret. Name it `CLOUDFLARE_READ_TOKEN` and paste the token. Do
   not paste the token anywhere else: not in a file, an issue or a chat.
3. **Run it.** In Actions, open "Cloudflare config drift" and run the workflow
   on `main`. Read the job summary and the `cloudflare-config-drift` artifact.
4. **Expect the first live run to be DRIFT or INCOMPLETE, not MATCH.** The
   15:08:20Z DNS record is not in the baseline, and ten values are marked
   uncaptured. Review the live export, then refresh the baseline in a pull
   request:

   ```bash
   CLOUDFLARE_READ_TOKEN=... python -I -B cloudflare/cf_config.py export --out cloudflare/snapshots/YYYY-MM-DD
   python -I -B cloudflare/cf_config.py verify-snapshot --snapshot cloudflare/snapshots/YYYY-MM-DD
   ```

   The drift check always uses the newest dated directory. Keep older
   snapshots as history. A live export that has unreadable sections cannot
   become a baseline: `verify-snapshot` rejects sections that carry an error.

## Not exported yet

These were not in the source captures:

- zone settings (TLS, HSTS);
- managed WAF ruleset overrides;
- redirect, cache and transform rules;
- Access applications;
- AI Gateway;
- R2 buckets;
- notification policies;
- certificates;
- Workers routes and custom domains.

C-29 also names AI Gateway, R2 and alert policies. Each needs its own read
permission and a normalizer before it can join the baseline.

## Proof boundary

A `MATCH` shows that the sections listed in the baseline, as normalized here,
equalled the live API reads at the recorded time. It does **not** show:

- that the edge behaves as intended (szl-org-health's edge contract checks
  that from an unpaid client);
- that sections outside the baseline are unchanged;
- that nothing changed between two scheduled runs;
- that the token is read-only. Cloudflare enforces the token's scope, not this
  code.

The baseline is a derived view of specific reads, labelled with their file
times, not a complete Cloudflare configuration export. The unit tests run
against a stub. They prove the tool's behaviour, not the account's state.
