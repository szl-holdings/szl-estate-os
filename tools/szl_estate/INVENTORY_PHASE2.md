# Bounded Phase 2 inventory integration

This draft integrates existing frozen metadata and known local SZL checkout
metadata. It performs no GitHub/HF recrawl, source-body inspection, installation
or testing of other repositories, model/dataset retrieval, skill execution or
remote mutation. `betterwithage` identifies the connected execution computer
in the engineering request; it is not a GitHub organization inferred by this
tool. The frozen GitHub scope is `szl-holdings`. Broader GitHub/ai4science scope
needs explicit source evidence rather than an invented account or namespace.

Install the independent package using the existing small pinned build/test
closure, then run:

```text
python -m szl_estate inventory --backend-bundle EXISTING_BUNDLE.zip --hf-inventory EXISTING_HF.json --batch-size 64 --out NEW_OWNED_OUTPUT_DIRECTORY
```

No filesystem discovery occurs unless `--checkout-root` is explicitly supplied.
Repeat that option only for known authorized checkout/workspace paths. An
approved absolute `--git-executable` enables a config-only query from a private
empty directory; it never invokes Git from a checkout, runs status/diff,
follows includes, changes config, triggers hooks/filters/fsmonitor, or reads
working-file bodies. HEAD/ref/config reads are bounded Git metadata only.
Dirty state remains `null` / `UNKNOWN`; metadata does not prove a clean tree.
Worktree `.git` files and common-directory pointers are handled only within
validated explicit roots. Links/reparse points and denied paths are not walked.

The collector excludes credentials, `.env`, `.ssh`, Codex/session logs,
AppData, environments, node_modules, LFS/weights/checkpoints, dataset-row paths
and denied paths. Exclusions and caps remain visible. It preserves all existing
checkout and uncommitted work; no clean/reset/config edit/import/hook is used.

The bundle's repository metadata has an older 92-inspection baseline. Use the
latest content coverage, full file ledger and remaining inventory to reconcile
130 repositories / 120 public + 10 private, 32,748 pinned paths, 542 historical
static inspections and 32,206 unread/error/size-skipped paths. These are dated
observations, not current complete organization access. Gitlinks/symlinks and
unknown sizes/digests retain their types and unknowns. Eleven inspected rows
lack content digests; names/extensions/receipt presence cannot establish
loadability, scientific validity, training eligibility or behavioral safety.

The first selected file batch is a bounded proposal for later inspection.
Metadata integration does not reduce the unread content count. Existing
frontier source targets can receive explicit proposed priority through
`--priority-repo`; they are not automatically required masters. Only explicit
owner designation through `--master-repo` establishes that planning input.
Private file paths remain withheld by the conservative publication policy,
with counts and exclusions retained rather than a false completeness claim.

Outputs include a provenance-bound state envelope, aggregate inventory JSON,
per-repository batch-plan CSV, permitted pinned file-metadata JSONL, local
checkout metadata JSON and a human report. Large file indexes remain runtime
artifacts; no 32,000 source copies are created. Output requires a new owned
directory outside inspected checkouts, preserving prior and interrupted files.
CSV formula cells are neutralized. The human report contains aggregate counts
and fixed control labels rather than source paths or untrusted error text.

Successful integration can establish `report_ready` or `batch_ready` for its
narrow metadata operation. Full `phase2_ready` and `estate_ready` remain false
until actual current scope/visibility, coverage, local controls and applicable
behavioral/release evidence are verified. A partial inventory exits 1; input
or output failure exits 2. Neither exit is silently forced to success. The
Phase 0 setup gate remains a separate package/test/narrow-account decision.

No original payload/bytecode, borrowed PCM calibration/gates or real
`test.jsonl` is loaded. The Phase 1 static conflict and NOT_RUN fixture backlog
stays separate from this collector. Static results never establish behavioral
safety, and no quality/benchmark/promotion score is invented.
