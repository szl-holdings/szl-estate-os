# SZL Holdings open PR census — 2026-10-08

This is a **read-only, time-bounded GitHub metadata census**, not a merge clearance or a source audit. The authenticated account can see [141 repositories](october-8-refresh.md), including private and archived repositories where permitted. The repository inventory was collected at 10:04:35 UTC. Open PRs changed while this review ran, so the rows below are a combined **10:25–10:52 UTC observation window**, not one atomic organization-wide snapshot. Re-read the individual PR, its current head and base, checks, rules, reviews, and main-push effects before acting.

## Complete accessible-repository coverage

- The [67-row open PR ledger](open-pr-census-2026-10-08.csv), SHA-256 `189DF1E3203D080C810869045EEE208020876B2A0E445960D2C7E0DEC1EB60FD`, has each repository's immutable database and node IDs, PR number, head/base OIDs, draft and merge states, changed-file count, and UTC ISO-8601 timestamps. REST PR lists and separate GraphQL status reads matched head/base OIDs for all 67 frozen rows. Current mergeability remains mutable.
- Direct REST `GET /repos/szl-holdings/{repo}/pulls?state=open&per_page=100` was used for all 141 visible repositories. The [127-repository proof ledger](open-pr-repository-sweep-2026-10-08.csv), SHA-256 `CE99B4FF9E1CB0347BF01CEE75C8E4955407A75F2176080196AE5D106677A74D`, records 125 zero responses and two PRs that were open during its 10:32:29–10:36:00 UTC sweep. The other 14 repositories were listed directly in the census pass. Every direct list returned fewer than 100 rows, so page 1 was terminal for each; no REST request failed. Link headers were not saved.
- The two additional PRs found in the 127-repository sweep, anatomy #90 and frontier-bench #28, were merged at 10:37 UTC and returned zero open PRs on the later direct read. Command Lab #56 also merged and returned zero. The final combined readback is **67 open PRs in 13 repositories**; 128 repositories returned zero on their latest direct read. These readings were not simultaneous.
- GitHub organization search was useful for discovery but did not surface anatomy #90 or frontier-bench #28 in the sampled search responses; their open intervals and the search collection times differed. Search also temporarily lagged behind the new A11oy #2679. Its `incomplete_results=false` flag did not establish complete real-time coverage. The direct per-repository lists are the coverage basis.

| Repository | Frozen open PRs |
| --- | ---: |
| `a11oy` | 21 |
| `platform` | 26 |
| `.github` | 6 |
| `szl-frontier` | 3 |
| `lyte-lattice`, `szl-forge` | 2 each |
| `a11oy-factory`, `lutar-lean`, `szl-energy-attest`, `szl-formulas`, `szl-hf-frontier`, `szl-org-health`, `szl-typesafe-triage` | 1 each |

Of the 67 ledger rows, 24 are drafts and 43 are non-drafts. GitHub returned 22 `BEHIND`, five `BLOCKED`, seven `CLEAN`, 11 `DIRTY`/conflicting, five `UNSTABLE`, and **17 `UNKNOWN`** merge states during base recomputation. No all-PR exact-head check or effective required-check aggregate was established. A `CLEAN` or green check summary alone does not qualify a PR for merge.

## State changes observed during collection

| PR | GitHub transition | Immutable identity / significance |
| --- | --- | --- |
| [szl-forge #582](https://github.com/szl-holdings/szl-forge/pull/582) | Merged 10:01:34 UTC | Head `d2434d11292248d95075e0bfc8666ae11dbe12d1`; merge commit `ca20fbe716e234dc998da28bf0c4572d8055d058`. It is not in the open queue. Its main-push credential effects require separate outcome review. |
| [szl-command-lab #56](https://github.com/szl-holdings/szl-command-lab/pull/56) | Merged 10:34:55 UTC | Head `0704a438513eb3eb00d28fb008abe5ca8ec9faa8`; merge commit `8a5670938f02200b0090a9698fab92af0f1d7eee`. Previously held credential-related workflow effects must be evaluated against actual run outcomes. |
| [anatomy #90](https://github.com/szl-holdings/anatomy/pull/90) | Open during direct sweep; merged 10:37:08 UTC | Head `91ba252ccde4347983912abe6f3656663ab3c4c7`; merge commit `6066315e1de3dc3f17cf164a10fa708a64806c15`. |
| [frontier-bench #28](https://github.com/szl-holdings/frontier-bench/pull/28) | Open during direct sweep; merged 10:37:19 UTC | Head `5e557b99627d2d16936fce346d37c7a4638e81a7`; merge commit `a7b89eeb1c9aca5cae2cd046ec684c3f05f8c355`. |
| [a11oy #2677](https://github.com/szl-holdings/a11oy/pull/2677) | Merged 10:37:36 UTC | Head `f2ea333e950c4d7660c10a7f0170a92cf144a103`; merge commit `294937217445c137782e3576ccd5d07e300c12d5`. |
| [a11oy #2680](https://github.com/szl-holdings/a11oy/pull/2680) | Opened 10:36:42 UTC | Frozen head `111b9c8377b47abde7543212a194a6cd499d1d88`; non-draft, `BEHIND`. |
| [szl-forge #583](https://github.com/szl-holdings/szl-forge/pull/583) | Opened 10:43:39 UTC | Frozen head `8a19f593538943da6e5c6d395a51f973acc44962`; draft, `BLOCKED`. |
| [szl-hf-frontier #70](https://github.com/szl-holdings/szl-hf-frontier/pull/70) | Marked ready 10:27:34 UTC | Head `4060c2fc3dced84860bef5d153b1b875321d99da`; non-draft but `BLOCKED`, with independent final security review in progress. |

The merged Forge and Command Lab PRs have separate [Forge #582](forge-582-postmerge-effects.md) and [Command Lab #56](command-lab-56-postmerge-effects.md) main-push effect reviews. Forge's scoped portfolio checks passed but left artifact/runtime validity unevaluated; Command Lab's test-only merge did not trigger its HF sync path filter.

## Sequential review queue

1. **[szl-energy-attest #58](https://github.com/szl-holdings/szl-energy-attest/pull/58)** — first source-review candidate outside the held Frontier/Command Lab work. Pinned head `5699abb9383637714364c8c255101291b7d3afb0`, base `7823d106a8ecf056fa735af405cb658829a3f309`. The draft changes `szl_energy_attest/meter_proxy/proxy.py` and `tests/test_proxy_requester_privacy.py` to keep request credentials out of receipt attribution. An independent exact-head review found both new privacy tests skipped in hosted CI because the proxy extra was not installed; hold until those tests execute at the updated head. One-PR check read showed 11 successful contexts and a skipped publish job; it was `CLEAN` at readback, but the draft and source-review state block merge. The [pinned PyPI workflow](https://github.com/szl-holdings/szl-energy-attest/blob/7823d106a8ecf056fa735af405cb658829a3f309/.github/workflows/publish-pypi.yml) runs a build/gate on matching Python PRs and publishes only on a published GitHub Release, so a merge alone is not evidence of a PyPI release.
2. **[szl-hf-frontier #70](https://github.com/szl-holdings/szl-hf-frontier/pull/70)** — finish the independent cross-provider token-routing review and inspect current exact-head checks and effective rules. It is now non-draft but `BLOCKED`; do not infer approval from the draft transition.
3. **[szl-forge #583](https://github.com/szl-holdings/szl-forge/pull/583)** — review archive handoffs and ReceiptAgent copy against model holds, source boundaries, and the now-merged #582 main. It is a new draft and `BLOCKED`. Verify main workflow effects before any future merge.
4. **[a11oy #2660](https://github.com/szl-holdings/a11oy/pull/2660)** — coordinate the sovereign effects/receipts router review with ongoing client timeout work to avoid duplicate or conflicting changes. The frozen row is `DIRTY`/conflicting. Inspect its changed files and current head before proposing a fix.
5. **[platform #909](https://github.com/szl-holdings/platform/pull/909)** — dependency security fix remains draft/conflicting; the one-PR read showed failing vulnerability, Grype, unit, and blocking security gates. Preserve the gate rather than bypassing it.
6. **[platform #901](https://github.com/szl-holdings/platform/pull/901)** — one-file docs change (`.github/SURFACE_MAP.md`), but it is `BEHIND` and its one-PR read showed failing vulnerability/CVE/security gates. Review main-push side effects and only proceed after exact-head qualification.
7. Work through the remaining ledger rows **one repository and PR at a time**, with source pin, reviewed path coverage, current head/base, changed filenames, current required checks, unresolved reviews, and main-push side effects recorded before each decision. The October 3 triage is historical evidence, not current merge authorization.

No PR was merged or pushed by this census worker. No repository source, tests, model, training job, or live service was executed. Repository metadata access was complete for the account; exact current-head semantic review, all-PR check coverage, current effective branch rules, and other post-merge credential/workflow outcomes remain separate tasks.