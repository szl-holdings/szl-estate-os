# `szl-command-lab` PR #56: postmerge effects

Read-only observation on 2026-10-08. Identity: [PR #56](https://github.com/szl-holdings/szl-command-lab/pull/56) merged at `2026-10-08T10:34:55Z`; [`main` merge commit `8a5670938f02200b0090a9698fab92af0f1d7eee`](https://github.com/szl-holdings/szl-command-lab/commit/8a5670938f02200b0090a9698fab92af0f1d7eee) was the current branch head at observation. The commit changed only `tests/test_launchpad.py` (+8 lines).

The GitHub Actions API returned **five** runs for that exact head SHA (`total_count: 5`), all `push` events, completed with `success`:

| Workflow | Run | Observed jobs/effects |
| --- | --- | --- |
| base-python-ci | [37764413602](https://github.com/szl-holdings/szl-command-lab/actions/runs/37764413602) | Python 3.11 and 3.12 jobs succeeded; toolchain/package installs, Ruff and pytest steps succeeded. |
| Node source CI | [37764413640](https://github.com/szl-holdings/szl-command-lab/actions/runs/37764413640) | Node 22 and 24 jobs succeeded; `npm ci`, typecheck, tests and build steps succeeded. |
| SZL Public Experience v3 Contract | [37764413686](https://github.com/szl-holdings/szl-command-lab/actions/runs/37764413686) | Local browser/gateway and static/typed contract jobs succeeded. The PR-only Docker job was skipped. Screenshot/measurement/log artifact `atlas-responsive-8a5670938f02200b0090a9698fab92af0f1d7eee` (artifact ID `11543616921`) was uploaded to GitHub Actions. |
| Scorecard | [37764414799](https://github.com/szl-holdings/szl-command-lab/actions/runs/37764414799) | Scorecard, artifact upload and code-scanning upload steps succeeded. `scorecard-results` artifact ID `11544106161` exists. |
| CodeQL | [37764414531](https://github.com/szl-holdings/szl-command-lab/actions/runs/37764414531) | Python and JavaScript/TypeScript analysis jobs succeeded. The [pinned reusable workflow](https://github.com/szl-holdings/.github/blob/81bffda96e1a906397b9a921f0ff65df80f14cae/.github/workflows/reusable-codeql.yml) grants `security-events: write` and runs CodeQL analysis. |

## Credential, publication and deployment boundary

- The [Hugging Face sync workflow at the merge SHA](https://github.com/szl-holdings/szl-command-lab/blob/8a5670938f02200b0090a9698fab92af0f1d7eee/.github/workflows/hf-sync.yml) has a `main` push path filter that excludes `tests/test_launchpad.py`. There is **no HF sync run at this merge SHA**, so no HF credential acquisition, Space sync/deploy, source-binding probe, or deploy attestation is observed from PR #56. The GitHub Deployments API returned no deployment for the SHA. A successful HF sync on the preceding `main` SHA `75f7c8e3a28ff7c9c4d7664330fd387f670d7630` is a separate event.
- The [Scorecard caller](https://github.com/szl-holdings/szl-command-lab/blob/8a5670938f02200b0090a9698fab92af0f1d7eee/.github/workflows/scorecard.yml) grants `id-token: write`, `security-events: write` and passes `secrets: inherit` to the [pinned reusable workflow](https://github.com/szl-holdings/.github/blob/8dfc69d1de7ec825294e5b5407cf96097106de4e/.github/workflows/reusable-scorecard.yml). That reusable workflow defaults `publish-results` to `true`. Its Scorecard, artifact and SARIF upload steps succeeded. Run metadata does not independently prove OIDC issuance or external OSSF database acceptance. No credential values or run logs were accessed.
- The other observed external writes were GitHub Actions artifacts and code-scanning results. The browser workflow's test gateway was local to the Actions runner; the successful job is not evidence of a live service release.

Sources: GitHub REST PR, commit, branch, exact-head workflow runs, job steps, artifacts and deployments; workflow source pinned to the merge commit or called reusable-workflow commit. This report did not execute source or inspect secret values, run logs, protected data, or live HF state.