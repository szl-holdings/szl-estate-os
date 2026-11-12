# Provenance of this package

Status: internal draft; synthetic-only; not integrated with SZL; no release authority. No license file is included: the destination repository's license and owner decide that.

## Source

| File | Origin | SHA-256 |
|---|---|---|
| offline_ci_intake.py | mission file lines 897-1264 | `37143f6fc87d5be32b370f22a2822161dc5a98e89b3088e7af8746010e0678c1` |
| test_ci_intake.py | mission file lines 1273-1577 (sha256 `cb097423b67125717088f3371d4d0bfd9d8736171f88df58d99b917d47d9b639`) plus 3 revision-format tests | `44d772df7bb7033928cca82630577eb5f7dcd274e742965c9ea6e2841a17ddf9` |
| sample_input.json | mission file lines 1586-1629 | `13ad005af6d519a86f4aa048aef17dd7f1638385c22c3c59ea9072f8f2d79ebf` |
| sample_result.json | mission file lines 1638-1795 | `068141c3d027b75f4ddd3c871180eda95111fd19f61f3e2a6635f919604dd351` |
| README.md | mission file lines 820-889, plus a dated verification note | see SHA256SUMS |

Mission file: `SZL_CLAUDE_BUILD_TRAINING_EVIDENCE_MISSION (5).md`, 426,103 bytes, sha256 `69d47427a38cbc77ac1c1da9def921916a933b5a265e167a045463e3cd515064` (prepared 2026-10-23).

## Recorded runs

| Date (UTC) | Where | Suite | Result | Evidence class |
|---|---|---|---|---|
| 2026-10-23 | original author host | 45 tests | OK | REPORTED in the mission file |
| 2026-10-28 | szl-vm1, Python 3.10.12, job ed5893dd | 45 tests | OK; CLI on sample_input.json exits 2 (REQUIRES_REVIEW), output byte-identical to sample_result.json | MEASURED |
| 2026-11-03 | szl-vm2, job 8a17028e | 45 and 48 tests | both OK on this code | MEASURED |
| 2026-11-10 | szl-vm2, Python 3.10.12, this package | 48 tests | OK; CLI exit 2; CLI output identical to sample_result.json: yes | MEASURED |

## Mutants (deliberately broken copies; a suite should fail on each)

| Mutant | 45-test suite | 48-test suite |
|---|---|---|
| input validation disabled (`_require` no-op) | caught: 9 failures, 5 errors (2026-10-28) | not re-run |
| revision regex accepts any string | caught by 1 test | caught by 3 tests (21 failing cases) |
| revision regex accepts only 40-hex | NOT caught | caught by the 64-hex positive control |

These are synthetic offline checks. They do not qualify a live collector, an adapter integration, or a release.
