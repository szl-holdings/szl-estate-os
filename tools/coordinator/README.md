# SZL read-only coordinator (payload 2.3.0)

Read-only evidence collector. It appends one hash-chained receipt per run under
`<work root>/szl_execution_receipts/`, and can optionally sign the chain HEAD (DSSE, Ed25519).
It never pushes, merges, deploys, deletes, or touches credentials, VMs or jobs.

    python -I -B tools/coordinator/szl_coordinator.py                    # run (exit 0/2/3/4/5/6)
    python -I -B tools/coordinator/szl_coordinator.py verify [--pubkey F] # offline check
    python -I -B tools/coordinator/szl_coordinator.py keygen --out DIR    # new key pair

Ownership gate (2.3.0): the `ownership_reconciliation` step is PASS only for a valid lane lease
checked by `szl_lane_lease.py`, loaded from beside the coordinator. Set `SZL_LEASES_DIR`,
`SZL_LEASE_REPO`, `SZL_LEASE_PATHS` (comma-separated) and `SZL_LEASE_CLAIMANT`;
`SZL_LEASE_BASE_SHA` is optional because the base is read from git at the work root. Without a
valid lease the run records BLOCKED and exits 2 (fail closed). Lease commands: acquire, release,
check, list (see the module docstring). Leases expire within 24 h, are never overwritten or
deleted, and overlapping unexpired leases block each other.

The tests run in CI (`self-test` job): `test_szl_coordinator.py` and `test_szl_lane_lease.py`.
The mutant checks run locally and in the `coordinator-mutation` job of Estate OS CI, on
pull requests that touch `tools/coordinator/**` or `.github/workflows/ci.yml`, and weekly
against main. The job is fail-closed: it exits non-zero on any unjustified survivor.
`python -I -B tools/coordinator/mutate_szl_coordinator.py` runs
31 mutants (about 15 min) and exits 0 only if every mutant is killed and no test is skipped.
`SZL_COORD_PATCHED=tools/coordinator/szl_coordinator.py python -I -B tools/coordinator/mutate_szl_lane_lease.py`
runs 43 lease mutants (3 recorded as equivalent) and 6 coordinator-integration mutants.
The coordinator path is resolved against the process working directory, not the temporary mutant work dir.

Limits: the Ed25519 code is pure Python and not constant-time, so it is for local operator keys only.
The chain lock and the lease lock assume a local filesystem. Lease files are hashed, not signed. A crashed run leaves `.chain.lock` for an operator to remove.
`PREPARED` means every probe ran, not that any HOLD/PENDING/UNKNOWN item is resolved.
