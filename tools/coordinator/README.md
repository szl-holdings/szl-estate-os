# SZL read-only coordinator (payload 2.2.0)

Read-only evidence collector. It appends one hash-chained receipt per run under
`<work root>/szl_execution_receipts/`, and can optionally sign the chain HEAD (DSSE, Ed25519).
It never pushes, merges, deploys, deletes, or touches credentials, VMs or jobs.

    python -I -B tools/coordinator/szl_coordinator.py                    # run (exit 0/2/3/4/5/6)
    python -I -B tools/coordinator/szl_coordinator.py verify [--pubkey F] # offline check
    python -I -B tools/coordinator/szl_coordinator.py keygen --out DIR    # new key pair

The tests run in CI (`self-test` job). The mutant check (31 mutants, about 15 min) runs locally:
`python -I -B tools/coordinator/mutate_szl_coordinator.py`. It exits 0 only if every mutant is
killed and no test is skipped.

Limits: the Ed25519 code is pure Python and not constant-time, so it is for local operator keys only.
The lock assumes a local filesystem. A crashed run leaves `.chain.lock` for an operator to remove.
`PREPARED` means every probe ran, not that any HOLD/PENDING/UNKNOWN item is resolved.
