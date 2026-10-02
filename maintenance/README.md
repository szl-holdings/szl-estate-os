# SZL maintenance runner 2.1.2

This directory contains the Python source for the attached estate maintenance
build. It is a separate, explicitly invoked tool alongside Estate OS. The
existing Estate OS audit and proposal commands retain their read-only contract.

Run `python szl_operational.py --help` from this directory. The default command
audits GitHub `szl-holdings`, Hugging Face `SZLHOLDINGS`, and the two Cloudflare
zones `a-11-oy.com` and `a11oy.net`. It writes dated JSON and Markdown receipts
under `runs/`. Exit 2 retains incomplete inventory, drift, missing credentials,
and uncertain writes as explicit blockers.

On Windows, run `setup.ps1`, then `run-szl.ps1`. Setup creates a separate runtime,
installs the exact dependency lock, and runs the offline regression suite.
See [WINDOWS-RUNBOOK.md](WINDOWS-RUNBOOK.md) for the supported local setup.

`--apply` is deliberate. It enables only the controller's closed metadata and
settings operations: additive GitHub topics and two scoped issue destinations,
reviewed Hugging Face card decisions and migration evidence, and the named
zones' reviewed TLS settings. It does not merge source, train models, certify
inference, deploy products, or establish sole-writer ownership across machines.

Release order is canonical GitHub source and its checks, then the declared
Hugging Face publisher and immutable readback, then deployed domain source,
readiness, and allowed functional probes. Asset revisions, application health,
and retained failure evidence remain separate gates.

GitHub credentials use the existing CLI login or process environment. Hugging
Face uses the existing Hub cache or process environment. Cloudflare uses process
environment or the exact current-user Windows Credential Manager target
`SZL/Cloudflare/estate-api-token`. See [CLOUDFLARE-AUTH-SETUP.md](CLOUDFLARE-AUTH-SETUP.md).
Credential values are never accepted as command-line arguments or written into
source or reports.

The reviewed policy is configuration, not a perpetual approval. Changed card
revisions require immutable content and canonical source review. Current
provider observations are emitted by a fresh run; this source directory makes
no claim that every estate application is operational.

Validation: from this directory, run `python -m pytest -q`. The release was
locally verified on Windows with 105 tests and 18 subtests. Hosted CI executes
the same suite independently on Linux.

The October 1 card review advances eight explicitly reviewed immutable pins.
Each entry binds the canonical GitHub card bytes and its dated review in
`review_evidence/`. Four Nano cards preserve truthful synthetic limitations;
four reference cards were published by the canonical consumer and read back
with unchanged artifact manifests. These decisions establish card parity
and preserve model admission limits. Other card pins and legacy migration
evidence retain their original review timestamps.
