# Bounded pinned source review

The additive `python -I -m szl_estate.source_batch` reader accepts an explicit
Phase 2 proposal, its expected SHA256, the original pinned file index, a new
owned output directory, an existing approved absolute GitHub CLI executable,
and the exact audit base commit. `--help` performs no reads or writes.

Install this independent package before invoking the module. The reader uses
existing GitHub authorization for fixed GET endpoints only. It never runs,
imports, renders, installs, tests or repairs candidate repository code. There
is no write API, deployment or merge executor. All required flags are explicit;
there is no default output directory or default remote scope.

The plan is capped at 64 regular text blobs and 1 MiB declared bytes; a file is
capped at 256 KiB. The reader checks plan and index digests and exact membership
before creating outputs. Fresh public visibility is required. Pinned commits,
nonrecursive trees and canonical Git tree hashes establish selected path
membership; exact size and Git blob hashes establish byte identity. Tree
truncation, shape errors, cursor loops, mismatched identities, unknown HTTP and
partial failures never produce a successful read. Limits are 128 actual HTTP
attempts, 64 actual tree attempts, 512 KiB per response and 20 seconds per
owned GitHub subprocess. A validated numeric Retry-After of at most two seconds
allows one retry; other backoff headers stop collection.

Only bounded screened/redacted UTF-8 text and selected provenance are cached.
Binary/LFS content, sensitive records, private keys and ambiguous multiline
credential blocks are withheld. A block match is a conservative policy decision,
not proof that a source file contains an actual credential. Cache text preserves
line numbering; redacted files can receive only PARTIAL static review. Original
and cache hashes are separate. Tokens, authorization/cookie headers, arbitrary
API bodies, subprocess error bodies and source bodies are absent from reports.

Every file records COMPLETE, PARTIAL, SKIPPED or ERROR byte and static statuses
separately. Static review is a later human assessment; runtime remains NOT_RUN.
Git hashes do not establish signed authorship, security, scientific validity,
benchmark correctness, license eligibility or deployment behavior.

Progress is atomic and interrupted outputs are preserved. Existing output
directories are rejected; recovery selects a new explicit directory. The typed
offline cache loader rehashes unchanged cache bytes before granting byte credit;
serialized LIVE/COMPLETE labels cannot grant fresh proof. Redacted cache bytes
cannot reconstruct the original blob, so they require a new bound read for
original-byte credit. This command does not silently resume an interrupted
network run or overwrite its saved files.

Coverage uses exact repository/commit/path/blob identities. Historical baseline,
new verified reads and overlap are separate; mirrored paths and identical blob
objects are counted independently where appropriate. Unsupported metadata names
remain unread and cannot abort otherwise valid selected-path accounting. The
full estate denominator is retained, including excluded and private paths.

The reader returns exit 1 / PARTIAL after collection because static review and
estate controls remain incomplete. Input/runtime failures return exit 2. A
bounded report cannot establish whole-repository or estate readiness. Source
findings are pinned snapshots routed to existing owners; repair requires fresh
head revalidation. See `estate_reports/content_batch1_review.md` in the audit
repository for the first actual batch and its remaining acceptance checks.
