# Offline frontier evidence explorer

The explorer turns three local inventory snapshots into a single portable HTML
file. It supports search, source/type/notice filters, pagination, and a facts
dialog containing source revisions and separate evidence, provider runtime,
authorization, signer, and readiness states. It does not fetch data or execute
repository code.

```powershell
python tools/frontier_dashboard/build.py --estate-dir outputs/estate --output outputs/frontier.html
python ci/test_frontier_dashboard.py -v
node --check tools/frontier_dashboard/app.js
```

Input files must use these collector schemas:

| File | Schema field and value |
| --- | --- |
| github_inventory.json | schema: szl.github-metadata-inventory.v1 |
| huggingface_inventory.json | schema_version: szl.huggingface_inventory.v1 |
| local_inventory.json | schema_version: 1.0 |

The builder checks schema identity, record/count consistency, duplicate
identities, full immutable revisions where supplied, and input byte/record
budgets. Missing revisions remain unavailable. Output cannot alias an input
inventory. The generated page records SHA-256 hashes of the exact bytes it
read; these hashes are unsigned and do not authenticate the collector.

This reader is independent from public housekeeping and the existing Estate OS
service. It does not import, invoke, or modify tools/estate_inventory.py,
production routes, the evidence database, publication gates, or provider state.
It consumes explicit local files and adds no scheduled collection or deployment.
The input schemas are documented here so an incompatible collector output fails
instead of silently becoming a misleading dashboard.

## Privacy and trust boundaries

Authenticated inventories may contain private asset names and local filesystem
paths. The generated HTML inherits that sensitivity. Keep it in ignored local
outputs; do not commit or publish it. No inventory data or generated page is
included with the source change. Test fixtures use synthetic asset identities.

The build uses the Python standard library and reads no credential store,
environment credentials, browser storage, or network endpoint. Embedded JSON
escapes HTML delimiters. Template substitutions run once so untrusted values
cannot become template instructions. The client renders metadata with
textContent, uses hash-bound scripts/styles, and blocks automatic network access
with Content Security Policy. Optional user-clicked source links are restricted
to HTTPS GitHub and Hugging Face URLs; they disclose the chosen asset URL to its
provider when opened. Exact remote revision links are derived from asset identity
and the validated revision.

Metadata never promotes readiness, authorization, or signer verification. A
RUNNING Space is shown as provider hosting state. The same repository may appear
as both a remote record and one or more local checkout observations; the page
does not sum those as unique estate assets.

## Validation and release limits

Offline tests cover serialization, malformed inputs, identity and digest
bindings, privacy boundaries, and output preservation. JavaScript syntax and
responsive/preference CSS can be checked without a browser. These checks do not
establish rendered behavior, accessibility conformance, Core Web Vitals, or
production readiness.

Before treating this as a production frontend pilot, verify the search and
detail flow, keyboard navigation and dialog focus, 320px layout, light/dark and
reduced-motion/high-contrast behavior in an allowed browser. Record that evidence
separately. A browser policy denial must remain a verification gap.

Rollback is removal of this additive tool, test, documentation and dedicated
workflow. No database migration, API transition, runtime deployment or provider
rollback is needed because this change has no such side effect.
