# Public housekeeping evidence

`Estate Housekeeping` runs each Monday at 13:00 UTC, or manually on `main`.
It publishes one 30-day Actions artifact, `estate-housekeeping-public-<run>-<attempt>`,
containing only `estate_state.json`. It never commits, pushes, merges, changes
provider settings, or claims deployment authority.

The collector uses Python 3.12's standard library: there is no package install
or runtime dependency resolution. Actions use the same immutable pins as the
main CI/readiness workflows. Checkout does not persist its read-only credential.
The collector itself never reads environment tokens or cached provider login.

## Coverage and privacy boundary

- Anonymous GitHub organization repositories and Hugging Face models/datasets.
- Only rows explicitly marked `private: false` and belonging to the requested
  organization are retained. Unknown/private/malformed rows are omitted and
  make the source `PARTIAL`.
- The artifact allowlists identity, visibility, numeric counters and GitHub
  archive/fork flags. It excludes README/card text, descriptions, raw provider
  responses, configuration and error bodies.
- Spaces, collections, domains, private resources, file contents, training,
  runtime behavior and README-based retirement/classification are not assessed.
- `MEASURED` means all three bounded public listings were collected without
  detected errors. It is not an organization-wide completeness claim or an
  atomic snapshot. `complete_estate` and `runtime_verified` remain `false`.

Requests have 15-second timeouts, a 4 MiB response cap, no redirects or ambient
proxy credentials, and at most 20 pages per source. GitHub page numbers are
constructed on the original public-organization endpoint; Hugging Face next-page
links must stay on the same HTTPS endpoint and preserve the author query. Errors, duplicate
records, pagination cycles and limits produce `PARTIAL` and a nonzero exit.
The exact partial snapshot is still uploaded by the workflow; a failed job must
not be reinterpreted as an empty or complete inventory.

## Local verification

```powershell
py -3.12 ci/test_estate_inventory.py -v
py -3.12 tools/estate_inventory.py --out outputs/housekeeping/estate_state.json
```

The snapshot uses `szl.estate-housekeeping-public/v2`; consumers must not expect
the old heuristic `github_repos`/`hf_assets` representation. Authenticated estate
audits remain a separate workflow and must not be uploaded through this public
artifact lane. A resource observed publicly could later become private; artifact
retention does not retroactively revoke already observed public metadata.

API references: [GitHub organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)
and [Hugging Face Hub endpoints](https://huggingface.co/docs/hub/api).
