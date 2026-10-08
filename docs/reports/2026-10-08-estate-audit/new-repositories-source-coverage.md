# Newly added SZL repositories: first source review

Date: 2026-10-08. This is a read-only, commit-pinned review of the two repositories added after the 2026-10-03 census. Both `main` heads matched the pins when checked on 2026-10-08. GitHub tree responses were untruncated. File coverage below describes content actually read, not merely metadata returned by the tree API. No source, tests, or helper scripts were executed; no live endpoints or image assets were opened.

## `szl-holdings/agents-studio`

- GitHub repository ID: `1409740536`; private, unarchived.
- Commit: [`77e78631657bbcfbbf46110e704f3519d878e38c`](https://github.com/szl-holdings/agents-studio/tree/77e78631657bbcfbbf46110e704f3519d878e38c).
- Tree: 39 entries, including 34 blobs; untruncated.
- Full content read (3): `AGENTS.md`, `README.md`, `.github/workflows/ci.yml`.
- Targeted portions read (5): `app.py` function signatures; `cloud_connection.py` constants, function signatures, and selected `fetch`, source validation, and readiness code; `studio.py` signatures and HTTP route/guard snippets; `studio/studio.js` local API and browser-storage call sites; `tests/test_cloud_connection.py` test names. None of these five files received a full semantic review.
- Content unread (26): `.gitignore`, `Launch-Studio.ps1`, `Start-Agents.cmd`, `agent.json`, `new_agent.json`, `new_agent.py`, `run-new-agent.ps1`, `run.ps1`, `session_control.py`, `session_lock.py`, `session_recovery.py`, `studio/favicon.png`, `studio/index.html`, `studio/studio.css`, `studio/vendor/LICENSE-lucide.txt`, `studio/vendor/LICENSE-marked.md`, `studio/vendor/lucide.min.js`, `studio/vendor/marked.umd.js`, `tests/test_app.py`, `tests/test_control_transport.py`, `tests/test_new_agent.py`, `tests/test_run_new_agent.ps1`, `tests/test_session_lock.py`, `tests/test_session_recovery.py`, `tests/test_studio.py`, `tests/test_studio_frontier.py`.

The pinned source defines a local Windows Python and browser workspace. [`studio.py`](https://github.com/szl-holdings/agents-studio/blob/77e78631657bbcfbbf46110e704f3519d878e38c/studio.py) binds `127.0.0.1`, checks Host, Origin, and a local capability, serves static files, exposes local state/job/submission GET routes, and accepts local job, cancellation, and reconciliation POSTs. The browser's observed API calls target those local routes. [`cloud_connection.py`](https://github.com/szl-holdings/agents-studio/blob/77e78631657bbcfbbf46110e704f3519d878e38c/cloud_connection.py) defines a fixed, credential-free observation of `https://szlholdings-szl-router-control.hf.space` at `/api/source`, `/readyz`, and `/readyz/inference`. It treats source match, control readiness, and inference configuration separately. No live call was made during this review, so current hosted state is unknown.

The pinned [CI workflow](https://github.com/szl-holdings/agents-studio/blob/77e78631657bbcfbbf46110e704f3519d878e38c/.github/workflows/ci.yml) runs offline Windows Python and PowerShell contracts plus JavaScript syntax checks on main pushes and pull requests. The exact pinned commit has a successful [`studio/windows-contract` check](https://github.com/szl-holdings/agents-studio/actions/runs/37729521677/job/113155238169), completed 2026-10-08 04:53 UTC. This establishes that CI job's reported outcome; it does not establish local operation, cloud deployment, provider inference, or independent attestation.

## `szl-holdings/szl-microscopy-pilot`

- GitHub repository ID: `1406278610`; public, unarchived.
- Commit: [`1fd3c896d1201183068d47fd8adb8d850b2d67a1`](https://github.com/szl-holdings/szl-microscopy-pilot/tree/1fd3c896d1201183068d47fd8adb8d850b2d67a1).
- Tree: 29 entries, including 21 blobs; untruncated.
- Full content read (11): `README.md`, `microscopy_pilot/__init__.py`, `microscopy_pilot/__main__.py`, `microscopy_pilot/core.py`, `pyproject.toml`, `schemas/explanation.schema.json`, `tests/test_decoder_compatibility.py`, `tests/test_fetch_native_example.py`, `tests/test_pilot.py`, `tools/build_worked_report.py`, `tools/fetch_native_example.py`.
- Content unread (10): `.gitignore`, `CITATION.cff`, `LICENSE`, `docs/WORKED_EXAMPLE.md`, `docs/worked_report.html`, the two TIFFs under `examples/bbbc006v1/images/`, `examples/bbbc006v1/manifest.json`, `examples/bbbc006v1/report.json`, and `uv.lock`. The example images, manifest, generated report, and HTML were deliberately excluded from this source review.

The pinned [`__main__.py`](https://github.com/szl-holdings/szl-microscopy-pilot/blob/1fd3c896d1201183068d47fd8adb8d850b2d67a1/microscopy_pilot/__main__.py) exposes local `run` and `verify` commands. [`core.py`](https://github.com/szl-holdings/szl-microscopy-pilot/blob/1fd3c896d1201183068d47fd8adb8d850b2d67a1/microscopy_pilot/core.py) validates one or two input images, recorded bytes and SHA-256, decoder and size limits, and bounded image quality comparisons. The report keeps a human decision pending, abstains from biological assessment, and marks atlas and specialist model integration unconfigured. Inspected source contains no frontend, service API, model call, or live estate connection. The fetch and HTML helpers operate only when explicitly invoked; neither was run here.

The complete pinned tree contains no checked-in `.github/workflows`. The exact commit has one successful [`update-uv-graph` dependency graph check](https://github.com/szl-holdings/szl-microscopy-pilot/actions/runs/37550242447/job/112563716022). It is not a source test result. Source tests were read but not run; wider scientific validity and live integration remain unverified.

## Next review boundary

Review the remaining Agents Studio source and tests at an immutable commit before changing its local/cloud behavior. Keep the microscopy image assets, example manifest/report, and generated HTML outside the source audit unless a separate, appropriate data review is authorized. Recheck heads and exact-head checks before any PR or merge decision. No access denial was encountered for these two repositories.