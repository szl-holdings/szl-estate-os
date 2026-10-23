# SZL Evidence Explorer on Snowflake - pilot 1, v0.3 DRAFT

Status: DRAFT_READY. Not LOCAL_TESTED, not deployable, nothing approved for any Snowflake account.

- kit/: operator kit v0.3.0 (narrow privilege design: owner-created monitor, warehouse and roles; SZL_EE_SETUP deploy identity; SZL_EE_RUNTIME runtime identity) plus runner szl_ee_go.py v0.3.0.
- bundle/: Evidence Explorer bundle v4 (schema v4 without SYSADMIN hierarchy grants). The bundle receipt predates schema v4 and is marked STALE.
- READINESS_PACKET_2026-10-22.md: approval scope, privilege diff, cost-control limits, failure map, test evidence, open decisions. Artifact links inside it resolve only in the originating workspace.

Not run for v0.3/v4: kit suite (77) and sweep (88), runner suite (98) and sweep (83), bundle suite, dry run. This repository's CI does not run these files.
Last measured suites (v0.2.0-rc1 + v3 bundle, 2026-10-22): kit 64 OK, runner 65 OK, mutants 59/59 and 46/46 killed, bundle 80 OK, verifier 24 OK.

Withheld from this commit: approval.txt, APPROVAL_PROVENANCE.md and kit/test_szl_ee_go.py (contain the Snowflake account identifier), and two local test logs (contain local paths). KIT_SHA256SUMS.txt still lists them.
Synthetic demonstration data only. Not clinical; must never receive patient data.
