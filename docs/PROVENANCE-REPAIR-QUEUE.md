# Provenance Repair Queue: unreferenced GitHub repos

Source: provenance map v0 measured 2026-11-22/23 (VFE2 lane): 650 HF artifacts scanned against all 188 GH repos; **0 SHA-verified bindings estate-wide; 125 repos never referenced from any HF artifact.** Triage: [unref-triage-v1.json](../provenance/unref-triage-v1.json); full evidence bundle on HF wave-logs commit 31ce206f (w28-unref-triage).

## Buckets (125 total)
- **89 ALIGN_CANDIDATE_CODE_REPO** - code repos for the GitHub-is-source alignment repair queue (this document)
- 26 EXEMPT_ARCHIVED / 4 EXEMPT_BACKUP_SANDBOX / 2 EXEMPT_FROZEN_FAMILY / 4 REVIEW_MINOR

## Repair order (seat-converged: production-first; Astra+Sol advisories 2026-11-23, advisory-only)
### Tier 1 - production infrastructure / control (16)
- szl-org-health
- szl-provctl
- szl-portal
- szl-capability-ledger
- szl-serve
- frontier-console
- ci-witness-action
- szl-gov
- szl-ci-witness
- szl-doctrine
- szl-estate-os
- szlholdings.com
- szl-substrate
- szl-drift
- szl-pin
- registry-mirror
### Tier 2 - core tooling / evidence (20)
- szl-evidence-core
- agents-studio
- szl-asset-registry
- szl-ops-runbook
- szl-eval-harness
- szl-receipt
- szl-defensive-control-plane
- szl-trust
- szl-runbook-catalog
- szl-build-env
- szl-openshell-receipts
- szl-govsign
- szl-evidence-litellm
- evidence-studio
- governance-as-code
- szl-evidence-mandate
- szl-invariants
- szl-guardrail-receipt
- evidence-doctrine
- release-gate-fixture
### Tier 3 - research / benchmark / domain (29)
- YARQA-ATTN
- amaru
- ChaskaLLM
- acoustic-validation
- szl-retrieval-bench
- szl-quant-witness
- szl-quant-bench
- szl-microscopy-pilot
- szl-hf-frontier
- szl-nemo
- vgl-cold-replay
- szl-abstention-frontier
- szl-calibration
- rosie
- szl-sovereign-os
- szl-hatun-conformance
- szl-attestation
- szl-engine-bench
- szl-crosscheck
- puriq-live
- frontier-54-runs
- khipu-sda-core
- khipu-x1
- szl-eclipse
- szl-seismic-review
- pentagi
- szl-wave1-report
- szl-v14
- frontier-compass
### Tier 4 - utility / admin / other (24)
- ayllu-hf-space
- szl-billing
- szl-specdecode
- szl-ouroboros
- szl-energy-mcp
- szl-blocked
- szl-vertical-portal
- szl-humanitarian-causal-twin
- szl-block-kv
- szl-energy-attest
- szl-showcase
- conformance-corpus
- lyte-lattice
- szl-receipt-attn
- szl-lambda-gate
- szl-formulas
- szl-platform
- szl-maskmod
- szl-kernels
- szl-repo-template
- killinchu-ghsa-x4vh-8v6w-fg2m
- szl-skills-ghsa-7gvv-whrr-6q3x
- szl-kernel-attest
- pitch-collateral

## Repair content (minimal, per artifact)
```yaml
provenance:
  github_source: https://github.com/szl-holdings/<repo>
  source_commit_sha: <40-char SHA pinned at proposal time>
```

## Gates before rollout
1. Owner signature credential mint (trust layer; unsigned card edits stay propose-only).
2. 5-repo pilot with dual-publication + rollback records before any batch.
3. Coordination with the 133 propose-only ou30 card packages (no duplicate edits).
4. The 116 AMBIGUOUS_MULTI artifact bindings need per-artifact disambiguation owners first.

_Propose-only. No HF or GH artifact was modified by this triage. Tiering is heuristic/advisory._