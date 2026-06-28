---
title: Protocol Autoresearch Summary
visibility: internal
sources:
  - protocol-autoresearch/README.md
  - protocol-autoresearch/program.md
  - protocol-autoresearch/FINAL_REPORT.md
  - protocol-autoresearch/history/score_trajectory.jsonl
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [research, protocol, circuits, wire-format]
---

The protocol autoresearch loop iteratively improves the Bolyra identity protocol across four dimensions: correctness, completeness, adoption, and standards. It ran 3 iterations (plus baseline) in April 2026, reaching a total score of 42/100.

## Overview

The loop uses 8 constructive explorer personas (SDK designer, framework integrator, standards architect, circuit optimizer, security auditor, product visionary, cross-chain engineer, formal verifier) to propose protocol improvements. Candidates pass through Tier 1 (discovery + scoring), Tier 2 (build experiments in `experiments/` + 24-check harness), and Tier 3 (adversarial review on 6 axes). The loop targets all 4 dimensions >= 21 simultaneously (total >= 84).

## Key Findings

### Score Trajectory

```
iter 0 (baseline): 39/100  [correctness:17  completeness:16  adoption:8   standards:14]
iter 1:            39/100  [correctness:17  completeness:15  adoption:8   standards:11]  -- regression in completeness/standards
iter 2:            36/100  [correctness:17  completeness:15  adoption:5   standards:10]  -- adoption regressed
iter 3:            42/100  [correctness:18  completeness:13  adoption:4   standards:7]   -- correctness up, adoption/standards down
```

The loop showed uneven progress. Correctness improved slightly (+1 from baseline), but adoption and standards regressed. No Tier 2 winners were promoted in iterations 1-2.

### Dimension Analysis

**Correctness (18/25 at latest):** Three circuits (HumanUniqueness, AgentPolicy, Delegation) are structurally sound. CIP-1 (phantom delegatee fix) and CIP-2 (human root history buffer) landed. However: approximate Baby Jubjub subgroup check, 5 critical bugs found by Codex review (nonce equality unenforced on-chain, agent revocation key mismatch), and thin negative-path test coverage.

**Completeness (13/25 at latest):** Core circuits, verifier contracts, and IdentityRegistry implemented. But: sybil resistance is a Phase 1 stub (passphrase enrollment only), human-to-agent delegation pathway not fully implemented, recursive SNARK folding and off-chain verification are unbuilt CIPs.

**Adoption (4/25 at latest):** The weakest dimension. No framework integrations, no CLI tooling, no error message catalog, no getting-started guide, no example applications at the time of the loop. The protocol was "usable by its authors but not by external developers without significant reverse-engineering."

**Standards (7/25 at latest):** IETF internet-draft and conformance test vectors existed. However: undefined normative terms ("chain-state mapping", "identity-bound", "mutual authentication"), no RFC 2119 MUST/SHOULD/MAY language, no interop testing with external implementations, sessionNonce generation mechanism underdefined.

### Experiments Generated

The loop generated experiments in `experiments/` covering:
- Cross-chain root sync
- Chain-agnostic nullifier design
- Groth16-to-PLONK migration for HumanUniqueness
- W3C DID method implementation
- Python SDK snarkjs bridge

None were promoted to `winners/` -- all scored below the 75-point promote threshold.

## Current Status

The protocol loop ran in April 2026 and stalled at 42/100 (well below the 84 target). The adoption and standards gaps identified by this loop were subsequently addressed through significant development work:

- **Adoption** has improved dramatically since the loop: TS SDK v0.5.2, Python SDK v0.5.0, CLI v0.3.1, gateway v0.2.0, LangChain integration, CrewAI integration (v0.2.0, 99 tests), MCP packages, payment-protocols, 11+ published packages total.
- **Standards** have advanced: conformance vectors v3 (67 vectors), proof envelope format (`application/vnd.bolyra.proof+json`), cross-SDK interop verified via golden fixtures.
- **Correctness** baseline remains the same (385 tests passing across the repo).

A re-run of the protocol loop would likely show significantly higher scores, particularly on adoption (4 -> estimated 18+) and standards (7 -> estimated 16+).

## See Also

- `protocol-autoresearch/README.md` -- loop architecture
- `protocol-autoresearch/program.md` -- master specification with scoring rubric
- `protocol-autoresearch/FINAL_REPORT.md` -- summary with ASCII trajectory chart
- `protocol-autoresearch/experiments/` -- generated experiment artifacts
- `wiki/research/differentiation-summary.md` -- related differentiation findings
