---
title: Patent Autoresearch Summary
visibility: internal
sources:
  - patent-autoresearch/README.md
  - patent-autoresearch/history/score_trajectory.jsonl
  - patent-autoresearch/reports/adversarial-review-r4.md
  - patent-autoresearch/reports/adversarial-review-r5.md
  - patent-autoresearch/reports/adversarial-review-r6.md
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [research, patent, ip, adversarial-review]
---

The patent autoresearch loop iteratively strengthens Bolyra's provisional patent (No. 64/043,898, filed 2026-04-20) through automated adversarial review and claim rewriting. The patent covers the IdentityOS mutual ZKP authentication protocol.

## Overview

The loop uses 6 hostile reviewer personas (USPTO examiner, competitor attorney, 101 specialist, 103 specialist, 112 specialist, code/spec auditor) to attack the patent in parallel. An LLM judge ranks findings by severity. Top attacks advance to Tier 2, where candidate claim rewrites are generated and scored on 5 dimensions (Alice/101, obviousness/103, written description support/112, design-around resistance, scope). Winners are applied as mutations.

Non-provisional conversion deadline: **2027-04-20**.

## Key Findings

### Score Trajectory

| Iteration | Score | Delta | Notes |
|---|---|---|---|
| 0 (baseline) | 72 | -- | Initial patent quality assessment |
| 1 (r4) | 72 | +0 | Attacks found but mutations did not improve score |
| 2 (r5) | 74 | +2 | Minor improvements from claim broadening |
| 3 (r6) | 74 | +0 | Score plateaued; 4 mutations applied |

The loop plateaued at 74/100 after 3 iterations (delta < 2 for 2 consecutive rounds).

### Dimension Breakdown (Latest -- 74/100)

| Dimension | Score | Assessment |
|---|---|---|
| **Alice/101** | 16/25 | Strong technical anchoring (Poseidon, EdDSA/BabyJub, BN128 pairings, specific circuit constraints). Risk: examiner could frame as abstract "mutual authentication" concept. |
| **Obviousness/103** | 14/25 | Individual components are known (Semaphore, UCAN/Biscuit, EdDSA). Strongest novelty: identity-bound scope commitment chain-linking and mixed Groth16+PLONK in single transaction. |
| **112 Support** | 17/25 | Exceptionally detailed specification with circuit diagrams, constraint counts, gas estimates, and working code. Minor issues: coined terms ("identity-bound", "Merkle-included"), 4 alternative nonce mechanisms without preferred embodiment. |
| **Design-around** | 13/25 | Biggest gap: claims locked to Poseidon hash specifically. Competitor using Rescue/Griffin/Anemoi escapes all claims. Also: mixed proving system easily avoided, bitmask encoding easily varied. |
| **Scope** | 14/25 | Claims require blockchain verification (off-chain escapes), require both human + agent populations, miss enrollment/SDK/API layers. |

### Top Vulnerabilities

**101 risks:**
- "Mutual authentication" is a fundamental cryptographic concept; ZKP could be characterized as mere implementation
- Delegation chain maps to Electric Power Group pattern (collect, analyze, store)
- Cumulative bit encoding is a mathematical relationship expressible as pure logic

**103 risks:**
- Semaphore + UCAN/Biscuit + Tornado Cash Nova combination covers most delegation claims
- Mixed Groth16/PLONK is an engineering optimization, not an inventive step
- Root history buffer directly anticipated by Tornado Cash MerkleTreeWithHistory

**Design-around gaps:**
- Replace Poseidon with any other algebraic hash -- escapes all claims
- Use single proving system (all-PLONK or all-Groth16) -- escapes Claim 1
- Replace bitmask with different permission encoding -- escapes delegation claims
- Move to off-chain verification -- escapes all claims (blockchain-specific)
- Use recursive SNARKs to collapse delegation chain

### Mutations Applied (r6)

1. Broadened Claim 15(a) from Poseidon-specific to genus-level ("collision-resistant algebraic hash")
2. Added anti-impersonation narrowing to Claim 15 (entities with identical permissions but different identity produce different commitments)
3. Converted Claim 1 from species (Groth16+PLONK) to genus (any pair of ZK proving systems)
4. Added dependent claim with bilateral Merkle-included identity binding

## Current Status

Loop plateaued at 74/100. Key next steps for non-provisional filing:
- Broaden at least one independent claim to "algebraic hash function" (partially done in r6)
- Add off-chain verification mode claims
- Address "AI agent" definitional gap (no definition distinguishing from any software process)
- Resolve scope commitment brute-force vulnerability (2^64 enumeration)
- Consider TEE integration claims for C7 model-instance binding

## See Also

- `patent-autoresearch/README.md` -- loop architecture and safety properties
- `patent-autoresearch/reports/adversarial-review-r6.md` -- latest adversarial review
- `patents/` -- provisional and non-provisional patent drafts
- `wiki/research/differentiation-summary.md` -- related differentiation findings
