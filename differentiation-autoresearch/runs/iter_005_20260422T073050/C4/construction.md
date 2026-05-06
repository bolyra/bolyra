The file write was blocked by permissions. Could you approve the write permission so I can save the construction.md? It addresses all 6 judge-identified gaps:

1. **FATAL: Corrupt-escrow oracle** — Redesigned from single-key ECIES to threshold ECIES (t=3, n=5) with **channel separation** (verifier never sees ciphertext). dIND-ISS game now includes `CorruptEscrow(member_id)` oracle allowing up to t-1 corruption.

2. **Corrupt-AS nullifier precomputation** — Added per-user `blindingFactor` (128-bit) to nullifier derivation: `Poseidon2(Poseidon2(credCommitment, blindingFactor), sessionNonce)`. MUNL game includes `CorruptAS()` oracle returning all credential commitments. Precomputation cost: O(2^128 × k) — infeasible.

3. **Universal circuit mechanism** — Specified: fixed D=8, W=8 universal Boolean evaluator with 7 opcodes. Not folding/recursion. Worst-case benchmark (all 8 LessThan(64) clauses) is the cost baseline. Argued why folding is unnecessary (bounded schema → bounded circuit).

4. **Escrow < AS disclosure surface** — Section 4.5 provides structural argument across 6 dimensions: online vs. cold-path, single-party vs. multi-party compellability, bulk vs. per-event, automated vs. ceremonial, audit trail verifiability, and residual breach risk.

5. **Registry timing side channel** — New Section 2.11 (fixed-cadence epoch protocol): deterministic 6-hour epochs, root changes even with no mutations, padded batch sizes, encrypted per-issuer detail. Section 3.5 analyzes residual risk and mitigations.

6. **Proof-size comparison** — Section 6 now includes a full table: Bolyra (128B/600B constant) vs. BBS+ variants (368B–5,696B scaling with predicate complexity) vs. SD-JWT (~900B–1,500B), all without issuer-hiding.
