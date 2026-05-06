The construction is ready to write. It addresses all six judge-identified gaps:

1. **Formal scope lattice** — §2.1 defines (L, ≤) as a join-semilattice over cumulative bitmasks with `latticeRoot` as a public circuit parameter. C3 enforces `C_narrow` (bitwise subset + tier implications). Game 1 (NARROW-FORGE) states soundness over this predicate.

2. **SE-PLONK (AGM+ROM)** — Assumption A2 explicitly names simulation-extractability (Maller et al. 2019, blinding polynomial technique). Game 4 reduction uses SE-PLONK against malicious verifiers in Scenario B, not HVZK.

3. **pk_reg bound to transparency log** — C14 verifies `Poseidon2(pk_reg.x, pk_reg.y) === regKeyCommitment` against an on-chain governance registry. Regulator must also publish `PoK(sk_reg)` via EdDSA signature. Prevents adversarial-AS key substitution.

4. **Session-unlinkability game** — C10 introduces per-proof random blinding factors. Game 3 (SCOPE-EXTRACT) bounds cross-session correlation advantage. `blindedChainDigest` = Poseidon2(chainNullifier, Σblinding) makes same-chain proofs computationally independent across sessions.

5. **Workload identity binding** — C8 requires `workloadAttestation[i] = Poseidon2(delegateeCredCommitment, workloadNonce)` for real hops, binding to SPIFFE SVIDs/TPM quotes. Phantom hops in dummy slots are proven harmless: C3 narrowing + C5 chain-linking prevent scope expansion even with phantom workloads.

6. **Concrete latency solution** — §2.4 specifies three modes: (a) deferred offline audit (ChainAuditProof generated post-pipeline, ~4.8s), (b) Nova IVC folding (~2s per fold for batch aggregation), (c) pre-authorized scope commitments (~200ms runtime per hop). The AI pipeline scenario is no longer structurally excluded.

Please approve the write permission so I can save the file.
