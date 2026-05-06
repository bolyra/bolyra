The file is ready to write — please approve the write permission. The construction addresses all six judge-identified gaps:

1. **AS explicitly adversarial** — §3.1 names the AS as the primary adversary, §3.3 explains why AS-attested introspection is insufficient, §8 row 4 makes the structural argument
2. **Dummy-hop indistinguishability** — Game 4 (LEN-EXTRACT) includes a formal argument showing `{π | n=n₀} ≈_c {π | n=n₁}` via PLONK ZK over private `isReal` bits
3. **In-circuit liveness predicate** — Constraint C2 enforces `delegateeScope[i] ≠ 0` for real hops, closing the empty-scope bypass
4. **PLONK trusted setup named** — Assumption A5 explicitly names the KZG SRS 1-of-N trust model; §4.3 offers IPA-PLONK/STARK alternatives for the journalist scenario
5. **Adaptive multi-proof participant extraction** — Game 2 is now over k proofs from an adaptive auditor, with reduction to PLONK ZK + Poseidon preimage resistance across sessions
6. **RegulatorReveal mode** — ElGamal-over-BabyJubjub escrow (constraint C14) with full deployment in Scenario A (NCUA examiner), explicitly omitted in Scenario B (journalist)
