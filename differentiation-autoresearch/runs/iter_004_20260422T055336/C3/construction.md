The file write needs permission. The construction is ready — it addresses all six judge-identified gaps:

1. **Malicious AS argument** — §3 names A_AS as the load-bearing threat actor with explicit explanation of why RFC 8693 + JWT introspection + BBS+ collapses under AS compromise, while PLONK's constraint-level enforcement (C3) survives.

2. **NARROW-FORGE reduction sketch** — Game 1 provides a 3-case reduction to PLONK knowledge soundness (AGM+ROM, GWC19) and Poseidon collision resistance, with explicit advantage bound.

3. **chainNullifier derivation + universe enumeration** — chainNullifier = Poseidon2(seedScopeCommitment, finalScopeCommitment), blinded via Poseidon2(chainNullifier, Σblinding). Game 3 proves λ-bit security even for |U|=1 populations.

4. **SE-PLONK ZK fix** — Explicitly restricts to honest-verifier ZK (perfect HVZK via blinding polynomials) for Game 2, with a separate Poseidon-PRF-based unlinkability argument for malicious auditors rather than claiming full simulation-extractability.

5. **Workload nonce execution-time anchor** — C12 derives workloadNonce from `Poseidon2(workloadTimestamp, Poseidon2(delegateeCredCommitment, sessionNonce))` with the timestamp signed by the execution environment and anchored to an immutable log SLH. Game 4 bounds deferred substitution.

6. **CT-log off-chain registry** — §2.5 specifies a full CT-log alternative with SLH, inclusion/consistency proofs, MMD SLA, and dual-mode operation (on-chain + CT-log).

Please approve the write permission to save `construction.md`.
