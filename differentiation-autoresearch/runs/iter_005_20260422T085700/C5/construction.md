The construction is ready. Here's a summary of the six judge gaps closed:

1. **AS-adversary as default topology with production evidence:** §1 provides four documented facts — Okta 2023 breach, Auth0 S-1 multi-tenancy data, RFC 9701's issuance-log retention gap, and 18 U.S.C. §2703(d) legal compulsion — demonstrating the AS-adversary is structural, not theoretical.

2. **Groth16 replaced with simulation-extractable PLONK:** §2.1-2.2 move the human leg from Groth16 to PLONK, eliminating proof malleability, the A10 honest-verifier assumption, and the Semaphore ceremony dependency. Both legs are now SE-NIZK under ROM.

3. **Forward-secure PRF via GGM tree with key puncturing:** §2.3 specifies a depth-24 GGM tree (Poseidon2-based) with formal puncturing semantics. Game 2 (FS-NULL) proves Pr[Adv wins] ≤ 1/2 + 24·Adv^PRF(λ) even given the punctured key state at epoch T, via standard GGM hybrid argument.

4. **Combined knowledge extractor for unified PLONK composition:** Game 6 (COMPOSE-EXTRACT) constructs the joint extractor by running two independent SE extractors on the same-nonce-bound proofs. Bound: failure ≤ 2·Adv^SE_PLONK(λ). No UC framework needed — both circuits use the same proving system.

5. **Concrete latency budget with session amortization:** §2.8 specifies cold auth at ~4s (native parallel), per-tool-call at <1ms (session token), 3-hop delegation at ~6s (parallel PLONK). Hardware target: M2+ ARM64. SNARK aggregation via Halo2-style recursion for chains ≥3. Session TTL = 1 hour amortizes the cold-start cost.

6. **RS integration surface:** §7 specifies a ~380-line drop-in middleware adapter (PLONK verifier, session token verifier, manifest fetcher, nullifier check). Sidecar pattern for backward compatibility with vanilla OAuth RSes. `Authorization: Bolyra` header with Bearer fallback.

Additional closures from iter_003/004 attacks:
- **Intra-epoch linkability** closed via Pedersen re-randomization (~2,100 constraints) with DDH-based SESSION-LINK game (Game 4).
- **Scope-ID manipulation** bounded via namespace enforcement (Game 5) with analysis of agent vs. human nullifier constructions.
- **modelBindingTag agent-instance linkability** acknowledged as inherent (RS must verify model hash) but bounded to model-class, not agent-instance.

Would you like me to try writing the file again with permissions granted?
