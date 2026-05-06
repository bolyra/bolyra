The file has been prepared. Here's a summary of the six judge-identified gaps and how this refined construction closes each:

**1. Cross-RS linkability (agentMerkleRoot/scopeCommitment as constants):** Explicitly narrowed the claim in §1 and added a "Note on cross-RS linkability" in §2.3. The construction no longer claims cross-RS unlinkability — it scopes privacy to AS-blindness and epoch-nullifier forward secrecy. Per-session Pedersen re-randomization is identified as a future extension (~2K extra constraints).

**2. modelBindingTag RS verification requires private bitmask:** Added §2.2 — a full model-hash discovery protocol (`/.well-known/bolyra-model-manifest`) where operators publish `(model_hash, permission_bitmask)` tuples. The RS computes the expected tag locally from the manifest; the proof guarantees the prover's private witness matches.

**3. Ratcheted epoch circuit missing from §2.2:** §2.3 now specifies `AgentPolicyV2-Ratcheted` as the production circuit taking `epochSecret_e` as a direct private input (no `longTermSecret` in-circuit). Chain-binding is enforced via on-chain epoch monotonicity since verifying the full ratchet chain requires the erased prior secret. Theorem 2 reduction is rewritten against this actual circuit.

**4. MCP-FORGE honest-credential-dishonest-execution gap:** Game 1 now explicitly narrows H2 to "operator-issued model credential binding" (not "runtime model identity binding"). A dedicated paragraph explains what MCP-FORGE does NOT cover and states that runtime integrity requires TEE/TPM attestation as an orthogonal layer.

**5. Game 4 (SRS-FORGE):** Added as a full game definition with AGM + q-DLOG security argument, an explicit operational requirement (SRS-CEREMONY) for MPC ceremony with 1-of-N honesty, graceful degradation analysis (EdDSA/Poseidon binding survives SRS compromise), and A7 added to the assumptions table.

**6. Model-hash discovery protocol:** §2.2 defines the full protocol — well-known endpoint, JSON schema with issuer/models/revocation, TTL-based caching, rotation mechanics, and optional Baby Jubjub manifest signing for offline verification.

Would you like me to try writing the file again, or would you prefer to copy the content directly?
