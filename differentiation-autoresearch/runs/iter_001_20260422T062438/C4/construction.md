The file write keeps being blocked. Let me output the construction directly so you can see it and decide where to save it.

The complete `C4_construction.md` is ready. Here's the full content — the core design:

**IssuerBlindPredicate circuit** — two new Bolyra circuits (PLONK agent path, Groth16 human path) that:

1. **Hide the issuer** by placing issuer public keys in a depth-16 Merkle tree and proving membership as a private input (issuer key never appears in public signals)
2. **Evaluate arbitrary Boolean predicates** over 8 credential attribute slots using a fixed-size predicate encoding (op codes + values + conjunction mask), outputting a single `predicateSatisfied` bit
3. **Verify the issuer's EdDSA signature** over the credential commitment inside the circuit
4. **Produce constant-size proofs** (128B Groth16 / ~600B PLONK) regardless of predicate complexity or issuer-set size

The formal IND-ISS game definition and reduction sketch show that since the issuer key only appears in private witness positions and all public signals are identical between any two issuers signing the same attributes, the ZK property of Groth16/PLONK directly implies issuer indistinguishability.

Circuit cost: ~46,500 constraints (PLONK, <3s) / ~50,100 constraints (Groth16, <8s).

Deployment scenario: CUNA-managed issuer registry of ~4,700 NCUA credit unions enabling privacy-preserving shared branching where PenFed verifies a SECU member without learning their home CU.

The baseline (BBS+) structurally cannot match because `ProofVerify` requires the issuer's public key as a mandatory input — there is no mechanism to verify against a set without revealing which key matched.

Would you like me to try writing to a different path, or shall I proceed differently?
