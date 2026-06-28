# Teach: Bolyra Circuits & Cryptography (Deep Dive)

## Status: IN PROGRESS

---

## 1. Cryptographic Primitives — The Building Blocks
- [ ] 1.1 Poseidon hash — why it's used (ZKP-friendly), what makes it different from SHA-256
- [ ] 1.2 Baby Jubjub curve — what it is, why EdDSA runs on it, the subgroup order (l)
- [ ] 1.3 BabyPbk — scalar multiplication for key derivation, discrete log hardness
- [ ] 1.4 EdDSA over Poseidon — why not ECDSA, what EdDSAPoseidonVerifier does internally

## 2. HumanUniqueness Circuit — Constraint-Level Understanding
- [ ] 2.1 Signal flow: secret -> BabyPbk -> Poseidon2(Ax,Ay) -> leaf -> BinaryMerkleRoot -> root
- [ ] 2.2 Nullifier construction: Poseidon2(scope, secret) — why scope AND secret, not just secret
- [ ] 2.3 Nonce binding construction: Poseidon2(nullifierHash, sessionNonce)
- [ ] 2.4 Range check: Num2Bits(251) on secret — why 251, why approximate is safe
- [ ] 2.5 What's NOT constrained: scope/sessionNonce have no range checks (by design — verifier controls them)

## 3. AgentPolicy Circuit — Constraint-Level Understanding
- [ ] 3.1 Credential commitment: Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)
- [ ] 3.2 Scope check constraint: required[i] * (1 - permission[i]) === 0 — why this formula works
- [ ] 3.3 Cumulative bit enforcement constraints — how bit4*(1-bit3)===0 enforces implication
- [ ] 3.4 Expiry check: LessThan(64) — why 64 bits, what about field overflow
- [ ] 3.5 Scope commitment as Poseidon3(perm, cred, expiry) — the UC3.2 fix story

## 4. Delegation Circuit — The Hardest One
- [ ] 4.1 Chain linking: how previousScopeCommitment connects hops
- [ ] 4.2 UC3.1 fix: recomputing delegatorCredCommitment from preimage to bind signing key
- [ ] 4.3 UC3.2 fix: including expiry in scope commitment to prevent self-assertion
- [ ] 4.4 CIP-1: phantom delegatee attack and the Merkle inclusion fix
- [ ] 4.5 Why chain depth (3 hops max) is enforced on-chain, not in-circuit

## 5. Security Analysis — Attack Vectors & Defenses
- [ ] 5.1 Field overflow attacks — why Num2Bits range checks exist at the Solidity boundary
- [ ] 5.2 Underconstraint risks — what it means for a signal to be unconstrained, real examples
- [ ] 5.3 Trusted setup: ceremony reuse (Semaphore) vs universal setup (PLONK) — security tradeoffs
- [ ] 5.4 Known limitations: no revocation in-circuit, timestamp oracle trust, scope=0 edge case

## 6. Cross-Circuit Composition
- [ ] 6.1 AgentPolicy.scopeCommitment -> Delegation.previousScopeCommitment (the chain link)
- [ ] 6.2 Monotone attenuation: why scope can only narrow across the full chain (by transitivity)
- [ ] 6.3 Privacy boundary: what's public vs private across all three circuits
