# Bolyra Security Model

This document describes the security guarantees provided by the Bolyra
identity protocol, including nullifier domain separation, proof soundness,
and threat mitigations.

## 1. Overview

Bolyra uses three ZK circuits (HumanUniqueness, AgentPolicy, Delegation)
to enable mutual authentication between humans and AI agents. Security
rests on three pillars:

1. **Poseidon hash security** — preimage and collision resistance at
   128-bit security level.
2. **Groth16/PLONK soundness** — valid proofs imply valid witnesses.
3. **Domain separation** — cross-circuit nullifier independence.

## 2. Nullifier Domain Separation

### 2.1 Problem

Without domain separation, all three circuits use `Poseidon(a, b)` (arity 2)
for nullifier derivation. If an attacker can arrange for inputs to one circuit
to match inputs to another (e.g., `scope == credentialCommitment`), the
resulting nullifiers would collide. This enables:

- **Cross-circuit replay**: Using a human nullifier as an agent nullifier.
- **Nullifier set confusion**: On-chain registries cannot distinguish which
  circuit produced a given nullifier.

### 2.2 Solution: Domain Separation Tags

Each circuit prepends a unique, frozen constant (the **domain tag**) as the
first input to its nullifier Poseidon call:

| Tag | Circuit          | Construction                                              | Arity |
|-----|------------------|-----------------------------------------------------------|-------|
| 1   | HumanUniqueness  | `Poseidon₃(1, scope, secret)`                              | 3     |
| 2   | AgentPolicy      | `Poseidon₃(2, agentSecret, policyScope)`                   | 3     |
| 3   | Delegation       | `Poseidon₄(3, delegatorSecret, delegateeCredComm, scope)`  | 4     |

### 2.3 Guarantees

**Formal property P-DS-1** (see `circuits/FORMAL-PROPERTIES.md`):

> Under the Poseidon preimage resistance assumption (128-bit), no efficient
> adversary can produce a cross-circuit nullifier collision.

Separation is enforced at two levels:

1. **Domain tag divergence**: For same-arity circuits (Human vs. Agent),
   `input[0]` is always 1 vs. 2. A collision requires a second-preimage
   attack on Poseidon₃.

2. **Arity divergence**: For different-arity circuits (Human/Agent vs.
   Delegation), the Poseidon instances use different state sizes, round
   constants, and MDS matrices. A collision requires a cross-parameter
   preimage attack.

### 2.4 Tag Registry

Domain tags are **frozen constants**. The registry lives in
`circuits/FORMAL-PROPERTIES.md` (§P-DS-1) and
`spec/draft-bolyra-mutual-zkp-auth-01.md` (§4.2).

New circuits MUST:
1. Allocate the next sequential tag (currently: next = 4).
2. Update both registry locations.
3. Add regression tests to `circuits/test/nullifier-domain-separation.test.js`.

### 2.5 Design Rationale

The domain separation design follows IETF RFC 9380 (Hashing to Elliptic
Curves), Section 3.1, which establishes the convention of unique domain
separation tags for each usage context of a hash function. Small consecutive
integers (1, 2, 3) were chosen for auditability and circuit efficiency
(single constraint per tag).

## 3. Merkle Membership

All three circuits verify that a leaf (identity commitment or credential
commitment) exists in a depth-20 binary Merkle tree. The `BinaryMerkleRoot`
template enforces correct path computation.

## 4. Credential Expiry

The AgentPolicy circuit enforces `currentTimestamp < expiryTimestamp` via
a `LessThan(64)` comparator with range-checked inputs.

## 5. Phantom Delegatee Prevention

The Delegation circuit verifies that `delegateeCredCommitment` exists in
the agent Merkle tree before accepting the delegation. This mitigates
CVE-BOLYRA-2026-001 (phantom delegatee attack).

## 6. Handshake Nonce Binding

Every handshake commits to a fresh `sessionNonce`. Replaying
`(humanProof, agentProof)` without rebinding the nonce fails verification.

## 7. Trusted Setup

- HumanUniqueness: reuses the public Semaphore v4 ceremony (depth 20).
- AgentPolicy, Delegation: project-specific `.zkey` from `pot16.ptau`.
- Changing any circuit requires regenerating `.zkey` and Solidity verifiers.

## 8. Threat Model

| Threat                        | Mitigation                          |
|-------------------------------|-------------------------------------|
| Cross-circuit nullifier reuse | Domain separation (§2)              |
| Phantom delegatee             | Merkle inclusion check (§5)         |
| Expired credential use        | Timestamp range check (§4)          |
| Proof replay                  | Session nonce binding (§6)          |
| Nullifier linkability         | Poseidon preimage resistance (§2.3) |
