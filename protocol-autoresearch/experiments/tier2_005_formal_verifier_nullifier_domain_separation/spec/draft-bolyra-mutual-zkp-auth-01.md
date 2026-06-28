---
title: "Bolyra Mutual ZKP Authentication Protocol"
abbrev: "Bolyra Auth"
docname: draft-bolyra-mutual-zkp-auth-01
category: exp
ipr: trust200902
area: Security
workgroup: None
keyword: ZKP, authentication, identity, agents
author:
  -
    fullname: Vishwanath Mansakar
    organization: ZKProva Inc.
    email: viswa@zkprova.com
---

# 1. Introduction

The Bolyra Mutual ZKP Authentication Protocol enables mutual authentication
between human users and AI agents using zero-knowledge proofs. Both parties
prove identity properties without revealing secret key material.

This document specifies the wire format, proof construction, and verification
procedures for Bolyra v2.0 (Proof of Enrollment).

# 2. Terminology

- **Human Identity**: A Semaphore v4-style enrollment commitment in a Merkle tree.
- **Agent Credential**: An EdDSA-signed credential with cumulative-bit permissions.
- **Delegation**: A scope-narrowing credential chain from delegator to delegatee.
- **Nullifier**: A deterministic, unlinkable value derived from secret inputs that
  prevents double-spending or replay without revealing the secret.
- **Domain Separation Tag (DST)**: A constant prefix prepended to hash inputs to
  ensure outputs from different contexts cannot collide.

# 3. Cryptographic Primitives

## 3.1 Poseidon Hash Function

All hash operations use the Poseidon hash function family over the BN254 scalar
field. Poseidon is an algebraic hash function optimized for arithmetic circuits
(ZK-SNARKs). The protocol uses Poseidon with arities 2, 3, and 4.

## 3.2 Proving Systems

| Circuit          | Proving System     | Ceremony                      |
|------------------|--------------------|-------------------------------|
| HumanUniqueness  | Groth16            | Semaphore v4 (depth 20)       |
| AgentPolicy      | Groth16 + PLONK    | Project-specific (pot16.ptau) |
| Delegation       | Groth16 + PLONK    | Project-specific (pot16.ptau) |

# 4. Nullifier Derivation with Domain Separation

## 4.1 Rationale

Prior to v2.0.0, all three circuits derived nullifiers using `Poseidon(a, b)`
with arity 2 and no domain separator. If input values happened to coincide
across circuits (e.g., a `scope` equaling a `credentialCommitment`), nullifier
collisions were theoretically possible. This violated the cross-circuit
nullifier independence property.

Domain separation tags eliminate this class of vulnerability by ensuring every
Poseidon input vector is structurally distinct across circuits. This follows
the domain separation conventions established in IETF RFC 9380 (Hashing to
Elliptic Curves), Section 3.1, which mandates unique DSTs for each usage
context of a hash function.

## 4.2 Domain Tag Registry

The following domain tags are **frozen constants**. New circuits MUST allocate
the next sequential tag and register it here before deployment.

| Tag (hex) | Tag (decimal) | Circuit          | Nullifier Arity | Status |
|-----------|---------------|------------------|-----------------|--------|
| 0x01      | 1             | HumanUniqueness  | 3               | Active |
| 0x02      | 2             | AgentPolicy      | 3               | Active |
| 0x03      | 3             | Delegation       | 4               | Active |
| 0x04–0xFF | 4–255         | (reserved)       | —               | —      |

## 4.3 Nullifier Construction

Each circuit computes its nullifier as:

```
nullifier = Poseidon(DST || inputs)
```

where `||` denotes ordered concatenation of field elements as Poseidon inputs.

### 4.3.1 HumanUniqueness Nullifier

```
N_H = Poseidon₃(0x01, scope, secret)
```

- `0x01`: HUMAN_NULLIFIER_DOMAIN tag
- `scope`: application scope identifier (public)
- `secret`: human prover's secret key (private)

The nullifier is deterministic for a given `(scope, secret)` pair, enabling
the verifier to detect double-signaling within a scope without learning the
prover's secret.

### 4.3.2 AgentPolicy Nullifier

```
N_A = Poseidon₃(0x02, agentSecret, policyScope)
```

- `0x02`: AGENT_NULLIFIER_DOMAIN tag
- `agentSecret`: agent's secret key (private)
- `policyScope`: policy scope identifier (private)

### 4.3.3 Delegation Nullifier

```
N_D = Poseidon₄(0x03, delegatorSecret, delegateeCredCommitment, scope)
```

- `0x03`: DELEGATION_NULLIFIER_DOMAIN tag
- `delegatorSecret`: delegator's secret key (private)
- `delegateeCredCommitment`: delegatee's credential commitment (private)
- `scope`: delegation scope identifier (private)

Note: The Delegation nullifier uses arity 4 (vs. arity 3 for the other two
circuits), providing an additional structural separation layer.

## 4.4 Cross-Circuit Collision Resistance

**Theorem (Domain Separation).** Under the Poseidon preimage resistance
assumption (128-bit security), no efficient adversary can produce a
cross-circuit nullifier collision between any two of `(N_H, N_A, N_D)`.

**Proof sketch.** For each pair of circuits:

1. **N_H vs. N_A**: Same arity (3), but `input[0]` is constrained to `1`
   vs. `2`. Collision requires a second-preimage attack on Poseidon₃.

2. **N_H vs. N_D**: Different arities (3 vs. 4). Collision requires a
   cross-parameter preimage attack between distinct Poseidon instances.

3. **N_A vs. N_D**: Different arities (3 vs. 4) and different tags (2 vs. 3).
   Double separation.

Full formal proof: `circuits/FORMAL-PROPERTIES.md`, property P-DS-1.

# 5. Handshake Protocol

The mutual authentication handshake proceeds as follows:

1. **Nonce Exchange**: Verifier generates a fresh `sessionNonce`.
2. **Human Proof**: Human generates `(humanProof, nullifierHash)` binding
   to `sessionNonce` via the `scope` input.
3. **Agent Proof**: Agent generates `(agentProof, nullifierHash)` binding
   to `sessionNonce` via `policyScope`.
4. **Mutual Verification**: Both proofs are verified against on-chain
   verifier contracts. The `sessionNonce` binding prevents replay.

## 5.1 Nonce Binding

Every handshake commits to a fresh `sessionNonce`. Replaying
`(humanProof, agentProof)` without rebinding the nonce fails verification
by design.

# 6. Security Considerations

## 6.1 Nullifier Unlinkability

Nullifiers are deterministic within a scope but unlinkable across scopes.
Two proofs in different scopes by the same identity produce unrelated
nullifier values.

## 6.2 Domain Separation Guarantees

Domain separation tags are enforced at the circuit constraint level, not
merely by convention. A malicious prover cannot choose a different tag
without producing an invalid proof. See Section 4.4.

## 6.3 Trusted Setup

HumanUniqueness reuses the public Semaphore v4 ceremony (depth 20).
AgentPolicy and Delegation use project-specific `.zkey` files generated
from `pot16.ptau`. Changing any circuit (including domain tag additions)
requires regenerating the `.zkey` and corresponding Solidity verifier.

# 7. References

- RFC 9380: Hashing to Elliptic Curves (IETF)
- Grassi et al., "Poseidon: A New Hash Function for Zero-Knowledge Proof
  Systems" (USENIX Security 2021)
- Semaphore v4 Protocol Specification
- Bolyra FORMAL-PROPERTIES.md (property P-DS-1)
