# Formal Properties

This document catalogues the formally specified invariants enforced by Bolyra's
circuit constraints. Each property has a unique identifier (P-*), a formal
statement, enforcement location, and description of the attack class it prevents.

---

## P-RANGE-DEPTH: Merkle Proof Depth Range Check

**Invariant:** For all accepted witnesses in every Bolyra circuit that uses
`BinaryMerkleRoot`, the private input `merkleProofLength` is range-checked
to `[1, MAX_DEPTH]` via `Num2Bits` + `LessThan` constraints prior to
`BinaryMerkleRoot` instantiation.

**Formal statement:**

```
forall W in SatisfyingWitnesses(C):
    1 <= W.merkleProofLength <= MAX_DEPTH
```

where `C in {HumanUniqueness(20), AgentPolicy(20), Delegation(20), ModelInstanceBinding(16)}`.

**Enforcement mechanism (per circuit):**

| Component | Purpose | Constraints |
|---|---|---|
| `Num2Bits(5)` | Decomposes `merkleProofLength` into 5 bits, preventing field-element overflow beyond [0, 31] | ~6 |
| `LessThan(5)` upper | Asserts `merkleProofLength < MAX_DEPTH + 1`, i.e. `merkleProofLength <= MAX_DEPTH` | ~6 |
| `LessThan(5)` lower | Asserts `0 < merkleProofLength`, i.e. `merkleProofLength >= 1` | ~6 |

Total: ~18 R1CS constraints per circuit, ~72 across all four circuits.

**Enforcement locations:**

| Circuit | File | MAX_DEPTH | Constraint block |
|---|---|---|---|
| HumanUniqueness | `circuits/src/HumanUniqueness.circom` | 20 | Section 1 |
| AgentPolicy | `circuits/src/AgentPolicy.circom` | 20 | Section 1 |
| Delegation | `circuits/src/Delegation.circom` | 20 | Section 1 |
| ModelInstanceBinding | `circuits/src/ModelInstanceBinding.circom` | 16 | Section 1 |

---

## P-RANGE-FIELD: Public Signal Canonical Field Element Check

**Invariant:** Every public input signal that crosses the circuit/Solidity
boundary as `uint256` is constrained to a canonical field element
(value < 2^n for an appropriate n), preventing modular aliasing attacks.

**Formal statement:**

```
forall W in SatisfyingWitnesses(C), forall S in PublicInputs(C):
    W.S < 2^width(S)
```

where `width(S)` is the declared range-check width for signal `S`.

**Attack class closed:** Modular aliasing. A malicious prover submits
`x + k*r` (where `r` is the BN254 scalar field order) instead of `x`.
Since Circom arithmetic operates mod `r`, the circuit accepts `x + k*r`
as equivalent to `x`. But the Solidity verifier receives the full
`uint256` value, so the on-chain public input differs from what the
circuit actually proved. This enables proof reuse, nullifier bypass,
and nonce replay.

### Public Signal Range Guarantee Table

| Signal | Circuit | Width | Method | Attack Class Closed |
|---|---|---|---|---|
| `sessionNonce` | HumanUniqueness | 253 | `RangeCheck(253)` | Modular aliasing: nonce replay via `nonce + r` |
| `externalNullifier` | HumanUniqueness | 253 | `RangeCheck(253)` | Modular aliasing: nullifier domain confusion |
| `humanMerkleRoot` | HumanUniqueness | < r | Poseidon-implied | N/A (Poseidon output is inherently canonical) |
| `nullifierHash` | HumanUniqueness (output) | < r | Poseidon-implied | N/A |
| `nonceBinding` | HumanUniqueness (output) | < r | Poseidon-implied | N/A |
| `sessionNonce` | AgentPolicy | 253 | `RangeCheck(253)` | Modular aliasing: nonce replay via `nonce + r` |
| `agentMerkleRoot` | AgentPolicy | < r | Poseidon-implied | N/A |
| `currentTimestamp` | AgentPolicy | 64 | `LessThan(64)` (internal `Num2Bits`) | Already bounded by expiry check |
| `requiredPermissions` | AgentPolicy | 8 | `Num2Bits(8)` | Already bounded by permission bitmask check |
| `credentialHash` | AgentPolicy (output) | < r | Poseidon-implied | N/A |
| `nonceBinding` | AgentPolicy (output) | < r | Poseidon-implied | N/A |
| `sessionNonce` | Delegation | 253 | `RangeCheck(253)` | Modular aliasing: nonce replay via `nonce + r` |
| `delegationMerkleRoot` | Delegation | < r | Poseidon-implied | N/A |
| `currentTimestamp` | Delegation | 64 | `LessThan(64)` (internal `Num2Bits`) | Already bounded by expiry check |
| `delegationHash` | Delegation (output) | < r | Poseidon-implied | N/A |
| `narrowedPermissions` | Delegation (output) | 8 | `Num2Bits(8)` via `childPermissions` | Already bounded by scope narrowing |
| `nonceBinding` | Delegation (output) | < r | Poseidon-implied | N/A |

### Constraint cost

Each `RangeCheck(253)` instantiates `Num2Bits(253)`, which adds exactly
253 R1CS constraints (one binary decomposition constraint per bit plus
one summation constraint, totaling 253).

| Circuit | New RangeCheck(253) instances | Added constraints |
|---|---|---|
| HumanUniqueness | 2 (`sessionNonce`, `externalNullifier`) | 506 |
| AgentPolicy | 1 (`sessionNonce`) | 253 |
| Delegation | 1 (`sessionNonce`) | 253 |
| **Total** | **4** | **1012** |

### Why Poseidon outputs need no check

Poseidon is a permutation over the BN254 scalar field F_r. Its output is
computed entirely within the circuit as field arithmetic, so it is
guaranteed to be in [0, r-1]. There is no external input path that could
feed an overflow value into a Poseidon output signal.

### Why LessThan(64) covers `currentTimestamp`

The `LessThan(n)` template internally instantiates `Num2Bits(n)` on both
inputs. The `expiryCheck` in AgentPolicy and Delegation uses
`LessThan(64)` with `currentTimestamp` as `in[0]`, which decomposes it
into 64 bits, bounding it to [0, 2^64 - 1]. This is far below the field
modulus and prevents aliasing.

---
