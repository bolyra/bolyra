# Bolyra Circuit Formal Properties

This document enumerates the formal properties that the Bolyra circuit suite
must satisfy. Each property is stated as a theorem with assumptions and a
proof sketch. Properties are referenced by ID throughout the codebase.

---

## P-MEM-1: Merkle Membership Soundness

For all three circuits, the prover must demonstrate that a leaf (identity
commitment or credential commitment) exists in the relevant Merkle tree.
The `BinaryMerkleRoot(20)` template enforces correct path computation at
depth 20.

**Property:** A valid proof implies the claimed leaf is a member of the
tree with root `identityTreeRoot` (or `agentTreeRoot`).

---

## P-NULL-1: Nullifier Determinism

Within a single circuit, the nullifier output is a deterministic function
of the secret inputs and scope. Given the same `(secret, scope)` pair
(or equivalent inputs for AgentPolicy/Delegation), the same nullifier
is always produced.

**Property:** For fixed inputs, `nullifierHash` is unique and reproducible.

---

## P-NULL-2: Nullifier Unlinkability

Across different scopes, nullifiers produced by the same identity are
computationally unlinkable. This follows from the preimage resistance of
Poseidon: given `N₁ = Poseidon(DST, scope₁, secret)` and
`N₂ = Poseidon(DST, scope₂, secret)`, an observer cannot determine
whether `N₁` and `N₂` share the same `secret` without breaking Poseidon.

---

## P-DS-1: Cross-Circuit Nullifier Collision Resistance (Domain Separation)

**Added in v2.0.0.**

### Statement

No efficient adversary can produce valid witnesses `(w_i, w_j)` for two
distinct circuits `C_i ≠ C_j` such that `nullifierHash(w_i) = nullifierHash(w_j)`.

### Domain Tag Constants (Frozen)

These constants are immutable once deployed. New circuits MUST allocate the
next sequential integer and update this table.

| Constant                    | Value | Circuit          | Poseidon Arity |
|-----------------------------|-------|------------------|----------------|
| `HUMAN_NULLIFIER_DOMAIN`    | 1     | HumanUniqueness  | 3              |
| `AGENT_NULLIFIER_DOMAIN`    | 2     | AgentPolicy      | 3              |
| `DELEGATION_NULLIFIER_DOMAIN`| 3    | Delegation       | 4              |

### Nullifier Derivation Definitions

```
N_H = Poseidon₃(1, scope, secret)
N_A = Poseidon₃(2, agentSecret, policyScope)
N_D = Poseidon₄(3, delegatorSecret, delegateeCredCommitment, scope)
```

### Proof

**Assumption:** Poseidon preimage resistance at 128-bit security level.

**Case 1: HumanUniqueness vs. AgentPolicy (N_H vs. N_A)**

Both use `Poseidon₃` (arity 3). The domain tag is constrained by the circuit:
`input[0] = 1` for HumanUniqueness, `input[0] = 2` for AgentPolicy. Any valid
witness must satisfy this constraint, so the preimages differ in at least
position 0. A collision requires a second-preimage attack on Poseidon₃,
which requires `Ω(2¹²⁸)` operations.

**Case 2: HumanUniqueness vs. Delegation (N_H vs. N_D)**

`N_H` uses `Poseidon₃`, `N_D` uses `Poseidon₄`. These are distinct hash
functions with different state sizes, round constants, and MDS matrices.
A collision requires a cross-parameter preimage attack — strictly harder
than standard preimage resistance. Requires `Ω(2¹²⁸)` operations.

**Case 3: AgentPolicy vs. Delegation (N_A vs. N_D)**

Same argument as Case 2: `Poseidon₃` vs. `Poseidon₄`, plus different domain
tags (2 vs. 3). Double separation.

**QED.** □

### Worst-Case Verification

Even when all raw input values are identical:
```
scope = secret = agentSecret = policyScope = delegatorSecret = delegateeCredComm = V
```

The full Poseidon input vectors remain distinct:
- HumanUniqueness: `[1, V, V]`
- AgentPolicy:     `[2, V, V]`
- Delegation:      `[3, V, V, V]`

See `circuits/test/nullifier-domain-separation.test.js` for regression tests.

### Design Rationale

Domain separation follows IETF RFC 9380 (Hashing to Elliptic Curves) Section 3.1,
which requires unique domain separation tags for each usage context of a hash
function. The tags are small consecutive integers (1, 2, 3) for auditability.

---

## P-EXP-1: Credential Expiry Enforcement

The AgentPolicy circuit enforces `currentTimestamp < expiryTimestamp` via a
`LessThan(64)` comparator with range-checked inputs (both timestamps must
fit in 64 bits via `Num2Bits(64)`).

**Property:** An expired credential (currentTimestamp ≥ expiryTimestamp)
cannot produce a valid proof.

---

## P-DEL-1: Scope Narrowing Invariant

The Delegation circuit enforces that delegated permissions can only narrow
scope, never expand. The cumulative-bit encoding ensures higher-tier bits
imply lower-tier bits. See `validateCumulativeBitEncoding()` in the SDK.

---

## P-DEL-2: Phantom Delegatee Prevention

**Added after CVE-BOLYRA-2026-001.**

The Delegation circuit verifies that `delegateeCredCommitment` exists in the
agent Merkle tree before accepting the delegation. This prevents a delegator
from creating delegations to non-existent agents.

---

## P-NONCE-1: Handshake Nonce Binding

Every handshake commits to a fresh `sessionNonce`. The `nonceBinding` public
output in HumanUniqueness (and the `policyScope` binding in AgentPolicy)
ensures that replaying a `(humanProof, agentProof)` pair without rebinding
the nonce fails verification.

---

## Constraint Budget

All circuits must remain within the 2^16 (65,536) constraint ceiling imposed
by `pot16.ptau`.

| Circuit          | Estimated Constraints | Headroom      |
|------------------|-----------------------|---------------|
| HumanUniqueness  | ~40,601               | ~24,935 (38%) |
| AgentPolicy      | ~40,859               | ~24,677 (38%) |
| Delegation       | ~41,051               | ~24,485 (37%) |
