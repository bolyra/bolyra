# Experiment: Expiry Ordering Constraint Fix

**ID:** `formal_verifier_expiry_ordering_unsound`  
**Priority:** High  
**Dimension:** Correctness  

## Problem

The AgentPolicy and Delegation circuits perform `Num2Bits(64)` range checks
on timestamps but lack explicit `LessThan(64)` constraints to enforce temporal
ordering. This means:

- A prover can generate a valid proof with an **expired** credential
  (`currentTimestamp >= expiryTimestamp`)
- A delegatee can claim a delegation window **exceeding** the delegator's
  authority (`delegateeExpiry > delegatorExpiry`)

If the on-chain verifier does not independently re-check these orderings
(or if a third-party verifier is used), expired or over-extended credentials
are accepted.

## Fix

Add in-circuit comparator constraints:

| Circuit | Constraint | Component |
|---------|------------|-----------|
| AgentPolicy | `currentTimestamp < expiryTimestamp` | `LessThan(64)` |
| Delegation | `delegateeExpiry <= delegatorExpiry` | `LessEqThan(64)` |
| Delegation | `currentTimestamp < delegateeExpiry` | `LessThan(64)` |

Total additional constraint cost: ~390 (~0.6% of circuit size).

## Artifacts

```
circuits/
  AgentPolicy.circom       # New circuit with LessThan(64) expiry check
  Delegation.circom         # Extended delegation circuit with expiry ordering
contracts/
  AgentPolicyVerifier.sol   # Placeholder verifier (no redundant expiry check)
test/circuits/
  AgentPolicy.test.ts       # Expiry enforcement tests
  Delegation.test.ts        # Delegation ordering tests
specs/
  expiry-constraint-audit.md # Invariant table and rationale
```

## Prerequisites

- circom >= 2.1.6
- snarkjs >= 0.7.0
- circomlib (npm)
- circomlibjs (npm, for tests)
- circom_tester (npm, for tests)
- Node.js >= 18

## Setup

```bash
npm install circomlib circomlibjs circom_tester snarkjs
```

## Compile Circuits

```bash
# AgentPolicy
circom circuits/AgentPolicy.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -o build/agent_policy

# Delegation
circom circuits/Delegation.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -o build/delegation_expiry
```

## Run Tests

```bash
npx mocha --require ts-node/register test/circuits/AgentPolicy.test.ts
npx mocha --require ts-node/register test/circuits/Delegation.test.ts
```

## Trusted Setup (after circuit changes)

```bash
# Download powers of tau (if not already available)
snarkjs powersoftau new bn128 16 pot16_0000.ptau
snarkjs powersoftau contribute pot16_0000.ptau pot16_final.ptau
snarkjs powersoftau prepare phase2 pot16_final.ptau pot16_final.ptau

# AgentPolicy setup
snarkjs groth16 setup build/agent_policy/AgentPolicy.r1cs pot16_final.ptau ap_0000.zkey
snarkjs zkey contribute ap_0000.zkey ap_final.zkey
snarkjs zkey export solidityverifier ap_final.zkey contracts/AgentPolicyVerifier.sol

# Delegation setup
snarkjs groth16 setup build/delegation_expiry/Delegation.r1cs pot16_final.ptau del_0000.zkey
snarkjs zkey contribute del_0000.zkey del_final.zkey
snarkjs zkey export solidityverifier del_final.zkey contracts/DelegationVerifier.sol
```

## Verify Constraint Counts

```bash
snarkjs r1cs info build/agent_policy/AgentPolicy.r1cs
# Expected: ~40,758 constraints (was ~40,628 before fix)

snarkjs r1cs info build/delegation_expiry/Delegation.r1cs
# Expected: ~41,302 constraints (was ~41,042 before fix)
```

## Spec

See [specs/expiry-constraint-audit.md](specs/expiry-constraint-audit.md) for
the full invariant table, rationale, and constraint cost breakdown.
