---
title: Circom Circuits Overview
visibility: public
sources:
  - circuits/src/HumanUniqueness.circom
  - circuits/src/AgentPolicy.circom
  - circuits/src/Delegation.circom
  - CLAUDE.md
last-updated: 2026-06-28
staleness-threshold: 60d
tags: [circuits, circom, groth16, plonk, zkp]
---

Three Circom 2 circuits implement the Bolyra protocol's zero-knowledge proofs: HumanUniqueness for human identity, AgentPolicy for agent credentials, and Delegation for scope-narrowing chains. All circuits use MAX_DEPTH=20 (~1M entities).

## Overview

The circuits live in `circuits/src/` and compile to R1CS via Circom 2.1.6. They share common dependencies from circomlib (Poseidon, EdDSA, comparators, bitify) and @zk-kit (BinaryMerkleRoot). Build artifacts land in `circuits/build/`.

Each circuit produces a Groth16 proof. AgentPolicy and Delegation also have PLONK builds (universal setup, no per-circuit ceremony). HumanUniqueness is Groth16-only because it reuses the public Semaphore v4 Powers of Tau ceremony at depth 20.

## Key Concepts

**Proving systems**: Groth16 is required for all circuits. PLONK is optional for AgentPolicy and Delegation.

**Powers of Tau**: `pot16.ptau` (2^16 constraints) is the universal SRS for project-specific Groth16 keys. HumanUniqueness reuses the Semaphore v4 Phase 1 ceremony and only needs a circuit-specific Phase 2.

**Test split**: Intentional two-tier testing. `test:circuits:fast` runs witness-generation only (mock proofs). `test:circuits:slow` sets `FULL_PROOF=1` and runs real Groth16/PLONK proving (~2 min). CI defaults to fast.

**rapidsnark vs snarkjs**: Production proving uses the native `rapidsnark_prover` binary in `circuits/build/`. snarkjs is dev/test only. Benchmarks in `circuits/scripts/bench_rapidsnark.js`.

## How It Works

### HumanUniqueness

Proves a human is enrolled in the identity group and binds the proof to a session nonce.

| Property | Value |
|---|---|
| Proving system | Groth16 only |
| Estimated constraints | ~15,000 |
| Ceremony | Semaphore v4 (depth 20) -- no project-specific setup |

**Steps:**
1. Derive public key from secret via `BabyPbk()` (compatible with Semaphore v4 Identity)
2. Compute identity commitment: `Poseidon2(Ax, Ay)` (leaf in humanTree)
3. Prove Merkle membership via `BinaryMerkleRoot(20)`
4. Compute nullifier: `Poseidon2(scope, secret)` -- one per identity per scope
5. Compute nonce binding: `Poseidon2(nullifierHash, sessionNonce)`
6. Range-check secret to `[0, 2^251)` via `Num2Bits(251)`

**Public inputs:** `scope`, `sessionNonce`
**Public outputs:** `humanMerkleRoot`, `nullifierHash`, `nonceBinding`

### AgentPolicy

Proves an AI agent holds a valid, operator-signed credential that satisfies a required permission policy.

| Property | Value |
|---|---|
| Proving system | Groth16 + PLONK |
| Estimated constraints | ~50,000 |
| Ceremony | Project-specific Phase 2 against pot16.ptau |

**Steps:**
1. Range-check all uint64 fields (`Num2Bits(64)`) -- prevents field overflow attacks
2. Compute credential commitment: `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` (leaf in agentTree)
3. Verify operator EdDSA signature over credential commitment
4. Prove Merkle membership via `BinaryMerkleRoot(20)`
5. Check scope satisfaction: `requiredBits[i] * (1 - permBits[i]) === 0` for each bit
6. Enforce cumulative bit encoding invariant (bit 4 implies 2+3, bit 3 implies 2)
7. Check expiry: `currentTimestamp < expiryTimestamp`
8. Compute nullifier: `Poseidon2(credentialCommitment, sessionNonce)`
9. Compute scope commitment: `Poseidon3(bitmask, credentialCommitment, expiry)` for delegation chain linking

**Public inputs:** `requiredScopeMask`, `currentTimestamp`, `sessionNonce`
**Public outputs:** `agentMerkleRoot`, `nullifierHash`, `scopeCommitment`

### Delegation

Proves a valid one-way scope-narrowing delegation from delegator to delegatee.

| Property | Value |
|---|---|
| Proving system | Groth16 + PLONK |
| Estimated constraints | ~55,000 |
| Ceremony | Project-specific Phase 2 against pot16.ptau |

**Steps:**
1. Range-check all scope and expiry fields (`Num2Bits(64)`)
2. Recompute delegator credential commitment and verify it matches the claimed value (UC3.1 fix -- binds signing key to credential)
3. Verify chain link: `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorExpiry) === previousScopeCommitment`
4. Check scope subset: `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for each bit
5. Enforce cumulative bit encoding on delegatee scope
6. Check expiry narrowing: `delegateeExpiry <= delegatorExpiry`
7. Check delegatee expiry liveness: `currentTimestamp < delegateeExpiry`
8. Verify delegator EdDSA signature over delegation token
9. Prove delegatee Merkle membership (CIP-1: prevents phantom delegatee attacks)
10. Compute new scope commitment and delegation nullifier

**Public inputs:** `previousScopeCommitment`, `sessionNonce`, `currentTimestamp`
**Public outputs:** `newScopeCommitment`, `delegationNullifier`, `delegateeMerkleRoot`

## Build Process

```bash
# Compile all circuits to build/
npm run compile:circuits

# Test (witness-only, fast)
npm run test:circuits:fast

# Test (real proofs, ~2 min)
npm run test:circuits:slow

# Build artifacts produced:
# circuits/build/*.r1cs
# circuits/build/*_final.zkey (Groth16)
# circuits/build/*_plonk.zkey (PLONK, AgentPolicy + Delegation)
# circuits/build/*_vkey.json
# circuits/build/*_js/*.wasm
```

## Current Status

- All three circuits are stable and production-ready for Phase 1.
- Constraint budgets are within target (<80k for AgentPolicy/Delegation).
- Solidity verifiers must be regenerated from `vkey.json` whenever a circuit changes.
- Conformance test suite: 37 vectors covering all circuits.

## See Also

- [zkp-handshake.md](zkp-handshake.md) -- How circuits are used in the handshake protocol
- [delegation.md](delegation.md) -- Delegation circuit in detail
- [permissions-model.md](permissions-model.md) -- The bitmask encoding enforced by circuits
- `circuits/scripts/` -- 9 benchmarks (groth16/plonk/rapidsnark)
