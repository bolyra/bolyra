# Delegation Circuit v2 — Phantom Delegatee Fix

**Experiment:** `formal_verifier_phantom_delegatee_inclusion`  
**Priority:** Critical  
**Status:** Implementation complete

## Overview

This experiment fixes CVE-BOLYRA-2026-001: the Delegation circuit v1 accepts `delegateeCredCommitment` as a private input without proving it exists in the agent Merkle tree. An attacker can fabricate any credential commitment, receive a valid delegation, and use the resulting `scopeCommitment` downstream.

The fix adds a BinaryMerkleRoot(20) inclusion proof against the `agentTreeRoot` (new public input), validated on-chain against the IdentityRegistry's root history buffer.

## Artifacts

```
circuits/
  lib/binary_merkle_root.circom    # Poseidon-based binary Merkle root template
  delegation/delegation.circom     # Delegation circuit v2 (with inclusion proof)
contracts/
  IRootHistory.sol                 # Shared root validation interface
  DelegationVerifier.sol           # Groth16 verifier (placeholder — regenerate after ceremony)
  DelegationRegistry.sol           # On-chain delegation registry with root validation
sdk/src/delegation/
  prover.ts                        # Proof generation helper with Merkle witness builder
specs/
  delegation-circuit-v2.md         # Full circuit specification
docs/security/
  delegation-soundness.md          # Vulnerability writeup + fix + trust model
test/
  circuits/delegation.test.ts      # Circom unit tests (8 cases)
  contracts/DelegationRegistry.test.ts  # Contract tests (8 cases)
```

## Prerequisites

- **circom** >= 2.1.6
- **snarkjs** >= 0.7.0
- **Node.js** >= 18
- **circomlib** and **circomlibjs** (npm packages)
- **Hardhat** with `@nomicfoundation/hardhat-chai-matchers`
- **Foundry** (for Solidity-level testing, optional)

## Quick Start

### 1. Install Dependencies

```bash
npm install circomlib circomlibjs snarkjs circom_tester
npm install --save-dev hardhat @nomicfoundation/hardhat-chai-matchers
```

### 2. Compile the Circuit

```bash
circom circuits/delegation/delegation.circom \
  --r1cs --wasm --sym \
  -o build/delegation \
  -l node_modules
```

### 3. Trusted Setup (Development)

```bash
# Download Powers of Tau (2^16 supports ~65k constraints)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau

# Phase 2 setup
snarkjs groth16 setup build/delegation/delegation.r1cs \
  powersOfTau28_hez_final_16.ptau \
  build/delegation/delegation_0000.zkey

# Contribute entropy
snarkjs zkey contribute \
  build/delegation/delegation_0000.zkey \
  build/delegation/delegation_final.zkey \
  --name="dev-contribution" -v

# Export verification key
snarkjs zkey export verificationkey \
  build/delegation/delegation_final.zkey \
  build/delegation/verification_key.json

# Export Solidity verifier (replace placeholder)
snarkjs zkey export solidityverifier \
  build/delegation/delegation_final.zkey \
  contracts/DelegationVerifier.sol
```

### 4. Run Circuit Tests

```bash
npx mocha --require ts-node/register test/circuits/delegation.test.ts
```

### 5. Run Contract Tests

```bash
npx hardhat test test/contracts/DelegationRegistry.test.ts
```

### 6. Generate a Proof (SDK)

```typescript
import { DelegationProver } from "./sdk/src/delegation/prover";

const prover = new DelegationProver({
  wasmPath: "./build/delegation/delegation_js/delegation.wasm",
  zkeyPath: "./build/delegation/delegation_final.zkey",
});

const result = await prover.prove({
  delegatorSecret: 12345n,
  delegatorNonce: 67890n,
  delegateeCredCommitment: /* from agent tree */ 0xabcn,
  scope: 42n,
  agentTreeSnapshot: { leaves: [/* ... */], depth: 20 },
  leafIndex: 7,
});

console.log("Proof:", result.proof);
console.log("Agent Tree Root:", result.agentTreeRoot);
```

## Estimated Constraints

~42,060 (fits within 2^16 Powers of Tau)

## Security

See [docs/security/delegation-soundness.md](docs/security/delegation-soundness.md) for the full vulnerability analysis, trust model, and upgrade path.
