# Bolyra Cross-Chain Conformance: Implementer Guide

## Introduction

This guide is for third-party bridge implementers who want to verify their cross-chain verifier implementation against the Bolyra conformance suite. The suite contains 15 test vectors (5 expected PASS, 10 expected FAIL) covering six protocol invariants.

## Quick Start

### 1. Install Dependencies

```bash
cd conformance/runner
npm install
# or
yarn install
```

Required packages:
- `typescript` >= 5.0
- `ts-node`
- `ajv` (JSON Schema validation)
- `ethers` >= 6.0 (only for on-chain mode)

### 2. Run Off-Chain (Reference Implementation)

```bash
npx ts-node cross_chain_runner.ts --vectors ../vectors --mode offchain
```

This runs all vectors against the built-in `OffChainMockVerifier`, which implements the five invariant checks in TypeScript. All 15 vectors should match their expected results.

### 3. Run On-Chain (Against Your Verifier)

```bash
npx ts-node cross_chain_runner.ts \
  --vectors ../vectors \
  --mode onchain \
  --rpc http://localhost:8545 \
  --contract 0xYourVerifierAddress
```

On-chain mode requires you to deploy a verifier contract that implements the `verify(VerifyParams)` interface defined in `MockCrossChainVerifier.sol`.

## Plugging In Your Verifier

### Off-Chain Verifier

Implement the `Verifier` interface from `cross_chain_runner.ts`:

```typescript
import { Verifier, TestVector, VerificationResult } from './cross_chain_runner';

class MyVerifier implements Verifier {
  async setup(vector: TestVector): Promise<void> {
    // Pre-condition setup: register block hashes, seed nullifiers, etc.
  }

  async verify(vector: TestVector): Promise<VerificationResult> {
    // Your verification logic here
    // Return { success: true } or { success: false, error: "FAILURE_REASON" }
  }
}
```

### On-Chain Verifier

Your Solidity contract must implement the `VerifyParams` struct and `verify()` function signature from `MockCrossChainVerifier.sol`. The error reasons should match the canonical failure reason strings.

## Invariant Checks

Your verifier must enforce these five independently testable invariants:

### 1. Chain ID Binding
- Public input at index 2 must be non-zero
- Must equal the chain ID the verifier is deployed on
- Failure codes: `CHAIN_ID_UNBOUND`, `CHAIN_ID_MISMATCH`

### 2. Root Age TTL
- `block.timestamp - relayTimestamp` must be <= `maxRootAge`
- Failure code: `ROOT_EXPIRED`

### 3. Storage Proof Block Hash Verification
- Block hash in the storage proof must be registered as valid for the declared `sourceChainId`
- Must reject hashes valid on a different chain than declared
- Failure codes: `INVALID_BLOCK_HASH`, `BLOCK_HASH_CHAIN_MISMATCH`

### 4. Batch Merkle Inclusion
- Recompute the Merkle root from `leaf + leafIndex + proofPath`
- Computed root must match a registered `batchRoot`
- Failure codes: `BATCH_INVALID_LEAF`, `BATCH_ROOT_MISMATCH`

### 5. Scoped Nullifier Set
- **Global scope:** nullifier hash must not appear in the cross-chain nullifier set
- **Chain scope:** nullifier hash must not appear in the per-chain nullifier set for the target chain
- Failure codes: `NULLIFIER_ALREADY_USED`, `NULLIFIER_CROSS_CHAIN_REPLAY`

### 6. Relay Timestamp Integrity
- `relayTimestamp` must be present in public inputs
- Must not exceed `block.timestamp + futureTolerance`
- Failure codes: `RELAY_TIMESTAMP_MISSING`, `RELAY_TIMESTAMP_FUTURE`

## Expected Pass/Fail Counts

| Category | Vectors | Expected PASS | Expected FAIL |
|----------|---------|--------------|---------------|
| chain_id_binding | cv_01, cv_02 | 1 | 1 |
| root_staleness | cv_03, cv_04 | 1 | 1 |
| storage_proof | cv_05, cv_06, cv_07 | 1 | 2 |
| batch_checkpoint | cv_08, cv_09, cv_10 | 1 | 2 |
| nullifier_replay | cv_11, cv_12, cv_13 | 1 | 2 |
| relay_timestamp | cv_14, cv_15 | 0 | 2 |
| **Total** | **15** | **5** | **10** |

## Adding Custom Vectors

1. Create a new JSON file in `conformance/vectors/` following the naming convention `cv_NN_description.json`
2. Validate against `cross_chain_vector_schema.json` using any JSON Schema validator
3. Required fields: `vectorId`, `version`, `category`, `description`, `sourceChainId`, `targetChainId`, `relayTimestamp`, `rootAge`, `maxRootAge`, `proof`, `publicInputs`, `expectedResult`, `failureReason`
4. Category-specific fields are required based on the `category` value (see schema `allOf` conditions)
5. Run the test suite to verify your new vector produces the expected result

### Custom Vector Example

```json
{
  "vectorId": "cv_16_custom_example",
  "version": "1.0.0",
  "category": "chain_id_binding",
  "description": "Custom vector testing chain ID binding on Arbitrum",
  "sourceChainId": 42161,
  "targetChainId": 42161,
  "relayTimestamp": 1713340800,
  "rootAge": 60,
  "maxRootAge": 3600,
  "proof": "0x...",
  "publicInputs": ["0x...", "0x...", "0x000000000000000000000000000000000000000000000000000000000000a4b1"],
  "expectedResult": "pass",
  "failureReason": null
}
```

## Troubleshooting

| Symptom | Likely Cause |
|---------|-------------|
| All nullifier vectors fail | Nullifier set not being pre-seeded in `setup()` |
| Storage proof vectors all pass | Block hash validation not implemented; verifier accepts any hash |
| cv_07 passes (should fail) | Verifier checks hash existence but not chain-scoping |
| cv_12 passes (should fail) | Global nullifier synchronization not implemented |
| cv_15 passes (should fail) | Input arity check missing; verifier doesn't validate public input count |
| All root age vectors pass | Root age check uses wrong time source or maxRootAge is too large |

## Reference Implementation

The `MockCrossChainVerifier.sol` contract serves as the reference implementation. Each invariant check can be independently toggled via the `toggleInvariant()` function, making it useful for testing individual checks in isolation.

## Protocol Version

These vectors target Bolyra protocol version **0.5.0**. The `version` field in each vector is `1.0.0` (schema version, not protocol version). Protocol version is tracked in `metadata.protocolVersion`.
