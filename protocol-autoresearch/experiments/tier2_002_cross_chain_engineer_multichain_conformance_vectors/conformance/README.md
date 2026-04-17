# Bolyra Cross-Chain Conformance Suite

Test vectors and tooling for verifying cross-chain identity proof implementations against the Bolyra protocol specification.

## Structure

```
conformance/
  cross_chain_vector_schema.json   # JSON Schema for test vectors
  CROSS_CHAIN_VECTORS.md           # Detailed specification of each vector
  IMPLEMENTER_GUIDE.md             # Integration guide for bridge implementers
  vectors/
    cv_01_unbound_chain_id.json    # Chain ID binding: unbound (FAIL)
    cv_02_bound_chain_id_valid.json# Chain ID binding: valid (PASS)
    cv_03_stale_root_within_ttl.json   # Root age: fresh (PASS)
    cv_04_stale_root_exceeded_ttl.json # Root age: stale (FAIL)
    cv_05_storage_proof_valid_blockhash.json    # Storage proof: valid (PASS)
    cv_06_storage_proof_invalid_blockhash.json  # Storage proof: invalid (FAIL)
    cv_07_storage_proof_wrong_chain_blockhash.json # Storage proof: wrong chain (FAIL)
    cv_08_batch_checkpoint_valid.json          # Batch: valid inclusion (PASS)
    cv_09_batch_checkpoint_invalid_leaf.json   # Batch: wrong leaf (FAIL)
    cv_10_batch_checkpoint_wrong_root.json     # Batch: wrong root (FAIL)
    cv_11_nullifier_replay_same_chain.json     # Nullifier: same chain replay (FAIL)
    cv_12_nullifier_replay_cross_chain.json    # Nullifier: cross-chain replay (FAIL)
    cv_13_nullifier_cross_chain_scoped_valid.json # Nullifier: fresh scoped (PASS)
    cv_14_relay_timestamp_future.json          # Timestamp: future (FAIL)
    cv_15_relay_timestamp_missing.json         # Timestamp: missing (FAIL)
  runner/
    cross_chain_runner.ts          # TypeScript test harness
  contracts/
    MockCrossChainVerifier.sol     # Solidity reference verifier
```

## Usage

### Run the conformance suite (off-chain)

```bash
cd conformance/runner
npm install
npx ts-node cross_chain_runner.ts --vectors ../vectors --mode offchain
```

Expected output: 15 vectors run, 5 PASS, 10 FAIL — all matching expected results.

### Validate vectors against schema

The runner validates all vectors against `cross_chain_vector_schema.json` before execution.

### Run against your verifier

See [IMPLEMENTER_GUIDE.md](./IMPLEMENTER_GUIDE.md) for instructions on plugging in your own verifier implementation.

## Protocol Invariants Covered

1. **Chain ID Binding** — proofs must commit to the verification chain
2. **Root Staleness (TTL)** — relayed roots expire after maxRootAge
3. **Storage Proof Verification** — block hashes must be valid on the declared source chain
4. **Batch Checkpoint Inclusion** — Merkle inclusion proofs must be valid against registered roots
5. **Nullifier Replay Protection** — nullifiers cannot be reused (same-chain or cross-chain)
6. **Relay Timestamp Integrity** — timestamps must be present and not in the future

## Dependencies

- Node.js >= 18
- TypeScript >= 5.0
- ajv (JSON Schema validation)
- ethers >= 6.0 (on-chain mode only)
- Solidity ^0.8.24 (reference contract)

## Adding Vectors

Create a new `cv_NN_*.json` file following the schema. See IMPLEMENTER_GUIDE.md for details.
