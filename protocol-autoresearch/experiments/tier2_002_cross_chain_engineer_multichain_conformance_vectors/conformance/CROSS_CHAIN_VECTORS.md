# Bolyra Cross-Chain Conformance Test Vectors

## Overview

This document specifies 15 cross-chain test vectors for the Bolyra identity protocol conformance suite. Each vector targets a specific protocol invariant that any cross-chain verifier implementation must enforce.

## Protocol Invariants Tested

| # | Invariant | Vectors | Description |
|---|-----------|---------|-------------|
| 1 | **Chain ID Binding** | cv_01, cv_02 | Proofs must commit to the chain ID where they will be verified. Unbound or mismatched chain IDs must be rejected. |
| 2 | **Root Staleness (TTL)** | cv_03, cv_04 | Relayed Merkle roots have a maximum age. Roots older than `maxRootAge` seconds must be rejected. |
| 3 | **Storage Proof Verification** | cv_05, cv_06, cv_07 | Storage proofs must reference valid block hashes from the declared source chain. Tampered hashes and cross-chain hash substitution must be rejected. |
| 4 | **Batch Checkpoint Inclusion** | cv_08, cv_09, cv_10 | Batch Merkle inclusion proofs must correctly prove that a leaf is part of a registered batch root. Invalid leaves and mismatched roots must be rejected. |
| 5 | **Nullifier Replay Protection** | cv_11, cv_12, cv_13 | Nullifiers must not be reusable. Same-chain replay, cross-chain replay (global scope), and valid fresh usage (chain-scoped) are tested. |
| 6 | **Relay Timestamp Integrity** | cv_14, cv_15 | Relay timestamps must be present and not set in the future beyond tolerance. |

## Vector Details

### cv_01: Unbound Chain ID (FAIL)

**Invariant:** Chain ID Binding 
**Scenario:** Proof generated on Ethereum (chainId=1) submitted to Polygon verifier (chainId=137). The proof's public inputs have a zero value in the chain ID slot, meaning the proof does not commit to any specific chain. 
**Why it must fail:** Without chain ID binding, a proof valid on one chain can be replayed on any other chain, breaking identity isolation.

### cv_02: Bound Chain ID Valid (PASS)

**Invariant:** Chain ID Binding 
**Scenario:** Proof generated and verified on Ethereum (chainId=1). The chain ID commitment in public inputs matches the verifier's chain. 
**Why it passes:** This is the correct happy-path where the proof is bound to the chain it's being verified on.

### cv_03: Stale Root Within TTL (PASS)

**Invariant:** Root Staleness 
**Scenario:** Merkle root relayed from Ethereum to Polygon with 30-minute age (1800s), within the 1-hour TTL (3600s). 
**Why it passes:** The root is still fresh enough for the verifier to trust it.

### cv_04: Stale Root Exceeded TTL (FAIL)

**Invariant:** Root Staleness 
**Scenario:** Same root but with 2-hour age (7200s), exceeding the 1-hour TTL. Simulates bridge congestion or sequencer delay. 
**Why it must fail:** Stale roots may not reflect recent membership changes (revocations, additions).

### cv_05: Storage Proof Valid Block Hash (PASS)

**Invariant:** Storage Proof Verification 
**Scenario:** Storage proof from Ethereum verified on Arbitrum. The block hash is registered as valid for Ethereum. 
**Why it passes:** All storage proof fields are consistent and the block hash is known-valid on the source chain.

### cv_06: Storage Proof Invalid Block Hash (FAIL)

**Invariant:** Storage Proof Verification 
**Scenario:** Storage proof with a fabricated block hash (0xdeaddead...) that does not correspond to any real block. 
**Why it must fail:** Accepting fabricated block hashes allows forging arbitrary state proofs.

### cv_07: Storage Proof Wrong Chain Block Hash (FAIL)

**Invariant:** Storage Proof Verification 
**Scenario:** Storage proof with a block hash that is valid on Polygon but the vector declares sourceChainId=1 (Ethereum). 
**Why it must fail:** A verifier must ensure the block hash belongs to the declared source chain, not just that it exists somewhere.

### cv_08: Batch Checkpoint Valid (PASS)

**Invariant:** Batch Checkpoint Inclusion 
**Scenario:** Identity commitment correctly included in a batch Merkle tree (depth 3). Proof path hashes to the registered batch root. 
**Why it passes:** The inclusion proof is mathematically valid against the registered root.

### cv_09: Batch Checkpoint Invalid Leaf (FAIL)

**Invariant:** Batch Checkpoint Inclusion 
**Scenario:** Same proof path as cv_08 but with a different leaf value. The recomputed root will not match. 
**Why it must fail:** The prover is claiming inclusion of a different identity commitment than what was actually batched.

### cv_10: Batch Checkpoint Wrong Root (FAIL)

**Invariant:** Batch Checkpoint Inclusion 
**Scenario:** Valid leaf and proof path that hash to a consistent root, but that root is not the one registered on-chain. 
**Why it must fail:** The proof is from a different (possibly fabricated) batch, not the one the verifier trusts.

### cv_11: Nullifier Replay Same Chain (FAIL)

**Invariant:** Nullifier Replay Protection 
**Scenario:** Same nullifier hash submitted twice on Ethereum. The nullifier set already contains this hash from a prior valid submission. 
**Why it must fail:** Nullifier reuse allows double-spending of identity attestations.

### cv_12: Nullifier Replay Cross-Chain (FAIL)

**Invariant:** Nullifier Replay Protection 
**Scenario:** Nullifier used on Ethereum replayed on Polygon with global nullifier scope. The cross-chain nullifier set must catch this. 
**Why it must fail:** With global scope, nullifiers must be synchronized across chains to prevent cross-chain double-spend. This is the hardest invariant for bridge implementers.

### cv_13: Nullifier Cross-Chain Scoped Valid (PASS)

**Invariant:** Nullifier Replay Protection 
**Scenario:** A fresh (never-before-used) nullifier submitted on Polygon with chain-scoped nullifier set. 
**Why it passes:** With chain-scoped nullifiers, each chain maintains an independent registry. A new nullifier on a new chain is valid.

### cv_14: Relay Timestamp Future (FAIL)

**Invariant:** Relay Timestamp Integrity 
**Scenario:** Relay timestamp set 2 hours in the future beyond block.timestamp. 
**Why it must fail:** Future timestamps could be used to artificially extend root TTL or manipulate freshness checks.

### cv_15: Relay Timestamp Missing (FAIL)

**Invariant:** Relay Timestamp Integrity 
**Scenario:** The relayTimestamp field is absent from the proof public inputs. 
**Why it must fail:** Every cross-chain proof must include a relay timestamp for freshness assessment. Its absence is a schema violation.

## Public Input Layout Convention

| Index | Field | Description |
|-------|-------|-------------|
| 0 | `merkleRoot` | Identity Merkle tree root |
| 1 | `nullifierHash` | Nullifier derived from identity secret + external nullifier |
| 2 | `chainId` | EIP-155 chain ID the proof is bound to |
| 3 | `blockHash` | (Optional) Block hash for storage proof vectors |

## Expected Results Summary

| Vector | Category | Expected | Failure Reason |
|--------|----------|----------|----------------|
| cv_01 | chain_id_binding | FAIL | CHAIN_ID_UNBOUND |
| cv_02 | chain_id_binding | PASS | — |
| cv_03 | root_staleness | PASS | — |
| cv_04 | root_staleness | FAIL | ROOT_EXPIRED |
| cv_05 | storage_proof | PASS | — |
| cv_06 | storage_proof | FAIL | INVALID_BLOCK_HASH |
| cv_07 | storage_proof | FAIL | BLOCK_HASH_CHAIN_MISMATCH |
| cv_08 | batch_checkpoint | PASS | — |
| cv_09 | batch_checkpoint | FAIL | BATCH_INVALID_LEAF |
| cv_10 | batch_checkpoint | FAIL | BATCH_ROOT_MISMATCH |
| cv_11 | nullifier_replay | FAIL | NULLIFIER_ALREADY_USED |
| cv_12 | nullifier_replay | FAIL | NULLIFIER_CROSS_CHAIN_REPLAY |
| cv_13 | nullifier_replay | PASS | — |
| cv_14 | relay_timestamp | FAIL | RELAY_TIMESTAMP_FUTURE |
| cv_15 | relay_timestamp | FAIL | RELAY_TIMESTAMP_MISSING |

**Expected totals: 5 PASS, 10 FAIL**
