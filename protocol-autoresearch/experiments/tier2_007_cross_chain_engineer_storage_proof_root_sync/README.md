# Cross-chain Merkle root sync via EIP-1186 storage proofs with Base/Arbitrum/Polygon adapters

Deploy read-only IdentityRegistry mirrors on Arbitrum and Polygon that accept EIP-1186 storage proofs of humanTree/agentTree roots from the canonical Base registry. Implement a CrossChainRootRelay base contract with chain-specific adapters (ArbSys for Arbitrum, CheckpointManager for Polygon), a 30-slot root history ring buffer, and replay protection. Ship an SDK helper generateStorageProof() wrapping eth_getProof plus an operator runbook for relay bot operation.

## Status

Placeholder — awaiting implementation.
