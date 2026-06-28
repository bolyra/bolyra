# Cross-chain root sync via EIP-1186 storage proofs

Deploy IdentityRegistry on Arbitrum and Polygon alongside the existing Base Sepolia deployment, then implement a StorageProofRootRelay contract that accepts EIP-1186 storage proofs of the humanTree and agentTree roots from the canonical chain. This eliminates reliance on trusted relayers: any user can submit a storage proof from Base to update the mirrored root on Arbitrum/Polygon. The relay contract verifies the RLP-encoded account proof against the L1 state root (available via each L2's precompile: ArbSys on Arbitrum, L1Block on OP-stack/Base) and extracts the specific storage slot holding the Merkle root.

## Status

Placeholder — awaiting implementation.
