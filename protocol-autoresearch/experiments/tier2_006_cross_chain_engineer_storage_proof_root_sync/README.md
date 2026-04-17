# EIP-1186 storage proof cross-chain root sync

Implement cross-chain root synchronization using EIP-1186 storage proofs. Deploy a BolyraRootRelay contract on Arbitrum and Polygon that accepts an RLP-encoded storage proof of IdentityRegistry's humanTree and agentTree roots from Base. The relay contract verifies the proof against a known Base block hash (available via L1 state roots on each L2), then caches the verified roots locally. This eliminates reliance on trusted relayers and lets proofs generated against Base roots be verified on any target chain with ~15 minute latency.

## Status

Placeholder — awaiting implementation.
