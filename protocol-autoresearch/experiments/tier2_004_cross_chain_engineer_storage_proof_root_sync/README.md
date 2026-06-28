# Cross-chain Merkle root sync via EIP-1186 storage proofs

Deploy IdentityRegistry on Arbitrum and Polygon alongside Base Sepolia, then implement a RootRelay contract that accepts EIP-1186 storage proofs to sync humanTree and agentTree roots across chains without a trusted relayer. The source chain's root slot is proven against a block hash anchored by each L2's native L1 state oracle (Arbitrum's ArbSys, Polygon's StateSender). This eliminates the single-chain bottleneck where agents on Arbitrum cannot verify credentials enrolled on Base.

## Status

Placeholder — awaiting implementation.
