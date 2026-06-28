# Cross-chain root sync via EIP-1186 storage proofs

Deploy IdentityRegistry on Arbitrum and Polygon alongside Base Sepolia, then implement a CrossChainRootRelay contract that accepts EIP-1186 storage proofs to sync humanTree and agentTree roots across chains without a trusted relayer. The relay verifies the source chain's state root (available via L1 block hash precompiles on L2s) and extracts the registry's root slot value. This lets a proof generated against Base's tree verify on Arbitrum or Polygon with ~30-root-buffer latency.

## Status

Placeholder — awaiting implementation.
