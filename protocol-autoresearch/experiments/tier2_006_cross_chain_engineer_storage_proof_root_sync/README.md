# Cross-chain root sync via EIP-1186 storage proofs

Deploy IdentityRegistry on Arbitrum and Polygon alongside the existing Base deployment. Implement a RootRelay contract that accepts EIP-1186 storage proofs of humanRootHistory/agentRootHistory slots from the source chain, verified against the source chain's state root available via each L2's L1 block oracle. This avoids bridges entirely — any relayer can post a storage proof and the destination chain verifies it trustlessly. Add a `foreignRootExists` mapping and extend `handshakeVerify` to accept roots from any registered source chain.

## Status

Placeholder — awaiting implementation.
