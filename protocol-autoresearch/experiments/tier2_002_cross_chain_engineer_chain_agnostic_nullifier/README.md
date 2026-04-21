# Chain-agnostic nullifier registry to prevent cross-chain replay

The current nullifier check (`usedNonces`, `usedNullifiers`) is per-contract, meaning a handshake proof verified on Base can be replayed on Arbitrum if the same root is synced. Add a `chainId` field to the nullifier derivation: `nullifier = Poseidon3(scope, secret, chainId)` in HumanUniqueness and `Poseidon3(credentialCommitment, sessionNonce, chainId)` in AgentPolicy. This makes nullifiers chain-specific at the circuit level. Publish a shared nullifier Bloom filter commitment on-chain that cross-chain relayers can reference for probabilistic double-spend detection before full finality.

## Status

Placeholder — awaiting implementation.
