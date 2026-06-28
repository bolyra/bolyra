# Chain-scoped nullifier domain separation

The current nullifierHash in HumanUniqueness is Poseidon2(scope, secret) and in AgentPolicy is Poseidon2(credentialCommitment, sessionNonce). Neither includes a chain identifier, so a valid proof on Base can be replayed on Arbitrum or Polygon if the same IdentityRegistry is deployed with the same roots. Add a public input chainId to all three circuits and bind it into the nullifier: Poseidon3(scope, secret, chainId) for humans, Poseidon3(credentialCommitment, sessionNonce, chainId) for agents. The on-chain verifier checks chainId == block.chainid.

## Status

Placeholder — awaiting implementation.
