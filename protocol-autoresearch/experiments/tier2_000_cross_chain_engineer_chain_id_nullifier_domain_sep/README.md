# Domain-separate nullifiers and nonces by chainId

Currently nullifierHash in both HumanUniqueness and AgentPolicy circuits is computed without chain context (Poseidon2(scope, secret) and Poseidon3(credentialCommitment, sessionNonce, ...)). If the same registry is deployed on multiple chains, a proof verified on Base can be replayed on Arbitrum since the nullifier is identical. Add chainId as a public input to all three circuits and include it in nullifier derivation: nullifier = Poseidon3(scope, secret, chainId) for humans, Poseidon4(..., chainId) for agents. The on-chain verifier passes block.chainid and checks it matches the public signal.

## Status

Placeholder — awaiting implementation.
