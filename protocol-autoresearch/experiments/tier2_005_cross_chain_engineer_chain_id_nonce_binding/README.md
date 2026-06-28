# Bind sessionNonce to chainId to prevent cross-chain replay

The current sessionNonce is chain-agnostic: a valid handshake proof generated for Base can be replayed on Arbitrum or Polygon if the same IdentityRegistry is deployed there with the same roots. Fix: change nonceBinding in HumanUniqueness and nullifierHash in AgentPolicy to include block.chainid as a Poseidon input (nonceBinding = Poseidon3(nullifierHash, sessionNonce, chainId)). Update IdentityRegistry.verifyHandshake to pass block.chainid as the expected chainId public signal. This is a prerequisite for any multi-chain deployment.

## Status

Placeholder — awaiting implementation.
