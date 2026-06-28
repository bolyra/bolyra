# Bind chain ID into sessionNonce to prevent cross-chain proof replay

The current sessionNonce is chain-agnostic: a valid handshake proof generated for Base can be replayed on Arbitrum or Polygon if both chains share the same Merkle roots. Fix this by defining sessionNonce = Poseidon2(verifierNonce, chainId) and requiring the contract to enforce block.chainid matches the chainId embedded in the nonce. This is a single-line change in HumanUniqueness and AgentPolicy circuits (add a chainId public input, bind it into the nonce hash), plus a require(chainId == block.chainid) in IdentityRegistry.verifyHandshake().

## Status

Placeholder — awaiting implementation.
