# Chain-agnostic nullifier registry with cross-chain replay protection

The current nullifierHash is Poseidon2(scope, secret) and is chain-unaware. If the same verifier contract is deployed on Base and Arbitrum, a proof verified on Base can be replayed on Arbitrum since nullifier sets are per-chain. Fix: include chainId in the nullifier derivation (Poseidon3(scope, secret, chainId)) and add a chainId public input to HumanUniqueness and AgentPolicy circuits. This is a breaking change to the circuit but critical before multi-chain deployment.

## Status

Placeholder — awaiting implementation.
