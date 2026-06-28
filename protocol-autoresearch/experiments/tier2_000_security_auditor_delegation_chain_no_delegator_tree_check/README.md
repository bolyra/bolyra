# Delegation circuit does not prove delegator is enrolled — phantom delegator attack

The Delegation circuit takes `delegatorCredCommitment` as a private input and verifies the delegator's EdDSA signature over the delegation token, but never proves that `delegatorCredCommitment` exists in the agent Merkle tree. The chain-link is via `previousScopeCommitment` (a public input matched on-chain), but a first-hop delegation from a fabricated agent whose credential was never enrolled can produce a valid `previousScopeCommitment` if the attacker controls the AgentPolicy proof (e.g., in a compromised relayer scenario where the relayer submits both proofs). Fix: add a Merkle inclusion proof for `delegatorCredCommitment` against the agent tree root, similar to the existing delegatee inclusion check (CIP-1). Cost: one additional BinaryMerkleRoot(20) (~6k constraints).

## Status

Placeholder — awaiting implementation.
