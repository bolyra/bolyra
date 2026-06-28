# Delegation circuit does not verify delegator is enrolled in agentTree

The Delegation circuit takes `delegatorCredCommitment` as a private input and uses it to recompute the previousScopeCommitment check, but it never proves that `delegatorCredCommitment` is a leaf in the agentTree Merkle tree. The CIP-1 fix added a Merkle inclusion proof for the *delegatee*, but the *delegator* side relies entirely on chain-linking (previousScopeCommitment matching). An attacker who knows a valid previousScopeCommitment (emitted publicly in events) can forge a delegatorCredCommitment that hashes to the right scopeCommitment without being an enrolled agent. Add a delegator Merkle inclusion proof (reusing the same MAX_DEPTH parameter), or alternatively verify the delegator's AgentPolicy proof on-chain before accepting the delegation and pass the verified agentMerkleRoot as a public input to the delegation circuit.

## Status

Placeholder — awaiting implementation.
