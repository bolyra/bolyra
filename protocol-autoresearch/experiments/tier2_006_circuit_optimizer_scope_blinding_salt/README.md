# Add blinding salt to scope commitment in AgentPolicy and Delegation

scopeCommitment = Poseidon(permissionBitmask, credentialCommitment) is vulnerable to offline brute-force since the 64-bit bitmask has at most 2^64 preimages and credentialCommitment is a public Merkle leaf. Adding a random blinding salt as a third Poseidon input (Poseidon3) makes the commitment computationally hiding. Cost is ~1 additional Poseidon round (~300 constraints). Deliverable: updated AgentPolicy.circom and Delegation.circom with blindingSalt private input, updated scope commitment computation, and matching contract-side changes to accept the new public signal layout.

## Status

Placeholder — awaiting implementation.
