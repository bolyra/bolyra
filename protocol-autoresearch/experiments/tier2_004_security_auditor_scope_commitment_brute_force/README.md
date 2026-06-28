# scopeCommitment is brute-forceable — missing blinding salt

In AgentPolicy, scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment). The permissionBitmask is only 8 meaningful bits (256 values). An observer who knows the credentialCommitment (it's the Merkle leaf, publicly computable from enrollment events) can hash all 256 candidates and recover the exact permission set, breaking the privacy model. Add a private `blindingSalt` input and compute scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingSalt). Propagate the same change to Delegation.circom's scope commitment computation and regenerate verifier contracts.

## Status

Placeholder — awaiting implementation.
