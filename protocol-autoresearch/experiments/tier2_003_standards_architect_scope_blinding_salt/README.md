# Add blinding salt to scope commitment to prevent brute-force

scopeCommitment = Poseidon2(bitmask, credCommitment) is deterministic over a 256-value bitmask space (8 bits). An observer can precompute all 256 possible commitments for a known credCommitment and determine the exact permission set. Change to Poseidon3(bitmask, credCommitment, blindingSalt) where blindingSalt is a private random field element. Update AgentPolicy, Delegation circuits, SDK proof generation, and the IETF draft's privacy analysis section. This is a protocol-level privacy fix that must happen before any production deployment.

## Status

Placeholder — awaiting implementation.
