# Add blinding salt to scope commitment to prevent bitmask brute-force

The current scopeCommitment = Poseidon2(bitmask, credCommitment) is deterministic over a 64-bit bitmask space — an observer can brute-force all 2^8 valid cumulative-bit encodings (realistically ~20 valid combinations) to recover the exact permission set from any on-chain scopeCommitment. Add a random blindingSalt private input and compute Poseidon3(bitmask, credCommitment, blindingSalt) in both AgentPolicy and Delegation circuits. Update the IETF draft security considerations to document the entropy requirement (128-bit salt minimum).

## Status

Placeholder — awaiting implementation.
