# Blind scope commitments against bitmask brute-force

scopeCommitment in AgentPolicy is Poseidon(permissionBitmask, credentialCommitment). The permissionBitmask is 64 bits with cumulative encoding, yielding at most ~2^16 realistic combinations. An observer who knows the credentialCommitment (public at enrollment) can brute-force the bitmask from the public scopeCommitment, breaking scope privacy. Replace with Poseidon3(permissionBitmask, credentialCommitment, blindingSalt) where blindingSalt is a fresh private input. Update the Delegation circuit's chain-linking check to use the same 3-ary hash. This is a straightforward privacy fix with minimal constraint cost (~800 additional constraints for one extra Poseidon input).

## Status

Placeholder — awaiting implementation.
