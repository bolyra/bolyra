# Cross-chain test vectors in conformance suite

Extend the existing conformance test suite with 10+ vectors covering multi-chain scenarios: valid storage proof relay, stale foreign root rejection, cross-chain nullifier replay (must fail), delegation chain spanning two chains, and chainId mismatch in nullifier derivation. Each vector should include the source chainId, destination chainId, and the storage proof or CCIP payload. This ensures any new chain deployment can validate interop correctness before going live.

## Status

Placeholder — awaiting implementation.
