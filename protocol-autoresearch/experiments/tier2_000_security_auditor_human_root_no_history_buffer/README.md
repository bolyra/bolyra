# HumanUniqueness proofs go stale instantly — no root history buffer

IdentityRegistry maintains a 30-root history buffer for agentTree but has NO equivalent for humanTree. The contract checks `humanTree._root()` (current root only) against the humanMerkleRoot public output. Any new enrollment between proof generation and on-chain verification invalidates the proof. This is a liveness denial-of-service: a single enrollment transaction front-runs every in-flight human proof. Add a `humanRootHistory[30]` ring buffer identical to `agentRootHistory`, update it in `enrollHuman()`, and check `humanMerkleRoot` against the buffer in `verifyHandshake()`.

## Status

Placeholder — awaiting implementation.
