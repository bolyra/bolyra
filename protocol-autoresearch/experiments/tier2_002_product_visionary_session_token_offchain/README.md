# Off-chain session token with on-chain checkpoint batching

After a successful handshake, emit a signed session token (JWT/SD-JWT with the nullifier, scopeCommitment, and expiry embedded) that parties can verify off-chain for subsequent calls within the session window. Batch session roots on-chain every N minutes. This eliminates per-call proving cost — the single biggest adoption blocker for agentic commerce where agents make dozens of tool calls per minute. Implement in the TS SDK as `createSessionToken()` and `verifySessionToken()`, with a new `SessionCheckpoint.sol` contract that accepts Merkle roots of verified sessions.

## Status

Placeholder — awaiting implementation.
