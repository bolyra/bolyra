# Human tree root history buffer parity with agent tree

The IdentityRegistry maintains a 30-root history buffer for agentTree but has no equivalent for humanTree — human proofs go stale the instant a new enrollment lands. This is a spec-level gap: the IETF draft's Security Considerations section claims 'proofs remain valid across concurrent enrollments' but the contract doesn't enforce it for humans. Add a matching `humanRootHistory[30]` ring buffer, update `verifyHandshake` to accept any root in the buffer, and add a conformance test vector for 'human proof against root N-15'.

## Status

Placeholder — awaiting implementation.
