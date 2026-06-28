# Human tree root history buffer (parity with agent tree)

The agentTree has a 30-root history buffer preventing proof staleness during concurrent enrollments, but humanTree has none — any new human enrollment instantly invalidates all in-flight human proofs. Add the same `uint256[30] humanRootHistory` ring buffer to IdentityRegistry.sol and update `verifyHandshake` to check membership in the buffer. Without this, production deployments with >1 human enrolling concurrently will see random handshake failures, which is a dealbreaker for any real adoption.

## Status

Placeholder — awaiting implementation.
