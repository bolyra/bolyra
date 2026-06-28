# Add human tree root history buffer matching agent tree's 30-root buffer

IdentityRegistry maintains a 30-root history buffer for agentTree but humanTree has no such buffer — any new enrollment instantly invalidates in-flight human proofs. This is a correctness gap the IETF draft should normatively require: the contract comment even says 'humanTree uses Semaphore's' but the code doesn't actually use Semaphore's group contract with its root history. Add a 30-entry ring buffer for humanTree roots (mirroring the existing agentRootHistory pattern), update the verifyHandshake function to check against it, and add a normative requirement to the IETF draft §Security Considerations noting the staleness window.

## Status

Placeholder — awaiting implementation.
