# Add human tree root history buffer matching agent tree's 30-root buffer

IdentityRegistry maintains a 30-root history buffer for agentTree but humanTree has no equivalent — any new enrollment immediately invalidates all in-flight human proofs. This is an interop hazard: a compliant prover generating a proof during an enrollment window gets a spurious rejection. Add the same ROOT_HISTORY_SIZE=30 circular buffer to humanTree with an isKnownHumanRoot() check in verifyHandshake(). This is a one-line architectural parity fix but has significant correctness impact. Deliver: contract change, updated test coverage, and a note in the IETF draft Security Considerations about root staleness windows.

## Status

Placeholder — awaiting implementation.
