# Machine-readable conformance test vectors (JSON)

Produce 50+ JSON test vectors organized by circuit (HumanUniqueness, AgentPolicy, Delegation) and scenario: valid witness, expired credential (expiryTimestamp < currentTimestamp), revoked human nullifier, stale Merkle root not in history buffer, scope subset violation (delegateeScope & ~delegatorScope != 0), cumulative bit encoding violation (bit 4 without bits 2+3), delegation chain at depths 1/2/3/4 (4 must fail), and replay with reused nonce. Each vector specifies inputs, expected outputs, and whether the proof MUST succeed or MUST fail with a specific error code. This is the minimum bar for any second implementation to claim conformance.

## Status

Placeholder — awaiting implementation.
