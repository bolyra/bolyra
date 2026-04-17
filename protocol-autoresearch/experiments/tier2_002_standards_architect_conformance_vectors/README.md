# Conformance Test Suite with JSON Test Vectors

Produce a machine-readable test suite (JSON) with 50+ vectors covering: valid handshake (human+agent proofs accepted), expired credential (expiryTimestamp < currentTimestamp, must reject), revoked human (nullifier in revocation set), stale agent root (root not in 30-entry history buffer), scope subset violation (delegateeScope & ~delegatorScope != 0), delegation chain at depths 1, 3, and 4 (4 must fail), nonce reuse (must reject), and the phantom delegatee attack (delegatee commitment not in any tree, must reject once fixed). Each vector specifies: circuit name, all public inputs/outputs, expected verdict (accept/reject), and failure reason code. This is essential for any second implementation to prove conformance without reverse-engineering the Circom source.

## Status

Placeholder — awaiting implementation.
