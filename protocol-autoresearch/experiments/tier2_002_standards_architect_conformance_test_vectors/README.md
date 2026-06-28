# Machine-readable conformance test vectors (JSON) for all three circuits

No implementation can claim Bolyra conformance without shared test vectors. Create a spec/test-vectors/ directory with JSON files covering: valid handshake (human+agent), expired agent credential, revoked human identity, stale Merkle root, scope subset violation, cumulative bit encoding violation, delegation chain at depth 1/2/3, and nonce replay. Each vector includes: circuit name, witness inputs, expected public outputs (or expected rejection reason). This is the minimum bar for a second implementer to verify compatibility. Deliverable: 30+ vectors across the three circuits, plus a lightweight Node runner script.

## Status

Placeholder — awaiting implementation.
