# Machine-readable conformance test vectors (JSON Schema + vectors)

Create a `spec/conformance/` directory with a JSON Schema defining the test vector format and 30+ vectors covering: valid handshake round-trip, expired agent credential, revoked human identity, stale root (both trees), scope subset violation, cumulative-bit encoding violation, delegation chain at max hops, nonce replay, and the phantom-delegatee attack. Each vector includes inputs, expected circuit output (accept/reject), and the specific error code. This is the minimum viable interop artifact for any alternative SDK implementation to prove compatibility.

## Status

Placeholder — awaiting implementation.
