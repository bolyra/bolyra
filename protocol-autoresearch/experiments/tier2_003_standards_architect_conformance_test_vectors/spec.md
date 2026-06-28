# Publish machine-readable conformance test vector suite

## Abstract

No independent implementation can validate correctness without canonical test vectors. Create a spec/test-vectors/ directory with JSON files covering: valid handshake (human + agent), expired agent credential, stale Merkle root (both trees), scope subset violation in delegation, cumulative bit encoding violation (bit 4 without bits 2+3), delegation chain at max depth (3 hops), nonce replay rejection, and revoked human nullifier. Each vector includes all circuit inputs, expected public outputs, and expected contract revert reason. This is table-stakes for any IETF submission. Deliverable: 30+ test vectors in JSON with a conformance runner script in spec/conformance/.

## Normative Requirements

Implementations MUST ...
