# Machine-readable conformance test vectors (JSON fixtures)

## Abstract

The spec lacks test vectors that independent implementations can run against. Produce 40+ JSON fixtures covering: valid handshake round-trip, expired agent credential (expiryTimestamp < currentTimestamp), revoked human identity, stale Merkle root (not in 30-root buffer), scope subset violation in delegation, cumulative bit encoding violation (bit 4 without bit 2+3), delegation chain at max depth (3 hops), and cross-nonce replay rejection. Each fixture includes input witness, expected public signals, and expected pass/fail. Deliverable: `spec/test-vectors/` directory with categorized JSON files and a conformance runner script.

## Normative Requirements

Implementations MUST ...
