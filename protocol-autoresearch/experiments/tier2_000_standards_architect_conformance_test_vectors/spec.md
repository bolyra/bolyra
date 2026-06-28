# Publish canonical JSON test vectors for all proof verification paths

## Abstract

The spec lacks machine-readable test vectors that alternative implementations can use for conformance testing. Produce 30+ JSON test vectors covering: valid handshake (human+agent proofs with matching nonce), expired agent credential, stale Merkle root (outside 30-root buffer), scope subset violation in delegation, cumulative bit encoding violation (bit 4 without bit 2+3), delegation chain at max depth (3 hops), and replay (reused nullifier). Each vector includes inputs, expected public signals, and expected accept/reject verdict with error code. Place in spec/test-vectors/ and reference from the IETF draft.

## Normative Requirements

Implementations MUST ...
