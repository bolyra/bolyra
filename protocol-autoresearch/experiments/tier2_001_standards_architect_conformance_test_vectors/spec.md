# Publish deterministic JSON test vectors for cross-implementation conformance

## Abstract

Create a `spec/test-vectors/` directory with 30+ JSON files covering: valid handshake round-trip, expired agent credential rejection, stale Merkle root, scope subset violation, cumulative bit encoding violations (bit 4 without 3, bit 3 without 2), delegation chain at max depth, and nullifier replay. Each vector includes deterministic inputs (using a fixed secret/key pair), expected intermediate values (commitment hashes), and expected pass/fail outcome. Reference these from the IETF draft §A (Appendix). This is the single most impactful interop artifact — any alternative SDK implementation can validate correctness against these vectors.

## Normative Requirements

Implementations MUST ...
