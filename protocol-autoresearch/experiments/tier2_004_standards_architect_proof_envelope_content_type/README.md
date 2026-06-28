# Register application/bolyra-proof+cbor media type and define proof envelope format

The protocol currently has no canonical serialization for proof payloads exchanged between prover and verifier. Define a CBOR-based proof envelope (leveraging RFC 9052 COSE structure patterns) with fields for proof type (human/agent/delegation), public signals array, proof bytes (a/b/c points), protocol version, and an optional delegation chain. Register the application/bolyra-proof+cbor media type per RFC 6838. This is critical for interop: without a wire format, every integration reinvents serialization. Deliverable: spec/proof-envelope.md with CDDL schema, SDK encode/decode functions, and conformance test vectors.

## Status

Placeholder — awaiting implementation.
