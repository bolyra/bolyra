# Define proof envelope MIME type and serialization format

Register an application/bolyra-proof+cbor media type and define a canonical CBOR serialization for proof envelopes (human proof, agent proof, delegation chain). The current SDK passes raw JSON arrays of BigInt strings with no schema versioning or content negotiation. A COSE-style envelope with a version field, proof-system discriminator (groth16 vs plonk), and public-signals layout tag would let any HTTP/MCP transport negotiate format without out-of-band schema knowledge. Deliverable: ABNF grammar in spec/, CBOR CDDL schema, and a round-trip test in the conformance suite.

## Status

Placeholder — awaiting implementation.
