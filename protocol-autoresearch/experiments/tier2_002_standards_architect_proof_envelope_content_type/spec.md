# Register application/bolyra-proof+cbor media type and define proof envelope

## Abstract

The protocol currently has no standardized wire format for transmitting proofs between prover and verifier. Define a CBOR-based proof envelope (application/bolyra-proof+cbor) with a fixed schema: version (uint), circuit_id (text), proving_system (text: 'groth16'|'plonk'), public_signals (array<bstr>), proof (bstr), and optional delegation_chain (array<envelope>). Include a CDDL grammar in the IETF draft. This replaces ad-hoc JSON serialization in the SDK and enables language-agnostic interop — any conformant implementation can parse and forward proofs without SDK-specific knowledge.

## Normative Requirements

Implementations MUST ...
