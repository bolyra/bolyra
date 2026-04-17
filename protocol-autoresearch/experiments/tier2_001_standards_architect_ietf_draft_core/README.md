# IETF Internet-Draft: Bolyra Core Protocol Specification

Author an Internet-Draft following RFC 7942 (Running Code) and using RFC 2119/8174 keywords. Sections: Introduction, Terminology (human/agent/delegatee/scope/nullifier), Protocol Overview (enrollment, handshake, delegation), Circuit Public Interface (inputs/outputs/semantics for all three circuits without implementation details), Wire Format (CBOR-encoded proof payloads with CDDL schema), On-Chain Verification Interface (ABI-level contract interface as normative), and Security Considerations (replay, linkability, root staleness, delegation chain depth). This is the foundational document that all interop work depends on — without it, independent implementations will diverge on semantics like nullifier derivation order or scope commitment structure.

## Status

Placeholder — awaiting implementation.
