# Interoperability profile for multi-verifier deployments

Write an interop profile document (modeled on OIDC Conformance) that specifies the exact wire format for proof exchange between provers and verifiers across different deployments. Define: (1) a JSON-based proof envelope with fields for circuit type, public signals array, proof bytes, and metadata; (2) content-type negotiation (application/bolyra-proof+json); (3) version negotiation via a 'protocol-version' header; (4) mandatory-to-implement cipher suites (BN254/Groth16 for human, BN254/PLONK for agent). This enables independent verifier implementations to accept proofs from any compliant prover.

## Status

Placeholder — awaiting implementation.
