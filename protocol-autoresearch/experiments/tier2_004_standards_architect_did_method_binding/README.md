# W3C DID Method Specification: did:bolyra

Define did:bolyra:<tree>:<commitment> as a W3C DID method per the DID Core v1.0 specification. The DID Document maps identityCommitment (human) and credentialCommitment (agent) to verification methods using the JsonWebKey2020 type with Baby Jubjub curve parameters. Resolution algorithm: given a DID, query the on-chain LeanIMT for membership, return a DID Document with the Merkle root as metadata. Define a VC issuance flow where a successful handshake produces a VerifiableCredential with proof type 'Groth16Proof2024' or 'PlonkProof2024', enabling interop with existing W3C VC wallets and verifiers.

## Status

Placeholder — awaiting implementation.
