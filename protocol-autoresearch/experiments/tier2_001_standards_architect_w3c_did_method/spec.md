# did:bolyra DID method specification

## Abstract

Write a W3C DID method spec for did:bolyra:<network>:<identityCommitment>. Define the DID Document structure mapping: humanMerkleRoot as verification method, nullifierHash as authentication proof, scopeCommitment as capability delegation. Specify the resolution algorithm (query IdentityRegistry for enrollment status, check revocation by nullifier). Include a Verifiable Credential issuance flow where a successful handshake produces a VC with the session nonce as challenge and both nullifiers as evidence. This bridges Bolyra into the existing SSI ecosystem.

## Normative Requirements

Implementations MUST ...
