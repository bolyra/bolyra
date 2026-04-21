# W3C DID method specification for did:bolyra

## Abstract

Define a complete W3C DID method binding: did:bolyra:<identityCommitment>. Specify the DID Document structure (verification methods map to EdDSA Baby Jubjub keys, service endpoints for handshake initiation), the resolution algorithm (on-chain lookup via IdentityRegistry humanTree/agentTree), and CRUD operations (create = enroll, deactivate = revoke). Include a Verifiable Credential issuance flow where successful handshake verification produces a VC with the nullifier as proof, enabling interop with any W3C VC-compatible wallet.

## Normative Requirements

Implementations MUST ...
