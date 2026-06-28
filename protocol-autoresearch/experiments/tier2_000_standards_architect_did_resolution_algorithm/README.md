# Complete DID method resolution algorithm per W3C DID Core §7

spec/did-method-bolyra.md defines the DID syntax (did:bolyra:<commitment>) but lacks a conformant resolution algorithm. Implement the resolve(did, resolutionOptions) → {didDocument, didResolutionMetadata, didDocumentMetadata} interface per W3C DID Core §7.1. The resolver must query IdentityRegistry for enrollment status, populate the verificationMethod array with the BabyJubjub public key (type JsonWebKey2020 with crv=Baby-Jubjub), and set didDocumentMetadata.deactivated=true for revoked identities. Without this, did:bolyra cannot pass the W3C DID Test Suite.

## Status

Placeholder — awaiting implementation.
