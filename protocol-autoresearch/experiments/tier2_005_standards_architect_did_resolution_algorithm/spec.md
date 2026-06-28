# Complete DID method resolution algorithm with revocation and delegation discovery

## Abstract

The existing did-method-bolyra.md defines the DID scheme but lacks a complete resolution algorithm per W3C DID Core §7.1. Specifically: (1) resolving did:bolyra:<commitment> must query the IdentityRegistry to check enrollment and revocation status, (2) the DID Document should include a verificationMethod referencing the on-chain Merkle root and a service endpoint for proof submission, (3) delegation relationships should appear as delegateOf entries linking to the delegator's DID. Without this, no DID resolver can implement the method. Deliverable: updated spec/did-method-bolyra.md with resolution pseudocode, error handling for revoked/unknown DIDs, and 5 resolution test vectors (enrolled human, enrolled agent, revoked, delegated, unknown).

## Normative Requirements

Implementations MUST ...
