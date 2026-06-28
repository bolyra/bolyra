# Specify deterministic DID resolution algorithm for did:bolyra

spec/did-method-bolyra.md defines the DID method but the resolution algorithm is underspecified — it doesn't define how a resolver maps did:bolyra:<commitment> to a DID Document when the commitment lives in a Merkle tree with no key-value lookup. Define a resolution algorithm that queries the IdentityRegistry contract for membership (via root history buffer), constructs a minimal DID Document with the verification method (EdDSA on BabyJubJub), and specifies the deactivation check (revoked nullifier). Include the W3C DID Resolution metadata fields (contentType, created, deactivated). This is required for any VC/VP interop.

## Status

Placeholder — awaiting implementation.
