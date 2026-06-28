# Complete DID method resolution algorithm with deactivation semantics

## Abstract

The existing spec/did-method-bolyra.md defines the DID syntax but lacks a normative resolution algorithm. Define how did:bolyra:<commitment> resolves to a DID Document by querying IdentityRegistry on-chain state, including: (1) how revoked identities produce a deactivated DID Document per W3C DID Core §8.2, (2) how agent credentials populate verificationMethod with the operator's EdDSA key, (3) how delegation chains appear as delegateGrant entries. Deliverable: complete resolution algorithm in the DID method spec, plus a reference resolver in the TS SDK that returns conformant DID Documents.

## Normative Requirements

Implementations MUST ...
