# Formalize did:bolyra resolution algorithm with DID Core conformance

## Abstract

spec/did-method-bolyra.md exists but lacks the required resolution algorithm per W3C DID Core §7.1. Define the concrete steps: parse did:bolyra:<commitment>, query IdentityRegistry for enrollment status and current Merkle root, construct the DID Document with verificationMethod (BabyJubJub key for humans, EdDSA operator key for agents), and authentication/assertionMethod relationships. Include the CRUD operations matrix (Create=enroll, Read=resolve, Update=N/A for humans, Deactivate=revoke). Without this, no universal resolver can implement did:bolyra.

## Normative Requirements

Implementations MUST ...
