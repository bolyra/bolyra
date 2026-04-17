# W3C DID Method Specification: did:bolyra

## Abstract

Define a DID method binding per W3C DID Core 1.0. Method-specific identifier is the identity/credential commitment (base58btc-encoded). DID Document includes a verificationMethod of type EcdsaSecp256k1VerificationKey2019 for the operator key (agents) or Ed25519VerificationKey2020 mapped from BabyJubjub for humans, plus a BolyraProofService endpoint. Resolution algorithm: given did:bolyra:<commitment>, query the IdentityRegistry to confirm tree membership and non-revocation, then construct the DID Document. Also define a VerifiableCredential schema for handshake results (issuer = verifier, subject = DID pair, evidence = proof hashes). This bridges Bolyra into the existing decentralized identity ecosystem and enables interop with any W3C VC wallet.

## Normative Requirements

Implementations MUST ...
