# did:bolyra DID Method Specification with VC issuance

Define a W3C DID method `did:bolyra:<base58(identityCommitment)>` with a DID Document structure that includes a `BolyraVerification2024` verification method type pointing to the on-chain IdentityRegistry. Specify the resolution algorithm: given a DID, derive the identity commitment, query the humanTree or agentTree for membership, and return the DID Document with service endpoints. Define a Verifiable Credential schema for handshake results (issuer = verifier service, subject = did:bolyra:*, credentialSubject includes scopeCommitment and sessionNonce). This bridges Bolyra into the existing SSI ecosystem and enables interop with any W3C DID-compatible wallet or verifier.

## Status

Placeholder — awaiting implementation.
