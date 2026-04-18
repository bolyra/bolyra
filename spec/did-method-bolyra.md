# DID Method: did:bolyra

## Method Syntax

```
did:bolyra:<network>:<commitment>
```

Where:
- `network` is the chain identifier (e.g., `base`, `base-sepolia`, `ethereum`)
- `commitment` is the hex-encoded identity or credential commitment
  (Poseidon hash, 256-bit field element)

### Examples

```
did:bolyra:base:0x2345...abcd          (human identity on Base)
did:bolyra:base-sepolia:0x6789...ef01  (agent credential on Base Sepolia)
```

## DID Document

A Bolyra DID resolves to a DID Document with the following structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/eddsa-2022/v1"
  ],
  "id": "did:bolyra:base:0x2345...abcd",
  "verificationMethod": [
    {
      "id": "did:bolyra:base:0x2345...abcd#key-1",
      "type": "EdDSA2022",
      "controller": "did:bolyra:base:0x2345...abcd",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication": [
    "did:bolyra:base:0x2345...abcd#key-1"
  ],
  "service": [
    {
      "id": "did:bolyra:base:0x2345...abcd#registry",
      "type": "BolyraIdentityRegistry",
      "serviceEndpoint": "https://base.bolyra.ai/registry"
    }
  ]
}
```

## Resolution Algorithm

1. Parse the DID string to extract `network` and `commitment`
2. Connect to the IdentityRegistry contract on the specified network
3. Check if `commitment` is a leaf in `humanTree` or `agentTree`:
   - Query `humanTree` Merkle membership (human identity)
   - Query `agentTree` Merkle membership (agent credential)
4. If found in `humanTree`:
   - The DID represents a human identity
   - The verification method is the EdDSA public key whose
     Poseidon2 hash equals the commitment
   - Note: the public key is NOT stored on-chain; the resolver
     needs the key provided by the DID subject
5. If found in `agentTree`:
   - The DID represents an agent credential
   - The verification method is the operator's EdDSA public key
6. If not found in either tree: resolution fails (DID deactivated or not enrolled)

## Verifiable Credential Issuance

After a successful mutual handshake, the verifier can issue a Verifiable
Credential attesting to the authenticated session:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://bolyra.ai/credentials/v1"
  ],
  "type": ["VerifiableCredential", "BolyraHandshakeCredential"],
  "issuer": "did:bolyra:base:0x...(registry-contract)",
  "issuanceDate": "2026-04-18T00:00:00Z",
  "credentialSubject": {
    "humanDid": "did:bolyra:base:0x...(human-commitment)",
    "agentDid": "did:bolyra:base:0x...(agent-commitment)",
    "handshakeNonce": "0x...",
    "scopeCommitment": "0x...",
    "proof": {
      "type": "Groth16Proof2022",
      "proofValue": "..."
    }
  }
}
```

## Security Considerations

- The DID commitment is a Poseidon hash -- it is computationally infeasible
  to derive the private key from the DID alone
- DID deactivation is handled by removing the commitment from the on-chain
  Merkle tree (human: via revocation; agent: via tree update to zero)
- Privacy: the DID itself reveals only the commitment, not the identity.
  Linking a DID to a real-world identity requires the private key holder's
  consent (via ZKP handshake)
