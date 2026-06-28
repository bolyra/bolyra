---
title: "DID Method: did:bolyra"
visibility: public
sources:
  - spec/did-method-bolyra.md
last-updated: 2026-06-28
staleness-threshold: 60d
tags: [did, identity, w3c, decentralized-identifier]
---

The `did:bolyra` DID method maps on-chain Poseidon commitments (human identity or agent credential) to W3C-compliant Decentralized Identifiers, enabling interoperability with the broader DID ecosystem.

## Overview

A Bolyra DID encodes a network identifier and a commitment hash. The commitment is either a human identity commitment (`Poseidon2(Ax, Ay)`) or an agent credential commitment (`Poseidon5(modelHash, Ax, Ay, bitmask, expiry)`), both stored as leaves in their respective on-chain Merkle trees. Resolution checks which tree contains the commitment and constructs an appropriate DID Document.

## Key Concepts

### Syntax

```
did:bolyra:<network>:<commitment>
```

- **network**: Chain identifier (e.g., `base`, `base-sepolia`, `ethereum`)
- **commitment**: Hex-encoded Poseidon hash (256-bit field element)

### Examples

```
did:bolyra:base:0x2345...abcd          # human identity on Base
did:bolyra:base-sepolia:0x6789...ef01  # agent credential on Base Sepolia
```

### DID Document Structure

A resolved DID Document follows W3C DID Core:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/eddsa-2022/v1"
  ],
  "id": "did:bolyra:base:0x2345...abcd",
  "verificationMethod": [{
    "id": "did:bolyra:base:0x2345...abcd#key-1",
    "type": "EdDSA2022",
    "controller": "did:bolyra:base:0x2345...abcd",
    "publicKeyMultibase": "z..."
  }],
  "authentication": ["did:bolyra:base:0x2345...abcd#key-1"],
  "service": [{
    "id": "did:bolyra:base:0x2345...abcd#registry",
    "type": "BolyraIdentityRegistry",
    "serviceEndpoint": "https://base.bolyra.ai/registry"
  }]
}
```

## How It Works

### Resolution Algorithm

1. Parse the DID string to extract `network` and `commitment`.
2. Connect to the `IdentityRegistry` contract on the specified network.
3. Check Merkle membership in both trees:
   - Query `humanTree` for the commitment
   - Query `agentTree` for the commitment
4. **If found in humanTree**: DID represents a human identity. The verification method is the EdDSA public key whose `Poseidon2` hash equals the commitment. Note: the public key is not stored on-chain; the resolver needs it provided by the DID subject.
5. **If found in agentTree**: DID represents an agent credential. The verification method is the operator's EdDSA public key.
6. **If not found in either tree**: Resolution fails (DID deactivated or never enrolled).

### Verifiable Credential Issuance

After a successful mutual handshake, a verifier can issue a `BolyraHandshakeCredential` attesting to the authenticated session. The credential includes both DIDs, the handshake nonce, the scope commitment, and the Groth16 proof.

### Deactivation

- **Human**: Revocation by recording the nullifier hash in the `humanRevocations` mapping. The commitment remains in the tree but proofs are rejected.
- **Agent**: Tree-level revocation by updating the credential's leaf to zero. This invalidates all subsequent Merkle proofs. In-flight proofs remain valid for up to 30 tree operations (root history buffer window).

## Security Considerations

- The DID commitment is a Poseidon hash -- deriving the private key from the DID alone is computationally infeasible.
- The DID reveals only the commitment, not the identity. Linking to a real-world identity requires the private key holder's consent via ZKP handshake.
- Public key resolution requires cooperation from the DID subject (key is not stored on-chain).

## Current Status

- DID method specification is defined but not yet registered with W3C DID Methods registry.
- Resolution depends on the `IdentityRegistry` contract being deployed on the target network.
- Current deploy target: Base Sepolia (`baseSepolia` in Hardhat config).

## See Also

- [zkp-handshake.md](zkp-handshake.md) -- The handshake protocol that authenticates DID subjects
- [proof-envelope.md](proof-envelope.md) -- Wire format for proof transport
- `spec/did-method-bolyra.md` -- Full specification
