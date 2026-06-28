# Bolyra DID Resolution: Developer Guide

This guide explains how to resolve `did:bolyra` Decentralized Identifiers and integrate the Bolyra DID resolver with universal resolver infrastructure.

## Overview

A `did:bolyra` DID encodes an on-chain identity registered in the `BolyraRegistry` contract. Resolution reads the identity's Merkle root and metadata from the chain and constructs a W3C DID Document.

**DID Format:**
```
did:bolyra:<chain-id>:<registry-address>:<subject-id>
```

- `chain-id`: EVM chain ID (e.g., `84532` for Base Sepolia)
- `registry-address`: `BolyraRegistry` contract address
- `subject-id`: 32-byte identity commitment hash

## Quick Start

### Using `@bolyra/sdk` directly

```typescript
import { resolve } from '@bolyra/sdk/did/resolver';

const result = await resolve(
  'did:bolyra:84532:0xABCD...1234:0x0011...eeff'
);

if (result.didResolutionMetadata.error) {
  console.error('Resolution failed:', result.didResolutionMetadata.error);
} else {
  console.log('DID Document:', result.didDocument);
  console.log('Metadata:', result.didDocumentMetadata);
}
```

### Using `did-resolver` v4

```typescript
import { Resolver } from 'did-resolver';
import { getResolver } from '@bolyra/sdk/did/resolver';

const resolver = new Resolver(getResolver({
  rpcEndpoints: {
    '84532': 'https://sepolia.base.org',
    '8453': 'https://mainnet.base.org',
  }
}));

const result = await resolver.resolve(
  'did:bolyra:84532:0xABCD...1234:0x0011...eeff'
);
```

## Universal Resolver Integration

### Docker Driver for uniresolver

To add `did:bolyra` to a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver) deployment, configure the driver:

```json
{
  "pattern": "^did:bolyra:.+$",
  "url": "http://bolyra-driver:8080/1.0/identifiers/",
  "testIdentifiers": [
    "did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678:0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  ]
}
```

The driver image wraps the `@bolyra/sdk` resolver in an HTTP server conforming to the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `BOLYRA_RPC_84532` | RPC endpoint for Base Sepolia | `https://sepolia.base.org` |
| `BOLYRA_RPC_8453` | RPC endpoint for Base Mainnet | `https://mainnet.base.org` |
| `BOLYRA_RPC_1` | RPC endpoint for Ethereum Mainnet | `https://eth.llamarpc.com` |

## DID Document Structure

### Human Identity

Human DIDs use the `BolyraHumanMerkleRoot2026` verification method type. The key material is the 32-byte Merkle root from the Semaphore v4-style enrollment tree (depth 20).

```json
{
  "verificationMethod": [{
    "id": "did:bolyra:...#human-merkle-root",
    "type": "BolyraHumanMerkleRoot2026",
    "controller": "did:bolyra:...",
    "publicKeyBase64url": "<base64url-encoded root>"
  }]
}
```

Supported proof purposes: `authentication`, `assertionMethod`.

### Agent Identity

Agent DIDs use the `BolyraAgentMerkleRoot2026` verification method type. Both Groth16 and PLONK proving systems are supported.

```json
{
  "verificationMethod": [{
    "id": "did:bolyra:...#agent-merkle-root",
    "type": "BolyraAgentMerkleRoot2026",
    "controller": "did:bolyra:...",
    "publicKeyBase64url": "<base64url-encoded root>"
  }]
}
```

### Service Endpoints

Every resolved DID Document includes a `BolyraProofSubmission` service endpoint encoded as a [CAIP-10](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md) URI:

```json
{
  "service": [{
    "id": "did:bolyra:...#proof-submission",
    "type": "BolyraProofSubmission",
    "serviceEndpoint": "eip155:84532:0x1234...5678",
    "proofType": "Groth16",
    "supportedCircuits": ["HumanUniqueness"]
  }]
}
```

## Deactivation

A DID is deactivated when its associated nullifier hash is revoked on-chain. Deactivated DID Documents:

- Return `"deactivated": true` in metadata
- Omit verification methods and service endpoints
- Are permanent (no re-activation mechanism)

```json
{
  "didDocumentMetadata": {
    "deactivated": true,
    "updated": 12345
  }
}
```

## Error Handling

| Error | Meaning |
|---|---|
| `invalidDid` | DID string does not match `did:bolyra` syntax |
| `notFound` | No identity registered for the given subject-id |
| `unsupportedChainId` | Resolver has no RPC endpoint for the requested chain |

## Security Notes

- **Merkle root staleness**: On-chain roots may lag behind off-chain state. Wait for block finality before trusting resolution results.
- **RPC trust**: The resolver trusts the configured RPC endpoint. Use multiple endpoints and cross-validate for high-assurance use cases.
- **Nullifier privacy**: Nullifier hashes are context-specific. Do not index across unrelated verification contexts.

See `spec/did-resolution-algorithm.md` §5 for the full security analysis.

## References

- [Bolyra DID Method Specification](../spec/did-method-bolyra.md)
- [Bolyra DID Resolution Algorithm](../spec/did-resolution-algorithm.md)
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [did-resolver npm package](https://www.npmjs.com/package/did-resolver)
- [Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
