# DID Resolution Quickstart

Resolve `did:bolyra` identifiers using the `@bolyra/sdk` TypeScript package.

## Prerequisites

- Node.js 18+
- Access to an Ethereum JSON-RPC endpoint (e.g., Base Sepolia)
- The deployed `IdentityRegistry` contract address

## Step 1: Install

```bash
npm install @bolyra/sdk ethers
```

## Step 2: Configure the Resolver

```typescript
import { ethers } from 'ethers';
import { DIDResolver } from '@bolyra/sdk';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const registryAddress = '0xYOUR_IDENTITY_REGISTRY_ADDRESS';

const resolver = new DIDResolver(provider, registryAddress);
```

## Step 3: Resolve a DID

```typescript
const result = await resolver.resolve(
  'did:bolyra:0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
);

if (result.didResolutionMetadata.error) {
  console.error('Resolution failed:', result.didResolutionMetadata.error);
} else {
  console.log('DID Document:', JSON.stringify(result.didDocument, null, 2));
  console.log('Metadata:', result.didDocumentMetadata);
}
```

## Error Handling

| Error Code | Meaning | Action |
|---|---|---|
| `invalidDid` | DID string is malformed | Check DID format: `did:bolyra:<hex>` |
| `notFound` | Commitment not registered on-chain | Verify enrollment transaction |
| `deactivated` | Identity was revoked | The DID is no longer active |
| `internalError` | RPC or contract failure | Check provider connectivity |

## Integration with W3C did-resolver

To use with the [`did-resolver`](https://www.npmjs.com/package/did-resolver) npm package:

```typescript
import { Resolver } from 'did-resolver';
import { ethers } from 'ethers';
import { DIDResolver as BolyraResolver } from '@bolyra/sdk';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const bolyra = new BolyraResolver(provider, registryAddress);

function getResolver() {
  return {
    bolyra: async (did: string) => {
      return bolyra.resolve(did);
    },
  };
}

const resolver = new Resolver(getResolver());
const result = await resolver.resolve('did:bolyra:0xabc...');
```

## DID Document Structure

A successfully resolved human identity returns:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/eddsa-2022/v1",
    "https://bolyra.ai/ns/v1"
  ],
  "id": "did:bolyra:0x...",
  "verificationMethod": [{
    "id": "did:bolyra:0x...#key-1",
    "type": "EdDSAVerificationKey2022",
    "controller": "did:bolyra:0x...",
    "publicKeyMultibase": "z..."
  }],
  "authentication": ["did:bolyra:0x...#key-1"],
  "assertionMethod": ["did:bolyra:0x...#key-1"],
  "service": [{
    "id": "did:bolyra:0x...#proof-exchange",
    "type": "BolyraProofExchange",
    "serviceEndpoint": "https://relay.bolyra.ai/exchange"
  }]
}
```

Agent identities include an additional `BolyraAgentPolicy` service with the `permissions` field.

## References

- [DID Method Spec](../spec/did-method-bolyra.md)
- [Resolution Algorithm](../spec/did-resolution-algorithm.md)
- [Test Vectors](../spec/test-vectors/did-resolution-vectors.json)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
