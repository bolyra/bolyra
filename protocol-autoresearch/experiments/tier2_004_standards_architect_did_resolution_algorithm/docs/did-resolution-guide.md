# DID Resolution Guide

Resolve `did:bolyra` identifiers using the `@bolyra/sdk` TypeScript package.

## Prerequisites

- Node.js 18+
- Access to an Ethereum JSON-RPC endpoint (e.g., Base Sepolia)
- The deployed `IdentityRegistry` contract address

## Installation

```bash
npm install @bolyra/sdk ethers
```

## Quick Start

```typescript
import { ethers } from 'ethers';
import { BolyraResolver } from '@bolyra/sdk';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const registryAddress = '0xYOUR_IDENTITY_REGISTRY_ADDRESS';

const resolver = new BolyraResolver(provider, registryAddress);

const result = await resolver.read(
  'did:bolyra:0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890'
);

if (result.didResolutionMetadata.error) {
  console.error('Resolution failed:', result.didResolutionMetadata.error);
} else {
  console.log('DID Document:', JSON.stringify(result.didDocument, null, 2));
  console.log('Metadata:', result.didDocumentMetadata);
}
```

## Configuring Staleness Threshold

The resolver detects stale Merkle roots. If the enrollment block is older than the configured threshold, `didDocumentMetadata.staleRoot` will be `true` and `didResolutionMetadata.warning` will be `"staleRoot"`.

```typescript
// Set threshold at construction time (default: 3600s = 1 hour)
const resolver = new BolyraResolver(provider, registryAddress, {
  stalenessThresholdSeconds: 7200, // 2 hours
});

// Or override per-call
const result = await resolver.read(did, {
  stalenessThresholdSeconds: 1800, // 30 minutes for this call
});
```

## Interpreting DIDResolutionResult

The `read()` method returns a `DIDResolutionResult` with three components:

| Component | Type | Description |
|---|---|---|
| `didDocument` | `DIDDocument \| null` | The resolved DID Document, or `null` on error |
| `didResolutionMetadata` | `DIDResolutionMetadata` | Contains `contentType`, optional `error` code, and optional `warning` |
| `didDocumentMetadata` | `DIDDocumentMetadata` | Contains `created`, `updated`, `versionId`, optional `deactivated` and `staleRoot` |

### DID Document Fields

- **`verificationMethod[0].publicKeyJwk`** — JsonWebKey2020 with `crv: "BabyJubJub"`, containing `x` and `y` coordinates as base64url strings.
- **`service[0]`** — `BolyraHandshakeEndpoint` with the gateway URL. For agent DIDs, includes `permissionMask` (0–255).

## Error Handling

| Error Code | Meaning | Recommended Action |
|---|---|---|
| `invalidDid` | DID string is malformed | Check format: `did:bolyra:<hex>` |
| `notFound` | Commitment not registered on-chain | Verify enrollment transaction |
| `deactivated` | Identity was revoked | The DID is no longer active |
| `methodNotSupported` | DID method is not `bolyra` | Use the correct method prefix |
| `internalError` | RPC or contract failure | Check provider connectivity |

## Integration with did-resolver

To use with the [`did-resolver`](https://www.npmjs.com/package/did-resolver) universal resolver framework:

```typescript
import { Resolver } from 'did-resolver';
import { ethers } from 'ethers';
import { BolyraResolver } from '@bolyra/sdk';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const bolyra = new BolyraResolver(provider, registryAddress);

function getBolyraResolver() {
  return {
    bolyra: async (did: string) => bolyra.read(did),
  };
}

const resolver = new Resolver(getBolyraResolver());
const result = await resolver.resolve('did:bolyra:0xabc...');
```

## Universal Resolver Driver

To expose the Bolyra resolver as a [Universal Resolver](https://dev.uniresolver.io/) HTTP driver:

```typescript
import express from 'express';
import { ethers } from 'ethers';
import { BolyraResolver } from '@bolyra/sdk';

const app = express();
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const resolver = new BolyraResolver(provider, process.env.REGISTRY_ADDRESS!);

app.get('/1.0/identifiers/:did', async (req, res) => {
  const result = await resolver.read(req.params.did);
  const status = result.didResolutionMetadata.error === 'notFound' ? 404
    : result.didResolutionMetadata.error === 'invalidDid' ? 400
    : result.didResolutionMetadata.error ? 500
    : 200;
  res.status(status).json(result);
});

app.listen(8080);
```

## References

- [DID Method Spec](../spec/did-method-bolyra.md)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C DID Resolution](https://w3c-ccg.github.io/did-resolution/)
- [Resolution Types](../sdk/src/types/resolution.ts)
