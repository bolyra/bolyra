# DID Resolver Integration Guide

This guide shows how to integrate the `did:bolyra` resolver into your application using the standard [did-resolver](https://github.com/decentralized-identity/did-resolver) npm package or the DIF Universal Resolver.

## DID Syntax

### ABNF

```abnf
bolyra-did      = "did:bolyra:" commitment
commitment      = 64HEXDIG
HEXDIG          = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

### Rules

- Exactly 64 lowercase hex characters (32 bytes)
- No `0x` prefix
- Leading zeros are significant
- Uppercase is rejected

### Examples

```
did:bolyra:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
did:bolyra:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344
```

## Quick Start: did-resolver

```typescript
import { Resolver } from "did-resolver";
import { getBolyraResolver } from "@bolyra/sdk/resolver";

// Configure the resolver driver
const bolyraResolver = getBolyraResolver({
  provider: "https://sepolia.base.org",        // or ethers.Provider instance
  registryAddress: "0x<deployed-registry>",     // IdentityRegistry address
  chainId: 84532,                               // Base Sepolia
  chainName: "Base Sepolia",
});

// Create a multi-method resolver
const resolver = new Resolver(bolyraResolver);

// Resolve a DID
const result = await resolver.resolve(
  "did:bolyra:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
);

console.log(result.didDocument);           // Full DID Document
console.log(result.didResolutionMetadata); // { contentType: "application/did+ld+json" }
console.log(result.didDocumentMetadata);   // { created, updated, deactivated }
```

## Standalone Usage (without did-resolver)

```typescript
import { resolve } from "@bolyra/sdk/resolver";

const result = await resolve(
  "did:bolyra:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
  {
    provider: "https://sepolia.base.org",
    registryAddress: "0x<deployed-registry>",
  }
);

if (result.didResolutionMetadata.error) {
  console.error("Resolution failed:", result.didResolutionMetadata.error);
} else {
  console.log("Resolved:", result.didDocument);
}
```

## RPC Provider Configuration

### Base Sepolia (testnet)

```typescript
{
  provider: "https://sepolia.base.org",
  chainId: 84532,
  chainName: "Base Sepolia"
}
```

### Base Mainnet

```typescript
{
  provider: "https://mainnet.base.org",
  chainId: 8453,
  chainName: "Base"
}
```

### Custom Provider (e.g., Alchemy, Infura)

```typescript
import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider(
  "https://base-sepolia.g.alchemy.com/v2/<API_KEY>"
);

const bolyraResolver = getBolyraResolver({
  provider,
  registryAddress: "0x<deployed-registry>",
});
```

## Veramo Integration

```typescript
import { createAgent } from "@veramo/core";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import { Resolver } from "did-resolver";
import { getBolyraResolver } from "@bolyra/sdk/resolver";

const agent = createAgent({
  plugins: [
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...getBolyraResolver({
          provider: "https://sepolia.base.org",
          registryAddress: "0x<deployed-registry>",
        }),
        // Add other method resolvers here
      }),
    }),
  ],
});

const result = await agent.resolveDid({ didUrl: "did:bolyra:<commitment>" });
```

## Error Handling

| Error Code | Meaning |
|---|---|
| `invalidDid` | DID string does not match the ABNF syntax |
| `methodNotSupported` | Method is not `bolyra` |
| `notFound` | No registration exists for the commitment |
| `deactivated` | Registration was revoked |

Check `result.didResolutionMetadata.error` — if it is defined, resolution failed.

## Caching Recommendations

- **Cache DID Documents** with a TTL of 5-15 minutes for production use.
- **Invalidate on `RegistrationRevoked` events** — subscribe to the registry contract's events via WebSocket provider to detect revocations in real time.
- **Use `didDocumentMetadata.versionId`** (block number) to detect stale entries.
- **Do NOT cache error results** — transient RPC failures should be retried.

## Known Limitations

1. **No Universal Resolver driver submitted yet** — the `did:bolyra` method is not registered with the DIF Universal Resolver. A driver will be submitted once the method reaches v1.0 stability.
2. **No key rotation in v1** — revoked DIDs cannot be re-activated. A new commitment must be registered.
3. **Single chain only** — resolution queries a single EVM chain. Cross-chain resolution is not supported in v1.
4. **`resolveRepresentation` only supports `application/did+ld+json`** — CBOR and other representations are not yet implemented.
