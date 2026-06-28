# Experiment: Complete DID Method Resolution Algorithm per W3C DID Core §7.1

**ID:** `standards_architect_did_resolution_algorithm`  
**Dimension:** Standards  
**Priority:** High  

## Summary

Implements the full `did:bolyra` resolution algorithm conforming to W3C DID Core §7.1 and the DID Resolution specification. The resolver maps a `did:bolyra:<commitment>` identifier to a W3C-compliant DID Document by querying the on-chain `IdentityRegistry` contract.

## Key Design Decisions

1. **JsonWebKey2020 with `crv: BabyJubJub`** — verification methods use JWK encoding with x/y coordinates as base64url, rather than multibase. This aligns with the W3C DID Specification Registries and provides direct interop with JOSE-based tooling.

2. **`BolyraHandshakeEndpoint` service type** — replaces the prior `BolyraProofExchange` + `BolyraAgentPolicy` dual-service pattern with a single endpoint. Agent DIDs include a `permissionMask` property on the service.

3. **Staleness detection** — the resolver checks the age of the enrollment block against a configurable `stalenessThresholdSeconds`. Stale roots surface as `didDocumentMetadata.staleRoot = true` and `didResolutionMetadata.warning = "staleRoot"`.

4. **`read()` method name** — per the W3C DID Resolution spec §3, the primary resolution function is named `read(did, resolutionOptions)`.

## Artifacts

| File | Type | Description |
|---|---|---|
| `spec/did-method-bolyra.md` | Spec | Extended DID method spec with §7.1-compliant resolution algorithm, ABNF, error codes |
| `sdk/src/types/resolution.ts` | Types | W3C-aligned TypeScript interfaces (DIDDocument, JsonWebKey2020, etc.) |
| `sdk/src/resolver.ts` | SDK | Reference `BolyraResolver` implementing `read()` |
| `sdk/test/resolver.test.ts` | Test | 5 test vectors + parse/RPC error coverage |
| `contracts/interfaces/IIdentityRegistry.sol` | Contract | Read interface for on-chain queries |
| `docs/did-resolution-guide.md` | Docs | Developer guide with quickstart, error table, universal-resolver driver |

## Test Vectors

| # | Scenario | Expected Outcome |
|---|---|---|
| 1 | Active human identity with valid Merkle root | Full DID Document with JsonWebKey2020, no permissionMask |
| 2 | Active agent credential with cumulative-bit permissions | DID Document with `permissionMask: 7` on service |
| 3 | Revoked identity (IdentityRevoked event) | `deactivated: true`, minimal document |
| 4 | Not-found DID (commitment absent) | `notFound` error, null document |
| 5 | Stale root (block timestamp drift > threshold) | Full document + `staleRoot: true` + warning |

## Usage

```typescript
import { ethers } from 'ethers';
import { BolyraResolver } from './sdk/src/resolver';

const provider = new ethers.JsonRpcProvider('https://sepolia.base.org');
const resolver = new BolyraResolver(provider, '0xREGISTRY_ADDRESS');

const result = await resolver.read('did:bolyra:0x1a2b...');
console.log(result.didDocument);
```

## Dependencies

- `ethers` v6 — on-chain queries
- `IIdentityRegistry` — `getEnrollmentStatus()`, `isRevoked()`, `getAgentCredential()`, `getMerkleRoot()`
- W3C DID Core §7.1 and DID Resolution spec for data model conformance
- JsonWebKey2020 spec for `crv: BabyJubJub` JWK encoding
- Hardhat in-process node (test infrastructure)
