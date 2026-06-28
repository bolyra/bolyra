# Bolyra DID Resolution Algorithm

**Version:** 1.0.0  
**Status:** Draft  
**Date:** 2026-06-19  

## Overview

This document specifies the step-by-step resolution algorithm for `did:bolyra` DIDs. It complements the DID method specification at `spec/did-method-bolyra.md` and provides implementation-level detail for resolver authors.

## Prerequisites

- Access to an Ethereum JSON-RPC endpoint connected to the chain hosting `IdentityRegistry.sol`
- The deployed address of the `IdentityRegistry` contract
- An implementation of BabyJubJub point compression and multibase encoding

## Resolution Pipeline

```
Input:  did (string), options { registryAddress, provider, chainId }
Output: DIDResolutionResult { didDocument, didResolutionMetadata, didDocumentMetadata }
```

### Phase 1: DID String Parsing

```
1. Verify did starts with "did:bolyra:"
   - If not → return { error: "invalidDid", message: "Missing did:bolyra: prefix" }

2. Extract identifier = did.substring(10)

3. Strip optional "0x" prefix: identifier = identifier.replace(/^0x/i, "")

4. Convert to lowercase: identifier = identifier.toLowerCase()

5. Validate hex format: /^[0-9a-f]{1,64}$/
   - If invalid → return { error: "invalidDid", message: "Invalid hex commitment" }

6. Left-pad to 64 chars: commitment = "0x" + identifier.padStart(64, "0")

7. Return { commitment }
```

### Phase 2: On-Chain State Query

The resolver queries the `IIdentityRegistry` interface. To minimize RPC round-trips, implementations SHOULD batch calls using `ethers.Contract.multicall` or an equivalent batching mechanism.

```
1. Call registry.getEnrollmentStatus(commitment)
   Returns: { enrolled: bool, publicKey: [uint256, uint256], blockNumber: uint256 }

2. Call registry.isRevoked(commitment)
   Returns: bool

3. Call registry.getAgentCredential(commitment)
   Returns: { agentId: bytes32, modelHash: bytes32, operatorPubKey: [uint256, uint256],
              permissions: uint8, expiry: uint256 }

4. Call registry.getMerkleRoot()
   Returns: uint256
```

**Batching strategy:** Calls 1-4 are independent and SHOULD be issued as a single `multicall` batch to reduce latency.

### Phase 3: State Interpretation

```
1. If enrollmentStatus.enrolled == false AND agentCred.agentId == bytes32(0):
   → return { error: "notFound", message: "Commitment not enrolled" }

2. If isRevoked == true:
   → return deactivated result (see Phase 4, deactivated path)

3. Determine identity type:
   - If agentCred.agentId != bytes32(0) → type = "agent"
   - Else → type = "human"

4. Extract public key:
   - If type == "human" → pubKey = enrollmentStatus.publicKey
   - If type == "agent" → pubKey = agentCred.operatorPubKey
```

### Phase 4: DID Document Construction

#### Active Identity

```
1. Encode pubKey as publicKeyMultibase:
   a. Compress BabyJubJub point (x, y) → 32 bytes
   b. Prepend multicodec prefix 0xed01
   c. Encode as base58btc, prepend 'z'

2. Build verificationMethod:
   {
     id: did + "#key-1",
     type: "EdDSAVerificationKey2022",
     controller: did,
     publicKeyMultibase: <encoded>
   }

3. Build service array:
   services = [{
     id: did + "#proof-exchange",
     type: "BolyraProofExchange",
     serviceEndpoint: "https://relay.bolyra.ai/exchange"
   }]
   
   If type == "agent":
     services.push({
       id: did + "#agent-policy",
       type: "BolyraAgentPolicy",
       serviceEndpoint: "https://relay.bolyra.ai/agent/policy",
       permissions: agentCred.permissions
     })

4. Assemble DID Document:
   {
     "@context": [
       "https://www.w3.org/ns/did/v1",
       "https://w3id.org/security/suites/eddsa-2022/v1",
       "https://bolyra.ai/ns/v1"
     ],
     "id": did,
     "verificationMethod": [verificationMethod],
     "authentication": [did + "#key-1"],
     "assertionMethod": [did + "#key-1"],
     "service": services
   }

5. Assemble metadata:
   didDocumentMetadata = {
     created: blockToISO(enrollmentStatus.blockNumber),
     updated: blockToISO(enrollmentStatus.blockNumber),
     versionId: toHex(merkleRoot)
   }

6. Return:
   {
     didDocument,
     didResolutionMetadata: { contentType: "application/did+ld+json" },
     didDocumentMetadata
   }
```

#### Deactivated Identity

```
Return:
  {
    didDocument: {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": did
    },
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: { deactivated: true }
  }
```

Per W3C DID Core §7.1.2, a deactivated DID returns a minimal document with only `@context` and `id`.

## Error Code Reference

| Code | HTTP Analog | When Returned |
|---|---|---|
| `invalidDid` | 400 | DID string fails Phase 1 parsing |
| `notFound` | 404 | Commitment absent from IdentityRegistry |
| `deactivated` | 410 | `isRevoked()` returns true |
| `methodNotSupported` | 501 | DID method is not `bolyra` |
| `internalError` | 500 | RPC failure, contract revert, timeout |

## Caching Strategy

1. **Cache key:** `(commitment, chainId, merkleRoot)`
2. **Invalidation:** When `getMerkleRoot()` returns a new value, all cached entries for that chain are stale.
3. **TTL recommendation:** 60 seconds for active identities; indefinite for `deactivated` results (revocation is irreversible).
4. **ETag equivalent:** The `versionId` field in `didDocumentMetadata` serves as a cache validator.

## Deterministic Ordering Rules

To ensure byte-identical DID Documents across resolver implementations:

1. JSON keys in alphabetical order within each object.
2. `verificationMethod` entries ordered by key ID suffix (numeric ascending).
3. `service` entries ordered: `BolyraProofExchange` before `BolyraAgentPolicy`.
4. `@context` array order is fixed and MUST NOT be reordered.
