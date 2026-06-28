# Bolyra DID Resolution Algorithm

**Version:** 1.0.0  
**Status:** Draft  
**Date:** 2026-06-20  

## Overview

This document specifies the standalone resolution algorithm for `did:bolyra` DIDs. It complements the DID Method Specification (`spec/did-method-bolyra.md`) with implementation-ready pseudo-code.

## Types

```typescript
interface ResolutionResult {
  didDocument: DIDDocument | null;
  didDocumentMetadata: DIDDocumentMetadata;
  didResolutionMetadata: DIDResolutionMetadata;
}

interface DIDDocumentMetadata {
  created?: string;        // ISO 8601 timestamp
  updated?: string;        // ISO 8601 timestamp
  versionId?: string;      // block number as string
  deactivated?: boolean;
}

interface DIDResolutionMetadata {
  contentType?: string;    // "application/did+ld+json"
  error?: string;          // "invalidDid" | "notFound" | "deactivated" | "methodNotSupported"
}

interface ResolutionOptions {
  accept?: string;         // desired content type
}

interface RegistrationRecord {
  keyType: number;         // 0 = human, 1 = agent
  publicKey: Uint8Array;   // Baby Jubjub pubkey (agent) or empty (human)
  merkleRoot: Uint8Array;  // 32 bytes
  timestamp: bigint;       // block timestamp of registration
  active: boolean;
}
```

## Algorithm: `resolve(did, resolutionOptions)`

```pseudo
function resolve(did: string, options: ResolutionOptions = {}): ResolutionResult {

  // Step 1: Parse DID string
  let segments = did.split(":")
  if segments.length != 3:
    return errorResult("invalidDid")

  let [scheme, method, commitmentHex] = segments

  // Step 2: Validate scheme
  if scheme != "did":
    return errorResult("invalidDid")

  // Step 3: Validate method
  if method != "bolyra":
    return errorResult("methodNotSupported")

  // Step 4: Validate commitment format
  if not matches(commitmentHex, /^[0-9a-f]{64}$/):
    return errorResult("invalidDid")

  // Step 5: Convert to bytes32
  let commitment = hexToBytes32("0x" + commitmentHex)

  // Step 6: Query IdentityRegistry
  let reg: RegistrationRecord = IdentityRegistry.getRegistration(commitment)

  // Step 7: Check existence
  if reg.timestamp == 0:
    return errorResult("notFound")

  // Step 8: Check deactivation
  if reg.active == false:
    return {
      didDocument: null,
      didDocumentMetadata: { deactivated: true },
      didResolutionMetadata: { error: "deactivated" }
    }

  // Step 9: Determine subject type and build verification method
  let verificationMethod, authentication, assertionMethod

  if reg.keyType == 0:  // Human
    let vmId = did + "#human-auth-1"
    verificationMethod = [{
      id: vmId,
      type: "BolyraZkpAuthentication2024",
      controller: did,
      nullifierCommitment: commitmentHex,
      proofPurpose: "authentication",
      merkleTreeDepth: 20
    }]
    authentication = [vmId]
    assertionMethod = []

  else if reg.keyType == 1:  // Agent
    let vmId = did + "#agent-key-1"
    let [x, y] = decodeBabyJubjubPublicKey(reg.publicKey)
    verificationMethod = [{
      id: vmId,
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: {
        kty: "OKP",
        crv: "Baby-Jubjub",
        x: base64url(x),
        y: base64url(y)
      }
    }]
    authentication = [vmId]
    assertionMethod = [vmId]

  else:
    return errorResult("invalidDid")  // unknown keyType

  // Step 10: Build service endpoints
  let service = [{
    id: did + "#registry",
    type: "BolyraRegistryService",
    serviceEndpoint: {
      registryAddress: IDENTITY_REGISTRY_ADDRESS,
      chainId: CHAIN_ID,
      chainName: CHAIN_NAME
    }
  }]

  // Step 11: Assemble DID Document
  let didDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://bolyra.ai/ns/did/v1"
    ],
    id: did,
    controller: did,
    verificationMethod: verificationMethod,
    authentication: authentication,
    assertionMethod: assertionMethod,
    service: service
  }

  // Step 12: Populate metadata
  let didDocumentMetadata = {
    created: isoTimestamp(reg.timestamp),
    updated: isoTimestamp(reg.timestamp),
    versionId: String(reg.blockNumber),
    deactivated: false
  }

  // Step 13: Return
  return {
    didDocument: didDocument,
    didDocumentMetadata: didDocumentMetadata,
    didResolutionMetadata: {
      contentType: "application/did+ld+json"
    }
  }
}

function errorResult(error: string): ResolutionResult {
  return {
    didDocument: null,
    didDocumentMetadata: {},
    didResolutionMetadata: { error: error }
  }
}
```

## Algorithm: `resolveRepresentation(did, resolutionOptions)`

```pseudo
function resolveRepresentation(did: string, options: ResolutionOptions = {}): ResolutionResult {
  let accept = options.accept || "application/did+ld+json"

  if accept != "application/did+ld+json":
    return {
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: { error: "representationNotSupported" }
    }

  let result = resolve(did, options)

  if result.didDocument != null:
    result.didDocumentStream = JSON.stringify(result.didDocument)

  return result
}
```

## Helper Functions

### `decodeBabyJubjubPublicKey(publicKey: Uint8Array)`

The `publicKey` field stored in the registry is a 64-byte concatenation of the x and y coordinates of the Baby Jubjub point, each as a 32-byte big-endian unsigned integer.

```pseudo
function decodeBabyJubjubPublicKey(publicKey: Uint8Array): [Uint8Array, Uint8Array] {
  assert publicKey.length == 64
  let x = publicKey.slice(0, 32)
  let y = publicKey.slice(32, 64)
  return [x, y]
}
```

### `hexToBytes32(hex: string)`

Converts a `0x`-prefixed 66-character hex string to a 32-byte value.

## Edge Cases

1. **Multiple registrations**: The registry enforces one registration per commitment. Re-registration after revocation is not permitted in v1.
2. **Chain reorgs**: Resolvers SHOULD wait for sufficient block confirmations before caching results.
3. **RPC failures**: Resolvers SHOULD return a transient error (not `notFound`) when the RPC call fails.
