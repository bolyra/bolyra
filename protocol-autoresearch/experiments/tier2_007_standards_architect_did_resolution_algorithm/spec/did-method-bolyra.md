# DID Method Specification: `did:bolyra`

**Method Name:** `bolyra`  
**Version:** 0.2.0  
**Status:** Draft  
**Authors:** ZKProva Inc.  
**Latest Update:** 2026-06-19  

## 1. Introduction

The `did:bolyra` method enables decentralized identifiers for both human and AI agent identities within the Bolyra ZKP identity protocol. Human identities are enrolled via Semaphore v4-style commitments; agent identities are registered via EdDSA-signed credentials with cumulative-bit permissions.

This specification conforms to [W3C DID Core v1.0](https://www.w3.org/TR/did-core/), including the resolution contract defined in §7.1.

## 2. DID Syntax

```abnf
did-bolyra      = "did:bolyra:" bolyra-id
bolyra-id       = 1*64HEXDIG
```

The `bolyra-id` is the hex-encoded identity commitment (Poseidon hash). For human identities this is the Semaphore v4 identity commitment; for agent identities this is the `keccak256(agentId)` credential commitment.

Examples:
- `did:bolyra:0x1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890`
- `did:bolyra:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890`

The `0x` prefix is optional. Resolvers MUST normalize to lowercase without prefix.

## 3. DID Document Structure

A resolved `did:bolyra` DID Document conforms to the following structure:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/eddsa-2022/v1",
    "https://bolyra.ai/ns/v1"
  ],
  "id": "did:bolyra:<commitment>",
  "verificationMethod": [
    {
      "id": "did:bolyra:<commitment>#key-1",
      "type": "EdDSAVerificationKey2022",
      "controller": "did:bolyra:<commitment>",
      "publicKeyMultibase": "z<base58btc-encoded-babyjubjub-point>"
    }
  ],
  "authentication": ["did:bolyra:<commitment>#key-1"],
  "assertionMethod": ["did:bolyra:<commitment>#key-1"],
  "service": [
    {
      "id": "did:bolyra:<commitment>#proof-exchange",
      "type": "BolyraProofExchange",
      "serviceEndpoint": "https://relay.bolyra.ai/exchange"
    }
  ]
}
```

For agent identities, an additional service endpoint is included:

```json
{
  "id": "did:bolyra:<commitment>#agent-policy",
  "type": "BolyraAgentPolicy",
  "serviceEndpoint": "https://relay.bolyra.ai/agent/policy",
  "permissions": 255
}
```

## 4. Verification Methods

Bolyra uses EdDSA signatures over the BabyJubJub elliptic curve. The `publicKeyMultibase` field encodes the BabyJubJub public key point as:

1. Compress the (x, y) point to 32 bytes using the standard BabyJubJub compression.
2. Prepend the multicodec varint for EdDSA (`0xed`).
3. Encode with base58btc and prepend `z`.

## 5. Identity Types

### 5.1 Human Identities

Human identities are created via Semaphore v4 enrollment. The commitment is `Poseidon(secret, nullifier)` and is inserted into the on-chain Merkle tree via `IdentityRegistry.enroll(commitment)`.

### 5.2 Agent Identities

Agent identities are registered via `IdentityRegistry.registerAgent(agentId, modelHash, operatorPubKey, permissions, expiry)`. The commitment is derived as `keccak256(agentId)`. The `permissions` field is an 8-bit cumulative encoding.

## 6. CRUD Operations

### 6.1 Create

A DID is created by enrolling a commitment on-chain:
- Human: `IdentityRegistry.enroll(commitment)` 
- Agent: `IdentityRegistry.registerAgent(agentId, ...)`

The DID becomes resolvable once the transaction is confirmed.

### 6.2 Read (Resolve)

See §7 Resolution Algorithm.

### 6.3 Update

Bolyra identities are immutable by design. Key rotation is achieved by revoking the existing identity and enrolling a new commitment. The old DID resolves with `deactivated: true`.

### 6.4 Deactivate (Revoke)

Human identities are revoked by publishing a nullifier via `IdentityRegistry.revoke(nullifierHash)`. Agent identities are revoked via `IdentityRegistry.revokeAgent(agentId)`. Once revoked, the DID Document metadata includes `deactivated: true` and the DID Document body is empty per W3C DID Core §7.1.2.

## 7. Resolution Algorithm

This section defines the complete DID resolution algorithm per W3C DID Core §7.1.

### 7.1 Error Codes

| Error Code | Condition |
|---|---|
| `invalidDid` | DID string fails syntactic parsing (missing prefix, invalid hex, wrong length) |
| `notFound` | Commitment is not enrolled in IdentityRegistry |
| `deactivated` | Identity has been revoked (nullifierHash flagged) |
| `methodNotSupported` | DID method is not `bolyra` |
| `internalError` | RPC or contract call failure |

### 7.2 Resolution Pipeline

```
resolve(did, options) → DIDResolutionResult
```

#### Step 1: Parse

```pseudocode
function parse(did):
  if not did.startsWith("did:bolyra:"):
    return error("invalidDid", "Missing did:bolyra: prefix")
  
  commitment = did.substring(10)  // after "did:bolyra:"
  commitment = commitment.replace(/^0x/, "").toLowerCase()
  
  if not /^[0-9a-f]{1,64}$/.test(commitment):
    return error("invalidDid", "Commitment must be 1-64 hex characters")
  
  return { commitment: "0x" + commitment.padStart(64, "0") }
```

#### Step 2: Read (On-Chain Query)

```pseudocode
function read(commitment, options):
  registry = IdentityRegistry.at(options.registryAddress)
  
  // Batch these into a single multicall for efficiency
  [enrollmentStatus, isRevoked, agentCred] = multicall(
    registry.getEnrollmentStatus(commitment),
    registry.isRevoked(commitment),
    registry.getAgentCredential(commitment)
  )
  
  if enrollmentStatus == NOT_ENROLLED and agentCred.agentId == 0:
    return error("notFound", "Commitment not in registry")
  
  if isRevoked:
    return error("deactivated", "Identity has been revoked")
  
  merkleRoot = registry.getMerkleRoot()
  
  identityType = agentCred.agentId != 0 ? "agent" : "human"
  
  return {
    commitment,
    identityType,
    merkleRoot,
    publicKey: enrollmentStatus.publicKey or agentCred.operatorPubKey,
    permissions: agentCred.permissions,  // 0 for humans
    expiry: agentCred.expiry,            // 0 for humans
    blockNumber: enrollmentStatus.blockNumber
  }
```

#### Step 3: Construct DID Document

```pseudocode
function resolve(did, options):
  parsed = parse(did)
  if parsed.error:
    return DIDResolutionResult(
      didDocument: null,
      didResolutionMetadata: { error: parsed.error.code, message: parsed.error.message },
      didDocumentMetadata: {}
    )
  
  record = read(parsed.commitment, options)
  
  if record.error and record.error.code == "deactivated":
    return DIDResolutionResult(
      didDocument: { "@context": ["https://www.w3.org/ns/did/v1"], "id": did },
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: { deactivated: true }
    )
  
  if record.error:
    return DIDResolutionResult(
      didDocument: null,
      didResolutionMetadata: { error: record.error.code, message: record.error.message },
      didDocumentMetadata: {}
    )
  
  pubKeyMultibase = encodeBabyJubJubMultibase(record.publicKey)
  
  didDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/eddsa-2022/v1",
      "https://bolyra.ai/ns/v1"
    ],
    "id": did,
    "verificationMethod": [{
      "id": did + "#key-1",
      "type": "EdDSAVerificationKey2022",
      "controller": did,
      "publicKeyMultibase": pubKeyMultibase
    }],
    "authentication": [did + "#key-1"],
    "assertionMethod": [did + "#key-1"],
    "service": [{
      "id": did + "#proof-exchange",
      "type": "BolyraProofExchange",
      "serviceEndpoint": "https://relay.bolyra.ai/exchange"
    }]
  }
  
  if record.identityType == "agent":
    didDocument.service.push({
      "id": did + "#agent-policy",
      "type": "BolyraAgentPolicy",
      "serviceEndpoint": "https://relay.bolyra.ai/agent/policy",
      "permissions": record.permissions
    })
  
  metadata = {
    "created": blockToISO(record.blockNumber),
    "updated": blockToISO(record.blockNumber),
    "versionId": record.merkleRoot
  }
  
  return DIDResolutionResult(
    didDocument: didDocument,
    didResolutionMetadata: { contentType: "application/did+ld+json" },
    didDocumentMetadata: metadata
  )
```

### 7.3 Caching Hints

- Resolvers SHOULD cache results keyed by `(commitment, merkleRoot)` since the DID Document is deterministic given these inputs.
- Cache entries MUST be invalidated when a new Merkle root is observed on-chain.
- The `versionId` field in `didDocumentMetadata` serves as an ETag equivalent.

### 7.4 Deterministic Ordering

- `verificationMethod` entries are ordered by key ID suffix (numeric ascending).
- `service` entries are ordered: `BolyraProofExchange` first, then `BolyraAgentPolicy` if present.

## 8. Security Considerations

- **Commitment privacy:** The commitment alone does not reveal the underlying secret or nullifier.
- **Revocation finality:** Once a nullifier is published on-chain, revocation is irreversible.
- **BabyJubJub curve security:** ~126-bit security level, suitable for identity applications.
- **Replay protection:** Handshake proofs are bound to a session nonce.

## 9. Privacy Considerations

- DID resolution reveals that a commitment exists on-chain but does not link to a real-world identity.
- Human identities use nullifiers for revocation to avoid correlating enrollment with revocation.
- Agent identities are pseudo-public by design (operator-controlled).

## 10. Conformance

Test vectors for the resolution algorithm are available at `spec/test-vectors/did-resolution-vectors.json`. See `spec/test-vectors/README.md` for usage.

## 11. References

- [W3C DID Core v1.0](https://www.w3.org/TR/did-core/)
- [W3C DID Resolution v0.3](https://w3c-ccg.github.io/did-resolution/)
- [Semaphore v4 Protocol](https://semaphore.pse.dev/)
- [BabyJubJub Curve](https://eips.ethereum.org/EIPS/eip-2494)
- Bolyra Resolution Algorithm: `spec/did-resolution-algorithm.md`
- Bolyra Test Vectors: `spec/test-vectors/did-resolution-vectors.json`
