# DID Method Specification: `did:bolyra`

**Version:** 0.2.0  
**Status:** Draft  
**Authors:** ZKProva Inc.  
**License:** Apache-2.0  
**Last Updated:** 2026-06-20  

## 1. Introduction

The `did:bolyra` DID method enables decentralized identifiers for both human and AI agent subjects within the Bolyra ZKP identity protocol. Human DIDs are rooted in Semaphore v4-style enrollment commitments; agent DIDs are rooted in EdDSA Baby Jubjub credential commitments. Both are anchored on-chain via the `IdentityRegistry` smart contract.

This specification conforms to [W3C DID Core v1.0](https://www.w3.org/TR/did-core/) and addresses the resolution algorithm requirements of sections 7.1 (resolve), 7.2 (resolveRepresentation), and 7.3 (dereference).

## 2. DID Syntax

### 2.1 ABNF

```abnf
bolyra-did      = "did:bolyra:" commitment
commitment      = 64HEXDIG
HEXDIG          = DIGIT / "a" / "b" / "c" / "d" / "e" / "f"
```

### 2.2 Normalization Rules

1. The commitment MUST be exactly 64 lowercase hexadecimal characters (32 bytes).
2. No `0x` prefix.
3. Leading zeros are significant and MUST be preserved.
4. Implementations MUST reject commitments containing uppercase characters.

### 2.3 Examples

```
did:bolyra:0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b
did:bolyra:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

## 3. DID Document

### 3.1 Context

All DID Documents MUST include the following `@context` array:

```json
[
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/jws-2020/v1",
  "https://bolyra.ai/ns/did/v1"
]
```

### 3.2 Controller

The DID Document controller is always the DID subject itself (self-sovereign):

```json
{ "controller": "did:bolyra:<commitment>" }
```

### 3.3 Subject Types

The `IdentityRegistry` stores a `keyType` field per registration:

| keyType | Subject | Description |
|---------|---------|-------------|
| `0`     | Human   | Semaphore v4 identity commitment (Poseidon hash of secret + nullifier) |
| `1`     | Agent   | EdDSA Baby Jubjub credential commitment (Poseidon hash of model hash + public key + permissions + expiry) |

## 4. Verification Methods

### 4.1 Agent Verification Method: `JsonWebKey2020`

For agent DIDs (keyType=1), the verification method uses `JsonWebKey2020` with a Baby Jubjub public key encoded as a JWK:

```json
{
  "id": "did:bolyra:<commitment>#agent-key-1",
  "type": "JsonWebKey2020",
  "controller": "did:bolyra:<commitment>",
  "publicKeyJwk": {
    "kty": "OKP",
    "crv": "Baby-Jubjub",
    "x": "<base64url-encoded x coordinate>",
    "y": "<base64url-encoded y coordinate>"
  }
}
```

Agent verification methods appear in both `authentication` and `assertionMethod` arrays.

### 4.2 Human Verification Method: `BolyraZkpAuthentication2024`

For human DIDs (keyType=0), the verification method uses a custom type that references the nullifier commitment rather than exposing a public key:

```json
{
  "id": "did:bolyra:<commitment>#human-auth-1",
  "type": "BolyraZkpAuthentication2024",
  "controller": "did:bolyra:<commitment>",
  "nullifierCommitment": "<hex-encoded commitment>",
  "proofPurpose": "authentication",
  "merkleTreeDepth": 20
}
```

Human verification methods appear ONLY in the `authentication` array. They do NOT appear in `assertionMethod` since humans authenticate via ZKP, not via signing assertions.

## 5. Resolution Algorithm (Normative)

### 5.1 resolve(did, resolutionOptions)

The `resolve` function accepts a `did:bolyra` DID string and optional resolution options, returning the tuple `{didDocument, didDocumentMetadata, didResolutionMetadata}`.

#### 5.1.1 Algorithm Steps

1. **Parse DID string**: Split on `:` — expect exactly 3 segments: `did`, `bolyra`, `<commitment>`.
2. **Validate method**: The second segment MUST be `bolyra`. Otherwise return `didResolutionMetadata.error = "methodNotSupported"`.
3. **Validate commitment**: The third segment MUST match `/^[0-9a-f]{64}$/`. Otherwise return `didResolutionMetadata.error = "invalidDid"`.
4. **Normalize commitment**: Convert to 32-byte `bytes32` value (prepend `0x` for EVM call).
5. **Query registry**: Call `IdentityRegistry.getRegistration(bytes32 commitment)`. This returns `(uint8 keyType, bytes publicKey, bytes32 merkleRoot, uint256 timestamp, bool active)`.
6. **Not found**: If `timestamp == 0` (never registered), return `didResolutionMetadata.error = "notFound"`.
7. **Deactivated**: If `active == false`, return:
   - `didResolutionMetadata.error = "deactivated"`
   - `didDocumentMetadata.deactivated = true`
   - `didDocument = null`
8. **Determine subject type**: If `keyType == 0` → human; if `keyType == 1` → agent.
9. **Construct verification method**: See section 4.
10. **Assemble DID Document**: See section 3.
11. **Populate metadata**:
    - `didDocumentMetadata.created`: block timestamp of the `RegistrationRecorded` event for this commitment.
    - `didDocumentMetadata.updated`: block timestamp of the most recent event for this commitment.
    - `didDocumentMetadata.versionId`: block number of the most recent event.
    - `didDocumentMetadata.deactivated`: `false` (since we reached this step).
12. **Return**: `{didDocument, didDocumentMetadata, didResolutionMetadata: {contentType: "application/did+ld+json"}}`.

### 5.2 resolveRepresentation(did, resolutionOptions)

Same as `resolve` but returns the DID Document serialized as a byte stream. The `contentType` in `resolutionOptions` determines the serialization format. Only `application/did+ld+json` is supported in v1.

### 5.3 Dereference

Fragment dereferencing follows W3C DID Core section 7.3. Fragments reference verification method IDs (e.g., `did:bolyra:<commitment>#agent-key-1`).

## 6. Service Endpoints (Normative)

Every DID Document includes a service entry pointing to the on-chain registry:

```json
{
  "id": "did:bolyra:<commitment>#registry",
  "type": "BolyraRegistryService",
  "serviceEndpoint": {
    "registryAddress": "0x<IdentityRegistry contract address>",
    "chainId": 84532,
    "chainName": "Base Sepolia"
  }
}
```

## 7. Error Codes

| Error | Description |
|-------|-------------|
| `invalidDid` | DID string does not conform to the ABNF syntax |
| `methodNotSupported` | Method name is not `bolyra` |
| `notFound` | No registration exists for the given commitment |
| `deactivated` | Registration exists but has been revoked |

## 8. Security Considerations

### 8.1 Nullifier Linkability

Human DIDs are based on identity commitments, not nullifiers. The commitment itself is a public identifier. Nullifiers are generated per-session and are unlinkable across sessions. Resolving a human DID does NOT reveal any nullifier — it only confirms enrollment status.

### 8.2 Key Rotation

Key rotation is NOT supported in v1. A revoked DID cannot be re-activated with a new key. Future versions may introduce key rotation via a replacement registration pattern.

### 8.3 On-Chain Privacy

The `IdentityRegistry` stores commitments and public keys on-chain. For agents, the Baby Jubjub public key is visible. For humans, only the identity commitment is stored — the underlying secret and nullifier remain private.

### 8.4 Replay Protection

DID resolution results should be cached with appropriate TTLs. The `versionId` metadata field allows clients to detect stale cached documents.

## 9. Privacy Considerations

Resolving a `did:bolyra` DID reveals:
- Whether the commitment is registered (existence)
- Whether it is active or revoked (status)
- The subject type (human vs agent)
- For agents: the Baby Jubjub public key
- For humans: only the commitment (no key material)

Resolving does NOT reveal:
- The human's secret or nullifier
- Session-specific nullifier hashes
- Delegation relationships (these require separate proof verification)

## 10. Conformance

Conformance test vectors are provided in `spec/conformance/did-resolution-vectors.json`. A conformant resolver MUST pass all four test cases.
