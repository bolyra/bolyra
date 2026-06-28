# Bolyra DID Resolution Algorithm

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-06-19  
**DID Method:** `did:bolyra`  
**Normative Reference For:** `spec/did-method-bolyra.md` §7–9  

This document specifies the normative resolution algorithm for `did:bolyra` Decentralized Identifiers. It is a companion to the [Bolyra DID Method Specification](./did-method-bolyra.md) and conforms to [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) §7 (Resolution), §8 (Deactivation), and §9 (Security Considerations).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. DID Syntax

A Bolyra DID conforms to the following ABNF:

```abnf
bolyra-did      = "did:bolyra:" chain-id ":" registry-address ":" subject-id
chain-id        = 1*DIGIT
registry-address = "0x" 40HEXDIG
subject-id      = "0x" 64HEXDIG
```

- `chain-id`: The [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md) numeric chain identifier (e.g., `84532` for Base Sepolia).
- `registry-address`: The EVM address of the `BolyraRegistry` contract, lowercase hex.
- `subject-id`: A 32-byte identifier derived from the identity commitment (Poseidon hash of the secret for humans, or keccak256 of the agent credential for agents), lowercase hex.

### 1.1 Normalization

- The `registry-address` and `subject-id` components MUST be normalized to lowercase hex.
- Leading zeros in `chain-id` MUST be stripped (e.g., `084532` is invalid; `84532` is valid).
- Two DIDs are considered equivalent if and only if their normalized string representations are byte-identical.

### 1.2 Examples

```
did:bolyra:84532:0x1234567890abcdef1234567890abcdef12345678:0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

---

## 2. DID Document Structure

### 2.1 Human DID Document

A resolved human DID Document MUST contain:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://bolyra.ai/ns/did/v1"
  ],
  "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
  "controller": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
  "verificationMethod": [
    {
      "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>#human-merkle-root",
      "type": "BolyraHumanMerkleRoot2026",
      "controller": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
      "publicKeyBase64url": "<base64url-encoded 32-byte humanMerkleRoot>"
    }
  ],
  "authentication": [
    "did:bolyra:<chain-id>:<registry-address>:<subject-id>#human-merkle-root"
  ],
  "assertionMethod": [
    "did:bolyra:<chain-id>:<registry-address>:<subject-id>#human-merkle-root"
  ],
  "service": [
    {
      "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>#proof-submission",
      "type": "BolyraProofSubmission",
      "serviceEndpoint": "eip155:<chain-id>:<registry-address>",
      "proofType": "Groth16",
      "supportedCircuits": ["HumanUniqueness"]
    }
  ]
}
```

### 2.2 Agent DID Document

A resolved agent DID Document MUST contain:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://bolyra.ai/ns/did/v1"
  ],
  "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
  "controller": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
  "verificationMethod": [
    {
      "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>#agent-merkle-root",
      "type": "BolyraAgentMerkleRoot2026",
      "controller": "did:bolyra:<chain-id>:<registry-address>:<subject-id>",
      "publicKeyBase64url": "<base64url-encoded 32-byte agentMerkleRoot>"
    }
  ],
  "authentication": [
    "did:bolyra:<chain-id>:<registry-address>:<subject-id>#agent-merkle-root"
  ],
  "assertionMethod": [
    "did:bolyra:<chain-id>:<registry-address>:<subject-id>#agent-merkle-root"
  ],
  "service": [
    {
      "id": "did:bolyra:<chain-id>:<registry-address>:<subject-id>#proof-submission",
      "type": "BolyraProofSubmission",
      "serviceEndpoint": "eip155:<chain-id>:<registry-address>",
      "proofType": ["Groth16", "PLONK"],
      "supportedCircuits": ["AgentPolicy", "Delegation"]
    }
  ]
}
```

### 2.3 Verification Method Types

| Type | Key Material | Proof Purpose | Source Circuit |
|---|---|---|---|
| `BolyraHumanMerkleRoot2026` | 32-byte `humanMerkleRoot` (Poseidon Merkle root at depth 20) | `authentication`, `assertionMethod` | `HumanUniqueness.circom` |
| `BolyraAgentMerkleRoot2026` | 32-byte `agentMerkleRoot` (Poseidon hash of agent credential tree) | `authentication`, `assertionMethod` | `AgentPolicy.circom` |

The key material MUST be encoded as base64url (no padding) in the `publicKeyBase64url` property.

---

## 3. Resolution Algorithm

### 3.1 Inputs

| Input | Type | Description |
|---|---|---|
| `did` | string | The DID to resolve |
| `resolutionOptions` | object | OPTIONAL. May contain `accept` (media type) |

### 3.2 Algorithm

```
function resolve(did, resolutionOptions):

  // Step 1: Parse DID
  components = parseDID(did)
  IF components is NULL:
    RETURN {
      didResolutionMetadata: { error: "invalidDid" },
      didDocument: NULL,
      didDocumentMetadata: {}
    }

  chainId       = components.chainId
  registryAddr  = components.registryAddress
  subjectId     = components.subjectId

  // Step 2: Validate chain-id
  rpcEndpoint = getRpcEndpoint(chainId)
  IF rpcEndpoint is NULL:
    RETURN {
      didResolutionMetadata: { error: "unsupportedChainId",
                               message: "Chain " + chainId + " is not supported" },
      didDocument: NULL,
      didDocumentMetadata: {}
    }

  // Step 3: Connect to registry
  registry = connectToRegistry(registryAddr, rpcEndpoint)

  // Step 4: Retrieve on-chain identity
  identity = registry.getIdentity(subjectId)
  IF identity is NULL OR identity.identityType == 0:
    RETURN {
      didResolutionMetadata: { error: "notFound" },
      didDocument: NULL,
      didDocumentMetadata: {}
    }

  // Step 5: Check revocation / deactivation
  isRevoked = registry.isNullifierRevoked(identity.nullifierHash)

  IF isRevoked:
    RETURN {
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocument: {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "controller": did
      },
      didDocumentMetadata: {
        deactivated: true,
        updated: identity.revokedAtBlock
      }
    }

  // Step 6: Construct DID Document
  didDocument = constructDIDDocument(did, identity)

  // Step 7: Build metadata
  didDocumentMetadata = {
    created: identity.registeredAtBlock,
    updated: identity.lastUpdatedBlock,
    versionId: toString(identity.version)
  }

  RETURN {
    didResolutionMetadata: {
      contentType: "application/did+ld+json"
    },
    didDocument: didDocument,
    didDocumentMetadata: didDocumentMetadata
  }
```

### 3.3 `parseDID` Subroutine

```
function parseDID(did):
  parts = did.split(":")
  IF parts.length != 5:
    RETURN NULL
  IF parts[0] != "did" OR parts[1] != "bolyra":
    RETURN NULL
  chainId = parts[2]
  IF NOT isNumeric(chainId) OR hasLeadingZeros(chainId):
    RETURN NULL
  registryAddress = parts[3]
  IF NOT isValidAddress(registryAddress):
    RETURN NULL
  subjectId = parts[4]
  IF NOT isValid32ByteHex(subjectId):
    RETURN NULL
  RETURN {
    chainId: chainId,
    registryAddress: toLowerCase(registryAddress),
    subjectId: toLowerCase(subjectId)
  }
```

### 3.4 `constructDIDDocument` Subroutine

```
function constructDIDDocument(did, identity):
  doc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://bolyra.ai/ns/did/v1"
    ],
    "id": did,
    "controller": did
  }

  IF identity.identityType == 1:  // Human
    vmId = did + "#human-merkle-root"
    doc.verificationMethod = [{
      "id": vmId,
      "type": "BolyraHumanMerkleRoot2026",
      "controller": did,
      "publicKeyBase64url": base64url(identity.humanMerkleRoot)
    }]
    doc.service = [{
      "id": did + "#proof-submission",
      "type": "BolyraProofSubmission",
      "serviceEndpoint": caip10(identity),
      "proofType": "Groth16",
      "supportedCircuits": ["HumanUniqueness"]
    }]

  ELSE IF identity.identityType == 2:  // Agent
    vmId = did + "#agent-merkle-root"
    doc.verificationMethod = [{
      "id": vmId,
      "type": "BolyraAgentMerkleRoot2026",
      "controller": did,
      "publicKeyBase64url": base64url(identity.agentMerkleRoot)
    }]
    doc.service = [{
      "id": did + "#proof-submission",
      "type": "BolyraProofSubmission",
      "serviceEndpoint": caip10(identity),
      "proofType": ["Groth16", "PLONK"],
      "supportedCircuits": ["AgentPolicy", "Delegation"]
    }]

  doc.authentication = [vmId]
  doc.assertionMethod = [vmId]

  RETURN doc
```

---

## 4. Deactivation Semantics

### 4.1 Deactivation Trigger

A `did:bolyra` DID is considered **deactivated** when the `nullifierHash` associated with the identity's subject-id appears in the `BolyraRegistry` contract's revocation set.

Deactivation is triggered by calling `registry.revokeNullifier(nullifierHash)` on-chain. This is an irreversible operation.

### 4.2 Deactivated DID Document

When resolving a deactivated DID:

1. The resolver MUST return a minimal DID Document containing only `@context`, `id`, and `controller`.
2. The `didDocumentMetadata` MUST include `"deactivated": true`.
3. The `didDocumentMetadata` SHOULD include an `updated` field set to the block number at which revocation occurred.
4. Verification methods MUST be omitted from the deactivated DID Document.
5. Service endpoints MUST be omitted from the deactivated DID Document.
6. The `didResolutionMetadata` MUST NOT contain an `error` property (deactivation is not an error).

### 4.3 Deactivation Finality

Deactivation in `did:bolyra` is permanent. Once a nullifier is revoked on-chain, there is no mechanism to re-activate the DID. A new identity commitment and new DID MUST be created.

---

## 5. Security Considerations

### 5.1 Nullifier Linkability Across Contexts

The `nullifierHash` is derived from a per-context external nullifier. Two proof submissions using different external nullifiers produce unlinkable nullifier hashes. However, if a resolver caches or indexes nullifier hashes across contexts, it MAY be possible to correlate identities. Implementers MUST NOT store nullifier hashes in shared indices across unrelated verification contexts.

### 5.2 Merkle Root Staleness Window

The `humanMerkleRoot` and `agentMerkleRoot` values stored on-chain reflect the state at the block in which the last registration or update transaction was mined. Between the time a new identity is committed off-chain and the on-chain Merkle root update, there is a staleness window during which:

- A newly registered identity MAY NOT be resolvable.
- A recently revoked identity MAY still appear active.

Resolvers SHOULD document their staleness tolerance. For chains with probabilistic finality, resolvers MUST wait for sufficient block confirmations (RECOMMENDED: 12 blocks on Ethereum L1, 1 block on Base L2) before treating a resolution result as final.

### 5.3 Key Compromise and Revocation Latency

If an identity secret is compromised, the legitimate owner MUST revoke the associated nullifier by calling `revokeNullifier()` on-chain. The time between compromise and on-chain revocation is a vulnerability window. Mitigations:

- Relying parties SHOULD implement short proof validity windows (e.g., `sessionNonce` binding).
- High-value verifiers SHOULD require recent block confirmations in the proof.
- The `nonceBinding` public output in `HumanUniqueness` prevents proof replay but does not prevent a compromised key from generating new proofs until revocation is finalized.

### 5.4 Replay Attacks on Resolution Responses

A cached or replayed DID Resolution Result may contain stale data. To mitigate:

- Resolvers MUST include `didDocumentMetadata.versionId` corresponding to the on-chain identity version.
- Consumers SHOULD compare `versionId` against a direct on-chain query when making high-assurance decisions.
- Resolution results SHOULD NOT be cached beyond the chain's block time.

### 5.5 Resolver Trust Model

The `did:bolyra` method relies on an RPC endpoint to read on-chain state. The resolver trusts that:

1. The RPC endpoint faithfully reports chain state (not censoring or fabricating data).
2. The `BolyraRegistry` contract at the specified address is the canonical registry.

To mitigate RPC trust issues:

- Resolvers SHOULD support multiple RPC endpoints per chain and cross-validate results.
- Resolvers MAY use light client verification where available.
- The `registry-address` component in the DID pins the contract, preventing address substitution.

### 5.6 Privacy Considerations

Resolution itself does not reveal the identity holder's real-world identity. The `humanMerkleRoot` proves membership in a set without revealing which leaf. However:

- The `subject-id` is a persistent pseudonym. Repeated resolution of the same DID is linkable.
- On-chain registration transactions are publicly visible and may be correlated with the submitting wallet address.
- Resolvers SHOULD minimize logging of resolution requests to avoid building surveillance profiles.

---

## 6. Conformance

An implementation conforms to this specification if it:

1. Correctly implements the resolution algorithm in §3.
2. Returns DID Documents matching the structure in §2.
3. Handles deactivated DIDs per §4.
4. Passes the test vectors defined in `spec/conformance/did-resolution-vectors.json`.

---

## 7. References

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [W3C DID Resolution](https://w3c-ccg.github.io/did-resolution/)
- [CAIP-2: Blockchain ID Specification](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md)
- [CAIP-10: Account ID Specification](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-10.md)
- [Bolyra DID Method Specification](./did-method-bolyra.md)
- [Semaphore v4](https://semaphore.pse.dev/)
