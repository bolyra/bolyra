# Bolyra DID Resolution Test Vectors

This directory contains conformance test vectors for the `did:bolyra` DID resolution algorithm.

## Files

| File | Description |
|---|---|
| `did-resolution-vectors.json` | 7 test vectors covering all resolution paths |

## Schema

Each test vector has the following structure:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique test vector identifier |
| `description` | string | Human-readable description of what the vector tests |
| `input.did` | string | The DID string to resolve |
| `input.registryAddress` | string | The IdentityRegistry contract address |
| `onChainState` | object \| null | Mock return values for each IIdentityRegistry method. `null` when the test does not reach on-chain queries (e.g., parse failures). |
| `onChainState.getEnrollmentStatus` | object | `{ enrolled, publicKey, blockNumber }` |
| `onChainState.isRevoked` | bool | Whether the commitment is revoked |
| `onChainState.getAgentCredential` | object | `{ agentId, modelHash, operatorPubKey, permissions, expiry }` |
| `onChainState.getMerkleRoot` | string | Current Merkle root hex |
| `expectedOutput` | object | The expected `DIDResolutionResult` |
| `expectedOutput.didDocument` | object \| null | Expected DID Document (null on error) |
| `expectedOutput.didResolutionMetadata` | object | `{ contentType?, error?, message? }` |
| `expectedOutput.didDocumentMetadata` | object | `{ versionId?, deactivated?, created?, updated? }` |

### Notes on `publicKeyMultibase`

Test vectors use the placeholder `"z__COMPUTED_FROM_BABYJUBJUB_POINT__"` for the `publicKeyMultibase` field. Conformance test runners MUST compute the actual multibase encoding from the `publicKey` coordinates in `onChainState` and compare against the resolver output.

The encoding algorithm:
1. Compress the BabyJubJub `(x, y)` point to 32 bytes.
2. Prepend the multicodec varint `0xed01`.
3. Base58btc encode and prepend `z`.

## Test Vector Coverage

| ID | Scenario | Expected Outcome |
|---|---|---|
| `human-enrolled` | Valid human identity | Full DID Document with BolyraProofExchange service |
| `agent-enrolled` | Valid agent identity | DID Document with BolyraAgentPolicy service |
| `revoked-identity` | Revoked human identity | `deactivated: true`, minimal document |
| `not-found` | Commitment not in registry | `notFound` error |
| `malformed-did` | Missing `did:` prefix | `invalidDid` error |
| `invalid-hex` | Non-hex characters | `invalidDid` error |
| `no-0x-prefix` | Valid DID without `0x` prefix | Same document as with prefix |

## Running Conformance Checks

### With @bolyra/sdk

```typescript
import { DIDResolver } from '@bolyra/sdk';
import vectors from './did-resolution-vectors.json';

for (const vector of vectors.vectors) {
  // Create a mock provider that returns vector.onChainState
  const resolver = new DIDResolver(mockProvider, vector.input.registryAddress);
  const result = await resolver.resolve(vector.input.did);
  
  // Compare result against vector.expectedOutput
  // (skip publicKeyMultibase placeholder comparison — compute from onChainState.publicKey)
}
```

### Manual Verification

1. Parse the `input.did` string.
2. Stub the `IIdentityRegistry` contract to return `onChainState` values.
3. Run the resolution algorithm from `spec/did-resolution-algorithm.md`.
4. Assert the output matches `expectedOutput`.
