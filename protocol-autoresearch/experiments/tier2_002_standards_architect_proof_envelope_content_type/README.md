# Proof Envelope Wire Format

## Experiment: `standards_architect_proof_envelope_content_type`

Standardizes the Bolyra proof envelope wire format with IANA-style content types `application/bolyra-proof+json` and `application/bolyra-proof+cbor`.

## Problem

The SDK passes proof objects as ad-hoc JSON blobs with no schema versioning or content negotiation. Each integration reinvents serialization, making multi-implementation interop impossible.

## Solution

A versioned `ProofEnvelope` with:
- **`version`** — semver string (`1.0.0`)
- **`circuitId`** — URI identifying the circuit (`bolyra:circuit:HumanUniqueness`, etc.)
- **`provingSystem`** — `groth16` or `plonk`
- **`publicSignals`** — decimal string array
- **`proof`** — Groth16 (`pi_a/pi_b/pi_c`) or PLONK (`A/B/C/Z/T1/T2/T3/...`) structure
- **`metadata`** — chain ID, registry address, issuedAt timestamp

## Artifacts

| File | Description |
|------|-------------|
| `spec/proof-envelope-schema.json` | JSON Schema (draft 2020-12) with strict validation |
| `sdk/src/envelope.ts` | TypeScript types, serialize/deserialize, schema validation |
| `sdk/test/envelope.test.ts` | Round-trip tests, rejection tests, conformance vectors |
| `spec/conformance/proof-envelope-vectors.json` | Canonical test vectors (4 combinations) |
| `spec/draft-bolyra-mutual-zkp-auth-01.md` | §4 ABNF grammar addition |
| `sdk/QUICKSTART.md` | Content negotiation section |

## Usage

```typescript
import {
  createProofEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  CONTENT_TYPE_JSON,
  CONTENT_TYPE_CBOR,
} from '@bolyra/sdk';

// Create an envelope
const envelope = createProofEnvelope(
  'bolyra:circuit:HumanUniqueness',
  'groth16',
  publicSignals,
  proof,
  { chain: 84532, registryAddress: '0x...', issuedAt: Date.now() },
);

// Serialize to JSON
const jsonBuf = serializeEnvelope(envelope, 'json');

// Serialize to CBOR (smaller, for on-chain calldata)
const cborBuf = serializeEnvelope(envelope, 'cbor');

// Deserialize
const restored = deserializeEnvelope(jsonBuf, CONTENT_TYPE_JSON);
```

## Content-Type Negotiation

Clients set the `Accept` header to indicate preferred format:

```http
POST /verify HTTP/1.1
Content-Type: application/bolyra-proof+json
Accept: application/bolyra-proof+json, application/bolyra-proof+cbor;q=0.9
```

| Format | Content-Type | Best for |
|--------|-------------|----------|
| JSON | `application/bolyra-proof+json` | REST APIs, debugging, human readability |
| CBOR | `application/bolyra-proof+cbor` | On-chain calldata, bandwidth-constrained, mobile |

## Running Tests

```bash
cd sdk && npm test
```

## Dependencies

- `cbor-x` — CBOR encoding/decoding
- `ajv` + `ajv-formats` — JSON Schema validation
