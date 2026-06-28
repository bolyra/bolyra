# Experiment: Standardized Proof Envelope with MIME Content-Type

**ID:** `framework_integrator_proof_envelope_content_type`  
**Dimension:** standards  
**Priority:** high  
**Verdict:** consider (score: 71)

## Problem

Framework integrations currently serialize proofs as ad-hoc JSON blobs
with no standard envelope. This forces every integration (Express middleware,
FastAPI dependency, MCP tool wrapper) to understand the internal structure
of each circuit's proof output.

## Solution

Define `application/bolyra-proof+json` — a canonical proof envelope format
with a fixed JSON schema:

```json
{
  "version": "1.0",
  "circuit": "HumanUniqueness",
  "publicSignals": ["..."],
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...], "protocol": "groth16" },
  "metadata": { "prover": "@bolyra/sdk", "timestamp": "2026-06-19T12:00:00Z" }
}
```

## Artifacts

| File | Description |
|------|-------------|
| [`spec/draft-bolyra-mutual-zkp-auth-01.md`](spec/draft-bolyra-mutual-zkp-auth-01.md) | §6 Wire Format — normative schema, Content-Type requirements, version negotiation |
| [`sdk/src/envelope.ts`](sdk/src/envelope.ts) | TypeScript: `ProofEnvelope` type, Zod validation, serialize/deserialize, `CONTENT_TYPE` constant |
| [`sdk-python/bolyra/envelope.py`](sdk-python/bolyra/envelope.py) | Python: pydantic v2 `ProofEnvelope`, `to_json()`/`from_json()`, mirrors TS exactly |
| [`sdk/test/envelope.test.ts`](sdk/test/envelope.test.ts) | TS unit tests: round-trip, version rejection, missing fields, type errors |
| [`sdk-python/tests/test_envelope.py`](sdk-python/tests/test_envelope.py) | Python tests: mirrors TS cases + cross-SDK fixture interop |
| [`sdk/test/fixtures/envelope_v1.json`](sdk/test/fixtures/envelope_v1.json) | Golden fixture for cross-SDK interop testing |
| [`docs/proof-envelope.md`](docs/proof-envelope.md) | Integration guide: Express middleware, FastAPI dependency, MCP tool wrapper |

## Usage

### TypeScript

```typescript
import {
  CONTENT_TYPE,
  serializeEnvelope,
  deserializeEnvelope,
  envelopeFromSnarkjsProof,
} from '@bolyra/sdk';

// Wrap raw snarkjs output
const envelope = envelopeFromSnarkjsProof('HumanUniqueness', proof, signals);

// Send over HTTP
fetch('/verify', {
  method: 'POST',
  headers: { 'Content-Type': CONTENT_TYPE },
  body: serializeEnvelope(envelope),
});

// Receive and validate
const received = deserializeEnvelope(body);
```

### Python

```python
from bolyra.envelope import CONTENT_TYPE, ProofEnvelope, envelope_from_snarkjs_proof

envelope = envelope_from_snarkjs_proof("AgentPolicy", proof, signals)
json_str = envelope.to_json()

# Parse and validate
received = ProofEnvelope.from_json(json_str)
```

## Testing

```bash
# TypeScript
cd sdk && npm test

# Python
cd sdk-python && pytest tests/test_envelope.py -v
```

## Version Negotiation

- Major version mismatch → reject (error thrown)
- Minor version mismatch → accept (forward-compatible)
- Current version: `1.0`

## Re-export

The envelope module is re-exported from `@bolyra/sdk`'s public API via
`sdk/src/index.ts`. Add the following line to re-export:

```typescript
export { CONTENT_TYPE, ENVELOPE_VERSION, ProofEnvelope, ProofData, ProofMetadata, ProofEnvelopeSchema, serializeEnvelope, deserializeEnvelope, validateEnvelope, envelopeFromSnarkjsProof } from './envelope';
```
