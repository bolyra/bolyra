# Proof Envelope Developer Guide

## What is a Proof Envelope?

A **Proof Envelope** is the canonical JSON format for all Bolyra ZKP proof payloads. Instead of each integration (MCP, LangChain, REST, etc.) inventing its own serialization, every proof travels in one uniform wrapper.

```json
{
  "version": "1.0",
  "proofType": "handshake",
  "publicSignals": ["12345678901234567890", "98765432109876543210", "11111"],
  "proof": {
    "pi_a": ["1", "2", "1"],
    "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]],
    "pi_c": ["7", "8", "1"],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "metadata": {
    "issuedAt": 1719878400,
    "nonce": "session-abc123"
  }
}
```

## Content-Type

Use `application/bolyra+json` as the HTTP Content-Type header when sending or receiving proof envelopes.

```ts
import { BOLYRA_CONTENT_TYPE } from '@bolyra/sdk';
// BOLYRA_CONTENT_TYPE === 'application/bolyra+json'
```

## Constructing an Envelope

### From `proveHandshake()`

`proveHandshake()` now returns a `ProofEnvelope` directly:

```ts
import { proveHandshake, serializeEnvelope, BOLYRA_CONTENT_TYPE } from '@bolyra/sdk';

const envelope = await proveHandshake(human, agent, nonce);
const json = serializeEnvelope(envelope);

// Send over HTTP
fetch('/verify', {
  method: 'POST',
  headers: { 'Content-Type': BOLYRA_CONTENT_TYPE },
  body: json,
});
```

### From raw snarkjs output

If you have raw snarkjs proof output, use `createEnvelope()`:

```ts
import { createEnvelope, ProofType } from '@bolyra/sdk';

const envelope = createEnvelope(
  ProofType.Handshake,
  publicSignals,
  proof,  // { pi_a, pi_b, pi_c, protocol, curve }
  { nonce: 'session-123' },
);
```

## Receiving an Envelope

```ts
import { deserializeEnvelope, EnvelopeValidationError } from '@bolyra/sdk';

try {
  const envelope = deserializeEnvelope(requestBody);
  console.log(envelope.proofType);     // 'handshake'
  console.log(envelope.publicSignals); // ['123', '456', ...]
} catch (err) {
  if (err instanceof EnvelopeValidationError) {
    console.error(err.code, err.message);
    // err.code: 'INVALID_JSON' | 'SCHEMA_VIOLATION' | 'UNSUPPORTED_VERSION' | ...
  }
}
```

## Proof Types

| `proofType` | Circuit | Use case |
|---|---|---|
| `handshake` | HumanUniqueness | Human–agent mutual auth |
| `delegation` | Delegation | Scope-narrowing delegation proof |
| `agent_policy` | AgentPolicy | Agent permission proof |

## Version Compatibility

- **Major version** changes break the schema. The SDK rejects unknown major versions.
- **Minor version** changes add optional fields. The SDK accepts `1.1`, `1.2`, etc.

## Migration from Ad-Hoc Serialization

### Before (pre-envelope)

```ts
// Each integration serialized differently
const result = { proof, publicSignals, circuit: 'HumanUniqueness' };
res.json(result); // No standard schema, no validation
```

### After (with envelope)

```ts
import { createEnvelope, ProofType, serializeEnvelope, BOLYRA_CONTENT_TYPE } from '@bolyra/sdk';

const envelope = createEnvelope(ProofType.Handshake, publicSignals, proof);
res.set('Content-Type', BOLYRA_CONTENT_TYPE);
res.send(serializeEnvelope(envelope));
```

### Key differences

1. **Validation on both ends** — `createEnvelope()` validates on creation; `deserializeEnvelope()` validates on receipt.
2. **Version field** — enables future schema evolution without breaking existing consumers.
3. **Metadata** — `issuedAt` timestamp and optional `nonce` are always present.
4. **Strict schema** — `additionalProperties: false` at the top level prevents field drift.

## LangChain Integration

```ts
import { extractBolyraCredential, injectBolyraCredential } from '@bolyra/langchain';

// Inject proof into chain metadata
const metadata = injectBolyraCredential({}, envelope);
await chain.invoke(input, { metadata });

// Extract on the receiving end
const cred = extractBolyraCredential(metadata);
if (cred) {
  console.log(cred.envelope.proofType);
}
```

## MCP Integration

MCP tools return proof envelopes with `mimeType: 'application/bolyra+json'`:

```json
{
  "content": [{
    "type": "text",
    "text": "{\"version\":\"1.0\",...}",
    "mimeType": "application/bolyra+json"
  }]
}
```

## JSON Schema

The formal JSON Schema is at `sdk/src/envelope.schema.json` and can be used for validation in any language. See `spec/conformance/envelope-vectors.json` for test vectors.

## Further Reading

- Normative spec: `spec/proof-envelope.md`
- Conformance tests: `spec/conformance/envelope.test.ts`
- JSON Schema: `sdk/src/envelope.schema.json`
