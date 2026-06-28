---
title: Proof Envelope Format
visibility: public
sources:
  - sdk/src/envelope.ts
  - sdk/src/index.ts
last-updated: 2026-06-28
staleness-threshold: 60d
tags: [envelope, wire-format, proof, groth16, interop]
---

Self-describing JSON wire format for transporting ZKP proofs between systems. Content type: `application/vnd.bolyra.proof+json`. Includes circuit identity binding, version negotiation, and field element validation.

## Overview

The proof envelope wraps a Groth16 proof with metadata that makes it self-describing and safe to deserialize. A verifier receiving an envelope knows which circuit produced it, what version of the circuit was used, and can optionally verify the vkey hash before checking the proof. Unknown top-level fields are preserved for forward compatibility.

## Key Concepts

### Envelope Structure

```json
{
  "version": "1.0.0",
  "circuit": {
    "name": "AgentPolicy",
    "version": "0.4.0",
    "vkeyHash": "sha256:abcdef..."
  },
  "proofType": "groth16",
  "publicSignals": ["12345...", "67890..."],
  "proof": {
    "pi_a": ["...", "..."],
    "pi_b": [["...", "..."], ["...", "..."]],
    "pi_c": ["...", "..."]
  },
  "metadata": {
    "prover": "@bolyra/sdk@0.5.1",
    "timestamp": "2026-06-28T12:00:00.000Z"
  }
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Semver. Major mismatch = reject. Minor/patch = accept. |
| `circuit.name` | string | Yes | One of: `HumanUniqueness`, `AgentPolicy`, `Delegation` |
| `circuit.version` | string | Yes | Circuit version (e.g., `0.4.0`) |
| `circuit.vkeyHash` | string | No | `sha256:<64 lowercase hex>` -- binds to specific vkey |
| `proofType` | string | Yes | Currently only `groth16` (v1) |
| `publicSignals` | string[] | Yes | Non-empty array of decimal field element strings |
| `proof.pi_a` | [string, string] | Yes | G1 point (affine, decimal strings) |
| `proof.pi_b` | [[string, string], [string, string]] | Yes | G2 point (affine, decimal strings) |
| `proof.pi_c` | [string, string] | Yes | G1 point (affine, decimal strings) |
| `metadata` | object | No | Informational only. Verifiers MUST NOT reject based on metadata. |

### Validation Rules

- All field elements are decimal strings, no leading zeros (except `"0"` itself)
- Maximum string length: 78 characters per element (DoS prevention before BigInt parsing)
- Values must be less than the BN254 field modulus
- Version compatibility: major version must match; minor/patch differences are accepted
- Unknown top-level fields are preserved (forward compatibility)

## How It Works

### Creating an Envelope

Wrap raw snarkjs output:

```ts
import { envelopeFromSnarkjsProof } from '@bolyra/sdk';

const envelope = envelopeFromSnarkjsProof(
  'AgentPolicy',
  snarkjsProof,       // { pi_a, pi_b, pi_c }
  publicSignals,      // string[]
  { circuitVersion: '0.4.0', vkeyHash: 'sha256:...' }
);
```

### Serialization / Deserialization

```ts
import { serializeEnvelope, deserializeEnvelope, validateEnvelope } from '@bolyra/sdk';

// Serialize to JSON string
const json = serializeEnvelope(envelope);

// Deserialize and validate (throws on any violation)
const parsed = deserializeEnvelope(json);

// Validate an already-parsed object
const validated = validateEnvelope(rawObject);
```

### HTTP Transport

Set the content type header when sending proofs over HTTP:

```
Content-Type: application/vnd.bolyra.proof+json
```

The constant is exported as `CONTENT_TYPE` from the SDK.

### Exported API

From `@bolyra/sdk`:

- `CONTENT_TYPE` -- `'application/vnd.bolyra.proof+json'`
- `ENVELOPE_VERSION` -- `'1.0.0'`
- `serializeEnvelope(envelope)` -- JSON stringify
- `deserializeEnvelope(json)` -- Parse + validate, throws on error
- `validateEnvelope(obj)` -- Validate a raw object, throws on error
- `envelopeFromSnarkjsProof(name, proof, signals, opts?)` -- Wrap snarkjs output

Types: `ProofEnvelope`, `ProofData`, `ProofMetadata`, `CircuitIdentity`, `CircuitName`, `ProofType`

## Current Status

- Envelope version: 1.0.0
- Only `groth16` proof type supported in v1 (PLONK has a different coordinate shape)
- Used by the gateway, MCP server, and CrewAI integration for proof transport
- Cross-SDK interop: TS SDK and Python SDK share golden fixture tests (6 fixtures)
- TS: 55 tests, Python: 20 tests for envelope handling

## See Also

- [zkp-handshake.md](zkp-handshake.md) -- Protocol that generates the proofs wrapped by envelopes
- [circuits-overview.md](circuits-overview.md) -- The three circuits whose proofs are enveloped
- [did-method.md](did-method.md) -- DID resolution that may accompany envelope transport
- `sdk/src/envelope.ts` -- Full implementation
