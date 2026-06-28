# Proof Envelope Developer Guide

## Overview

Bolyra uses a CBOR-based binary envelope (`application/bolyra-proof+cbor`) to
transmit zero-knowledge proofs over HTTP. This replaces bespoke JSON proof
payloads with a compact, versioned, forward-compatible wire format.

## Quick Start

### Install the SDK

```bash
npm install @bolyra/sdk
```

### Encode a proof envelope

```typescript
import {
  encodeProofEnvelope,
  PROOF_ENVELOPE_CONTENT_TYPE,
} from '@bolyra/sdk';
import type { ProofEnvelope } from '@bolyra/sdk';

const envelope: ProofEnvelope = {
  version: 1,
  proofSystem: 'groth16',
  circuitId: 'HumanUniqueness',
  publicSignals: [merkleRoot, nullifierHash, nonceBinding],
  proofBytes: proofBuffer, // Uint8Array from snarkjs/rapidsnark
  timestamp: Math.floor(Date.now() / 1000),
};

const cbor = encodeProofEnvelope(envelope);
```

### Send over HTTP

```bash
curl -X POST https://verifier.example.com/verify \
  -H 'Content-Type: application/bolyra-proof+cbor; version=1' \
  --data-binary @proof.cbor
```

Or with `fetch`:

```typescript
const response = await fetch('https://verifier.example.com/verify', {
  method: 'POST',
  headers: {
    'Content-Type': PROOF_ENVELOPE_CONTENT_TYPE,
  },
  body: cbor,
});
```

### Decode on the receiving side

```typescript
import { decodeProofEnvelope } from '@bolyra/sdk';

// In an Express handler:
app.post('/verify', (req, res) => {
  const contentType = req.headers['content-type'];
  if (!contentType?.startsWith('application/bolyra-proof+cbor')) {
    return res.status(415).json({ error: 'Unsupported media type' });
  }

  const envelope = decodeProofEnvelope(new Uint8Array(req.body));
  console.log(envelope.proofSystem);  // 'groth16'
  console.log(envelope.circuitId);    // 'HumanUniqueness'
  console.log(envelope.publicSignals); // [merkleRoot, nullifierHash, ...]

  // Route to appropriate verifier based on proofSystem + circuitId
  // ...
});
```

## Envelope Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | `number` | Schema version (currently `1`) |
| `proofSystem` | `'groth16' \| 'plonk'` | Proving system |
| `circuitId` | `string` | Circuit name (e.g. `"HumanUniqueness"`) |
| `publicSignals` | `Array<number \| bigint>` | Ordered public outputs |
| `proofBytes` | `Uint8Array` | Opaque proof blob |
| `timestamp` | `number` | Unix epoch seconds |
| `metadata?` | `Record<string, unknown>` | Optional extensions |

## Size Limits

| Constraint | Limit |
|------------|-------|
| `circuit_id` | 128 bytes |
| `public_signals` | 64 elements |
| `proof_bytes` | 4096 bytes |
| Total envelope | 8192 bytes |

The SDK enforces these limits at both encode and decode time.

## Migration from JSON

If you previously sent proofs as JSON:

```json
{
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...] },
  "publicSignals": ["42", "1337"]
}
```

Migration steps:

1. **Serialize proof to bytes:** Use `snarkjs.groth16.exportSolidityCallData()`
   or the SDK's internal serializer to get a flat `Uint8Array`.
2. **Wrap in envelope:** Create a `ProofEnvelope` with the appropriate
   `proofSystem` and `circuitId`.
3. **Encode:** Call `encodeProofEnvelope()` to get CBOR bytes.
4. **Update Content-Type:** Change from `application/json` to
   `application/bolyra-proof+cbor`.

Benefits:
- ~40-60% smaller payloads (CBOR vs JSON)
- Binary `proofBytes` (no base64 overhead)
- Version field enables non-breaking evolution
- Forward-compatible: unknown fields are preserved, not rejected

## IANA Registration

The media type `application/bolyra-proof+cbor` is pending IANA registration.
See `spec/proof-envelope-cbor.md` Section 5 for the registration template.

## Specification

- Full spec: [`spec/proof-envelope-cbor.md`](../spec/proof-envelope-cbor.md)
- CDDL schema: [`spec/proof-envelope.cddl`](../spec/proof-envelope.cddl)
- IETF draft: [`spec/draft-bolyra-mutual-zkp-auth-01.md`](../spec/draft-bolyra-mutual-zkp-auth-01.md) Section 6
- Test vectors: [`spec/test-vectors/proof-envelope-vectors.json`](../spec/test-vectors/proof-envelope-vectors.json)
