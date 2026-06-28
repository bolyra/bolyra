# Proof Envelope Migration Guide

## Overview

The Bolyra SDK now supports a versioned **proof envelope** format that
replaces ad-hoc JSON proof objects with a self-describing, typed wrapper.
This guide helps SDK consumers migrate to the envelope API.

## Why Migrate?

| Before (ad-hoc JSON) | After (proof envelope) |
|---|---|
| No version field — breaking changes are silent | 2-byte version prefix enables graceful rejection |
| No circuit discriminator — consumers must guess | `CircuitId` enum identifies the circuit |
| No proving-system tag — Groth16 vs PLONK is implicit | `ProvingSystem` enum is explicit |
| No standard content type for HTTP | `application/bolyra-proof+cbor` and `+json` |

## Before / After

### Before: raw proof JSON

```typescript
import { proveHandshake } from '@bolyra/sdk';

const { humanProof, agentProof } = await proveHandshake(human, agent);

// Send as ad-hoc JSON — no version, no circuit tag
const response = await fetch('/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ humanProof, agentProof }),
});
```

### After: envelope API

```typescript
import {
  encodeProofEnvelope,
  CircuitId,
  ProvingSystem,
  CONTENT_TYPE_CBOR,
} from '@bolyra/sdk';

const envelope = encodeProofEnvelope({
  version: 0x0001,
  circuit: CircuitId.Human,
  provingSystem: ProvingSystem.Groth16,
  proof: humanProof.proof,
  publicSignals: humanProof.publicSignals,
});

const response = await fetch('/verify', {
  method: 'POST',
  headers: { 'Content-Type': CONTENT_TYPE_CBOR },
  body: envelope,
});
```

### Server-side decoding

```typescript
import {
  decodeProofEnvelope,
  CONTENT_TYPE_CBOR,
  CONTENT_TYPE_JSON,
  proofEnvelopeFromJSON,
} from '@bolyra/sdk';

app.post('/verify', async (req, res) => {
  const ct = req.headers['content-type'];
  let envelope;

  if (ct === CONTENT_TYPE_CBOR) {
    const bytes = new Uint8Array(await req.arrayBuffer());
    envelope = decodeProofEnvelope(bytes);
  } else if (ct === CONTENT_TYPE_JSON) {
    envelope = proofEnvelopeFromJSON(req.body);
  } else {
    return res.status(415).send('Unsupported Media Type');
  }

  // envelope.circuit tells you which verifier to use
  // envelope.provingSystem tells you Groth16 vs PLONK
});
```

### JSON fallback (debugging / curl)

```typescript
import {
  proofEnvelopeToJSON,
  CONTENT_TYPE_JSON,
  CircuitId,
  ProvingSystem,
} from '@bolyra/sdk';

const json = proofEnvelopeToJSON({
  version: 0x0001,
  circuit: CircuitId.Agent,
  provingSystem: ProvingSystem.PLONK,
  proof: agentProof.proof,
  publicSignals: agentProof.publicSignals,
});

console.log(JSON.stringify(json, null, 2));
// {
//   "version": "0x0001",
//   "circuit": "agent",
//   "provingSystem": "plonk",
//   "proof": { ... },
//   "publicSignals": [ ... ]
// }
```

## Content-Type Headers

| Scenario | Content-Type |
|---|---|
| Binary transport (default) | `application/bolyra-proof+cbor` |
| Human-readable / debugging | `application/bolyra-proof+json` |
| Legacy (deprecated) | `application/json` |

Use the exported constants `CONTENT_TYPE_CBOR` and `CONTENT_TYPE_JSON`
to avoid typos.

## Backward Compatibility Window

| SDK Version | Behavior |
|---|---|
| v0.3.x | Envelope API available alongside raw proof objects |
| v0.4.x | Raw proof serialization emits deprecation warning |
| v0.5.x | Raw proof serialization removed; envelope required |

During the compatibility window, the SDK accepts both formats on
decode.  Servers should check `Content-Type` to decide which decoder
to invoke.

## Content Negotiation

Use `negotiateProofContentType(acceptHeader)` to select the right
format based on the client's `Accept` header:

```typescript
import { negotiateProofContentType } from '@bolyra/sdk';

const ct = negotiateProofContentType(req.headers.accept ?? '*/*');
if (!ct) return res.status(406).send('Not Acceptable');
```
