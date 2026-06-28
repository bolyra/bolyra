# Proof Envelope Integration Guide

The Bolyra proof envelope (`application/bolyra-proof+json`) provides a
standard wire format for transporting ZKP proofs over HTTP. This guide
shows how to produce and consume envelopes in Express, FastAPI, and MCP
tool wrappers.

## Quick Start

### TypeScript (Node.js)

```typescript
import {
  CONTENT_TYPE,
  serializeEnvelope,
  deserializeEnvelope,
  envelopeFromSnarkjsProof,
} from '@bolyra/sdk';

// Wrap a snarkjs proof
const envelope = envelopeFromSnarkjsProof(
  'HumanUniqueness',
  snarkjsProof,
  publicSignals
);

// Serialize for HTTP transport
const body = serializeEnvelope(envelope);

// Parse incoming envelope
const received = deserializeEnvelope(requestBody);
```

### Python

```python
from bolyra.envelope import (
    CONTENT_TYPE,
    ProofEnvelope,
    envelope_from_snarkjs_proof,
)

# Wrap a proof
envelope = envelope_from_snarkjs_proof(
    "HumanUniqueness", snarkjs_proof, public_signals
)

# Serialize
json_str = envelope.to_json()

# Parse incoming
received = ProofEnvelope.from_json(request_body)
```

## Express Middleware

```typescript
import express from 'express';
import { CONTENT_TYPE, deserializeEnvelope } from '@bolyra/sdk';

const app = express();
app.use(express.text({ type: CONTENT_TYPE }));

/**
 * Middleware that validates incoming Bolyra proof envelopes.
 */
function requireBolyraProof(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const ct = req.headers['content-type'];
  if (ct !== CONTENT_TYPE) {
    return res.status(415).json({
      error: `Expected Content-Type: ${CONTENT_TYPE}`,
    });
  }

  try {
    req.body = deserializeEnvelope(req.body as string);
    next();
  } catch (err: any) {
    return res.status(400).json({ error: err.message });
  }
}

app.post('/verify', requireBolyraProof, (req, res) => {
  const envelope = req.body; // validated ProofEnvelope
  // ... verify the proof ...
  res.json({ verified: true });
});
```

## FastAPI Dependency

```python
from fastapi import Depends, Header, HTTPException, Request
from bolyra.envelope import CONTENT_TYPE, ProofEnvelope


async def require_bolyra_proof(
    request: Request,
    content_type: str = Header(...),
) -> ProofEnvelope:
    """FastAPI dependency that validates incoming Bolyra proof envelopes."""
    if content_type != CONTENT_TYPE:
        raise HTTPException(
            status_code=415,
            detail=f"Expected Content-Type: {CONTENT_TYPE}",
        )
    body = await request.body()
    try:
        return ProofEnvelope.from_json(body.decode())
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/verify")
async def verify(envelope: ProofEnvelope = Depends(require_bolyra_proof)):
    # ... verify the proof ...
    return {"verified": True}
```

## MCP Tool Wrapper

```typescript
import { CONTENT_TYPE, deserializeEnvelope } from '@bolyra/sdk';

// Inside an MCP tool handler
async function handleVerifyProof(args: { envelope: string }) {
  const proof = deserializeEnvelope(args.envelope);
  // Verify proof against on-chain registry...
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ verified: true, circuit: proof.circuit }),
    }],
  };
}
```

## Schema Reference

See [`spec/draft-bolyra-mutual-zkp-auth-01.md`](../spec/draft-bolyra-mutual-zkp-auth-01.md)
§6 Wire Format for the normative schema definition.

| Field | Type | Description |
|-------|------|-------------|
| `version` | `string` | Schema version (`"1.0"`) |
| `circuit` | `string` | `"HumanUniqueness"`, `"AgentPolicy"`, or `"Delegation"` |
| `publicSignals` | `string[]` | Public signal values as decimal strings |
| `proof.pi_a` | `string[]` | G1 point |
| `proof.pi_b` | `string[][]` | G2 point |
| `proof.pi_c` | `string[]` | G1 point |
| `proof.protocol` | `string` | `"groth16"` or `"plonk"` |
| `metadata.prover` | `string` | SDK identifier |
| `metadata.timestamp` | `string` | ISO 8601 timestamp |
