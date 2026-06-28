# Wire Format: application/bolyra-proof+cbor

This guide covers the Bolyra proof envelope wire format — how to encode, decode,
and exchange ZKP proofs over HTTP using the standardized `application/bolyra-proof+cbor`
content type.

## Overview

All Bolyra proof payloads are wrapped in a CBOR envelope containing:

| Field            | Type       | Description                                  |
|------------------|-----------|----------------------------------------------|
| `version`        | uint      | Envelope version (currently `1`)             |
| `circuitId`      | string    | `HumanUniqueness`, `AgentPolicy`, or `Delegation` |
| `provingSystem`  | string    | `groth16` or `plonk`                         |
| `proof`          | bytes     | JSON-encoded proof object as UTF-8 bytes     |
| `publicSignals`  | string[]  | Public signals as decimal strings            |
| `metadata`       | map?      | Optional: nonce, timestamp, chainId          |

## SDK Usage

### Encoding a proof

```typescript
import {
  encodeProofEnvelope,
  buildContentType,
} from "@bolyra/sdk/envelope";

// After generating a proof with snarkjs
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);

// Wrap in envelope
const envelope = encodeProofEnvelope(
  { proof, publicSignals },
  "AgentPolicy",
  "groth16",
  { timestamp: Math.floor(Date.now() / 1000), chainId: 84532 }
);

// Set Content-Type header
const contentType = buildContentType("AgentPolicy", "groth16");
// => "application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16; v=1"
```

### Decoding an envelope

```typescript
import {
  decodeProofEnvelope,
  envelopeToProofResult,
} from "@bolyra/sdk/envelope";

// Receive CBOR bytes from HTTP body
const envelope = decodeProofEnvelope(responseBody);

console.log(envelope.circuitId);      // "AgentPolicy"
console.log(envelope.provingSystem);  // "groth16"
console.log(envelope.publicSignals);  // ["123...", "456...", ...]

// Extract snarkjs-compatible ProofResult for verification
const { proof, publicSignals } = envelopeToProofResult(envelope);
const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
```

## HTTP Integration

### Setting headers

Servers returning proof envelopes:

```
Content-Type: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16; v=1
```

Clients requesting proofs:

```
Accept: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16,
        application/bolyra-proof+cbor; ps=plonk; q=0.8,
        application/json; q=0.5
```

### curl examples

Send a proof envelope:

```bash
curl -X POST https://api.example.com/verify \
  -H "Content-Type: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16; v=1" \
  --data-binary @proof.cbor
```

Request a specific proof format:

```bash
curl https://api.example.com/prove/agent-policy \
  -H "Accept: application/bolyra-proof+cbor; ps=groth16" \
  -o proof.cbor
```

### Express middleware

```typescript
import { decodeProofEnvelope, BOLYRA_PROOF_CONTENT_TYPE } from "@bolyra/sdk/envelope";

function bolyraProofParser(req, res, next) {
  const ct = req.headers["content-type"] || "";
  if (!ct.startsWith(BOLYRA_PROOF_CONTENT_TYPE)) {
    return next();
  }

  const chunks: Buffer[] = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    try {
      const buf = new Uint8Array(Buffer.concat(chunks));
      req.proofEnvelope = decodeProofEnvelope(buf);
      next();
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });
}

app.post("/verify", bolyraProofParser, async (req, res) => {
  const { circuitId, provingSystem } = req.proofEnvelope;
  // Route to appropriate verifier...
});
```

## Migration from Raw Proof Bytes

If you currently exchange proofs as raw JSON:

```json
{ "proof": { "pi_a": [...], ... }, "publicSignals": [...] }
```

Migrate in three steps:

1. **Add envelope encoding** on the sender side using `encodeProofEnvelope()`
2. **Update Content-Type** from `application/json` to `application/bolyra-proof+cbor`
3. **Add envelope decoding** on the receiver side using `decodeProofEnvelope()`

During migration, servers can support both formats by checking the Content-Type
header and dispatching accordingly.

## Conformance Testing

Test vectors are available in `spec/conformance/envelope-vectors.json`. Each
vector specifies the input ProofResult, expected envelope fields, and rejection
cases. Run the conformance suite:

```bash
npm run test:circuits:fast  # includes envelope round-trip tests
```

## Specification References

- CDDL Schema: `spec/bolyra-proof-content-type.cddl`
- ABNF Grammar: `spec/bolyra-proof-http-negotiation.abnf`
- IETF Draft: `spec/draft-bolyra-proof-envelope-00.md`
- RFC 8949 (CBOR)
- RFC 8610 (CDDL)
- RFC 6838 (Media Type Registration)
