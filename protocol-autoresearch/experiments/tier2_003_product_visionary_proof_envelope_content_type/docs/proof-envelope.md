# Proof Envelope Developer Guide

## Overview

The **Proof Envelope** is the canonical wire format for transmitting Bolyra ZKP proofs between services. It uses CBOR ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)) encoding with the media type `application/bolyra-proof+cbor`.

Every verifier receives a single self-describing payload containing everything it needs: proof bytes, public signals, circuit identifier, proving system, and an optional delegation chain.

## Wire Format

```
┌──────────────────────────────────────────────────────┐
│                  CBOR Map (int keys)                 │
├──────┬───────────────┬───────────────────────────────┤
│ Key  │ Field         │ Type                          │
├──────┼───────────────┼───────────────────────────────┤
│  1   │ version       │ uint (currently 1)            │
│  2   │ circuitId     │ tstr                          │
│  3   │ provingSystem │ tstr ("groth16" | "plonk")    │
│  4   │ proofBytes    │ bstr                          │
│  5   │ publicSignals │ [+ tstr]                      │
│  6   │ delegationChain│ [* bstr] (optional)          │
└──────┴───────────────┴───────────────────────────────┘
```

Integer keys keep the envelope compact. Unknown keys are ignored for forward compatibility.

## Field Reference

| Key | Field | Required | Description |
|-----|-------|----------|-------------|
| 1 | `version` | Yes | Schema version. Currently `1`. |
| 2 | `circuitId` | Yes | One of `HumanUniqueness`, `AgentPolicy`, `Delegation`. |
| 3 | `provingSystem` | Yes | `groth16` or `plonk`. |
| 4 | `proofBytes` | Yes | Serialized proof (binary). |
| 5 | `publicSignals` | Yes | Array of decimal-string signals. |
| 6 | `delegationChain` | No | Array of credential blobs, root-first. Max depth: 8. |

## TypeScript SDK

```typescript
import { encode, decode, buildContentType } from "@bolyra/sdk/proof-envelope";

// Encode
const envelope = {
  version: 1,
  circuitId: "HumanUniqueness" as const,
  provingSystem: "groth16" as const,
  proofBytes: myProofBytes,
  publicSignals: ["123", "456", "789"],
};
const cbor = encode(envelope);

// Decode
const restored = decode(cbor);
console.log(restored.circuitId); // "HumanUniqueness"

// Content-Type header
const ct = buildContentType("HumanUniqueness", "groth16");
// "application/bolyra-proof+cbor; circuit=HumanUniqueness; ps=groth16; v=1"
```

## Python SDK

```python
from bolyra import ProofEnvelope, encode, decode, build_content_type

# Encode
envelope = ProofEnvelope(
    version=1,
    circuit_id="HumanUniqueness",
    proving_system="groth16",
    proof_bytes=my_proof_bytes,
    public_signals=["123", "456", "789"],
)
cbor_data = encode(envelope)

# Decode
restored = decode(cbor_data)
print(restored.circuit_id)  # "HumanUniqueness"

# Content-Type header
ct = build_content_type("HumanUniqueness", "groth16")
```

## Content-Type Negotiation

When transmitting proofs over HTTP:

```http
POST /verify HTTP/1.1
Content-Type: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16; v=1
Accept: application/json

<CBOR envelope bytes>
```

The `circuit`, `ps`, and `v` parameters are informational hints. The values inside the CBOR envelope are authoritative if there is a mismatch.

## Migration Guide

### From ad-hoc JSON serialization

If your integration currently sends proofs as JSON:

```diff
- const body = JSON.stringify({ proof, publicSignals, circuit: "AgentPolicy" });
- const headers = { "Content-Type": "application/json" };
+ import { encode, buildContentType } from "@bolyra/sdk/proof-envelope";
+ const body = encode({
+   version: 1,
+   circuitId: "AgentPolicy",
+   provingSystem: "groth16",
+   proofBytes: serializeProof(proof),
+   publicSignals: publicSignals.map(String),
+ });
+ const headers = { "Content-Type": buildContentType("AgentPolicy", "groth16") };
```

### MCP Integration

The MCP integration at `integrations/mcp/` attaches `Content-Type: application/bolyra-proof+cbor` when transmitting envelopes. Update your MCP tool handlers to decode the envelope:

```typescript
import { decode } from "@bolyra/sdk/proof-envelope";

// In your MCP tool handler
const envelope = decode(new Uint8Array(request.body));
const { circuitId, provingSystem, proofBytes, publicSignals } = envelope;
```

## Size Efficiency

CBOR with integer keys is significantly more compact than JSON for binary proof data:

| Format | 256-byte proof, 3 signals |
|--------|---------------------------|
| JSON (base64 proof) | ~550 bytes |
| JSON (array proof) | ~900 bytes |
| CBOR envelope | ~310 bytes |

The envelope adds modest overhead (~50-60 bytes) for the metadata fields.
