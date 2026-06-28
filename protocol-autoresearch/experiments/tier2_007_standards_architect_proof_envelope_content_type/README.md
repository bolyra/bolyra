# Experiment: Define application/bolyra-proof+cbor content type and envelope format

**ID:** `standards_architect_proof_envelope_content_type`
**Dimension:** standards
**Priority:** high

## Problem

The Bolyra protocol lacks a standardized wire format for proof exchange. Proofs are currently sent as ad-hoc JSON payloads with no content type, making it impossible for HTTP middleware to route, validate, or inspect proofs without parsing internals.

## Solution

Define an IANA-registrable media type (`application/bolyra-proof+cbor`) with:

- **CDDL schema** defining the CBOR envelope structure
- **ABNF grammar** for HTTP content negotiation parameters
- **IETF-style draft** following RFC 6838 registration template
- **Reference encoder/decoder** in the TypeScript SDK
- **Conformance test vectors** for all circuit/proving-system combinations

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/bolyra-proof-content-type.cddl` | spec | CDDL schema for the proof envelope |
| `spec/bolyra-proof-http-negotiation.abnf` | spec | ABNF for Content-Type/Accept negotiation |
| `spec/draft-bolyra-proof-envelope-00.md` | spec | IETF-style media type registration draft |
| `sdk/src/envelope.ts` | sdk | Reference CBOR encoder/decoder |
| `sdk/src/envelope.test.ts` | test | Unit tests (round-trip, validation, rejection) |
| `spec/conformance/envelope-vectors.json` | test | Canonical test vectors |
| `docs/wire-format.md` | docs | Developer guide with curl/middleware examples |

## Envelope Structure

```
{
  version:        1,
  circuitId:      "AgentPolicy",
  provingSystem:  "groth16",
  proof:          <bytes>,           // JSON-encoded proof as UTF-8
  publicSignals:  ["123...", ...],   // decimal strings
  metadata?: {
    nonce:      <32 bytes>,
    timestamp:  1750000000,
    chainId:    84532
  }
}
```

## Usage

```typescript
import { encodeProofEnvelope, decodeProofEnvelope } from "@bolyra/sdk/envelope";

// Encode
const cbor = encodeProofEnvelope({ proof, publicSignals }, "AgentPolicy", "groth16");

// Decode (validates version, circuit, arity)
const envelope = decodeProofEnvelope(cbor);
```

## Running Tests

```bash
cd sdk && npx vitest run src/envelope.test.ts
```

## Circuit Signal Arity

| Circuit | Signals | Names |
|---------|---------|-------|
| HumanUniqueness | 3 | humanMerkleRoot, nullifierHash, nonceBinding |
| AgentPolicy | 4 | credCommitment, permissionHash, expiryBlock, nonceBinding |
| Delegation | 5 | delegatorCommitment, delegateeCommitment, scopeCommitment, permissionMask, nonceBinding |

## Dependencies

- `cbor-x` — CBOR encoder/decoder (transitive via snarkjs)
- RFC 6838 — media type registration procedures
- RFC 8949 — CBOR specification
- RFC 8610 — CDDL specification
