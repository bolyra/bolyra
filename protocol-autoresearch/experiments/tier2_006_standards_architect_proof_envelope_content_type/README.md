# Experiment: Standardized Proof Envelope with IANA Content Type

**ID:** `standards_architect_proof_envelope_content_type`  
**Dimension:** Standards  
**Priority:** High  

## Summary

Defines `application/bolyra-proof+cbor` and `application/bolyra-proof+json`
media types with a self-describing envelope that wraps ZKP proofs.  Replaces
the current ad-hoc JSON serialization with a versioned, typed format.

## Artifacts

| File | Type | Description |
|---|---|---|
| `sdk/src/types/envelope.ts` | Types | `ProofEnvelope`, `CircuitId`, `ProvingSystem` enums |
| `sdk/src/envelope.ts` | SDK | CBOR + JSON codec with validation |
| `sdk/test/envelope.test.ts` | Test | Round-trip, validation, and negotiation tests |
| `spec/proof-envelope-content-type.md` | Spec | Normative wire format specification |
| `spec/iana-registration-bolyra-proof-cbor.md` | Spec | IANA registration for +cbor |
| `spec/iana-registration-bolyra-proof-json.md` | Spec | IANA registration for +json |
| `docs/proof-envelope-migration.md` | Docs | Migration guide for SDK consumers |

## Key Design Decisions

1. **2-byte version prefix** before CBOR body — enables fast rejection
   without CBOR parsing.
2. **Integer enums on the wire** (CBOR), **string labels in JSON** —
   compact binary, readable text fallback.
3. **CBOR via `cborg`** — small, fast, pure-JS CBOR encoder already
   compatible with the snarkjs ecosystem.
4. **Content negotiation helper** — `negotiateProofContentType()` for
   HTTP middleware integration.

## Usage

```typescript
import {
  encodeProofEnvelope,
  decodeProofEnvelope,
  CircuitId,
  ProvingSystem,
  CONTENT_TYPE_CBOR,
} from '@bolyra/sdk';

// Encode
const bytes = encodeProofEnvelope({
  version: 0x0001,
  circuit: CircuitId.Human,
  provingSystem: ProvingSystem.Groth16,
  proof: snarkjsProof,
  publicSignals: snarkjsPublicSignals,
});

// Decode
const envelope = decodeProofEnvelope(bytes);
console.log(envelope.circuit);       // 0 (CircuitId.Human)
console.log(envelope.provingSystem); // 0 (ProvingSystem.Groth16)
```

## Running Tests

```bash
cd sdk && npx mocha test/envelope.test.ts --require ts-node/register
```

## Dependencies

- `cborg` — CBOR encoding/decoding
- `mocha` + `chai` — test framework (existing SDK test infrastructure)

## References

- [RFC 6838 — Media Type Registration](https://www.rfc-editor.org/rfc/rfc6838)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 5234 — ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [Bolyra Mutual ZKP Auth Draft](../spec/draft-bolyra-mutual-zkp-auth-01.md)
