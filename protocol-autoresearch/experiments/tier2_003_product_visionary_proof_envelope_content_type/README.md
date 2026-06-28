# Experiment: Standard Proof Envelope with IANA-Registerable Content Type

**ID:** `product_visionary_proof_envelope_content_type`  
**Persona:** Product Visionary  
**Dimension:** Adoption  
**Priority:** High  

## Problem

Without a standard wire format, every framework integration (LangChain, CrewAI, MCP) invents its own proof serialization, creating an interop nightmare as the ecosystem grows.

## Solution

Define `application/bolyra-proof+cbor` as the canonical wire format for transmitting proofs. The envelope wraps proof bytes, public signals, circuit identifier, proving system (groth16/plonk), and an optional delegation chain — everything a verifier needs in a single self-describing CBOR payload.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/proof-envelope.cddl` | Spec | CDDL schema for the CBOR envelope |
| `spec/proof-envelope-content-type.md` | Spec | IANA media type registration template (RFC 6838) |
| `sdk/src/proof-envelope.ts` | SDK | TypeScript `encode()`/`decode()` using cbor-x |
| `sdk/src/types.ts` | SDK | Public type exports |
| `sdk-python/bolyra/proof_envelope.py` | SDK | Python `encode()`/`decode()` using cbor2 |
| `sdk-python/bolyra/__init__.py` | SDK | Re-exports |
| `sdk/test/proof-envelope.test.ts` | Test | TS round-trip, validation, size benchmark |
| `sdk-python/tests/test_proof_envelope.py` | Test | Python tests + cross-language interop |
| `docs/proof-envelope.md` | Docs | Developer guide with wire format diagram |

## Key Design Decisions

1. **Integer keys** in CBOR map (not string keys) for compactness
2. **Append-only key allocation** — new fields use keys > 6
3. **Unknown keys silently ignored** for forward compatibility
4. **Delegation chain** as optional `[* bstr]` array, max depth 8
5. **Public signals as strings** (decimal) to avoid precision loss with large field elements
6. **64 KiB envelope limit** to prevent DoS

## Dependencies

- `cbor-x` (npm, MIT) — CBOR for TypeScript
- `cbor2` (PyPI, MIT) — CBOR for Python
- RFC 8949 — CBOR data format
- RFC 6838 — Media type registration

## Usage

### TypeScript

```typescript
import { encode, decode } from "./sdk/src/proof-envelope";

const envelope = encode({
  version: 1,
  circuitId: "HumanUniqueness",
  provingSystem: "groth16",
  proofBytes: new Uint8Array([...]),
  publicSignals: ["123", "456", "789"],
});

const restored = decode(envelope);
```

### Python

```python
from bolyra import ProofEnvelope, encode, decode

envelope = ProofEnvelope(
    version=1,
    circuit_id="HumanUniqueness",
    proving_system="groth16",
    proof_bytes=b"\xde\xad\xbe\xef",
    public_signals=["123", "456", "789"],
)
data = encode(envelope)
restored = decode(data)
```

## Scoring

| Dimension | Score |
|-----------|-------|
| Adoption | 19/25 |
| Standards | 18/25 |
| Completeness | 20/25 |
| Correctness | 14/25 |
| **Total** | **71/100** |
