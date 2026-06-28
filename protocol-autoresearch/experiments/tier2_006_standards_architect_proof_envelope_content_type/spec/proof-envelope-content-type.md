# Bolyra Proof Envelope Content Type Specification

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-06-20  
**Authors:** ZKProva Inc.  

## 1. Motivation

The Bolyra SDK currently serializes ZKP proofs as ad-hoc JSON objects with no
version field, circuit discriminator, or proving-system tag.  Consumers must
infer the proof layout from context, which is fragile and blocks
content-type-based routing in HTTP middleware and MCP transports.

This specification defines two media types:

| Media Type | Encoding | Primary Use |
|---|---|---|
| `application/bolyra-proof+cbor` | CBOR (RFC 8949) | Wire-efficient binary transport |
| `application/bolyra-proof+json` | JSON (RFC 8259) | Human-readable fallback, debugging |

Both carry the same logical envelope: a versioned wrapper around the proof
object, public signals array, circuit identifier, and proving-system tag.

## 2. Wire Format — CBOR Variant

### 2.1 Byte Layout

```
+--------+--------+-------------------------------+
| Byte 0 | Byte 1 | Bytes 2 .. N                  |
+--------+--------+-------------------------------+
| Version prefix   | CBOR-encoded map (§2.2)       |
| (big-endian u16) |                               |
+--------+--------+-------------------------------+
```

The 2-byte version prefix is **not** part of the CBOR payload.  It allows
receivers to reject incompatible versions before attempting CBOR decoding.

Current version: `0x0001`.

### 2.2 CBOR Map Keys

| Key | CBOR Major Type | Required | Description |
|---|---|---|---|
| `version` | unsigned int | ✓ | Must equal the prefix version |
| `circuit` | unsigned int | ✓ | CircuitId enum (§3) |
| `provingSystem` | unsigned int | ✓ | ProvingSystem enum (§3) |
| `proof` | map | ✓ | Proof object (snarkjs output format) |
| `publicSignals` | array of text | ✓ | Decimal-encoded field elements |
| `metadata` | map | ✗ | Optional string-keyed metadata |

### 2.3 Encoding Rules

- All CBOR encoding MUST use Deterministic Encoding per RFC 8949 §4.2.
- The `proof` map preserves snarkjs key names (`pi_a`, `pi_b`, `pi_c` for
  Groth16; `A`, `B`, `C`, `Z` for PLONK).
- `publicSignals` entries are text strings containing decimal integers
  (not CBOR bignums), matching snarkjs output conventions.

## 3. Enum Tables

### 3.1 CircuitId

| Value | Label | Circuit | Notes |
|---|---|---|---|
| 0 | `human` | HumanUniqueness | Semaphore v4 enrollment |
| 1 | `agent` | AgentPolicy | EdDSA credential + cumulative-bit perms |
| 2 | `delegation` | Delegation | One-way scope narrowing |
| 3 | `model-instance` | ModelInstance | Reserved (future) |

Values 4–255 are reserved.  New values MUST be appended; retired values
MUST NOT be reused.

### 3.2 ProvingSystem

| Value | Label | Notes |
|---|---|---|
| 0 | `groth16` | Requires per-circuit trusted setup |
| 1 | `plonk` | Universal SRS, no per-circuit ceremony |

Values 2–255 are reserved.

## 4. JSON Fallback Format

The `application/bolyra-proof+json` encoding uses human-readable string
labels instead of integer enums.

### 4.1 ABNF Grammar (RFC 5234)

```abnf
proof-envelope  = "{" version-member ","
                      circuit-member ","
                      proving-system-member ","
                      proof-member ","
                      public-signals-member
                      [ "," metadata-member ]
                  "}"

version-member          = %s"\"version\"" ":" version-value
version-value           = DQUOTE "0x" 4HEXDIG DQUOTE

circuit-member          = %s"\"circuit\"" ":" circuit-label
circuit-label           = DQUOTE ( "human" / "agent" / "delegation"
                                  / "model-instance" ) DQUOTE

proving-system-member   = %s"\"provingSystem\"" ":" proving-system-label
proving-system-label    = DQUOTE ( "groth16" / "plonk" ) DQUOTE

proof-member            = %s"\"proof\"" ":" json-object
public-signals-member   = %s"\"publicSignals\"" ":" json-array
metadata-member         = %s"\"metadata\"" ":" json-object

json-object             = <any valid JSON object per RFC 8259>
json-array              = <any valid JSON array per RFC 8259>
```

### 4.2 Example

```json
{
  "version": "0x0001",
  "circuit": "human",
  "provingSystem": "groth16",
  "proof": {
    "pi_a": ["1", "2", "1"],
    "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]],
    "pi_c": ["7", "8", "1"],
    "protocol": "groth16",
    "curve": "bn128"
  },
  "publicSignals": [
    "12345678901234567890",
    "98765432109876543210"
  ]
}
```

## 5. Content Negotiation

HTTP endpoints that accept or return Bolyra proofs SHOULD support both
media types via standard `Accept` / `Content-Type` negotiation:

1. If the client sends `Accept: application/bolyra-proof+cbor`, respond
   with the CBOR variant.
2. If the client sends `Accept: application/bolyra-proof+json`, respond
   with the JSON variant.
3. If the client sends `Accept: */*` or omits the header, default to CBOR.
4. If the client sends an unrecognized Accept type, respond `406 Not
   Acceptable`.

## 6. Versioning Policy

- The version prefix is incremented for **breaking** changes to the CBOR
  map schema (new required keys, changed key semantics, enum reordering).
- **Non-breaking** additions (new optional keys, new enum values at the
  end of the table) do NOT increment the version.
- Receivers MUST reject envelopes with an unrecognized version prefix
  before attempting to decode the CBOR body.

## 7. Security Considerations

- The envelope does NOT add cryptographic integrity.  Integrity is
  provided by the ZKP proof itself (soundness) and by the transport
  layer (TLS).  The envelope is a framing format, not a security
  boundary.
- Circuit-specific proof soundness guarantees depend on the trusted
  setup (Groth16) or universal SRS (PLONK).  The `provingSystem` tag
  lets verifiers select the correct verification key.
- Malicious CBOR payloads can attempt denial-of-service via deeply
  nested structures.  Decoders SHOULD enforce a maximum nesting depth
  and payload size.
