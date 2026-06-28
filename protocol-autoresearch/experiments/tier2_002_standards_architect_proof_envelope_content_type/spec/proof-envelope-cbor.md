# Bolyra Proof Envelope — `application/bolyra-proof+cbor`

**Status:** Draft  
**Version:** 1  
**Date:** 2026-06-19  
**Normative References:** RFC 8949 (CBOR), RFC 8610 (CDDL), RFC 6838 (Media Type Registration)  

## 1. Introduction

This document defines the canonical wire format for transmitting zero-knowledge
proofs between Bolyra protocol participants. The format uses CBOR (Concise
Binary Object Representation, RFC 8949) as the serialization layer and is
identified by the media type `application/bolyra-proof+cbor`.

The envelope is agnostic to the underlying proving system; it carries opaque
proof bytes alongside machine-readable metadata that allows any conforming
implementation to route, validate, and log proofs without parsing system-specific
internal structures.

## 2. Content-Type ABNF

The HTTP `Content-Type` header value for a Bolyra proof envelope follows this
ABNF grammar (RFC 5234):

```abnf
bolyra-proof-type = "application/bolyra-proof+cbor"
                    *( ";" SP parameter )
parameter         = "version" "=" 1*DIGIT
```

Example:

```
Content-Type: application/bolyra-proof+cbor; version=1
```

The `version` parameter is OPTIONAL. When absent, recipients MUST assume
version 1. When present, it MUST match the `version` field inside the CBOR
envelope body. A mismatch is a decoding error.

## 3. Envelope Structure

The envelope is a single CBOR map (major type 5) with the following fields:

| Key             | CBOR Type         | Required | Description |
|-----------------|-------------------|----------|-------------|
| `version`       | uint (major 0)    | Yes      | Envelope schema version. Currently `1`. |
| `proof_system`  | tstr (major 3)    | Yes      | Proving system identifier: `"groth16"` or `"plonk"`. |
| `circuit_id`    | tstr (major 3)    | Yes      | Circuit build artifact name, e.g. `"HumanUniqueness"`, `"AgentPolicy"`, `"Delegation"`. UTF-8 encoded. |
| `public_signals` | array (major 4)  | Yes      | Ordered array of public signals. Each element is a uint (major 0) or bstr (major 2) for field elements exceeding 2^64. |
| `proof_bytes`   | bstr (major 2)    | Yes      | Opaque proof blob. Internal structure is proving-system-specific. |
| `timestamp`     | uint (major 0)    | Yes      | Unix epoch seconds (UTC) at which the proof was generated. |
| `metadata`      | map (major 5)     | No       | Optional key-value map for implementation-specific extensions. |

### 3.1 Field Semantics

**`version`** — MUST be `1` for this specification. Decoders encountering a
higher version MUST reject the envelope unless they explicitly support that
version.

**`proof_system`** — Case-sensitive string. Allowed values:
- `"groth16"` — Groth16 proving system (requires trusted setup)
- `"plonk"` — PLONK proving system (universal SRS)

Future specifications MAY add values (e.g., `"fflonk"`, `"nova"`).

**`circuit_id`** — MUST match the filename stem of the compiled circuit
artifact (e.g., `HumanUniqueness.r1cs` → `"HumanUniqueness"`). The string
MUST be valid UTF-8, MUST NOT be empty, and SHOULD be at most 128 bytes.

**`public_signals`** — Ordered array matching the circuit's public output
order. Elements are unsigned integers when they fit in a CBOR uint (≤ 2^64 - 1)
or byte strings encoding big-endian unsigned integers for larger field elements
(e.g., BN254 scalar field elements up to ~254 bits).

**`proof_bytes`** — Opaque binary blob. For Groth16 (BN254), this is typically
256 bytes (π_A, π_B, π_C as compressed points). For PLONK, the size varies by
implementation. Decoders MUST NOT interpret the internal structure. Maximum
length: 4096 bytes. Envelopes with `proof_bytes` exceeding this limit MUST be
rejected.

**`timestamp`** — Informational. Not used for cryptographic binding. Receivers
MAY use it for replay-window checks but MUST NOT rely on it for security.

**`metadata`** — Forward-compatibility extension point. Decoders MUST tolerate
unknown keys in this map (and at the top level) without error. This enables
future envelope versions to add fields without breaking existing parsers.

### 3.2 CBOR Encoding Rules

- The envelope MUST be encoded as a single CBOR data item (no streaming).
- Map keys MUST be text strings (major type 3), not integers.
- Canonical CBOR (RFC 8949 §4.2.1 — deterministic encoding) is RECOMMENDED
  for interoperability but not required. Decoders MUST accept both canonical
  and non-canonical encodings.
- No CBOR tags are used in version 1. Future versions MAY assign a tag.

### 3.3 Size Limits

| Field            | Max Size  |
|------------------|-----------|
| `circuit_id`     | 128 bytes |
| `public_signals` | 64 elements |
| `proof_bytes`    | 4096 bytes |
| Total envelope   | 8192 bytes |

Implementations SHOULD reject envelopes exceeding these limits to prevent
resource exhaustion.

## 4. Versioning

The `version` field enables non-breaking evolution:

- **Version 1** (this document): baseline fields as defined above.
- **Forward compatibility:** decoders MUST ignore unknown map keys. Producers
  SHOULD NOT add keys outside `metadata` in version 1 envelopes.
- **Breaking changes** (new required fields, changed semantics) MUST increment
  `version` and update this specification.

## 5. IANA Considerations

### 5.1 Media Type Registration

```
Type name:               application
Subtype name:            bolyra-proof+cbor
Required parameters:     None
Optional parameters:     version (uint, default 1)
Encoding considerations: binary (CBOR, RFC 8949)
Security considerations: See Section 6
Interoperability:        See Section 3.2
Published specification: This document
Applications that use:   Bolyra ZKP identity protocol
Fragment identifier:     N/A
Person & email:          Viswa Vijayakumar <viswa@zkprova.com>
Intended usage:          COMMON
Restrictions on usage:   None
Author:                  ZKProva Inc.
Change controller:       ZKProva Inc.
```

## 6. Security Considerations

- **proof_bytes length:** Unbounded proof blobs enable memory exhaustion.
  The 4096-byte limit (Section 3.3) mitigates this. Implementations MUST
  enforce this limit before allocating buffers.
- **Replay protection:** The envelope itself provides no replay protection.
  Consumers MUST bind proofs to a session nonce at a higher protocol layer
  (see draft-bolyra-mutual-zkp-auth Section 4).
- **Timestamp trust:** The `timestamp` field is self-reported and unsigned.
  It MUST NOT be used as a sole freshness guarantee.
- **Forward compatibility abuse:** Malicious producers could stuff large
  values into `metadata` or unknown keys. The total envelope size limit
  (8192 bytes) bounds this attack surface.

## 7. References

- RFC 8949 — Concise Binary Object Representation (CBOR)
- RFC 8610 — Concise Data Definition Language (CDDL)
- RFC 6838 — Media Type Specifications and Registration Procedures
- RFC 5234 — Augmented BNF for Syntax Specifications (ABNF)
- draft-bolyra-mutual-zkp-auth-01 — Mutual ZKP Authentication for Humans and AI Agents
