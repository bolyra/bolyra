# IANA Media Type Registration: application/bolyra-proof+cbor

Per RFC 6838, Section 4.

## Registration Template

**Type name:** application

**Subtype name:** bolyra-proof+cbor

**Required parameters:** None

**Optional parameters:**

- `v` — envelope version as a decimal integer (e.g., `v=1`).  When
  present, the receiver MAY use this hint for fast rejection before
  parsing the binary prefix.  The authoritative version is the 2-byte
  big-endian prefix in the payload body.

**Encoding considerations:** Binary.  The payload consists of a 2-byte
big-endian version prefix followed by a CBOR-encoded map per RFC 8949.
The CBOR portion uses Deterministic Encoding (RFC 8949 §4.2).

**Security considerations:**

The content type wraps a zero-knowledge proof and public signals.  The
envelope itself provides no cryptographic integrity; integrity relies on
the soundness property of the proving system (Groth16 or PLONK) and
transport-layer security (e.g., TLS).

Receivers MUST validate the CBOR structure before processing proof data.
Maliciously crafted CBOR (e.g., excessively nested maps, very large byte
strings) can cause denial-of-service.  Implementations SHOULD enforce
maximum payload size limits (recommended: 1 MiB) and maximum CBOR
nesting depth (recommended: 8).

The `circuit` and `provingSystem` enum values select which verification
key the receiver applies.  An attacker who can manipulate these fields
without detection could cause the receiver to apply the wrong verifier.
Transport integrity (TLS) mitigates this.

**Interoperability considerations:** The CBOR map schema is defined in
the Bolyra Proof Envelope specification
(spec/proof-envelope-content-type.md).  All implementations MUST use
Deterministic Encoding for CBOR to ensure byte-identical representations.

**Published specification:**
https://github.com/bolyra/bolyra/blob/main/spec/proof-envelope-content-type.md

**Applications which use this media type:** Bolyra SDK (@bolyra/sdk),
Bolyra MCP server, HTTP-based ZKP verification endpoints.

**Fragment identifier considerations:** N/A

**Restrictions on usage:** None

**Additional information:**

- Deprecated alias names: None
- Magic number(s): First two bytes are 0x00 0x01 (version 1)
- File extension(s): `.bproof`
- Macintosh file type code: None

**Person & email address to contact for further information:**
ZKProva Inc., hello@bolyra.ai

**Intended usage:** COMMON

**Author/Change controller:** ZKProva Inc.
