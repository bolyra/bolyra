# IANA Media Type Registration: application/bolyra-proof+json

Per RFC 6838, Section 4.

## Registration Template

**Type name:** application

**Subtype name:** bolyra-proof+json

**Required parameters:** None

**Optional parameters:**

- `v` — envelope version as a decimal integer (e.g., `v=1`).  When
  present, the receiver MAY use this hint for fast rejection before
  parsing the JSON body.  The authoritative version is the `"version"`
  field inside the JSON object.

**Encoding considerations:** UTF-8.  The payload is a single JSON object
per RFC 8259 conforming to the ABNF grammar defined in the Bolyra Proof
Envelope specification.

**Security considerations:**

Same considerations as `application/bolyra-proof+cbor`.  The content
type wraps a zero-knowledge proof and public signals in a JSON envelope.
The envelope provides no cryptographic integrity; integrity relies on
proof soundness and transport-layer security.

Receivers MUST validate the JSON structure before processing proof data.
Maliciously crafted JSON (e.g., deeply nested objects, very large string
values) can cause denial-of-service.  Implementations SHOULD enforce
maximum payload size limits (recommended: 2 MiB) and maximum nesting
depth.

The `circuit` and `provingSystem` string labels select which
verification key the receiver applies.  Transport integrity (TLS)
prevents manipulation.

**Interoperability considerations:** The JSON schema and ABNF grammar
are defined in the Bolyra Proof Envelope specification
(spec/proof-envelope-content-type.md §4).  All implementations MUST
accept the canonical label spellings defined in the CircuitId and
ProvingSystem enum tables.

**Published specification:**
https://github.com/bolyra/bolyra/blob/main/spec/proof-envelope-content-type.md

**Applications which use this media type:** Bolyra SDK (@bolyra/sdk),
browser-based proof verifiers, debugging tools.

**Fragment identifier considerations:** Per RFC 6901 (JSON Pointer)

**Restrictions on usage:** None

**Additional information:**

- Deprecated alias names: None
- Magic number(s): None
- File extension(s): `.bproof.json`
- Macintosh file type code: None

**Person & email address to contact for further information:**
ZKProva Inc., hello@bolyra.ai

**Intended usage:** COMMON

**Author/Change controller:** ZKProva Inc.
