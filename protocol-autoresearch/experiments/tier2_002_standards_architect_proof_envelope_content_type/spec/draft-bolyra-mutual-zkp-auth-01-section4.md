## 4. Proof Envelope Wire Format

### 4.1. Overview

This section defines the canonical wire format for transmitting zero-knowledge
proofs between Bolyra protocol participants. The envelope provides versioning,
circuit identification, proving system metadata, and content-type negotiation.

Two media types are registered:

- `application/bolyra-proof+json` — JSON [RFC8259] encoding
- `application/bolyra-proof+cbor` — CBOR [RFC8949] encoding

### 4.2. ABNF Grammar

The following ABNF [RFC5234] grammar defines the JSON text representation of
a proof envelope. The CBOR variant uses the same logical structure encoded
per [RFC8949] §3.

```abnf
proof-envelope  = "{" version-field ","
                      circuit-field ","
                      proving-field ","
                      signals-field ","
                      proof-field ","
                      metadata-field "}"

version-field   = %s"version" ":" DQUOTE semver DQUOTE
semver          = 1*DIGIT "." 1*DIGIT "." 1*DIGIT

circuit-field   = %s"circuitId" ":" DQUOTE circuit-uri DQUOTE
circuit-uri     = "bolyra:circuit:" circuit-name
circuit-name    = "HumanUniqueness" / "AgentPolicy" / "Delegation"

proving-field   = %s"provingSystem" ":" DQUOTE proving-system DQUOTE
proving-system  = "groth16" / "plonk"

signals-field   = %s"publicSignals" ":" "[" signal-list "]"
signal-list     = DQUOTE 1*DIGIT DQUOTE *("," DQUOTE 1*DIGIT DQUOTE)

proof-field     = %s"proof" ":" (groth16-proof / plonk-proof)

groth16-proof   = "{" %s"pi_a" ":" g1-point ","
                      %s"pi_b" ":" g2-point ","
                      %s"pi_c" ":" g1-point ","
                      %s"protocol" ":" DQUOTE "groth16" DQUOTE
                      [",%s\"curve\"" ":" DQUOTE "bn128" DQUOTE] "}"

plonk-proof     = "{" %s"A" ":" g1-point ","
                      %s"B" ":" g1-point ","
                      %s"C" ":" g1-point ","
                      %s"Z" ":" g1-point ","
                      %s"T1" ":" g1-point ","
                      %s"T2" ":" g1-point ","
                      %s"T3" ":" g1-point ","
                      %s"Wxi" ":" g1-point ","
                      %s"Wxiw" ":" g1-point ","
                      %s"eval_a" ":" field-element ","
                      %s"eval_b" ":" field-element ","
                      %s"eval_c" ":" field-element ","
                      %s"eval_s1" ":" field-element ","
                      %s"eval_s2" ":" field-element ","
                      %s"eval_zw" ":" field-element
                      [",%s\"eval_r\"" ":" field-element]
                      "," %s"protocol" ":" DQUOTE "plonk" DQUOTE
                      [",%s\"curve\"" ":" DQUOTE "bn128" DQUOTE] "}"

g1-point        = "[" field-element "," field-element "," field-element "]"
g2-point        = "[" g2-coord "," g2-coord "," g2-coord "]"
g2-coord        = "[" field-element "," field-element "]"
field-element   = DQUOTE 1*DIGIT DQUOTE

metadata-field  = %s"metadata" ":" "{" issued-at
                      ["," chain-field] ["," registry-field] "}"
issued-at       = %s"issuedAt" ":" 1*DIGIT
chain-field     = %s"chain" ":" 1*DIGIT
registry-field  = %s"registryAddress" ":" DQUOTE "0x" 40HEXDIG DQUOTE
```

### 4.3. Field Ordering

For JSON encoding, field ordering SHOULD follow the order specified in the
ABNF grammar. Implementations MUST accept any field order on input.

For CBOR encoding, fields MUST be encoded in the canonical deterministic
ordering defined in [RFC8949] §4.2.1 (sorted by encoded key length, then
lexicographic byte comparison).

### 4.4. Content-Type Suffix Semantics

The `+json` suffix indicates JSON [RFC8259] serialization:
- Character encoding: UTF-8
- All numeric field element values are decimal strings (no hex)
- No trailing commas or comments

The `+cbor` suffix indicates CBOR [RFC8949] serialization:
- Field element values remain text strings (CBOR major type 3), not bignums
- The `issuedAt` field is a CBOR unsigned integer (major type 0)
- The `chain` field, if present, is a CBOR unsigned integer

### 4.5. Version Negotiation

The `version` field uses semantic versioning [SemVer 2.0.0]. Implementations
MUST reject envelopes with a major version they do not support. Minor and
patch version differences within the same major version MUST be accepted
(forward-compatible).

Clients negotiate format via the HTTP `Accept` header:

```
Accept: application/bolyra-proof+json, application/bolyra-proof+cbor;q=0.9
```

Servers MUST respond with 406 Not Acceptable if they cannot produce any of
the requested media types.

### 4.6. Media Type Registration (per RFC 6838 §4.2)

Type name: application

Subtype name: bolyra-proof+json

Required parameters: None

Optional parameters: version (semver string; defaults to "1.0.0")

Encoding considerations: 8bit; UTF-8 encoded JSON

Security considerations: See Section 8 of this document.

Interoperability considerations: See Section 4.3 for field ordering.

Published specification: This document.

Applications which use this media type: Bolyra SDK, Bolyra MCP proxy,
  Bolyra-compatible verifier services.

Fragment identifier considerations: N/A

Restrictions on usage: None

---

Type name: application

Subtype name: bolyra-proof+cbor

Required parameters: None

Optional parameters: version (semver string; defaults to "1.0.0")

Encoding considerations: binary; CBOR encoded per RFC 8949

Security considerations: See Section 8 of this document.

Interoperability considerations: See Section 4.3 for deterministic encoding.

Published specification: This document.

Applications which use this media type: Bolyra SDK, on-chain verifier
  calldata, bandwidth-constrained agent-to-agent communication.

Fragment identifier considerations: N/A

Restrictions on usage: None
