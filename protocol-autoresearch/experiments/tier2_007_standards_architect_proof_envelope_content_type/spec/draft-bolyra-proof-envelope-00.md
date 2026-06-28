---
title: "The application/bolyra-proof+cbor Media Type"
abbrev: "Bolyra Proof Envelope"
docname: draft-bolyra-proof-envelope-00
date: 2026-06
category: std
area: Security
workgroup: Independent
keyword:
  - zero-knowledge proof
  - CBOR
  - media type
  - identity
author:
  - ins: V. Viswanathan
    name: Viswa Viswanathan
    organization: ZKProva Inc.
    email: viswa@bolyra.ai
normative:
  RFC8949:
  RFC8610:
  RFC6838:
  RFC9110:
informative:
  BOLYRA-AUTH:
    title: "Mutual Zero-Knowledge Proof Authentication for Human-Agent Identity"
    author:
      - ins: V. Viswanathan
    date: 2026
    target: "spec/draft-bolyra-mutual-zkp-auth-01.md"
---

# Abstract

This document defines the `application/bolyra-proof+cbor` media type for
exchanging zero-knowledge proof envelopes in the Bolyra identity protocol.
The envelope is a CBOR [RFC8949] map carrying the proof bytes, public signals,
circuit identifier, proving system tag, and protocol version. A CDDL [RFC8610]
schema provides formal structure. HTTP content negotiation parameters allow
middleware to route and validate proofs without parsing the CBOR body.

# Status of This Memo

This is an experimental specification for use within the Bolyra protocol
ecosystem. It is not yet submitted to IANA for registration.

# 1. Introduction

The Bolyra protocol enables mutual zero-knowledge proof authentication between
human identities and AI agent credentials [BOLYRA-AUTH]. Proof exchange
currently occurs over ad-hoc JSON payloads with no standardized content type.
This specification defines:

1. A CBOR-based envelope format for proof payloads
2. An IANA media type registration template
3. HTTP content negotiation parameters
4. Versioning policy for forward compatibility

## 1.1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174]
when, and only when, they appear in all capitals.

# 2. Envelope Structure

A Bolyra proof envelope is a CBOR map with the following required keys:

| Key              | CBOR Type    | Description                                     |
|------------------|-------------|--------------------------------------------------|
| `version`        | uint        | Envelope format version. Currently `1`.          |
| `circuitId`      | tstr        | Circuit identifier: `HumanUniqueness`, `AgentPolicy`, or `Delegation`. |
| `provingSystem`  | tstr        | `groth16` or `plonk`.                            |
| `proof`          | bstr        | Opaque proof bytes (proving-system-specific).    |
| `publicSignals`  | array<tstr> | Public signals as decimal strings.               |

An optional `metadata` map MAY carry additional context:

| Key         | CBOR Type | Description                              |
|-------------|----------|-------------------------------------------|
| `nonce`     | bstr     | Session nonce binding (32 bytes).         |
| `timestamp` | uint     | Unix epoch seconds of proof generation.   |
| `chainId`   | uint     | EVM chain ID for on-chain verification.   |

Unknown keys in the top-level map or metadata map MUST be ignored by
decoders to allow forward compatibility.

## 2.1. Proof Bytes Encoding

For Groth16 proofs (snarkjs format), the `proof` field contains the JSON
serialization of the proof object encoded as UTF-8 bytes. For PLONK proofs,
the same convention applies. Implementations MAY define compact binary
representations in future versions; the `version` field enables migration.

## 2.2. Public Signals

Public signals MUST be encoded as decimal string representations of
field elements. This matches the snarkjs convention and avoids precision
loss from JSON number encoding.

The expected number of public signals per circuit:

| Circuit           | Signal Count | Signals                                        |
|-------------------|-------------|------------------------------------------------|
| HumanUniqueness   | 3           | humanMerkleRoot, nullifierHash, nonceBinding   |
| AgentPolicy       | 4           | credCommitment, permissionHash, expiryBlock, nonceBinding |
| Delegation        | 5           | delegatorCommitment, delegateeCommitment, scopeCommitment, permissionMask, nonceBinding |

Decoders SHOULD validate that the public signals array length matches
the expected arity for the declared circuit.

# 3. Media Type Registration

Per RFC 6838 Section 4.2:

- **Type name:** application
- **Subtype name:** bolyra-proof+cbor
- **Required parameters:** None
- **Optional parameters:**
  - `circuit` — Circuit identifier (`HumanUniqueness`, `AgentPolicy`, `Delegation`)
  - `ps` — Proving system (`groth16`, `plonk`)
  - `v` — Envelope version (unsigned integer)
- **Encoding considerations:** Binary (CBOR, RFC 8949)
- **Security considerations:** See Section 5
- **Interoperability considerations:** See Section 6
- **Published specification:** This document
- **Applications that use this media type:** Bolyra SDK, MCP servers,
  HTTP middleware performing proof-aware routing
- **Fragment identifier considerations:** N/A
- **Person & email address to contact for further information:**
  Viswa Viswanathan <viswa@bolyra.ai>
- **Intended usage:** COMMON
- **Restrictions on usage:** None
- **Author/Change controller:** ZKProva Inc.

# 4. HTTP Negotiation

Clients requesting proof verification SHOULD set:

```
Content-Type: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16; v=1
```

Servers SHOULD include the same parameters in responses.

Clients MAY use the `Accept` header to express preference:

```
Accept: application/bolyra-proof+cbor; circuit=AgentPolicy; ps=groth16,
        application/bolyra-proof+cbor; ps=plonk; q=0.8,
        application/json; q=0.5
```

When the `Accept` header specifies `application/bolyra-proof+cbor` without
parameters, the server SHOULD respond with the proving system it considers
optimal (typically Groth16 for smaller proofs).

If a server cannot satisfy the requested circuit/proving-system combination,
it MUST respond with `406 Not Acceptable`.

# 5. Security Considerations

1. **Proof integrity:** The envelope does not provide integrity protection.
   Transport-layer security (TLS) MUST be used.

2. **Replay prevention:** The optional `nonce` metadata field binds the proof
   to a session. Verifiers SHOULD require and validate nonce freshness.

3. **Proof validation:** Receiving an envelope does not imply the proof is
   valid. Applications MUST run the appropriate verification algorithm
   (Groth16.Verify or PLONK.Verify) on the decoded proof and signals.

4. **Denial of service:** Implementations SHOULD enforce maximum envelope
   size (RECOMMENDED: 64 KiB) to prevent resource exhaustion.

5. **Version downgrade:** Implementations SHOULD reject envelopes with
   `version` values outside their supported range.

# 6. Interoperability

- Independent implementations MUST agree on CDDL schema version.
- The canonical test vectors in `spec/conformance/envelope-vectors.json`
  provide reference CBOR blobs for each circuit/proving-system combination.
- Implementations MUST round-trip test against these vectors before claiming
  conformance.

# 7. Versioning Policy

The `version` field uses monotonically increasing unsigned integers:

- **Version 1:** This specification. JSON-encoded proof bytes.
- **Version 2 (reserved):** Compact binary proof encoding.

Decoders MUST reject envelopes with unknown version values rather than
attempting best-effort parsing.

# 8. References

## 8.1. Normative References

- [RFC8949] Bormann, C. and P. Hoffman, "Concise Binary Object
  Representation (CBOR)", STD 94, RFC 8949, December 2020.
- [RFC8610] Birkholz, H., et al., "Concise Data Definition Language
  (CDDL)", RFC 8610, June 2019.
- [RFC6838] Freed, N., Klensin, J., and T. Hansen, "Media Type
  Specifications and Registration Procedures", BCP 13, RFC 6838,
  January 2013.
- [RFC9110] Fielding, R., et al., "HTTP Semantics", STD 97, RFC 9110,
  June 2022.

## 8.2. Informative References

- [BOLYRA-AUTH] Viswanathan, V., "Mutual Zero-Knowledge Proof
  Authentication for Human-Agent Identity",
  draft-bolyra-mutual-zkp-auth-01, 2026.

# Appendix A. Example Envelope (Diagnostic CBOR)

```cbor-diag
{
  "version": 1,
  "circuitId": "AgentPolicy",
  "provingSystem": "groth16",
  "proof": h'7b22...7d',   ; JSON-encoded Groth16 proof
  "publicSignals": [
    "12345678901234567890",
    "98765432109876543210",
    "11111111111111111111",
    "22222222222222222222"
  ],
  "metadata": {
    "nonce": h'deadbeef...32bytes',
    "timestamp": 1750000000,
    "chainId": 84532
  }
}
```
