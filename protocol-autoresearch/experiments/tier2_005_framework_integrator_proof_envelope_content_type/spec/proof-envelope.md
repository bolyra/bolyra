# Bolyra Proof Envelope Specification

**Version:** 1.0  
**Status:** Normative  
**Content-Type:** `application/bolyra+json`

## 1. Introduction

This specification defines a canonical JSON envelope format for all zero-knowledge proof payloads produced by the Bolyra protocol. The envelope provides a uniform serialization boundary so that framework integrations (MCP servers, LangChain middleware, OpenAI function-calling proxies, REST tool servers) can accept and emit proofs without framework-specific serialization logic.

## 2. MIME Type

The registered content type is:

```
application/bolyra+json
```

### 2.1 Rationale

- The `+json` structured syntax suffix indicates JSON-serialized content per RFC 6839.
- A dedicated media type allows HTTP content negotiation (`Accept: application/bolyra+json`) and middleware routing.
- The `bolyra` subtype is vendor-specific but intentionally short; a future IANA registration would use `application/vnd.bolyra.proof+json`.

## 3. Envelope Schema

### 3.1 Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | `string` | MUST | Schema version. Currently `"1.0"`. Consumers MUST reject envelopes with an unsupported major version. Minor version bumps are backwards-compatible. |
| `proofType` | `string` enum | MUST | One of `"handshake"`, `"delegation"`, `"agent_policy"`. Identifies the circuit that produced this proof. |
| `publicSignals` | `string[]` | MUST | Ordered array of public signals as decimal strings. Order matches the circuit's public output order. MUST contain at least one element. |
| `proof` | `object` | MUST | The snarkjs-compatible proof object. See §3.2. |
| `metadata` | `object` | MUST | Envelope metadata. See §3.3. |

### 3.2 Proof Object

The `proof` field contains the raw proving-system output:

| Field | Type | Required | Description |
|---|---|---|---|
| `pi_a` | `string[]` | MUST | Groth16/PLONK A point. Array of 3 decimal strings. |
| `pi_b` | `string[][]` | MUST | Groth16/PLONK B point. Array of 3 two-element arrays of decimal strings. |
| `pi_c` | `string[]` | MUST | Groth16/PLONK C point. Array of 3 decimal strings. |
| `protocol` | `string` | MUST | `"groth16"` or `"plonk"`. |
| `curve` | `string` | MUST | `"bn128"`. |

### 3.3 Metadata Object

| Field | Type | Required | Description |
|---|---|---|---|
| `issuedAt` | `number` | MUST | Unix timestamp (seconds) when the proof was generated. |
| `nonce` | `string` | MAY | Session nonce binding the proof to a particular handshake. |
| `sdkVersion` | `string` | MAY | Version of the SDK that produced this envelope (e.g. `"0.2.0"`). |

Additional keys in `metadata` are allowed for forward compatibility but MUST NOT conflict with the fields defined above.

## 4. Versioning

- The `version` field uses `major.minor` format.
- A **major** version bump indicates breaking schema changes. Consumers MUST reject unknown major versions.
- A **minor** version bump adds optional fields. Consumers MUST accept unknown minor versions within the same major.

## 5. HTTP Usage

### 5.1 Request Body

```http
POST /verify HTTP/1.1
Content-Type: application/bolyra+json

{"version":"1.0","proofType":"handshake",...}
```

### 5.2 Response Body

```http
HTTP/1.1 200 OK
Content-Type: application/bolyra+json

{"version":"1.0","proofType":"handshake",...}
```

### 5.3 Content Negotiation

Servers SHOULD check `Accept` headers. If a client sends `Accept: application/bolyra+json`, the server MUST return the envelope format or `406 Not Acceptable`.

## 6. Security Considerations

- **Replay protection:** Consumers MUST bind proofs to session nonces. The `metadata.nonce` field carries this binding.
- **Version pinning:** Consumers MUST NOT silently upgrade to a new major version.
- **Size limits:** Implementations SHOULD reject envelopes larger than 64 KiB to prevent DoS.
- **Proof verification:** Receipt of a valid envelope does NOT imply the proof has been verified. Verification against the on-chain verifier is a separate step.

## 7. Conformance

An implementation conforms to this specification if:

1. It produces envelopes matching the JSON Schema in `sdk/src/envelope.schema.json`.
2. It rejects envelopes with unsupported major versions.
3. It preserves field ordering during round-trip serialization.
4. It passes all test vectors in `spec/conformance/envelope-vectors.json`.
