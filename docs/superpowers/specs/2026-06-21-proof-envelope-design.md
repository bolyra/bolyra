# Proof Envelope Content Type -- Design Document

**Date:** 2026-06-21
**Author:** PDLC Orchestrator + Codex review
**Status:** APPROVED

## 1. Motivation

Framework integrations serialize ZKP proofs as ad-hoc JSON blobs with no standard
envelope. Every consumer (Express middleware, FastAPI dependency, MCP tool wrapper,
mobile SDK) must understand circuit internals. A canonical wire format eliminates
this coupling and gives IETF reviewers and enterprise evaluators a concrete,
versionable artifact.

## 2. Wire Format

Content-Type: `application/vnd.bolyra.proof+json` (vendor tree until IANA registration)

```json
{
  "version": "1.0.0",
  "circuit": {
    "name": "HumanUniqueness",
    "version": "0.4.0",
    "vkeyHash": "sha256:abcdef1234567890..."
  },
  "proofType": "groth16",  // v1 only supports groth16
  "publicSignals": ["12345678901234567890", "98765432109876543210"],
  "proof": {
    "pi_a": ["12345...", "67890..."],
    "pi_b": [["11111...", "22222..."], ["33333...", "44444..."]],
    "pi_c": ["55555...", "66666..."]
  },
  "metadata": {
    "prover": "@bolyra/sdk@0.4.0",
    "timestamp": "2026-06-21T12:00:00Z"
  }
}
```

### 2.1 Field Encoding Rules

- **Field elements and proof coordinates:** decimal string representation of
  the BN254 scalar field element. No hex. No bare numbers. Always strings.
  Leading zeros stripped (reject `"0042"`, accept `"42"`). Implementations MUST
  reject strings with leading zeros except for the value `"0"` itself.
  Implementations MUST reject strings longer than 78 characters before parsing
  to prevent BigInt allocation attacks. Example: `"42"`.
- **Array order:** pi_a is `[x, y]`. pi_b is `[[x1, x2], [y1, y2]]`.
  pi_c is `[x, y]`. Matches snarkjs output order.
- **Rejection:** Implementations MUST reject envelopes where any field element
  string cannot be parsed as a non-negative integer, or is greater than or
  equal to the BN254 field modulus (p = 2188...5617).

### 2.2 Circuit Identity

The `circuit` field binds the proof to a specific circuit version:

- `name`: one of `HumanUniqueness`, `AgentPolicy`, `Delegation` (enum, extensible).
- `version`: semver string matching the `@bolyra/circuits` package version.
- `vkeyHash`: `sha256:<64 lowercase hex chars>` digest of the verification key
  JSON serialized with sorted keys and no whitespace (JSON.stringify with sorted
  keys). Optional. Implementations SHOULD verify this against their local vkey
  before accepting.

This prevents version confusion where a proof generated against circuit v0.3.0
is verified against v0.4.0's vkey.

### 2.3 Version Negotiation

The `version` field uses semver (MAJOR.MINOR.PATCH):

- **Major mismatch:** MUST reject. Wire format is incompatible.
- **Minor mismatch:** MUST accept. New optional fields may be present.
  Unknown fields MUST be preserved (forward compatibility).
- **Patch mismatch:** MUST accept. No semantic difference.
- **Current version:** `1.0.0`

### 2.4 Metadata

The `metadata` object is INFORMATIONAL, not normative. Verifiers MUST NOT
reject envelopes based on metadata content.

- `prover`: string identifying the SDK that produced the proof. Informational.
- `timestamp`: RFC 3339 datetime. Informational. MUST NOT be used for
  expiry decisions (that's the circuit's job via public signals).

Additional metadata keys MAY be added. Consumers MUST ignore unknown keys.

### 2.5 Serialization

Serialization is **parse-compatible, not canonical**. Two valid serializations
of the same proof may differ in whitespace and key order. If envelopes need
to be signed or hashed in the future, a canonicalization step (JCS per
RFC 8785) will be added as a minor version bump.

## 3. Components

### 3.1 TypeScript (`sdk/src/envelope.ts`)

- `ProofEnvelope` type (runtime validation, no external library)
- `CONTENT_TYPE = "application/bolyra-proof+json"` constant
- `ENVELOPE_VERSION = "1.0.0"` constant
- `serializeEnvelope(envelope: ProofEnvelope): string` -- JSON.stringify
- `deserializeEnvelope(json: string): ProofEnvelope` -- parse + validate
- `envelopeFromSnarkjsProof(circuit, proof, signals, vkeyHash?): ProofEnvelope`
- Version check: reject major mismatch, accept minor/patch
- Re-exported from `sdk/src/index.ts`

### 3.2 Python (`sdk-python/bolyra/envelope.py`)

- `ProofEnvelope` (dataclass, mirrors TS fields exactly)
- `CONTENT_TYPE`, `ENVELOPE_VERSION` constants
- `to_json() -> str`, `from_json(raw: str) -> ProofEnvelope`
- `envelope_from_proof(circuit, proof, signals, vkey_hash=None) -> ProofEnvelope`
- Version check logic identical to TS

### 3.3 Golden Fixture (`sdk/test/fixtures/envelope_v1.json`)

A single valid envelope with known values. Both TS and Python tests
deserialize this fixture and verify field-by-field equality. This is
the cross-SDK interop contract.

### 3.4 Tests

**TypeScript (Mocha):**
- Round-trip: serialize then deserialize, assert deep equality
- Version rejection: major version "2.0.0" throws
- Version acceptance: minor version "1.1.0" parses
- Missing required field: no `proof` key throws
- Malformed proof coordinates: non-numeric string throws
- Forward compat: unknown top-level key preserved after round-trip
- Golden fixture: deserialize envelope_v1.json, assert all fields
- snarkjs integration: envelopeFromSnarkjsProof produces valid envelope

**Python (pytest):**
- Mirror all TS test cases
- Cross-SDK: deserialize the same envelope_v1.json fixture
- Type validation: wrong types rejected

## 4. Files

| File | Action |
|---|---|
| `sdk/src/envelope.ts` | Create |
| `sdk/src/index.ts` | Modify (add re-exports) |
| `sdk/test/envelope.test.ts` | Create |
| `sdk/test/fixtures/envelope_v1.json` | Create |
| `sdk-python/bolyra/envelope.py` | Create |
| `sdk-python/tests/test_envelope.py` | Create |

## 5. Out of Scope

- HTTP middleware (Express/FastAPI) -- future, layers on envelope
- MCP integration migration -- wait until envelope format is locked
- IANA content-type registration -- future, when IETF engagement materializes
- Canonical serialization (JCS) -- future minor version bump if signing needed
- Integration guide doc -- defer until HTTP middleware ships
