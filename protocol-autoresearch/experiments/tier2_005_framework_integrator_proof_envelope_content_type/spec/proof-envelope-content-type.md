# Bolyra Proof Envelope Content Type

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-06-20  
**Authors:** Bolyra Protocol Team  

## Abstract

This document defines the `application/bolyra-proof+json` MIME content type
and the canonical JSON envelope schema for transporting zero-knowledge proofs
over HTTP. The envelope supports all three Bolyra circuit types
(`HumanUniqueness`, `AgentPolicy`, `Delegation`) and provides a stable,
self-describing format that framework integrations (LangChain, AutoGen, MCP)
can rely on without reinventing serialization.

## 1. MIME Type Registration

| Field | Value |
|---|---|
| Type name | `application` |
| Subtype name | `bolyra-proof+json` |
| Required parameters | none |
| Optional parameters | `v` (envelope schema version, default `"1"`) |
| Encoding | UTF-8 |
| Restrictions | Valid JSON per RFC 8259 |

Example HTTP header:

```
Content-Type: application/bolyra-proof+json; v=1
```

## 2. Envelope Schema

```jsonc
{
  "version": "1",                       // REQUIRED — schema version string
  "circuit": "HumanUniqueness",          // REQUIRED — one of the CircuitId values
  "publicSignals": ["0x...", ...],       // REQUIRED — array of decimal or hex strings
  "proof": {                             // REQUIRED — snarkjs proof object
    "pi_a": ["...", "...", "1"],
    "pi_b": [["...", "..."], ["...", "..."], ["1", "0"]],
    "pi_c": ["...", "...", "1"]
  },
  "sessionToken": "eyJ...",              // OPTIONAL — JWT or opaque session token
  "delegationChain": [                   // OPTIONAL — only for Delegation circuit
    {
      "delegatorCommitment": "0x...",
      "delegateCommitment": "0x...",
      "scopeMask": 255,
      "expiry": 1719878400
    }
  ]
}
```

### 2.1 Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | `string` | Yes | Schema version. Currently `"1"`. |
| `circuit` | `string` | Yes | One of `"HumanUniqueness"`, `"AgentPolicy"`, `"Delegation"`. |
| `publicSignals` | `string[]` | Yes | Ordered array of public signal values as decimal strings. |
| `proof` | `object` | Yes | Groth16/PLONK proof with `pi_a`, `pi_b`, `pi_c` fields. |
| `proof.pi_a` | `string[]` | Yes | Three-element array of decimal strings. |
| `proof.pi_b` | `string[][]` | Yes | Three-element array of two-element string arrays. |
| `proof.pi_c` | `string[]` | Yes | Three-element array of decimal strings. |
| `sessionToken` | `string` | No | Opaque session token for binding proof to session. |
| `delegationChain` | `DelegationLink[]` | No | Chain of delegation links (Delegation circuit only). |

### 2.2 DelegationLink Schema

| Field | Type | Required | Description |
|---|---|---|---|
| `delegatorCommitment` | `string` | Yes | Poseidon commitment of the delegator. |
| `delegateCommitment` | `string` | Yes | Poseidon commitment of the delegate. |
| `scopeMask` | `number` | Yes | 8-bit cumulative permission bitmask (0–255). |
| `expiry` | `number` | Yes | Unix timestamp (seconds) when this link expires. |

### 2.3 Canonical Key Order

For byte-for-byte reproducibility across SDKs, `serialize()` MUST emit
keys in the following order:

1. `version`
2. `circuit`
3. `publicSignals`
4. `proof` (keys: `pi_a`, `pi_b`, `pi_c`)
5. `sessionToken` (if present)
6. `delegationChain` (if present)
   - Each link: `delegatorCommitment`, `delegateCommitment`, `scopeMask`, `expiry`

### 2.4 Forward Compatibility

Parsers MUST ignore unknown top-level keys. This allows future envelope
versions to add fields without breaking existing consumers.

## 3. Validation Rules

1. `version` MUST be `"1"` (string, not number).
2. `circuit` MUST be one of the three known circuit identifiers.
3. `publicSignals` MUST be a non-empty array of strings.
4. `proof.pi_a` MUST have exactly 3 elements.
5. `proof.pi_b` MUST have exactly 3 elements, each a 2-element array.
6. `proof.pi_c` MUST have exactly 3 elements.
7. `delegationChain`, if present, MUST be a non-empty array with each entry
   containing all four required DelegationLink fields.
8. `scopeMask` MUST be an integer in range [0, 255].
9. `expiry` MUST be a positive integer.

## 4. Security Considerations

- The envelope is a transport format. Proof verification MUST still happen
  on the receiving side via the appropriate circuit verifier.
- `sessionToken` is opaque to the envelope layer. Token validation is
  the responsibility of the application layer.
- Parsers SHOULD enforce a maximum envelope size (recommended: 64 KiB)
  to prevent denial-of-service via oversized payloads.

## 5. References

- [RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259)
- [Bolyra DID Method](did-method-bolyra.md)
- [Bolyra Mutual ZKP Auth Draft](draft-bolyra-mutual-zkp-auth-01.md)
