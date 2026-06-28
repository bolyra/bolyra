# Bolyra Proof Envelope v1 — Wire Format Specification

**Status:** Draft  
**Version:** 1.0.0  
**Date:** 2026-06-20  

## Abstract

This document defines the canonical JSON wire format for Bolyra ZKP proof
payloads. The `BolyraEnvelope` replaces bare `{ proof, publicSignals: bigint[] }`
objects with a self-describing structure that names every public signal,
identifies the circuit and proving system, and carries a schema version for
forward compatibility.

## 1. Envelope Schema

```jsonc
{
  "version": "1.0.0",                    // semver, MUST match ^1.x.x for v1 decoders
  "circuit": "HumanUniqueness",           // enum: see §2
  "provingSystem": "groth16",             // enum: see §3
  "signals": {                            // named public signals, all string-encoded bigints
    "nullifierHash": "123...",
    "nonceBinding": "456...",
    "humanMerkleRoot": "789...",
    "externalNullifier": "012...",
    "sessionNonce": "345..."
  },
  "proof": { /* snarkjs proof object passthrough */ }
}
```

## 2. Circuit Enum

| Value              | Description                                           |
|--------------------|-------------------------------------------------------|
| `HumanUniqueness`  | Semaphore v4 human enrollment proof                   |
| `AgentPolicy`      | EdDSA-signed agent credential with cumulative-bit perms |
| `Delegation`       | One-way scope-narrowing delegation proof              |

Unknown circuit values MUST cause a decode error.

## 3. Proving System Enum

| Value     | Notes                                    |
|-----------|------------------------------------------|
| `groth16` | All three circuits support Groth16       |
| `plonk`   | AgentPolicy and Delegation only          |

## 4. Signal Maps (Positional → Named)

The `signals` object is keyed by human-readable field name. The positional
index corresponds to the snarkjs `publicSignals` array order (outputs first
in declaration order, then public inputs in declaration order).

### 4.1 HumanUniqueness

| Index | Field Name          | Type    |
|-------|---------------------|---------|
| 0     | `nullifierHash`     | output  |
| 1     | `nonceBinding`      | output  |
| 2     | `humanMerkleRoot`   | input   |
| 3     | `externalNullifier` | input   |
| 4     | `sessionNonce`      | input   |

### 4.2 AgentPolicy

| Index | Field Name            | Type    |
|-------|-----------------------|---------|
| 0     | `credentialHash`      | output  |
| 1     | `nonceBinding`        | output  |
| 2     | `agentMerkleRoot`     | input   |
| 3     | `currentTimestamp`    | input   |
| 4     | `requiredPermissions` | input   |
| 5     | `sessionNonce`        | input   |

### 4.3 Delegation

| Index | Field Name            | Type    |
|-------|-----------------------|---------|
| 0     | `delegationHash`      | output  |
| 1     | `narrowedPermissions` | output  |
| 2     | `nonceBinding`        | output  |
| 3     | `delegationMerkleRoot`| input   |
| 4     | `currentTimestamp`    | input   |
| 5     | `sessionNonce`        | input   |

## 5. Field Semantics

- **version**: Semver string. Decoders MUST reject envelopes whose major
  version does not match their supported major version.
- **circuit**: One of the enum values in §2. Determines which signal map to
  apply during encode/decode.
- **provingSystem**: One of the enum values in §3.
- **signals**: A JSON object mapping field names to string-encoded decimal
  bigint values. The set of keys MUST exactly match the signal map for the
  declared circuit. Missing or extra keys are an error.
- **proof**: The snarkjs `SnarkjsProof` object, passed through verbatim.
  Contains `pi_a`, `pi_b`, `pi_c`, `protocol`, and `curve`.

## 6. Encoding

`encode(circuit, provingSystem, rawProof, rawSignals)` zips the positional
`rawSignals` array with the signal map for `circuit` to produce the named
`signals` object.

## 7. Decoding

`decode(envelope)` inverts the zip: reads the named `signals` object and
produces a positional `bigint[]` array suitable for `snarkjs.groth16.verify()`
or `snarkjs.plonk.verify()`.

## 8. Versioning Policy

- Patch: documentation-only changes
- Minor: new optional fields in `signals` or new circuit enum values
- Major: breaking changes to field semantics or signal reordering

## 9. Security Considerations

- Decoders MUST validate `circuit` and `provingSystem` against known enums
  before processing.
- Signal count MUST match the expected count for the circuit. A mismatch
  indicates a tampered or malformed envelope.
- The `proof` object is opaque to the envelope layer — verification is the
  caller's responsibility.
