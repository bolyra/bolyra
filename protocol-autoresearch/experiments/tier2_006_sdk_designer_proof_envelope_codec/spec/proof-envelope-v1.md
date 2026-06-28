# Bolyra Proof Envelope v1 Specification

## Status

Draft — v1.0.0

## Abstract

This document defines the **BolyraEnvelope** wire format: a self-describing
JSON wrapper around ZK proofs that replaces positional `publicSignals[]`
arrays with named signal records. The format carries a version string,
circuit identifier, proving system enum, and per-circuit named signals
so that integrators never index by position.

## 1. Envelope Structure

```jsonc
{
  "version": "1.0.0",                          // semver, currently "1.0.0"
  "circuit": "HumanUniqueness",                  // circuit enum
  "provingSystem": "groth16",                    // proving system enum
  "signals": {                                   // named public signals
    "humanMerkleRoot": "123...",
    "nullifierHash": "456...",
    "nonceBinding": "789..."
  },
  "proof": {                                     // opaque proof object
    "pi_a": ["...", "...", "..."],
    "pi_b": [["...", "..."], ["...", "..."], ["...", "..."]],
    "pi_c": ["...", "...", "..."],
    "protocol": "groth16",
    "curve": "bn128"
  }
}
```

## 2. Fields

### 2.1 `version` (string, required)

Semver string. Decoders MUST reject envelopes whose major version exceeds
the highest major version they support. Current version: `"1.0.0"`.

### 2.2 `circuit` (string enum, required)

One of:

| Value              | Circuit file                        | Signal count |
|--------------------|-------------------------------------|--------------|
| `HumanUniqueness`  | `circuits/src/HumanUniqueness.circom` | 3            |
| `AgentPolicy`      | `circuits/src/AgentPolicy.circom`     | 4            |
| `Delegation`       | `circuits/src/Delegation.circom`      | 4            |

Unknown values MUST cause a decode error.

### 2.3 `provingSystem` (string enum, required)

One of: `"groth16"`, `"plonk"`.

`HumanUniqueness` only supports `"groth16"`. `AgentPolicy` and `Delegation`
support both.

### 2.4 `signals` (object, required)

A record mapping signal names to their string-encoded values (decimal
bigint representation). The set of keys MUST exactly match the signal
map for the declared `circuit`. Missing or extra keys MUST cause a
decode error.

#### Signal Maps

**HumanUniqueness** (3 signals, positional order):

| Index | Name              | Description                           |
|-------|-------------------|---------------------------------------|
| 0     | `humanMerkleRoot` | Merkle root of the enrollment tree    |
| 1     | `nullifierHash`   | Nullifier for sybil/replay prevention |
| 2     | `nonceBinding`    | Session nonce binding                 |

**AgentPolicy** (4 signals, positional order):

| Index | Name                  | Description                             |
|-------|-----------------------|-----------------------------------------|
| 0     | `credentialCommitment`| Poseidon hash of agent credential       |
| 1     | `permissionsBitmask`  | 8-bit cumulative permission encoding    |
| 2     | `scopeCommitment`     | Committed scope for the credential      |
| 3     | `expiryTimestamp`     | Unix timestamp of credential expiry     |

**Delegation** (4 signals, positional order):

| Index | Name                        | Description                                |
|-------|-----------------------------|-----------------------------------------   |
| 0     | `delegatorCredCommitment`   | Delegator's credential commitment          |
| 1     | `delegateeCredCommitment`   | Delegatee's credential commitment          |
| 2     | `narrowedPermissionsBitmask`| Narrowed permissions (subset of delegator) |
| 3     | `delegationNullifier`       | Nullifier preventing delegation replay     |

### 2.5 `proof` (object, required)

Opaque proof object as emitted by the proving system. For Groth16 this
contains `pi_a`, `pi_b`, `pi_c`, `protocol`, and `curve`. For PLONK
this contains the PLONK-specific proof structure. Decoders SHOULD
treat this as opaque and pass it directly to the verifier.

## 3. Codec Contract

### 3.1 `encode(circuit, provingSystem, rawProof, rawSignals[])`

1. Look up the signal map for `circuit`. Error if unknown.
2. Assert `rawSignals.length === signalMap.length`. Error on mismatch.
3. Build `signals` record by zipping signal names with values.
4. Return `{ version: "1.0.0", circuit, provingSystem, signals, proof: rawProof }`.

### 3.2 `decode(envelope)`

1. Parse `version`. Error if major version > 1.
2. Look up signal map for `circuit`. Error if unknown.
3. Validate `provingSystem` is a known enum value.
4. Assert `Object.keys(signals)` exactly matches the signal map. Error on
   missing or extra keys.
5. Return the ordered `bigint[]` array by mapping signal names back to
   their positional indices, plus the parsed metadata.

### 3.3 `fromRaw(circuit, provingSystem, rawProof, rawSignals[])`

Alias for `encode()` — exists as a migration helper for integrators
upgrading from positional `publicSignals[]` arrays.

## 4. MIME Type

Envelopes SHOULD be transmitted with `Content-Type: application/bolyra-envelope+json`.

## 5. Versioning Policy

- Patch: editorial changes to this spec.
- Minor: new optional fields or new circuit types.
- Major: breaking changes to existing signal maps or envelope structure.

Decoders MUST reject unknown major versions. Decoders SHOULD accept
unknown minor versions by ignoring unknown optional fields.
