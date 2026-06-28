---
title: "Bolyra Mutual ZKP Authentication Protocol"
abbrev: "bolyra-mutual-zkp-auth"
version: "01"
date: 2026-06-19
author:
  - name: Viswa Viswanathan
    org: ZKProva Inc.
---

# Abstract

This document specifies the Bolyra mutual zero-knowledge proof (ZKP)
authentication protocol, enabling humans and AI agents to mutually
authenticate via Groth16/PLONK proofs without revealing underlying
credentials. It defines the handshake flow, proof semantics, and
wire format for HTTP transport.

# Status of This Memo

This is an informational Internet-Draft style specification.

# Table of Contents

1. Introduction
2. Terminology
3. Protocol Overview
4. Handshake Flow
5. Circuits and Public Signals
6. Wire Format
7. Security Considerations
8. IANA Considerations

# 1. Introduction

Bolyra enables mutual authentication between human users and AI agents
using zero-knowledge proofs. Humans prove enrollment in a Semaphore v4
group; agents prove EdDSA-signed credentials with cumulative-bit
permissions. A delegation circuit enables scope narrowing.

# 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

- **Prover**: The party generating a zero-knowledge proof.
- **Verifier**: The party validating a zero-knowledge proof.
- **Handshake**: A mutual authentication exchange where both parties
  submit proofs bound to a shared session nonce.
- **Proof Envelope**: The canonical JSON wrapper for proof transport
  (see §6).

# 3. Protocol Overview

The Bolyra protocol consists of three phases:

1. **Nonce Exchange**: Verifier generates a session nonce.
2. **Proof Generation**: Both parties generate proofs binding to the nonce.
3. **Mutual Verification**: Both parties verify each other's proofs.

# 4. Handshake Flow

```
Human                          Agent
  |                              |
  |<---- sessionNonce -----------|
  |                              |
  |--- HumanUniqueness proof --->|
  |<-- AgentPolicy proof --------|
  |                              |
  |  (both verify, session est.) |
```

Both proofs MUST bind to the same `sessionNonce`. Replaying proofs
without rebinding to a fresh nonce MUST fail verification.

# 5. Circuits and Public Signals

## 5.1 HumanUniqueness

Public signals: `humanMerkleRoot`, `nullifierHash`, `nonceBinding`.

Uses Semaphore v4 ceremony at depth 20.

## 5.2 AgentPolicy

Public signals: `credentialCommitment`, `permissionBits`, `nonceBinding`,
`expiryTimestamp`.

## 5.3 Delegation

Public signals: `parentCredCommitment`, `delegatedCredCommitment`,
`narrowedPermissionBits`, `nonceBinding`.

# 6. Wire Format

## 6.1 Content-Type

Bolyra proof envelopes MUST be transported using the MIME type:

```
application/bolyra-proof+json
```

HTTP requests and responses carrying proof envelopes MUST set the
`Content-Type` header to `application/bolyra-proof+json`.

Receivers MUST reject payloads with a different `Content-Type` when
a Bolyra proof envelope is expected.

## 6.2 Envelope Schema

The canonical proof envelope is a JSON object with the following fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | Schema version (e.g., `"1.0"`). See §6.3 for version negotiation. |
| `circuit` | string | REQUIRED | Circuit identifier: `"HumanUniqueness"`, `"AgentPolicy"`, or `"Delegation"`. |
| `publicSignals` | string[] | REQUIRED | Array of public signal values as decimal strings. |
| `proof` | object | REQUIRED | Proof data object (see §6.2.1). |
| `metadata` | object | REQUIRED | Envelope metadata (see §6.2.2). |

### 6.2.1 Proof Data Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pi_a` | string[] | REQUIRED | G1 point (affine x, y, "1"). |
| `pi_b` | string[][] | REQUIRED | G2 point (two G1 components). |
| `pi_c` | string[] | REQUIRED | G1 point (affine x, y, "1"). |
| `protocol` | string | REQUIRED | Proving system: `"groth16"` or `"plonk"`. |

### 6.2.2 Metadata Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `prover` | string | REQUIRED | Identifier of the SDK or tool that generated the proof (e.g., `"@bolyra/sdk"`). MUST NOT be empty. |
| `timestamp` | string | REQUIRED | ISO 8601 timestamp of proof generation (e.g., `"2026-06-19T12:00:00.000Z"`). |

### 6.2.3 Example Envelope

```json
{
  "version": "1.0",
  "circuit": "HumanUniqueness",
  "publicSignals": [
    "12345678901234567890",
    "98765432109876543210",
    "11111111111111111111"
  ],
  "proof": {
    "pi_a": ["1234567890", "9876543210", "1"],
    "pi_b": [
      ["1111111111", "2222222222"],
      ["3333333333", "4444444444"],
      ["1", "0"]
    ],
    "pi_c": ["5555555555", "6666666666", "1"],
    "protocol": "groth16"
  },
  "metadata": {
    "prover": "@bolyra/sdk",
    "timestamp": "2026-06-19T12:00:00.000Z"
  }
}
```

## 6.3 Version Negotiation

The `version` field uses semantic versioning (`MAJOR.MINOR`).

- Receivers MUST reject envelopes with an unrecognized **major** version.
- Receivers SHOULD accept envelopes with an unrecognized **minor** version
  (forward-compatible additions).
- Senders MUST set `version` to the highest version they support.
- The current version is `"1.0"`.

## 6.4 Transport Requirements

- HTTP requests carrying proof envelopes MUST use `POST` or `PUT`.
- The `Content-Type` header MUST be set to `application/bolyra-proof+json`.
- Servers SHOULD return `415 Unsupported Media Type` if the `Content-Type`
  does not match when a proof envelope is expected.
- Servers SHOULD return `400 Bad Request` with a JSON error body if
  envelope validation fails.

# 7. Security Considerations

- Proof envelopes do not contain private inputs. The zero-knowledge
  property is preserved during transport.
- Implementations MUST validate the `version` field before processing
  to prevent downgrade attacks.
- The `timestamp` in metadata is informational and MUST NOT be used
  for replay protection. Session nonce binding (§4) provides replay
  resistance.
- TLS SHOULD be used for all proof transport to prevent metadata
  leakage.

# 8. IANA Considerations

This document requests registration of the following media type:

- Type name: `application`
- Subtype name: `bolyra-proof+json`
- Required parameters: none
- Optional parameters: none
- Encoding considerations: 8bit (UTF-8 JSON)
- Security considerations: See §7
- Published specification: This document
