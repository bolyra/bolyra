---
title: Protocol Conformance Testing
visibility: public
sources:
  - spec/CONFORMANCE.md
  - spec/test-vectors.json
  - spec/conformance-runner.js
  - spec/conformance-schema.json
last-updated: 2026-06-28
staleness-threshold: 30d
tags: [security, conformance, test-vectors, spec]
---

Bolyra ships 67 conformance test vectors with a runner and JSON Schema. The
vectors verify that any implementation of the protocol (TS SDK, Python SDK,
third-party) correctly enforces the security invariants defined in the spec.

## Overview

The conformance suite lives in `spec/` and has three components:

| File | Purpose |
|------|---------|
| `spec/test-vectors.json` | 67 test vectors (v0.4.0) with inputs, expected results, and failure reasons |
| `spec/conformance-runner.js` | Node CLI that runs vectors against `circomlibjs` crypto primitives |
| `spec/conformance-schema.json` | JSON Schema (draft 2020-12) validating vector structure |
| `spec/CONFORMANCE.md` | Auto-generated report from the last runner invocation |

## Key Concepts

### Vector Structure

Each vector has five required fields:

```json
{
  "id": "kebab-case-unique-id",
  "description": "What this vector tests",
  "type": "handshake | delegation | enrollment | ...",
  "inputs": { /* type-specific test inputs */ },
  "expected": {
    "result": "PASS | FAIL",
    "reason": "why it should fail (FAIL vectors only)",
    "failsAt": "which constraint catches it (FAIL vectors only)"
  }
}
```

FAIL vectors document both the expected failure reason and the exact circuit
constraint or on-chain check that should reject the input. This makes the
vectors useful as a security regression suite.

### Vector Categories

| Category | Count | What It Tests |
|----------|-------|---------------|
| Handshake | 12 | Mutual ZKP auth: expiry, scope, nonce replay, nullifier determinism |
| Delegation | 19 | Scope narrowing, expiry attenuation, Poseidon formula binding, Merkle roots, public signals layout |
| Enrollment | 5 | Cumulative-bit encoding, field overflow, zero-permission edge case |
| Delegation Chain | 4 | Multi-hop (up to 3), max-hop enforcement, mid-chain scope violation |
| Signature Verification | 3 | EdDSA forgery, wrong-message signing, delegation token forgery |
| Merkle Inclusion | 5 | Stale roots, max depth, tampered siblings |
| SD-JWT | 8 | Receipt issuance, expiry, audience binding, nonce replay, selective disclosure, JTI uniqueness |
| Proof Envelope | 6 | Required fields, malformed proof bytes, forward compatibility, cross-circuit |
| Session Token | 5 | JWT validity, expiry, scope narrowing, nullifier binding, nonce replay (**skipped -- experimental**) |

### Normative Requirements

Six semantic constraints that JSON Schema cannot express. A conformant
implementation MUST satisfy all of them:

1. **Nonce Replay** -- reject handshake proofs reusing a `sessionNonce` seen in
   any prior verified handshake within the same scope.
2. **Token Replay** -- reject session tokens whose nonce was already consumed.
3. **Vault JTI Uniqueness** -- SD-JWT issuers must generate globally unique JTI
   values (UUID v4 or equivalent).
4. **Audience Binding** -- reject SD-JWT receipts presented to a non-matching
   `aud` claim (case-sensitive, exact-match).
5. **Nullifier Binding** -- session tokens must include `humanNullifierHash`
   from the originating handshake.
6. **Forward Compatibility** -- implementations must preserve unknown fields in
   proof envelopes without error.

## How It Works

### Running the Suite

```bash
# Run all vectors
node spec/conformance-runner.js

# Run a single vector
node spec/conformance-runner.js --vector valid-handshake-basic

# Run one category
node spec/conformance-runner.js --type delegation

# Skip experimental (session_token) vectors
node spec/conformance-runner.js --skip-experimental

# Validate vector file against JSON Schema
node spec/conformance-runner.js --validate-schema

# Generate markdown report
node spec/conformance-runner.js --report spec/CONFORMANCE.md
```

Exit codes: `0` = all pass, `1` = test failures, `2` = schema validation error.

### What the Runner Checks

The runner uses `circomlibjs` (Poseidon, EdDSA, BabyJub) to verify crypto
properties without compiling circuits. For each vector type it checks:

- **Handshake**: credential expiry (strict less-than), scope bitmask subset,
  nullifier determinism, scope commitment identity-binding, collision resistance
- **Delegation**: scope subset, expiry ordering, Poseidon formula binding
  (prevScopeCommitment, delegationToken, newScopeCommitment), nullifier
  uniqueness per nonce, Merkle root computation, public signals layout,
  cumulative-bit invariant on delegatee scope
- **Enrollment**: cumulative-bit encoding validation, BN254 field overflow
- **Delegation Chain**: per-hop scope subset, max-hop enforcement (3)
- **Signature Verification**: EdDSA sign-then-verify with key/message mismatch
- **Merkle Inclusion**: root freshness, depth bounds (max 20), sibling tampering
- **SD-JWT**: structural validation (DID format, audience URI, TTL, JTI)
- **Proof Envelope**: required field presence, base64 validity, forward compat

On-chain checks (nonce replay, stale roots, delegation-requires-handshake) are
verified by asserting the expected failure reason matches the on-chain revert.

## Current Status

- **62 passed, 0 failed, 5 skipped** (session token vectors -- experimental, no
  implementation yet)
- Spec version: 0.4.0
- Schema: JSON Schema draft 2020-12, validates all 67 vectors
- The runner does NOT compile circuits or generate real proofs; it validates
  crypto invariants at the primitive level

## See Also

- [wiki/security/threat-model.md](threat-model.md) -- what the vectors are protecting against
- `spec/draft-bolyra-mutual-zkp-auth-01.md` -- protocol specification
- `spec/did-method-bolyra.md` -- DID method specification
- `circuits/FORMAL-PROPERTIES.md` -- formal properties the vectors exercise
