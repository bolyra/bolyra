# Bolyra Protocol Conformance Report

**Generated:** 2026-06-21T05:49:58.101Z
**Spec version:** 0.4.0
**Runner:** spec/conformance-runner.js

## Summary

| Metric | Count |
|--------|-------|
| Total vectors | 67 |
| Passed | 62 |
| Failed | 0 |
| Skipped | 5 |

## Results by Category

### Handshake (12 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | valid-handshake-basic | PASS | ✓ PASS |
| 2 | expired-credential | FAIL | ✓ PASS |
| 3 | expired-credential-exact-boundary | FAIL | ✓ PASS |
| 4 | expired-credential-one-second-before | PASS | ✓ PASS |
| 5 | insufficient-permissions | FAIL | ✓ PASS |
| 6 | scope-escalation-all-bits | FAIL | ✓ PASS |
| 7 | zero-permission-bitmask-zero-scope | PASS | ✓ PASS |
| 8 | nonce-replay-attack | FAIL | ✓ PASS |
| 9 | nonce-reuse-different-agent | FAIL | ✓ PASS |
| 10 | timestamp-zero | FAIL | ✓ PASS |
| 11 | timestamp-max-uint64 | PASS | ✓ PASS |
| 12 | nullifier-collision-resistance | PASS | ✓ PASS |

### Signature Verification (3 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | invalid-eddsa-signature | FAIL | ✓ PASS |
| 2 | invalid-eddsa-signature-wrong-message | FAIL | ✓ PASS |
| 3 | delegation-forged-token-signature | FAIL | ✓ PASS |

### Merkle Inclusion (5 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | stale-merkle-root-handshake | FAIL | ✓ PASS |
| 2 | stale-merkle-root-after-rotation | FAIL | ✓ PASS |
| 3 | valid-merkle-proof-max-depth | PASS | ✓ PASS |
| 4 | merkle-proof-exceeds-max-depth | FAIL | ✓ PASS |
| 5 | merkle-proof-wrong-sibling | FAIL | ✓ PASS |

### Delegation (19 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | valid-delegation-single-hop | PASS | ✓ PASS |
| 2 | delegation-equal-scope | PASS | ✓ PASS |
| 3 | delegation-single-bit-escalation | FAIL | ✓ PASS |
| 4 | scope-escalation-attack | FAIL | ✓ PASS |
| 5 | expiry-escalation-attack | FAIL | ✓ PASS |
| 6 | delegation-expiry-equal | PASS | ✓ PASS |
| 7 | nonce-reuse-in-delegation | FAIL | ✓ PASS |
| 8 | delegation-without-handshake | FAIL | ✓ PASS |
| 9 | scope-chain-mismatch | FAIL | ✓ PASS |
| 10 | phantom-delegatee-attack | FAIL | ✓ PASS |
| 11 | delegation-nullifier-distinct-per-nonce | PASS | ✓ PASS |
| 12 | delegation-prev-scope-commitment-formula | PASS | ✓ PASS |
| 13 | delegation-token-poseidon4-formula | PASS | ✓ PASS |
| 14 | delegation-new-scope-commitment-formula | PASS | ✓ PASS |
| 15 | delegation-merkle-root-single-leaf | PASS | ✓ PASS |
| 16 | delegation-merkle-root-two-leaf | PASS | ✓ PASS |
| 17 | delegation-public-signals-layout | PASS | ✓ PASS |
| 18 | delegation-narrow-financial-scope | PASS | ✓ PASS |
| 19 | delegation-narrow-keep-cumulative-invariant | FAIL | ✓ PASS |

### Enrollment (5 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | cumulative-bit-violation | FAIL | ✓ PASS |
| 2 | cumulative-bit-violation-bit3-without-bit2 | FAIL | ✓ PASS |
| 3 | cumulative-bit-valid-full-chain | PASS | ✓ PASS |
| 4 | zero-permission-bitmask-enrollment | PASS | ✓ PASS |
| 5 | max-field-element-permission | FAIL | ✓ PASS |

### Delegation Chain (4 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | valid-delegation-chain-3-hops | PASS | ✓ PASS |
| 2 | delegation-chain-exceeds-max-hops | FAIL | ✓ PASS |
| 3 | delegation-chain-scope-violation-mid-chain | FAIL | ✓ PASS |
| 4 | delegation-valid-two-hop | PASS | ✓ PASS |

### Sd Jwt (8 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | sd-jwt-valid-issuance | PASS | ✓ PASS |
| 2 | sd-jwt-expired-receipt | FAIL | ✓ PASS |
| 3 | sd-jwt-wrong-audience | FAIL | ✓ PASS |
| 4 | sd-jwt-missing-nonce-production | FAIL | ✓ PASS |
| 5 | sd-jwt-nonce-replay | FAIL | ✓ PASS |
| 6 | sd-jwt-max-amount-exceeded | FAIL | ✓ PASS |
| 7 | sd-jwt-selective-disclosure | PASS | ✓ PASS |
| 8 | sd-jwt-jti-uniqueness | PASS | ✓ PASS |

### Proof Envelope (6 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | envelope-valid-handshake | PASS | ✓ PASS |
| 2 | envelope-missing-required-field | FAIL | ✓ PASS |
| 3 | envelope-malformed-proof-bytes | FAIL | ✓ PASS |
| 4 | envelope-unknown-fields-forward-compat | PASS | ✓ PASS |
| 5 | envelope-cross-circuit | PASS | ✓ PASS |
| 6 | envelope-empty-public-signals | FAIL | ✓ PASS |

### Session Token (5 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | session-valid-jwt | PASS | – SKIP |
| 2 | session-expired | FAIL | – SKIP |
| 3 | session-scope-narrowing | PASS | – SKIP |
| 4 | session-missing-nullifier-binding | FAIL | – SKIP |
| 5 | session-nonce-replay | FAIL | – SKIP |

## Normative Requirements

The following requirements are semantic constraints that the JSON Schema cannot
express. A conformant implementation MUST satisfy all of them.

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" in this section are to be
interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### Nonce Replay

A conformant implementation MUST reject a handshake proof that reuses a
`sessionNonce` seen in any prior verified handshake within the same scope.
Implementations SHOULD maintain a nonce registry scoped to the verifier's
operational lifetime.

### Token Replay

A session token MUST be rejected if its nonce has been consumed by a prior
verification within the token's audience scope. Stateless verifiers MAY use
short-lived nonce windows instead of persistent registries.

### Vault JTI Uniqueness

SD-JWT issuers MUST generate globally unique JTI values. Collision across any
two receipts issued by the same issuer constitutes a conformance failure.
Implementations SHOULD use UUID v4 or equivalent entropy source.

### Audience Binding

An SD-JWT receipt presented to an audience not matching the `aud` claim MUST be
rejected, even if the cryptographic signature is valid. The audience comparison
MUST be case-sensitive and exact-match.

### Nullifier Binding

Session tokens MUST include the `humanNullifierHash` from the originating
handshake as a claim. Tokens without this binding are non-conformant. Verifiers
MUST check that the nullifier claim matches the handshake that produced the
session.

### Forward Compatibility

Implementations MUST preserve unknown fields in proof envelopes without error.
Rejecting unknown fields is a conformance failure. This enables protocol
evolution without breaking existing implementations.

## References

- [Protocol Specification](draft-bolyra-mutual-zkp-auth-01.md)
- [DID Method](did-method-bolyra.md)
- [Test Vectors](test-vectors.json)
