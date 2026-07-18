# Bolyra Protocol Conformance Report

**Generated:** 2026-07-18T14:47:37.230Z
**Spec version:** 0.4.0
**Runner:** spec/conformance-runner.js

## Summary

| Metric | Count |
|--------|-------|
| Total vectors | 104 |
| Passed | 99 |
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

### External Verifier (10 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | external-verifier-allow-agent | PASS | ✓ PASS |
| 2 | external-verifier-allow-host-nonce | PASS | ✓ PASS |
| 3 | external-verifier-deny-malformed-input | PASS | ✓ PASS |
| 4 | external-verifier-deny-scope-exceeded | PASS | ✓ PASS |
| 5 | external-verifier-deny-model-mismatch | PASS | ✓ PASS |
| 6 | external-verifier-kind-zk-default | PASS | ✓ PASS |
| 7 | external-verifier-kind-zk-explicit | PASS | ✓ PASS |
| 8 | external-verifier-kind-classical-allow | PASS | ✓ PASS |
| 9 | external-verifier-kind-external-deny | PASS | ✓ PASS |
| 10 | external-verifier-kind-invalid-rejected | FAIL | ✓ PASS |

### Host Behavior (27 vectors)

| # | Vector ID | Expected | Status |
|---|-----------|----------|--------|
| 1 | host-allow-well-behaved | PASS | ✓ PASS |
| 2 | host-relay-well-behaved-deny | PASS | ✓ PASS |
| 3 | host-deny-non-json-stdout | PASS | ✓ PASS |
| 4 | host-deny-multiple-objects | PASS | ✓ PASS |
| 5 | host-deny-schema-invalid-verdict | PASS | ✓ PASS |
| 6 | host-deny-deny-missing-fields | PASS | ✓ PASS |
| 7 | host-deny-allow-trailing-garbage | PASS | ✓ PASS |
| 8 | host-deny-no-output-timeout | PASS | ✓ PASS |
| 9 | host-deny-partial-json-timeout | PASS | ✓ PASS |
| 10 | host-deny-nonzero-exit-after-allow | PASS | ✓ PASS |
| 11 | host-deny-killed-by-signal | PASS | ✓ PASS |
| 12 | host-deny-oversize-stdout | PASS | ✓ PASS |
| 13 | host-nonce-reserve-novel-allow | PASS | ✓ PASS |
| 14 | host-nonce-reserve-replay-deny | PASS | ✓ PASS |
| 15 | host-nonce-reserve-all-any-conflict-deny | PASS | ✓ PASS |
| 16 | host-deny-allow-extra-property | PASS | ✓ PASS |
| 17 | host-deny-bad-kind | PASS | ✓ PASS |
| 18 | host-deny-empty-consume-nonces | PASS | ✓ PASS |
| 19 | host-deny-malformed-consume-nonce | PASS | ✓ PASS |
| 20 | host-deny-deny-extra-property | PASS | ✓ PASS |
| 21 | host-deny-nonce-entry-extra-property | PASS | ✓ PASS |
| 22 | host-deny-nonce-entry-wrong-type | PASS | ✓ PASS |
| 23 | host-deny-binary-garbage-stdout | PASS | ✓ PASS |
| 24 | host-deny-leading-garbage | PASS | ✓ PASS |
| 25 | host-deny-slow-allow-past-deadline | PASS | ✓ PASS |
| 26 | host-allow-well-behaved-kind-classical | PASS | ✓ PASS |
| 27 | host-allow-well-behaved-kind-external | PASS | ✓ PASS |

## References

- [Protocol Specification](draft-bolyra-mutual-zkp-auth-01.md)
- [DID Method](did-method-bolyra.md)
- [Test Vectors](test-vectors.json)
