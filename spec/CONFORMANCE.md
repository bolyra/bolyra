# Bolyra Protocol Conformance Report

**Generated:** 2026-06-13T16:57:09.437Z
**Spec version:** 0.3.0
**Runner:** spec/conformance-runner.js

## Summary

| Metric | Count |
|--------|-------|
| Total vectors | 48 |
| Passed | 48 |
| Failed | 0 |
| Skipped | 0 |

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

## References

- [Protocol Specification](draft-bolyra-mutual-zkp-auth-01.md)
- [DID Method](did-method-bolyra.md)
- [Test Vectors](test-vectors.json)
