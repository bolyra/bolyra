---
title: Permissions Model
visibility: public
sources:
  - CLAUDE.md
  - sdk/src/types.ts
  - sdk/src/identity.ts
  - circuits/src/AgentPolicy.circom
  - circuits/src/Delegation.circom
  - spec/draft-bolyra-mutual-zkp-auth-01.md
last-updated: 2026-06-28
staleness-threshold: 60d
tags: [permissions, bitmask, cumulative-encoding, delegation]
---

An 8-bit cumulative permission encoding where higher financial tiers imply lower ones. Enforced in both circuits and SDK. Delegation can only narrow permissions, never expand.

## Overview

Agent permissions are encoded as a 64-bit unsigned integer bitmask. The first 8 bits are protocol-defined; bits 8-63 are reserved for application-specific use. The encoding uses cumulative implication rules for the financial permission tiers: if an agent has unlimited financial authority (bit 4), it must also have the lower tiers (bits 2 and 3). This invariant is enforced at three levels: SDK validation, the AgentPolicy circuit (at credential proof time), and the Delegation circuit (at delegation time).

## Key Concepts

### Bit Layout

| Bit | Name | SDK Enum | Implies |
|-----|------|----------|---------|
| 0 | `READ_DATA` | `Permission.READ_DATA` | -- |
| 1 | `WRITE_DATA` | `Permission.WRITE_DATA` | -- |
| 2 | `FINANCIAL_SMALL` | `Permission.FINANCIAL_SMALL` | < $100 |
| 3 | `FINANCIAL_MEDIUM` | `Permission.FINANCIAL_MEDIUM` | bit 2 (< $10K) |
| 4 | `FINANCIAL_UNLIMITED` | `Permission.FINANCIAL_UNLIMITED` | bits 2 + 3 |
| 5 | `SIGN_ON_BEHALF` | `Permission.SIGN_ON_BEHALF` | -- |
| 6 | `SUB_DELEGATE` | `Permission.SUB_DELEGATE` | -- |
| 7 | `ACCESS_PII` | `Permission.ACCESS_PII` | -- |
| 8-63 | Application-specific | -- | -- |

### Cumulative Encoding Invariant

Three rules must hold:

1. If bit 4 is set, bit 3 must be set
2. If bit 4 is set, bit 2 must be set
3. If bit 3 is set, bit 2 must be set

Without this invariant, an agent could be enrolled with bit 4 (unlimited financial) but without bit 2 (small financial), creating an inconsistent state.

### Delegation Narrowing

Delegation uses bitwise subset checking: `delegateeScope & ~delegatorScope === 0`. Combined with the cumulative invariant, this ensures tier downgrades work correctly. If a delegator has bits `0b11100` (financial tiers 2-4), delegating to scope `0b00100` (tier 2 only) is valid -- the subset check passes and the invariant holds on the narrower scope.

## How It Works

### SDK Enforcement

The SDK validates the cumulative invariant before creating credentials or generating proofs:

```ts
// Convert Permission flags to bitmask
const bitmask = permissionsToBitmask([
  Permission.READ_DATA,
  Permission.WRITE_DATA,
  Permission.FINANCIAL_SMALL,
]);
// Result: 0b00000111 (bits 0, 1, 2)

// Validate cumulative encoding -- throws InvalidPermissionError on violation
validateCumulativeBitEncoding(bitmask);
```

`validateCumulativeBitEncoding()` checks each implication rule and throws with a specific message:

```ts
// Throws: "FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)"
validateCumulativeBitEncoding(0b10100n); // bit 4 set, bit 3 missing
```

### Circuit Enforcement

Both AgentPolicy and Delegation circuits enforce the invariant using multiplication constraints:

```
// In Circom: higherBit * (1 - lowerBit) === 0
// This evaluates to 0 when either the higher bit is unset OR the lower bit is set.

signal bit4_requires_bit3;
bit4_requires_bit3 <== bitmaskRange.out[4] * (1 - bitmaskRange.out[3]);
bit4_requires_bit3 === 0;
```

AgentPolicy enforces this on the agent's own `permissionBitmask` at credential proof time. Delegation enforces it on the `delegateeScope` at delegation time. This means the invariant is checked at every point in the chain.

### Scope Satisfaction Check

The AgentPolicy circuit verifies an agent's permissions meet a verifier's requirements:

```
// For each bit: if required, the agent must have it
// requiredBits[i] * (1 - permBits[i]) === 0
```

This is a pure bitwise superset check -- the agent must have at least the bits the verifier requires.

### Range Protection

All bitmask values are range-checked to 64 bits via `Num2Bits(64)` to prevent field overflow attacks. A value valid in the BN254 scalar field (~254 bits) but exceeding uint64 would bypass Solidity-side checks.

## Current Status

- 8 protocol-defined permission bits are stable.
- Bits 8-63 reserved for application-specific use (not yet used by any integration).
- The spec notes that stronger scope privacy (against offline enumeration) would require a blinding salt in the scope commitment: `Poseidon3(bitmask, credCommitment, blindingSalt)`. Not implemented in Phase 1.
- Conformance suite: 4 cumulative bit encoding vectors.

## See Also

- [delegation.md](delegation.md) -- How permissions narrow through delegation chains
- [circuits-overview.md](circuits-overview.md) -- Circuit constraint details
- [zkp-handshake.md](zkp-handshake.md) -- Where scope satisfaction is checked
- `sdk/src/identity.ts` -- `validateCumulativeBitEncoding()` implementation
