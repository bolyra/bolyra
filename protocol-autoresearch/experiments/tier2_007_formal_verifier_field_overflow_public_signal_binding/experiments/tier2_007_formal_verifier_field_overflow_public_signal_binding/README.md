# Experiment: Field Overflow on Public Signal Round-Trip to Solidity (P-RANGE-FIELD)

**ID:** `formal_verifier_field_overflow_public_signal_binding`
**Persona:** Formal Verifier
**Dimension:** Standards / Correctness
**Priority:** High

## Problem

Bolyra's circuits use `Num2Bits(64)` for timestamp signals and `Num2Bits(8)` for
permission bitmasks, but `sessionNonce` (in all three circuits) and
`externalNullifier` (in HumanUniqueness) have **no range checks**. These signals
are full field elements (< BN254 r ~= 2^254). The Solidity verifier passes them
as `uint256`, so values near `r` can alias modularly: a prover submits `x + r`
instead of `x`, and the circuit accepts it (since `x + r === x mod r`) while the
on-chain verifier sees a different `uint256` value.

This enables nonce replay, nullifier domain confusion, and cross-context proof
migration.

## Solution

Add `RangeCheck(253)` (a thin wrapper around `Num2Bits(253)`) to all unranged
public inputs, constraining them to `[0, 2^253 - 1]`. Since `2^253 < r`, every
value in this range is a canonical field element with no alias in uint256 space.

## Artifacts

| Type | Path | Description |
|---|---|---|
| Circuit | `circuits/src/RangeChecks.circom` | Shared `RangeCheck(n)` template |
| Circuit | `circuits/src/AgentPolicy.circom` | +`RangeCheck(253)` on `sessionNonce` |
| Circuit | `circuits/src/HumanUniqueness.circom` | +`RangeCheck(253)` on `sessionNonce`, `externalNullifier` |
| Circuit | `circuits/src/Delegation.circom` | +`RangeCheck(253)` on `sessionNonce` |
| Spec | `circuits/FORMAL-PROPERTIES.md` | P-RANGE-FIELD invariant + signal table |
| Test | `circuits/test/range_checks.test.js` | 10 witness-generation boundary tests |
| Fixture | `circuits/test/fixtures/RangeCheckTest.circom` | Minimal wrapper for isolated testing |
| Docs | `docs/security/field-overflow-mitigation.md` | Vulnerability writeup + remediation |

## Constraint Cost

4 new `RangeCheck(253)` instances = **1012 R1CS constraints** total:
- HumanUniqueness: +506 (2 instances)
- AgentPolicy: +253 (1 instance)
- Delegation: +253 (1 instance)

## Usage

### Compile circuits

```bash
npm run compile:circuits
```

Verify R1CS constraint counts increase by exactly 253 per added `RangeCheck(253)`.

### Run fast tests (witness-only)

```bash
npm run test:circuits:fast
```

### Run full proof tests

```bash
FULL_PROOF=1 npm run test:circuits:slow
```

### Regenerate verifier contracts

After recompiling circuits with new constraints:

```bash
cd contracts && npm run compile:contracts
npm run test:contracts
```

## Test Coverage

| # | Case | Expected |
|---|---|---|
| 1 | `in = 0` | Witness succeeds |
| 2 | `in = 1` | Witness succeeds |
| 3 | `in = 2^253 - 1` | Witness succeeds |
| 4 | `in = 2^252` | Witness succeeds |
| 5 | `in = 2^253` | Constraint error |
| 6 | `in = BN254_r` | Constraint error |
| 7 | `in = BN254_r + 1` | Constraint error |
| 8 | `in = BN254_r + 42` | Constraint error |
| 9 | `in = BN254_r - 1` | Constraint error |
| 10 | `in = 2^254` | Constraint error |

## Design Decisions

1. **253-bit width, not 254:** `r ~= 2^253.97`, so 254 bits would allow values
   in `[r, 2^254 - 1]` that are valid bit decompositions but alias mod `r`.
   253 bits is the tightest safe bound.

2. **Shared template over inline:** A `RangeCheck(n)` template in a dedicated
   file avoids duplicating the `Num2Bits` include and instantiation pattern
   across all circuits. The template is parameterized so it can be reused at
   other widths if needed.

3. **Placement before all other constraints:** Range checks are the first
   constraint block (section 0) in each circuit, ensuring the prover cannot
   exploit the signal in any downstream constraint before it is validated.

4. **No check on Poseidon outputs:** Poseidon is a permutation over F_r, so
   its outputs are inherently in `[0, r-1]`. Adding a range check would waste
   253 constraints per output with no security benefit.

5. **No check on `currentTimestamp`:** The existing `LessThan(64)` expiry
   comparison internally uses `Num2Bits(64)` on both inputs, which already
   bounds `currentTimestamp` to `[0, 2^64 - 1]`.

## Status

Implemented — awaiting circuit compilation and test verification.
