# Field Overflow Mitigation: Modular Aliasing on Public Signals

## Vulnerability Class

**Modular aliasing** occurs when a ZKP circuit operates over a prime field
F_r (where r is the BN254 scalar field order, ~2^254) but the on-chain
verifier receives public inputs as `uint256` values. If a public input `x`
is not range-checked inside the circuit, a malicious prover can submit
`x + k*r` (for any positive integer k such that `x + k*r < 2^256`) as the
public input. The circuit accepts this because `x + k*r === x (mod r)`,
but the Solidity verifier sees a different `uint256` value.

### Impact

- **Nonce replay:** A proof bound to `sessionNonce = N` also verifies for
  `sessionNonce = N + r` on-chain, allowing replay without generating a
  new proof.
- **Nullifier domain confusion:** `externalNullifier + r` produces the
  same `nullifierHash` inside the circuit but a different on-chain
  identifier, potentially bypassing double-spend checks.
- **Cross-context proof migration:** A proof generated for one context
  (identified by a public input value) could verify in a different context
  that happens to be the aliased equivalent.

## Affected Signals (Pre-Fix)

| Signal | Circuit(s) | Risk |
|---|---|---|
| `sessionNonce` | HumanUniqueness, AgentPolicy, Delegation | Nonce replay |
| `externalNullifier` | HumanUniqueness | Nullifier domain confusion |

All other public signals were already bounded:
- Poseidon outputs (`humanMerkleRoot`, `agentMerkleRoot`, `delegationMerkleRoot`,
  `credentialHash`, `delegationHash`, `nullifierHash`, `nonceBinding`) are
  inherently < r because Poseidon operates within the field.
- `currentTimestamp` is bounded by `LessThan(64)` which internally uses
  `Num2Bits(64)`.
- `requiredPermissions` and `narrowedPermissions` are bounded by
  `Num2Bits(8)`.

## Fix Applied

A shared `RangeCheck(n)` template was created in `circuits/src/RangeChecks.circom`:

```circom
template RangeCheck(n) {
    signal input in;
    component bits = Num2Bits(n);
    bits.in <== in;
}
```

Each unranged public input now passes through `RangeCheck(253)` at the top
of its circuit, before any other constraint uses the signal. This
decomposes the value into 253 binary bits, enforcing `0 <= value < 2^253`.
Since `2^253 < r < 2^254`, any value in [0, 2^253 - 1] is a canonical
field element with no modular alias in the uint256 range.

### Constraint Cost

4 new `RangeCheck(253)` instances across 3 circuits = **1012 R1CS constraints**.

| Circuit | Instances | Signals | Added constraints |
|---|---|---|---|
| HumanUniqueness | 2 | `sessionNonce`, `externalNullifier` | 506 |
| AgentPolicy | 1 | `sessionNonce` | 253 |
| Delegation | 1 | `sessionNonce` | 253 |

### Why 253 bits?

The BN254 scalar field order `r` is approximately `2^253.97`. A 253-bit
decomposition constrains the input to [0, 2^253 - 1], which is strictly
less than `r`. This means:

1. Every value that passes the check is a unique, canonical field element.
2. No two uint256 values in [0, 2^253 - 1] are congruent mod `r`.
3. Values >= 2^253 are rejected, including all `x + r` aliases.

Using 254 bits would be insufficient because `2^254 > r`, so some values
in [r, 2^254 - 1] would pass the bit check but still be aliased.

## Verification

After applying the fix:

1. `npm run compile:circuits` — recompile all circuits with new constraints
2. `npm run test:circuits:fast` — witness-generation tests including new
   `range_checks.test.js` that verifies boundary values and aliased
   inputs are correctly accepted/rejected
3. `npm run test:contracts` — Solidity verifier integration tests with
   regenerated `.zkey` artifacts

## References

- [FORMAL-PROPERTIES.md](../../circuits/FORMAL-PROPERTIES.md) — P-RANGE-FIELD
  invariant with full signal table
- [Circomlib Num2Bits](https://github.com/iden3/circomlib/blob/master/circuits/bitify.circom)
- Daira Hopwood, "BN254 For The Rest Of Us" — field order and bit-width
  analysis
