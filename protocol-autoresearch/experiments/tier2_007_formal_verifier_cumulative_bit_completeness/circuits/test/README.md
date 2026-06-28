# Circuit Tests

This directory contains test suites for Bolyra's Circom circuits.

## Test Modes

| Mode | Command | What it does | Speed |
|------|---------|-------------|-------|
| Fast (witness-only) | `npm run test:circuits:fast` | Generates witnesses, checks constraints — no proof | ~10s |
| Slow (full proof) | `npm run test:circuits:slow` | Full Groth16/PLONK proving + verification | ~2min |

## Cumulative-Bit Completeness Harness

**File:** `cumulative_bit_completeness.test.js`

**Purpose:** Exhaustively verifies that the `CumulativeBitCheck` circuit accepts
exactly the same set of permission byte values as the SDK's
`validateCumulativeBitEncoding()`. This proves two properties:

1. **SOUNDNESS (CB-SOUND):** No invalid encoding is accepted by the circuit.
2. **COMPLETENESS (CB-COMPLETE):** No valid encoding is rejected by the circuit.

### Running

```bash
# Fast mode (witness-only, no proof generation)
npm run test:circuits:fast

# Or run just this test file
npx mocha circuits/test/cumulative_bit_completeness.test.js --timeout 120000
```

### Interpreting Failures

A failure in this harness means the circuit and SDK disagree on whether a
permission byte is valid. The output will show:

- **COMPLETENESS FAILURE:** A value the SDK considers valid but the circuit
  rejects. This means the circuit has an overly tight constraint. Fix
  `CumulativeBitCheck.circom`.

- **SOUNDNESS FAILURE:** A value the SDK considers invalid but the circuit
  accepts. This means the circuit is missing a constraint. Fix
  `CumulativeBitCheck.circom`.

- **SDK DISAGREEMENT:** If neither of the above, the SDK's
  `validateCumulativeBitEncoding()` may have a bug. Fix `sdk/src/permissions.ts`.

Each failure log includes the full bit breakdown and active permission names.

### Extending for New Permission Bits

When adding a new permission bit with implication rules:

1. Add the constraint to `circuits/src/CumulativeBitCheck.circom`.
2. Add the corresponding check to `validateCumulativeBitEncoding()` in
   `sdk/src/permissions.ts`.
3. Update the Solidity verifier if on-chain validation mirrors the rules.
4. Re-run this harness — it automatically covers all 256 values.
5. Update `circuits/FORMAL-PROPERTIES.md` with the new rule.

Both the circuit and SDK must be updated **in lockstep**. The harness will catch
any mismatch.

### Expected Counts

With the current 3-rule implication set (bits 2, 3, 4):
- **128** valid encodings (4 valid combos for bits 2-3-4 × 32 free-bit combos)
- **128** invalid encodings
- **256** total = complete coverage
