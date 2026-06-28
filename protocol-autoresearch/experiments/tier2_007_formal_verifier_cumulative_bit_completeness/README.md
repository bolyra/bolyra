# Experiment: Cumulative-Bit Encoding Completeness

**ID:** `formal_verifier_cumulative_bit_completeness`  
**Dimension:** correctness  
**Priority:** high  
**Persona:** formal_verifier

## Summary

Proves that the `CumulativeBitCheck` circuit's constraints on the 8-bit permission
byte are **necessary and sufficient** — i.e., they accept exactly the valid
cumulative-bit encodings and reject all others.

Two properties are verified exhaustively over all 256 byte values:

1. **SOUNDNESS (CB-SOUND):** No witness satisfying the circuit can violate the
   implication rules (bit4→bit3, bit4→bit2, bit3→bit2).
2. **COMPLETENESS (CB-COMPLETE):** Every valid encoding (per the SDK's
   `validateCumulativeBitEncoding()`) is accepted by the circuit.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuits/src/CumulativeBitCheck.circom` | circuit | Standalone sub-circuit enforcing implication rules |
| `circuits/test/cumulative_bit_completeness.test.js` | test | Exhaustive 256-value sweep comparing circuit vs SDK |
| `circuits/FORMAL-PROPERTIES.md` | spec | Formal statement of CB-SOUND and CB-COMPLETE |
| `circuits/test/README.md` | docs | Run instructions and extension guide |

## How to Run

```bash
# Fast mode — witness generation only, no proof
npm run test:circuits:fast

# Or run just this harness
npx mocha circuits/test/cumulative_bit_completeness.test.js --timeout 120000
```

## Key Design Decisions

- **Standalone template:** `CumulativeBitCheck` is a separate template that can be
  imported by `Delegation.circom` (and any future circuit needing scope validation),
  ensuring a single source of truth.

- **Byte wrapper:** `CumulativeBitCheckByte` accepts a single integer input,
  decomposes it to bits, and applies the check — convenient for exhaustive testing.

- **Defense-in-depth R3:** Rule 3 (bit4→bit2) is redundant given R1+R2 but is
  enforced explicitly to match the SDK validator and catch any future rule changes
  that might break transitivity.

- **LSB-first convention:** Bit index 0 = `READ_DATA` (LSB), matching circomlib's
  `Num2Bits` output ordering. This is confirmed by the exhaustive sweep.

## Estimated Constraints

~14 R1CS constraints (8 binary + 3 reconstruction + 3 implication rules).
