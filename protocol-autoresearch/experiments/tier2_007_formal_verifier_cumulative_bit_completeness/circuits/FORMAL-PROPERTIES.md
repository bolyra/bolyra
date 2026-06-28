# Formal Circuit Properties

This document states the formally verified properties of Bolyra's Circom circuits.
Each property references the test artifact that serves as its proof.

---

## Property: Cumulative-Bit Encoding Soundness (CB-SOUND)

**Statement:** For every satisfying witness of `CumulativeBitCheck`, the 8-bit
permission encoding satisfies all cumulative implication rules. No assignment of
`permBits[0..7]` can satisfy the circuit constraints while violating any of:

| Rule | Antecedent | Consequent | Constraint |
|------|-----------|------------|------------|
| R1 | `permBits[3]` (FINANCIAL_MEDIUM) | `permBits[2]` (FINANCIAL_SMALL) | `permBits[3] * (1 - permBits[2]) === 0` |
| R2 | `permBits[4]` (FINANCIAL_UNLIMITED) | `permBits[3]` (FINANCIAL_MEDIUM) | `permBits[4] * (1 - permBits[3]) === 0` |
| R3 | `permBits[4]` (FINANCIAL_UNLIMITED) | `permBits[2]` (FINANCIAL_SMALL) | `permBits[4] * (1 - permBits[2]) === 0` |

**Proof method:** Exhaustive enumeration. The test harness
`circuits/test/cumulative_bit_completeness.test.js` iterates all 256 possible
permission byte values. For each value where the SDK's
`validateCumulativeBitEncoding()` returns `false` (i.e., the encoding violates an
implication rule), the harness confirms that `CumulativeBitCheckByte` witness
generation or constraint checking fails.

**Result:** 128 invalid encodings are rejected. Zero false acceptances.

---

## Property: Cumulative-Bit Encoding Completeness (CB-COMPLETE)

**Statement:** Every valid cumulative-bit encoding is accepted by
`CumulativeBitCheck`. If an 8-bit permission byte satisfies all implication rules
(as determined by `validateCumulativeBitEncoding()`), then there exists a
satisfying witness for `CumulativeBitCheckByte` with that byte as input.

**Proof method:** Exhaustive enumeration. The same test harness iterates all 256
values. For each value where the SDK returns `true`, the harness confirms that
witness generation succeeds and all constraints are satisfied.

**Result:** 128 valid encodings are accepted. Zero false rejections.

---

## Bit-Index Mapping (Circom ↔ SDK ↔ Solidity)

All layers use LSB-first convention. Circom's `Num2Bits(8)` outputs `out[0]` as
the least-significant bit.

| Bit Index | `Num2Bits` output | Permission | Hex Mask |
|-----------|-------------------|------------|----------|
| 0 | `out[0]` (LSB) | `READ_DATA` | `0x01` |
| 1 | `out[1]` | `WRITE_DATA` | `0x02` |
| 2 | `out[2]` | `FINANCIAL_SMALL` (< $100) | `0x04` |
| 3 | `out[3]` | `FINANCIAL_MEDIUM` (< $10K) | `0x08` |
| 4 | `out[4]` | `FINANCIAL_UNLIMITED` | `0x10` |
| 5 | `out[5]` | `SIGN_ON_BEHALF` | `0x20` |
| 6 | `out[6]` | `SUB_DELEGATE` | `0x40` |
| 7 | `out[7]` (MSB) | `ACCESS_PII` | `0x80` |

### Implication DAG

```
FINANCIAL_UNLIMITED (bit 4)
    └──▶ FINANCIAL_MEDIUM (bit 3)
             └──▶ FINANCIAL_SMALL (bit 2)
```

Setting a higher-tier financial bit without its prerequisites is invalid.
Rule R3 (`bit4 → bit2`) is technically redundant given R1+R2, but is enforced
explicitly as defense-in-depth.

---

## Proof Artifacts

| Property | Test file | Command |
|----------|-----------|--------|
| CB-SOUND | `circuits/test/cumulative_bit_completeness.test.js` | `npm run test:circuits:fast` |
| CB-COMPLETE | `circuits/test/cumulative_bit_completeness.test.js` | `npm run test:circuits:fast` |
