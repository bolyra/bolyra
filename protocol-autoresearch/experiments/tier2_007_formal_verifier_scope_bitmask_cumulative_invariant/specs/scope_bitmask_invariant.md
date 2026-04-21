# Formal Invariant: Cumulative Scope Bitmask

## Property Statement

Let `w = (bit2, bit3, bit4)` be any satisfying witness for the
`ScopeBitmaskChip` constraint system. Then:

```
P(w) ≡ (bit4 = 1 → bit3 = 1) ∧ (bit3 = 1 → bit2 = 1)
```

Equivalently, the only valid scope encodings are:

| bit4 | bit3 | bit2 | Tier Name            |
|------|------|------|----------------------|
| 0    | 0    | 0    | None / Read-only     |
| 0    | 0    | 1    | Basic (Tier 2)       |
| 0    | 1    | 1    | Standard (Tier 2+3)  |
| 1    | 1    | 1    | Unlimited (Tier 2+3+4) |

## Constraint System

The chip defines five polynomial constraints, all activated by a single
row selector `s`:

| ID | Gate Name                        | Polynomial                     |
|----|----------------------------------|--------------------------------|
| G0 | `cumulative_bit4_implies_bit3`   | `s · bit4 · (1 − bit3) = 0`   |
| G1 | `cumulative_bit3_implies_bit2`   | `s · bit3 · (1 − bit2) = 0`   |
| G2 | `bool_bit2`                      | `s · bit2 · (1 − bit2) = 0`   |
| G3 | `bool_bit3`                      | `s · bit3 · (1 − bit3) = 0`   |
| G4 | `bool_bit4`                      | `s · bit4 · (1 − bit4) = 0`   |

All constraints are evaluated on the same row with `Rotation::cur()`.

## Proof Sketch

### Lemma 1: Boolean Range

From G2–G4, for each `b ∈ {bit2, bit3, bit4}` on any active row
(where `s = 1`):

```
b · (1 − b) = 0  ⟹  b ∈ {0, 1}
```

This is immediate from the constraint polynomial having roots at 0 and 1
over any field.

### Lemma 2: bit4 = 1 implies bit3 = 1

From G0 with `s = 1`:

```
bit4 · (1 − bit3) = 0
```

Assume `bit4 = 1` (the antecedent). Then:

```
1 · (1 − bit3) = 0
⟹ 1 − bit3 = 0
⟹ bit3 = 1  ∎
```

### Lemma 3: bit3 = 1 implies bit2 = 1

From G1 with `s = 1`:

```
bit3 · (1 − bit2) = 0
```

Assume `bit3 = 1`. Then:

```
1 · (1 − bit2) = 0
⟹ bit2 = 1  ∎
```

### Theorem: Cumulative Invariant

Combining Lemmas 1–3: for any satisfying witness `w` on an active row,
`w.bit4 = 1 ⟹ w.bit3 = 1 ⟹ w.bit2 = 1`.

Therefore `P(w)` holds for all satisfying witnesses. The only valid
assignments are the four rows in the table above.

## Security Implication

A delegatee **cannot** receive `financial-unlimited` scope (bit4) without
also holding `standard` (bit3) and `basic` (bit2). Privilege escalation
that skips intermediate tiers is impossible for any witness accepted by
the verifier.

## Cross-Reference

- Circuit implementation: `src/delegation/scope_bitmask.rs`
- Negative test vectors: `tests/scope_bitmask_negative.rs` (12 negative, 4 positive)
- Audit report: `docs/scope_bitmask_audit_report.md`
