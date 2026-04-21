# Scope Bitmask Cumulative Invariant — Halo2 Verification

This experiment verifies that the Bolyra Delegation circuit's scope
bitmask enforces cumulative encoding: a delegatee cannot hold a higher
privilege tier without the intermediate tiers.

## Invariant

```
bit4 = 1  →  bit3 = 1
bit3 = 1  →  bit2 = 1
```

Only four valid scope assignments exist: `000`, `001`, `011`, `111`.

## Structure

```
src/delegation/scope_bitmask.rs   — Halo2 chip (5 custom gates)
tests/scope_bitmask_negative.rs   — 12 negative + 4 positive MockProver tests
specs/scope_bitmask_invariant.md  — Formal property + proof sketch
docs/scope_bitmask_audit_report.md — Constraint coverage & test matrix
```

## Prerequisites

- Rust toolchain (edition 2021)
- `halo2_proofs` (PSE fork v0.3.0)

## Usage

```bash
# Run all tests (12 negative vectors + 4 positive controls)
cargo test --test scope_bitmask_negative

# Run with output to see constraint failures
cargo test --test scope_bitmask_negative -- --nocapture
```

## Constraints

| Gate | Polynomial | Purpose |
|------|------------|---------|
| G0   | `bit4 · (1 − bit3) = 0` | bit4 implies bit3 |
| G1   | `bit3 · (1 − bit2) = 0` | bit3 implies bit2 |
| G2   | `bit2 · (1 − bit2) = 0` | bit2 is boolean |
| G3   | `bit3 · (1 − bit3) = 0` | bit3 is boolean |
| G4   | `bit4 · (1 − bit4) = 0` | bit4 is boolean |

## Security Impact

Prevents privilege escalation where a delegatee could receive
`financial-unlimited` scope without holding `standard` and `basic`
tiers — closing the intermediate-tier bypass attack vector.
