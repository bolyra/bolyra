# Write machine-checkable circuit invariant properties for CI

Define and test 12 formal invariant properties across the 4 circuits: (1) no witness satisfies constraints with permissionBitmask ≥ 2^64, (2) nullifier uniqueness — distinct (scope, secret) pairs always produce distinct nullifiers, (3) scope monotonicity — delegateeScope & ~delegatorScope == 0 is enforced (never produces a satisfying witness otherwise), (4) cumulative bit encoding — bit 4 set without bits 2+3 is unsatisfiable, (5) expiry narrowing — delegateeExpiry > delegatorExpiry is unsatisfiable. Implement as a Mocha test suite using circom_tester's witness calculator: for each property, construct a violating witness and assert that calculateWitness throws. This is the practical equivalent of property-based testing for R1CS constraints and catches regressions on every CI run.

## Status

Placeholder — awaiting implementation.
