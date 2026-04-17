# Write formal invariant properties for all three circuits

Define and machine-check the following properties using circom-compat tooling or a custom R1CS analyzer: (1) No unconstrained signals — every private input flows into at least one constraint that gates an output. (2) Nullifier uniqueness — for fixed (scope, secret) or (credentialCommitment, nonce), exactly one nullifier value satisfies the constraints. (3) Scope monotonicity — in Delegation, prove that for any satisfying witness, delegateeScope & ~delegatorScope == 0 is enforced (no bit escalation). (4) Field overflow absence — all Num2Bits(64) decompositions fully constrain their input to [0, 2^64). Deliver as a test harness with property assertions that run in CI, using either ecne (R1CS constraint analyzer) or picus (underconstrained signal detector).

## Status

Placeholder — awaiting implementation.
