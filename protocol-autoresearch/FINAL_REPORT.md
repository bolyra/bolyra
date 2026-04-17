# Protocol AutoResearch Run Summary

Iterations: 3 (plus baseline)
Baseline total: 39
Latest total: 42
Delta: +3.0

## Score Trajectory

  iter   0: [###################...............................] 39
  iter   1: [###################...............................] 39
  iter   2: [##################................................] 36
  iter   3: [#####################.............................] 42

## Dimension Breakdown (latest)

- **correctness**: 18/25 — Three circuits (HumanUniqueness, AgentPolicy, Delegation) are structurally sound with range checks, 
- **completeness**: 13/25 — Core protocol layer is present: three circuits with generated verifiers (Groth16 for human, PLONK fo
- **adoption**: 4/25 — No SDK, no npm/pip package, no framework integrations, no CLI tooling, no developer documentation be
- **standards**: 7/25 — Circuit comments are thorough and explain architectural decisions well (proving system choice, const

## Run Directories

- iter_001_20260417T074942
- iter_002_20260417T084558
- iter_003_20260417T094202
