# Experiment: Nullifier Collision Independence

**ID:** `formal_verifier_nullifier_collision_independence`  
**Persona:** Formal Verifier  
**Dimension:** Correctness  
**Priority:** High  

## Summary

Proves that the three Bolyra identity protocol circuits (HumanUniqueness, AgentPolicy,
Delegation) produce pairwise-distinct nullifiers even on identical raw inputs,
by introducing domain tag constants and providing a formal domain separation argument.

## Problem

Prior to this experiment, all three circuits used `Poseidon(secret, scope)` (arity 2)
for nullifier computation. Identical `(secret, scope)` pairs across circuits would
produce identical nullifiers, enabling potential cross-circuit replay attacks.

## Solution

Prepend a circuit-specific domain tag to each Poseidon input vector:

| Circuit          | Tag | Nullifier Construction                                  | Arity |
|------------------|-----|---------------------------------------------------------|-------|
| HumanUniqueness  | 1   | `Poseidon([1, scope, secret])`                           | 3     |
| AgentPolicy      | 2   | `Poseidon([2, agentSecret, policyScope])`                | 3     |
| Delegation       | 3   | `Poseidon([3, delegatorSecret, delegateeCredComm, scope])`| 4     |

## Artifacts

### Circuits
- `circuits/human_uniqueness.circom` — HumanUniqueness with DOMAIN_HUMAN = 1
- `circuits/agent_policy.circom` — AgentPolicy with DOMAIN_AGENT = 2  
- `circuits/delegation.circom` — Delegation with DOMAIN_DELEG = 3

### Tests
- `tests/nullifier_collision_independence_test.rs` — Halo2 MockProver suite
  - Positive: each circuit satisfies constraints with correct domain tag
  - Cross-circuit: all three nullifiers are pairwise distinct on shared inputs
  - Negative: foreign nullifier injection rejected by domain tag constraint
- `tests/nullifier_domain_separation_symbolic.py` — Python/SymPy symbolic analysis

### Documentation
- `docs/nullifier_domain_separation.md` — Symbolic analysis with proof tables
- `docs/nullifier_formal_proof.md` — Formal theorem, proof sketch, security assumptions

## Prerequisites

### Circom circuits
```bash
npm install circomlib
circom circuits/human_uniqueness.circom --r1cs --wasm --sym
circom circuits/agent_policy.circom --r1cs --wasm --sym
circom circuits/delegation.circom --r1cs --wasm --sym
```

### Halo2 MockProver tests
```bash
# Requires Rust nightly and halo2_proofs
cargo test --test nullifier_collision_independence_test
```

### Symbolic analysis
```bash
pip install sympy prettytable
python tests/nullifier_domain_separation_symbolic.py
```

## Expected Output

### Symbolic analysis
```
RESULT: ✓ Domain separation PROVEN for all circuit pairs.
```

### MockProver tests
```
test tests::test_human_uniqueness_valid ... ok
test tests::test_agent_policy_valid ... ok
test tests::test_delegation_valid ... ok
test tests::test_human_vs_agent_nullifier_differ ... ok
test tests::test_human_vs_delegation_nullifier_differ ... ok
test tests::test_agent_vs_delegation_nullifier_differ ... ok
test tests::test_all_three_pairwise_distinct ... ok
test tests::test_agent_nullifier_rejected_by_human_circuit ... ok
test tests::test_human_nullifier_rejected_by_delegation_circuit ... ok
test tests::test_delegation_nullifier_rejected_by_agent_circuit ... ok
test tests::test_domain_tag_uniqueness_is_necessary ... ok
```

## Constraint Budget

| Circuit          | Added Constraints | Total Estimate |
|------------------|-------------------|----------------|
| HumanUniqueness  | ~101 (Poseidon₃ vs Poseidon₂ delta + tag gate) | ~40,601 |
| AgentPolicy      | ~101 (Poseidon₃ vs Poseidon₂ delta + tag gate) | ~40,859 |
| Delegation       | ~201 (Poseidon₄ vs Poseidon₂ delta + tag gate) | ~41,051 |

All circuits remain within the 2^16 (65,536) constraint ceiling.

## Dependencies

- circomlib (Poseidon)
- halo2_proofs (MockProver)
- poseidon2-halo2
- sympy + prettytable (symbolic analysis)
- Existing Bolyra circuits (HumanUniqueness, AgentPolicy, Delegation)
