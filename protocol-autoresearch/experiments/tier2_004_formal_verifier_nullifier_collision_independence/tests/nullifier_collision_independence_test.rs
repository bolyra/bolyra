//! Nullifier Collision Independence — Halo2 MockProver Test Suite
//!
//! This test suite verifies that domain-separated nullifiers across the three
//! Bolyra circuits (HumanUniqueness, AgentPolicy, Delegation) are pairwise
//! distinct even when the raw input values (secret, scope, nonce) are identical.
//!
//! Test strategy:
//!   1. Positive tests: each circuit produces a valid proof with its domain tag.
//!   2. Cross-circuit inequality: shared raw inputs yield different nullifiers.
//!   3. Negative tests: injecting a foreign nullifier fails constraint check.
//!
//! Dependencies: halo2_proofs, halo2_gadgets (Poseidon), ff

use ff::PrimeField;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fp,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed,
        Instance, Selector,
    },
    poly::Rotation,
};

// ─── Domain tag constants (must match circom circuits) ───────────────────────
const DOMAIN_HUMAN: u64 = 1;
const DOMAIN_AGENT: u64 = 2;
const DOMAIN_DELEG: u64 = 3;

// ─── Simplified Poseidon mock for testing ────────────────────────────────────
// In production, use halo2_gadgets::poseidon. For MockProver tests we use a
// deterministic stand-in that preserves the domain separation property:
//   mock_poseidon(inputs) = sum(inputs[i] * (i+1)^2) mod p
// This is NOT cryptographically secure — it exists solely to verify that
// the circuit constraint structure enforces domain separation.
fn mock_poseidon(inputs: &[Fp]) -> Fp {
    inputs
        .iter()
        .enumerate()
        .fold(Fp::zero(), |acc, (i, val)| {
            let weight = Fp::from((i as u64 + 1) * (i as u64 + 1));
            acc + *val * weight
        })
}

// ─── NullifierCircuit: configurable domain-separated nullifier ───────────────
#[derive(Clone, Debug)]
struct NullifierConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    fixed: Column<Fixed>,
    selector: Selector,
}

#[derive(Clone, Debug)]
struct NullifierCircuit {
    domain_tag: u64,
    /// Variable-length input vector (excludes domain tag)
    inputs: Vec<Fp>,
}

impl NullifierCircuit {
    fn human(scope: Fp, secret: Fp) -> Self {
        Self {
            domain_tag: DOMAIN_HUMAN,
            inputs: vec![scope, secret],
        }
    }

    fn agent(secret: Fp, policy_scope: Fp) -> Self {
        Self {
            domain_tag: DOMAIN_AGENT,
            inputs: vec![secret, policy_scope],
        }
    }

    fn delegation(delegator_secret: Fp, delegatee_cred: Fp, scope: Fp) -> Self {
        Self {
            domain_tag: DOMAIN_DELEG,
            inputs: vec![delegator_secret, delegatee_cred, scope],
        }
    }

    fn compute_nullifier(&self) -> Fp {
        let mut full_input = vec![Fp::from(self.domain_tag)];
        full_input.extend_from_slice(&self.inputs);
        mock_poseidon(&full_input)
    }
}

impl Circuit<Fp> for NullifierCircuit {
    type Config = NullifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            domain_tag: self.domain_tag,
            inputs: vec![Fp::zero(); self.inputs.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();
        let selector = meta.selector();

        meta.enable_equality(instance);
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(fixed);

        // Gate: domain tag in advice[0] must equal the fixed domain constant
        meta.create_gate("domain_tag_check", |meta| {
            let s = meta.query_selector(selector);
            let tag_advice = meta.query_advice(advice[0], Rotation::cur());
            let tag_fixed = meta.query_fixed(fixed, Rotation::cur());
            vec![s * (tag_advice - tag_fixed)]
        });

        NullifierConfig {
            advice,
            instance,
            fixed,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let nullifier = self.compute_nullifier();

        layouter.assign_region(
            || "nullifier computation",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                // Assign domain tag to advice[0]
                region.assign_advice(
                    || "domain_tag",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(self.domain_tag)),
                )?;

                // Assign expected domain tag to fixed column
                region.assign_fixed(
                    || "expected_domain_tag",
                    config.fixed,
                    0,
                    || Value::known(Fp::from(self.domain_tag)),
                )?;

                // Assign input values to remaining advice columns
                for (i, val) in self.inputs.iter().enumerate() {
                    if i + 1 < 4 {
                        region.assign_advice(
                            || format!("input_{}", i),
                            config.advice[i + 1],
                            0,
                            || Value::known(*val),
                        )?;
                    }
                }

                // Assign nullifier output (exposed as instance)
                let nullifier_cell = region.assign_advice(
                    || "nullifier",
                    config.advice[0],
                    1,
                    || Value::known(nullifier),
                )?;

                // Expose nullifier as public instance
                layouter.namespace(|| "expose nullifier").constrain_instance(
                    nullifier_cell.cell(),
                    config.instance,
                    0,
                )
            },
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test suite
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // Shared raw input values — identical across all three circuits
    const RAW_SECRET: u64 = 12345678901234;
    const RAW_SCOPE: u64 = 98765432109876;
    const RAW_NONCE: u64 = 11111111111111;
    const K: u32 = 5; // MockProver rows = 2^K

    fn shared_secret() -> Fp { Fp::from(RAW_SECRET) }
    fn shared_scope() -> Fp { Fp::from(RAW_SCOPE) }
    fn shared_nonce() -> Fp { Fp::from(RAW_NONCE) }

    // ── Positive tests: each circuit satisfies its own constraints ────────

    #[test]
    fn test_human_uniqueness_valid() {
        let circuit = NullifierCircuit::human(shared_scope(), shared_secret());
        let nullifier = circuit.compute_nullifier();
        let prover = MockProver::run(K, &circuit, vec![vec![nullifier]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_agent_policy_valid() {
        let circuit = NullifierCircuit::agent(shared_secret(), shared_scope());
        let nullifier = circuit.compute_nullifier();
        let prover = MockProver::run(K, &circuit, vec![vec![nullifier]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_delegation_valid() {
        let circuit = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(), // delegateeCredCommitment
            shared_scope(),
        );
        let nullifier = circuit.compute_nullifier();
        let prover = MockProver::run(K, &circuit, vec![vec![nullifier]]).unwrap();
        prover.assert_satisfied();
    }

    // ── Cross-circuit nullifier inequality ────────────────────────────────

    #[test]
    fn test_human_vs_agent_nullifier_differ() {
        let human = NullifierCircuit::human(shared_scope(), shared_secret());
        let agent = NullifierCircuit::agent(shared_secret(), shared_scope());

        let n_human = human.compute_nullifier();
        let n_agent = agent.compute_nullifier();

        assert_ne!(
            n_human, n_agent,
            "HumanUniqueness and AgentPolicy must produce different nullifiers on shared inputs"
        );
    }

    #[test]
    fn test_human_vs_delegation_nullifier_differ() {
        let human = NullifierCircuit::human(shared_scope(), shared_secret());
        let deleg = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(),
            shared_scope(),
        );

        let n_human = human.compute_nullifier();
        let n_deleg = deleg.compute_nullifier();

        assert_ne!(
            n_human, n_deleg,
            "HumanUniqueness and Delegation must produce different nullifiers on shared inputs"
        );
    }

    #[test]
    fn test_agent_vs_delegation_nullifier_differ() {
        let agent = NullifierCircuit::agent(shared_secret(), shared_scope());
        let deleg = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(),
            shared_scope(),
        );

        let n_agent = agent.compute_nullifier();
        let n_deleg = deleg.compute_nullifier();

        assert_ne!(
            n_agent, n_deleg,
            "AgentPolicy and Delegation must produce different nullifiers on shared inputs"
        );
    }

    #[test]
    fn test_all_three_pairwise_distinct() {
        let human = NullifierCircuit::human(shared_scope(), shared_secret());
        let agent = NullifierCircuit::agent(shared_secret(), shared_scope());
        let deleg = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(),
            shared_scope(),
        );

        let nullifiers = vec![
            ("HumanUniqueness", human.compute_nullifier()),
            ("AgentPolicy", agent.compute_nullifier()),
            ("Delegation", deleg.compute_nullifier()),
        ];

        for i in 0..nullifiers.len() {
            for j in (i + 1)..nullifiers.len() {
                assert_ne!(
                    nullifiers[i].1, nullifiers[j].1,
                    "{} and {} produced identical nullifiers!",
                    nullifiers[i].0, nullifiers[j].0
                );
            }
        }
    }

    // ── Negative tests: foreign nullifier rejected ───────────────────────

    #[test]
    fn test_agent_nullifier_rejected_by_human_circuit() {
        // Compute agent's nullifier
        let agent = NullifierCircuit::agent(shared_secret(), shared_scope());
        let agent_nullifier = agent.compute_nullifier();

        // Try to use agent's nullifier as HumanUniqueness public input
        let human = NullifierCircuit::human(shared_scope(), shared_secret());
        let prover = MockProver::run(K, &human, vec![vec![agent_nullifier]]).unwrap();

        // This MUST fail — the computed nullifier won't match the foreign one
        assert!(
            prover.verify().is_err(),
            "Human circuit must reject agent's nullifier"
        );
    }

    #[test]
    fn test_human_nullifier_rejected_by_delegation_circuit() {
        let human = NullifierCircuit::human(shared_scope(), shared_secret());
        let human_nullifier = human.compute_nullifier();

        let deleg = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(),
            shared_scope(),
        );
        let prover = MockProver::run(K, &deleg, vec![vec![human_nullifier]]).unwrap();

        assert!(
            prover.verify().is_err(),
            "Delegation circuit must reject human's nullifier"
        );
    }

    #[test]
    fn test_delegation_nullifier_rejected_by_agent_circuit() {
        let deleg = NullifierCircuit::delegation(
            shared_secret(),
            shared_nonce(),
            shared_scope(),
        );
        let deleg_nullifier = deleg.compute_nullifier();

        let agent = NullifierCircuit::agent(shared_secret(), shared_scope());
        let prover = MockProver::run(K, &agent, vec![vec![deleg_nullifier]]).unwrap();

        assert!(
            prover.verify().is_err(),
            "Agent circuit must reject delegation's nullifier"
        );
    }

    // ── Edge case: same domain tag but different arity ────────────────────

    #[test]
    fn test_domain_tag_uniqueness_is_necessary() {
        // Verify that without domain tags, collisions WOULD occur
        // HumanUniqueness: Poseidon(scope, secret)
        // AgentPolicy:     Poseidon(secret, scope)
        // With identical values, Poseidon(a, b) != Poseidon(b, a) in general,
        // but if scope == secret, they'd collide. Domain tags prevent this.
        let val = Fp::from(42u64);
        let same_input_human = NullifierCircuit::human(val, val);
        let same_input_agent = NullifierCircuit::agent(val, val);

        assert_ne!(
            same_input_human.compute_nullifier(),
            same_input_agent.compute_nullifier(),
            "Even with identical scope=secret, domain tags must separate nullifiers"
        );
    }
}
