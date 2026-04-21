//! ScopeBitmaskChip — Halo2 chip enforcing cumulative scope bitmask invariant.
//!
//! Invariant: bit4 => bit3, bit3 => bit2
//! Expressed as polynomial constraints:
//!   gate_0: (1 - bit4) * bit3_missing = 0  where bit3_missing = (1 - bit3)
//!           equivalently: bit4 * (1 - bit3) = 0
//!   gate_1: bit3 * (1 - bit2) = 0
//!
//! Any witness satisfying all circuit polynomials therefore satisfies:
//!   P(w) = (w.bit4=1 => w.bit3=1) AND (w.bit3=1 => w.bit2=1)

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ScopeBitmaskConfig {
    pub bit2: Column<Advice>,
    pub bit3: Column<Advice>,
    pub bit4: Column<Advice>,
    pub selector: Selector,
}

// ---------------------------------------------------------------------------
// Chip
// ---------------------------------------------------------------------------

pub struct ScopeBitmaskChip<F: FieldExt> {
    config: ScopeBitmaskConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for ScopeBitmaskChip<F> {
    type Config = ScopeBitmaskConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ScopeBitmaskChip<F> {
    pub fn construct(config: ScopeBitmaskConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Configure the chip: creates three advice columns and two custom gates.
    ///
    /// Gate 0 — "bit4 implies bit3":
    ///   selector * bit4 * (1 - bit3) = 0
    ///
    /// Gate 1 — "bit3 implies bit2":
    ///   selector * bit3 * (1 - bit2) = 0
    ///
    /// Gate 2-4 — Boolean constraints (each bit must be 0 or 1):
    ///   selector * bitN * (1 - bitN) = 0   for N in {2, 3, 4}
    pub fn configure(meta: &mut ConstraintSystem<F>) -> ScopeBitmaskConfig {
        let bit2 = meta.advice_column();
        let bit3 = meta.advice_column();
        let bit4 = meta.advice_column();
        let selector = meta.selector();

        meta.enable_equality(bit2);
        meta.enable_equality(bit3);
        meta.enable_equality(bit4);

        // Gate 0: bit4 => bit3  <==>  bit4 * (1 - bit3) = 0
        meta.create_gate("cumulative_bit4_implies_bit3", |meta| {
            let s = meta.query_selector(selector);
            let b4 = meta.query_advice(bit4, Rotation::cur());
            let b3 = meta.query_advice(bit3, Rotation::cur());
            vec![s * b4 * (Expression::Constant(F::one()) - b3)]
        });

        // Gate 1: bit3 => bit2  <==>  bit3 * (1 - bit2) = 0
        meta.create_gate("cumulative_bit3_implies_bit2", |meta| {
            let s = meta.query_selector(selector);
            let b3 = meta.query_advice(bit3, Rotation::cur());
            let b2 = meta.query_advice(bit2, Rotation::cur());
            vec![s * b3 * (Expression::Constant(F::one()) - b2)]
        });

        // Gate 2: bit2 is boolean
        meta.create_gate("bool_bit2", |meta| {
            let s = meta.query_selector(selector);
            let b2 = meta.query_advice(bit2, Rotation::cur());
            vec![s * b2.clone() * (Expression::Constant(F::one()) - b2)]
        });

        // Gate 3: bit3 is boolean
        meta.create_gate("bool_bit3", |meta| {
            let s = meta.query_selector(selector);
            let b3 = meta.query_advice(bit3, Rotation::cur());
            vec![s * b3.clone() * (Expression::Constant(F::one()) - b3)]
        });

        // Gate 4: bit4 is boolean
        meta.create_gate("bool_bit4", |meta| {
            let s = meta.query_selector(selector);
            let b4 = meta.query_advice(bit4, Rotation::cur());
            vec![s * b4.clone() * (Expression::Constant(F::one()) - b4)]
        });

        ScopeBitmaskConfig {
            bit2,
            bit3,
            bit4,
            selector,
        }
    }

    /// Assign a single row of scope bits.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        bit2_val: Value<F>,
        bit3_val: Value<F>,
        bit4_val: Value<F>,
    ) -> Result<
        (
            AssignedCell<F, F>,
            AssignedCell<F, F>,
            AssignedCell<F, F>,
        ),
        Error,
    > {
        let config = &self.config;
        layouter.assign_region(
            || "scope_bitmask",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                let c2 = region.assign_advice(|| "bit2", config.bit2, 0, || bit2_val)?;
                let c3 = region.assign_advice(|| "bit3", config.bit3, 0, || bit3_val)?;
                let c4 = region.assign_advice(|| "bit4", config.bit4, 0, || bit4_val)?;
                Ok((c2, c3, c4))
            },
        )
    }
}

// ---------------------------------------------------------------------------
// Standalone test circuit wrapping the chip
// ---------------------------------------------------------------------------

/// A minimal circuit that exposes bit2, bit3, bit4 as public witness inputs
/// and applies the ScopeBitmaskChip constraints.
#[derive(Clone, Default)]
pub struct ScopeBitmaskCircuit<F: FieldExt> {
    pub bit2: Value<F>,
    pub bit3: Value<F>,
    pub bit4: Value<F>,
}

impl<F: FieldExt> Circuit<F> for ScopeBitmaskCircuit<F> {
    type Config = ScopeBitmaskConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        ScopeBitmaskChip::<F>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = ScopeBitmaskChip::construct(config);
        chip.assign(layouter, self.bit2, self.bit3, self.bit4)?;
        Ok(())
    }
}
