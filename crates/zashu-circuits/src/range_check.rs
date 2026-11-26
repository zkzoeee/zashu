use ff::PrimeField;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

/// Enforces `0 <= v < 2^64` via 64-bit boolean decomposition:
/// 4 bits per row across 16 rows (`b * (1 - b) = 0`), accumulating `sum = sum * 16 + b0 + 2*b1 + 4*b2 + 8*b3`.
#[derive(Debug, Clone)]
pub struct RangeCheck64Config {
    pub bits: [Column<Advice>; 4],
    pub acc: Column<Advice>,
    pub q_bit: Selector,
    pub q_acc: Selector,
}

impl RangeCheck64Config {
    pub fn configure<F: PrimeField>(
        meta: &mut ConstraintSystem<F>,
        bits: [Column<Advice>; 4],
        acc: Column<Advice>,
    ) -> Self {
        let q_bit = meta.selector();
        let q_acc = meta.selector();

        meta.create_gate("boolean_bits", |meta| {
            let q = meta.query_selector(q_bit);
            let one = Expression::Constant(F::ONE);
            bits.iter()
                .map(|col| {
                    let b = meta.query_advice(*col, Rotation::cur());
                    q.clone() * b.clone() * (one.clone() - b)
                })
                .collect::<Vec<_>>()
        });

        meta.create_gate("nibble_accumulate", |meta| {
            let q = meta.query_selector(q_acc);
            let prev_acc = meta.query_advice(acc, Rotation::cur());
            let next_acc = meta.query_advice(acc, Rotation::next());
            let b0 = meta.query_advice(bits[0], Rotation::cur());
            let b1 = meta.query_advice(bits[1], Rotation::cur());
            let b2 = meta.query_advice(bits[2], Rotation::cur());
            let b3 = meta.query_advice(bits[3], Rotation::cur());
            let nibble = b0
                + b1 * Expression::Constant(F::from(2))
                + b2 * Expression::Constant(F::from(4))
                + b3 * Expression::Constant(F::from(8));
            let expected = prev_acc * Expression::Constant(F::from(16)) + nibble;
            vec![q * (next_acc - expected)]
        });

        Self {
            bits,
            acc,
            q_bit,
            q_acc,
        }
    }

    /// Assigns and constrains `val_cell` to be a valid 64-bit unsigned integer.
    pub fn constrain_u64<F: PrimeField>(
        &self,
        mut layouter: impl Layouter<F>,
        name: &str,
        val: Value<u64>,
        expected_cell: Option<&AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let out = layouter.assign_region(
            || format!("range_check_u64_{name}"),
            |mut region| {
                let mut cur_acc = Value::known(F::ZERO);
                let mut acc_cell = region.assign_advice(
                    || "acc_init",
                    self.acc,
                    0,
                    || cur_acc,
                )?;
                region.constrain_constant(acc_cell.cell(), F::ZERO)?;

                for row in 0..16 {
                    self.q_bit.enable(&mut region, row)?;
                    self.q_acc.enable(&mut region, row)?;

                    let shift = (15 - row) * 4;
                    let nibble_bits = val.map(|v| {
                        let nib = ((v >> shift) & 0xF) as u64;
                        [
                            F::from(nib & 1),
                            F::from((nib >> 1) & 1),
                            F::from((nib >> 2) & 1),
                            F::from((nib >> 3) & 1),
                        ]
                    });

                    for (i, col) in self.bits.iter().enumerate() {
                        region.assign_advice(
                            || format!("bit_{row}_{i}"),
                            *col,
                            row,
                            || nibble_bits.map(|b| b[i]),
                        )?;
                    }

                    cur_acc = cur_acc.zip(nibble_bits).map(|(a, b)| {
                        let nib = b[0]
                            + b[1] * F::from(2)
                            + b[2] * F::from(4)
                            + b[3] * F::from(8);
                        a * F::from(16) + nib
                    });

                    acc_cell = region.assign_advice(
                        || format!("acc_{}", row + 1),
                        self.acc,
                        row + 1,
                        || cur_acc,
                    )?;
                }

                if let Some(target) = expected_cell {
                    region.constrain_equal(acc_cell.cell(), target.cell())?;
                }

                Ok(acc_cell)
            },
        )?;
        Ok(out)
    }
}
