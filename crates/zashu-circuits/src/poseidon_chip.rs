use ff::{Field, PrimeField};
use halo2_poseidon::{P128Pow5T3, Spec};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use zashu_acc::ACC_DEPTH;
use zashu_core::poseidon::DOMAIN_ACC;

/// In-circuit Poseidon-128 (`P128Pow5T3`, T=3, RATE=2, R_F=8, R_P=56) and Merkle inclusion chip.
#[derive(Debug, Clone)]
pub struct PoseidonChipConfig {
    pub state: [Column<Advice>; 3],
    pub rc: [Column<Fixed>; 3],
    pub bit: Column<Advice>,
    pub q_full: Selector,
    pub q_part: Selector,
    pub q_merkle: Selector,
    pub q_add: Selector,
}

impl PoseidonChipConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        state: [Column<Advice>; 3],
        rc: [Column<Fixed>; 3],
        bit: Column<Advice>,
    ) -> Self {
        let q_full = meta.selector();
        let q_part = meta.selector();
        let q_merkle = meta.selector();
        let q_add = meta.selector();

        let (_round_constants, mds, _mds_inv) = <P128Pow5T3 as Spec<Fp, 3, 2>>::constants();

        let pow5 = |x: Expression<Fp>| -> Expression<Fp> {
            let x2 = x.clone() * x.clone();
            let x4 = x2.clone() * x2;
            x4 * x
        };

        meta.create_gate("poseidon_full_round", |meta| {
            let q = meta.query_selector(q_full);
            let s: [Expression<Fp>; 3] = std::array::from_fn(|i| {
                meta.query_advice(state[i], Rotation::cur()) + meta.query_fixed(rc[i])
            });
            let sbox: [Expression<Fp>; 3] = std::array::from_fn(|i| pow5(s[i].clone()));
            (0..3)
                .map(|i| {
                    let next_i = meta.query_advice(state[i], Rotation::next());
                    let expected = Expression::Constant(mds[i][0]) * sbox[0].clone()
                        + Expression::Constant(mds[i][1]) * sbox[1].clone()
                        + Expression::Constant(mds[i][2]) * sbox[2].clone();
                    q.clone() * (next_i - expected)
                })
                .collect::<Vec<_>>()
        });

        meta.create_gate("poseidon_partial_round", |meta| {
            let q = meta.query_selector(q_part);
            let s0 = meta.query_advice(state[0], Rotation::cur()) + meta.query_fixed(rc[0]);
            let s1 = meta.query_advice(state[1], Rotation::cur()) + meta.query_fixed(rc[1]);
            let s2 = meta.query_advice(state[2], Rotation::cur()) + meta.query_fixed(rc[2]);
            let sbox0 = pow5(s0);
            (0..3)
                .map(|i| {
                    let next_i = meta.query_advice(state[i], Rotation::next());
                    let expected = Expression::Constant(mds[i][0]) * sbox0.clone()
                        + Expression::Constant(mds[i][1]) * s1.clone()
                        + Expression::Constant(mds[i][2]) * s2.clone();
                    q.clone() * (next_i - expected)
                })
                .collect::<Vec<_>>()
        });

        meta.create_gate("poseidon_absorb_add", |meta| {
            let q = meta.query_selector(q_add);
            let a = meta.query_advice(state[0], Rotation::cur());
            let b = meta.query_advice(state[1], Rotation::cur());
            let c = meta.query_advice(state[2], Rotation::cur());
            vec![q * (a + b - c)]
        });

        // Merkle conditional swap gate:
        // cur = state[0], sibling = state[1], b = bit
        // next row: state[0] = left, state[1] = right
        meta.create_gate("merkle_cond_swap", |meta| {
            let q = meta.query_selector(q_merkle);
            let cur = meta.query_advice(state[0], Rotation::cur());
            let sib = meta.query_advice(state[1], Rotation::cur());
            let b = meta.query_advice(bit, Rotation::cur());
            let left = meta.query_advice(state[0], Rotation::next());
            let right = meta.query_advice(state[1], Rotation::next());

            let bool_check = q.clone() * b.clone() * (Expression::Constant(Fp::ONE) - b.clone());
            let expected_left = cur.clone() + b.clone() * (sib.clone() - cur.clone());
            let expected_right = sib.clone() + b * (cur - sib);

            vec![
                bool_check,
                q.clone() * (left - expected_left),
                q * (right - expected_right),
            ]
        });

        Self {
            state,
            rc,
            bit,
            q_full,
            q_part,
            q_merkle,
            q_add,
        }
    }

    pub fn permute(
        &self,
        mut layouter: impl Layouter<Fp>,
        init: [AssignedCell<Fp, Fp>; 3],
    ) -> Result<[AssignedCell<Fp, Fp>; 3], Error> {
        let (round_constants, mds, _) = <P128Pow5T3 as Spec<Fp, 3, 2>>::constants();
        let half_f = <P128Pow5T3 as Spec<Fp, 3, 2>>::full_rounds() / 2;
        let partial_r = <P128Pow5T3 as Spec<Fp, 3, 2>>::partial_rounds();

        layouter.assign_region(
            || "poseidon_permute",
            |mut region| {
                let mut cur_cells = [
                    init[0].copy_advice(|| "init0", &mut region, self.state[0], 0)?,
                    init[1].copy_advice(|| "init1", &mut region, self.state[1], 0)?,
                    init[2].copy_advice(|| "init2", &mut region, self.state[2], 0)?,
                ];
                let mut cur_vals: Value<[Fp; 3]> = cur_cells[0]
                    .value()
                    .copied()
                    .zip(cur_cells[1].value().copied())
                    .zip(cur_cells[2].value().copied())
                    .map(|((a, b), c)| [a, b, c]);

                for (r, rcs) in round_constants.iter().enumerate() {
                    let is_full = r < half_f || r >= half_f + partial_r;
                    if is_full {
                        self.q_full.enable(&mut region, r)?;
                    } else {
                        self.q_part.enable(&mut region, r)?;
                    }
                    for i in 0..3 {
                        region.assign_fixed(
                            || format!("rc_{r}_{i}"),
                            self.rc[i],
                            r,
                            || Value::known(rcs[i]),
                        )?;
                    }

                    cur_vals = cur_vals.map(|st| {
                        let s: [Fp; 3] = std::array::from_fn(|i| st[i] + rcs[i]);
                        let after_sbox = if is_full {
                            [s[0].pow_vartime([5]), s[1].pow_vartime([5]), s[2].pow_vartime([5])]
                        } else {
                            [s[0].pow_vartime([5]), s[1], s[2]]
                        };
                        std::array::from_fn(|i| {
                            mds[i][0] * after_sbox[0]
                                + mds[i][1] * after_sbox[1]
                                + mds[i][2] * after_sbox[2]
                        })
                    });

                    cur_cells = [
                        region.assign_advice(
                            || format!("s0_{}", r + 1),
                            self.state[0],
                            r + 1,
                            || cur_vals.map(|v| v[0]),
                        )?,
                        region.assign_advice(
                            || format!("s1_{}", r + 1),
                            self.state[1],
                            r + 1,
                            || cur_vals.map(|v| v[1]),
                        )?,
                        region.assign_advice(
                            || format!("s2_{}", r + 1),
                            self.state[2],
                            r + 1,
                            || cur_vals.map(|v| v[2]),
                        )?,
                    ];
                }

                Ok(cur_cells)
            },
        )
    }

    /// Matches `halo2_poseidon::Hash::<Fp, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([a, b, c])`.
    pub fn hash_3(
        &self,
        mut layouter: impl Layouter<Fp>,
        inputs: [AssignedCell<Fp, Fp>; 3],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let cap = Fp::from_u128(3u128 << 64);
        let init_cap = layouter.assign_region(
            || "init_cap",
            |mut region| {
                let c = region.assign_advice(|| "cap", self.state[2], 0, || Value::known(cap))?;
                region.constrain_constant(c.cell(), cap)?;
                Ok(c)
            },
        )?;

        let st1 = self.permute(
            layouter.namespace(|| "perm_1"),
            [inputs[0].clone(), inputs[1].clone(), init_cap],
        )?;

        let added = layouter.assign_region(
            || "absorb_2",
            |mut region| {
                self.q_add.enable(&mut region, 0)?;
                let s0 = st1[0].copy_advice(|| "st1_0", &mut region, self.state[0], 0)?;
                let i2 = inputs[2].copy_advice(|| "in2", &mut region, self.state[1], 0)?;
                let sum_val = s0.value().copied().zip(i2.value().copied()).map(|(a, b)| a + b);
                region.assign_advice(|| "sum", self.state[2], 0, || sum_val)
            },
        )?;

        let st2 = self.permute(
            layouter.namespace(|| "perm_2"),
            [added, st1[1].clone(), st1[2].clone()],
        )?;

        Ok(st2[0].clone())
    }

    /// Matches `zashu_core::poseidon::hash_acc_node(left, right)`.
    pub fn hash_acc_node(
        &self,
        mut layouter: impl Layouter<Fp>,
        left: AssignedCell<Fp, Fp>,
        right: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let dom = layouter.assign_region(
            || "domain_acc",
            |mut region| {
                let c = region.assign_advice(
                    || "dom",
                    self.state[0],
                    0,
                    || Value::known(Fp::from(DOMAIN_ACC)),
                )?;
                region.constrain_constant(c.cell(), Fp::from(DOMAIN_ACC))?;
                Ok(c)
            },
        )?;
        self.hash_3(layouter.namespace(|| "acc_hash_3"), [dom, left, right])
    }

    /// Enforces 24-level Poseidon Merkle inclusion from `leaf` up to `expected_root`.
    pub fn verify_merkle_inclusion(
        &self,
        mut layouter: impl Layouter<Fp>,
        mut cur: AssignedCell<Fp, Fp>,
        siblings: &[Value<Fp>; ACC_DEPTH],
        leaf_index: Value<u64>,
        expected_root: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        for (level, sib_val) in siblings.iter().enumerate() {
            let bit_val = leaf_index.map(|idx| Fp::from((idx >> level) & 1));
            let (left_cell, right_cell) = layouter.assign_region(
                || format!("merkle_swap_{level}"),
                |mut region| {
                    self.q_merkle.enable(&mut region, 0)?;
                    let c_cell = cur.copy_advice(|| "cur", &mut region, self.state[0], 0)?;
                    let s_cell = region.assign_advice(|| "sib", self.state[1], 0, || *sib_val)?;
                    let b_cell = region.assign_advice(|| "bit", self.bit, 0, || bit_val)?;

                    let lr = c_cell
                        .value()
                        .copied()
                        .zip(s_cell.value().copied())
                        .zip(b_cell.value().copied())
                        .map(|((c, s), b)| {
                            if b == Fp::ONE {
                                (s, c)
                            } else {
                                (c, s)
                            }
                        });

                    let left = region.assign_advice(|| "left", self.state[0], 1, || lr.map(|v| v.0))?;
                    let right =
                        region.assign_advice(|| "right", self.state[1], 1, || lr.map(|v| v.1))?;
                    Ok((left, right))
                },
            )?;

            cur = self.hash_acc_node(
                layouter.namespace(|| format!("merkle_hash_{level}")),
                left_cell,
                right_cell,
            )?;
        }

        layouter.assign_region(
            || "merkle_root_eq",
            |mut region| {
                let c = cur.copy_advice(|| "computed_root", &mut region, self.state[0], 0)?;
                let e = expected_root.copy_advice(|| "expected_root", &mut region, self.state[1], 0)?;
                region.constrain_equal(c.cell(), e.cell())
            },
        )
    }
}

/// Standalone Halo 2 circuit (`k = 13`) proving 24-level Poseidon Merkle inclusion in-circuit.
/// Public instances: `[leaf, root]`.
#[derive(Debug, Clone)]
pub struct MerkleInclusionCircuit {
    pub leaf: Value<Fp>,
    pub root: Value<Fp>,
    pub siblings: [Value<Fp>; ACC_DEPTH],
    pub leaf_index: Value<u64>,
}

impl Default for MerkleInclusionCircuit {
    fn default() -> Self {
        Self {
            leaf: Value::unknown(),
            root: Value::unknown(),
            siblings: [Value::unknown(); ACC_DEPTH],
            leaf_index: Value::unknown(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MerkleInclusionConfig {
    pub poseidon: PoseidonChipConfig,
    pub instance: Column<Instance>,
}

impl Circuit<Fp> for MerkleInclusionCircuit {
    type Config = MerkleInclusionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let bit = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        for c in state {
            meta.enable_equality(c);
        }
        meta.enable_equality(bit);
        meta.enable_constant(constant);
        meta.enable_equality(instance);

        let poseidon = PoseidonChipConfig::configure(meta, state, rc, bit);
        MerkleInclusionConfig { poseidon, instance }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (leaf_cell, root_cell) = layouter.assign_region(
            || "load_leaf_root",
            |mut region| {
                let l = region.assign_advice(|| "leaf", cfg.poseidon.state[0], 0, || self.leaf)?;
                let r = region.assign_advice(|| "root", cfg.poseidon.state[1], 0, || self.root)?;
                Ok((l, r))
            },
        )?;

        cfg.poseidon.verify_merkle_inclusion(
            layouter.namespace(|| "merkle_inclusion"),
            leaf_cell.clone(),
            &self.siblings,
            self.leaf_index,
            &root_cell,
        )?;

        layouter.constrain_instance(leaf_cell.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(root_cell.cell(), cfg.instance, 1)?;
        Ok(())
    }
}
