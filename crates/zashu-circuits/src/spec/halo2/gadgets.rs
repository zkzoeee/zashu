//! The shared column layout and the small gadgets both circuits are built
//! from: a generic arithmetic gate, the spec sponge, Merkle paths, range
//! checks and integer comparisons.

use std::collections::HashMap;

use ff::{Field, PrimeField};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance};
use halo2_proofs::poly::Rotation;
use zashu_core::spec::hash::{capacity, T_NODE};
use zashu_core::spec::less_than;

use crate::poseidon_chip::PoseidonChipConfig;
use crate::range_check::RangeCheck64Config;

pub(super) type Cell = AssignedCell<Fp, Fp>;

/// Rows one permutation takes in a Poseidon chip (64 rounds and the output).
const PERMUTATION_ROWS: usize = 65;

/// The columns of a spec circuit.
///
/// * `chips`: Poseidon chips side by side. Each owns three state columns and
///   a bit column, so permutations on different chips share rows.
/// * `range`: 4 bit columns and a running sum, for range checks.
/// * `adv`, `fix`: one generic gate per row,
///   `k0*a + k1*b + k2*a*b + k3*c + k4 = 0`.
#[derive(Clone, Debug)]
pub struct SpecConfig {
    chips: Vec<PoseidonChipConfig>,
    range: RangeCheck64Config,
    adv: [Column<Advice>; 3],
    fix: [Column<Fixed>; 5],
    instance: Column<Instance>,
}

impl SpecConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>, chips: usize) -> Self {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let constant = meta.fixed_column();
        meta.enable_constant(constant);

        let chips = (0..chips)
            .map(|_| {
                let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
                let rc = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
                let bit = meta.advice_column();
                for column in state {
                    meta.enable_equality(column);
                }
                meta.enable_equality(bit);
                PoseidonChipConfig::configure(meta, state, rc, bit)
            })
            .collect();

        let bits = [meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let acc = meta.advice_column();
        meta.enable_equality(acc);
        let range = RangeCheck64Config::configure(meta, bits, acc);

        let adv = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for column in adv {
            meta.enable_equality(column);
        }
        let fix = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.create_gate("spec arithmetic", |meta| {
            let a = meta.query_advice(adv[0], Rotation::cur());
            let b = meta.query_advice(adv[1], Rotation::cur());
            let c = meta.query_advice(adv[2], Rotation::cur());
            let k: Vec<_> = fix.iter().map(|column| meta.query_fixed(*column)).collect();
            vec![
                k[0].clone() * a.clone()
                    + k[1].clone() * b.clone()
                    + k[2].clone() * a * b
                    + k[3].clone() * c
                    + k[4].clone(),
            ]
        });

        SpecConfig { chips, range, adv, fix, instance }
    }
}

/// A Merkle sibling or index bit: a fresh witness, or a cell of an earlier
/// pass over the same path.
pub(super) enum Src {
    New(Value<Fp>),
    Old(Cell),
}

/// The two 128-bit limbs of a field element, as an integer in `[0, p)`.
pub(super) struct Limbs {
    hi: Cell,
    lo: Cell,
}

/// Rows used per column group. The groups sit side by side, so a circuit
/// needs as many rows as its tallest group (plus halo2's blinding rows).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rows {
    /// The tallest Poseidon chip.
    pub poseidon: usize,
    pub range: usize,
    pub arithmetic: usize,
}

impl Rows {
    pub fn max(&self) -> usize {
        self.poseidon.max(self.range).max(self.arithmetic)
    }
}

pub(super) fn fe(v: u64) -> Fp {
    Fp::from(v)
}

pub(super) fn pow2(bits: u64) -> Fp {
    Fp::from(2).pow_vartime([bits])
}

pub(super) fn bool_fe(b: bool) -> Fp {
    Fp::from(b as u64)
}

/// The nibble of `v` starting at bit `shift` (a multiple of 4).
fn nibble(v: &Fp, shift: usize) -> u64 {
    let repr = v.to_repr();
    ((repr[shift / 8] >> (shift % 8)) & 0xF) as u64
}

/// `v` as `(hi, lo)` with `v = hi * 2^128 + lo`.
pub(super) fn split(v: &Fp) -> (u128, u128) {
    let repr = v.to_repr();
    let (mut lo, mut hi) = ([0u8; 16], [0u8; 16]);
    lo.copy_from_slice(&repr[..16]);
    hi.copy_from_slice(&repr[16..]);
    (u128::from_le_bytes(hi), u128::from_le_bytes(lo))
}

/// Synthesis state: the layouter and where the next gadget goes.
pub(super) struct Ctx<'a, L: Layouter<Fp>> {
    cfg: &'a SpecConfig,
    layouter: L,
    chip_rows: Vec<usize>,
    range_rows: usize,
    arith_rows: usize,
    constants: HashMap<[u8; 32], Cell>,
}

impl<'a, L: Layouter<Fp>> Ctx<'a, L> {
    pub fn new(cfg: &'a SpecConfig, layouter: L) -> Self {
        Ctx {
            cfg,
            layouter,
            chip_rows: vec![0; cfg.chips.len()],
            range_rows: 0,
            arith_rows: 0,
            constants: HashMap::new(),
        }
    }

    pub fn rows(&self) -> Rows {
        Rows {
            poseidon: self.chip_rows.iter().copied().max().unwrap_or(0),
            range: self.range_rows,
            arithmetic: self.arith_rows,
        }
    }

    /// Binds `cell` to row `row` of the instance column.
    pub fn expose(&mut self, cell: &Cell, row: usize) -> Result<(), Error> {
        self.layouter.constrain_instance(cell.cell(), self.cfg.instance, row)
    }

    // ---- Arithmetic --------------------------------------------------------

    /// One row of the generic gate: `k0*a + k1*b + k2*a*b + k3*c + k4 = 0`.
    /// `c` is the given cell, or a new one holding the value that solves the
    /// gate (zero when `k3 = 0`, where it is not constrained).
    pub fn gate(&mut self, a: &Cell, b: &Cell, c: Option<&Cell>, k: [Fp; 5]) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.arith_rows += 1;
        self.layouter.assign_region(
            || "gate",
            |mut region| {
                let a = a.copy_advice(|| "a", &mut region, cfg.adv[0], 0)?;
                let b = b.copy_advice(|| "b", &mut region, cfg.adv[1], 0)?;
                for (column, value) in cfg.fix.iter().zip(k) {
                    region.assign_fixed(|| "k", *column, 0, || Value::known(value))?;
                }
                match c {
                    Some(c) => c.copy_advice(|| "c", &mut region, cfg.adv[2], 0),
                    None => {
                        let inverse = k[3].invert().unwrap_or(Fp::ZERO);
                        let value = a
                            .value()
                            .zip(b.value())
                            .map(|(a, b)| -(k[0] * a + k[1] * b + k[2] * a * b + k[4]) * inverse);
                        region.assign_advice(|| "c", cfg.adv[2], 0, || value)
                    }
                }
            },
        )
    }

    /// A free witness.
    pub fn witness(&mut self, value: Value<Fp>) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.arith_rows += 1;
        self.layouter
            .assign_region(|| "witness", |mut region| region.assign_advice(|| "w", cfg.adv[0], 0, || value))
    }

    pub fn witnesses<const N: usize>(&mut self, values: Value<[Fp; N]>) -> Result<Vec<Cell>, Error> {
        (0..N).map(|i| self.witness(values.map(|v| v[i]))).collect()
    }

    /// A witness constrained to 0 or 1.
    pub fn bit(&mut self, value: Value<bool>) -> Result<Cell, Error> {
        let cfg = self.cfg;
        self.arith_rows += 1;
        self.layouter.assign_region(
            || "bit",
            |mut region| {
                let a = region.assign_advice(|| "a", cfg.adv[0], 0, || value.map(bool_fe))?;
                a.copy_advice(|| "b", &mut region, cfg.adv[1], 0)?;
                // a*a - a = 0
                region.assign_fixed(|| "k0", cfg.fix[0], 0, || Value::known(-Fp::ONE))?;
                region.assign_fixed(|| "k2", cfg.fix[2], 0, || Value::known(Fp::ONE))?;
                Ok(a)
            },
        )
    }

    pub fn bits<const N: usize>(&mut self, values: Value<[bool; N]>) -> Result<Vec<Cell>, Error> {
        (0..N).map(|i| self.bit(values.map(|v| v[i]))).collect()
    }

    pub fn constant(&mut self, value: Fp) -> Result<Cell, Error> {
        if let Some(cell) = self.constants.get(&value.to_repr()) {
            return Ok(cell.clone());
        }
        let cfg = self.cfg;
        self.arith_rows += 1;
        let cell = self.layouter.assign_region(
            || "constant",
            |mut region| {
                let cell = region.assign_advice(|| "c", cfg.adv[0], 0, || Value::known(value))?;
                region.constrain_constant(cell.cell(), value)?;
                Ok(cell)
            },
        )?;
        self.constants.insert(value.to_repr(), cell.clone());
        Ok(cell)
    }

    /// `ka*a + kb*b`.
    pub fn lin(&mut self, a: &Cell, ka: Fp, b: &Cell, kb: Fp) -> Result<Cell, Error> {
        self.gate(a, b, None, [ka, kb, Fp::ZERO, -Fp::ONE, Fp::ZERO])
    }

    pub fn add(&mut self, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.lin(a, Fp::ONE, b, Fp::ONE)
    }

    pub fn sub(&mut self, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.lin(a, Fp::ONE, b, -Fp::ONE)
    }

    pub fn mul(&mut self, a: &Cell, b: &Cell) -> Result<Cell, Error> {
        self.gate(a, b, None, [Fp::ZERO, Fp::ZERO, Fp::ONE, -Fp::ONE, Fp::ZERO])
    }

    /// Enforces `a * b = 0`.
    pub fn zero_product(&mut self, a: &Cell, b: &Cell) -> Result<(), Error> {
        self.gate(a, b, None, [Fp::ZERO, Fp::ZERO, Fp::ONE, Fp::ZERO, Fp::ZERO]).map(|_| ())
    }

    /// Enforces `a + b = total`.
    pub fn sum_is(&mut self, a: &Cell, b: &Cell, total: Fp) -> Result<(), Error> {
        self.gate(a, b, None, [Fp::ONE, Fp::ONE, Fp::ZERO, Fp::ZERO, -total]).map(|_| ())
    }

    /// Enforces `ka*a + kb*b = c`.
    pub fn lin_is(&mut self, a: &Cell, ka: Fp, b: &Cell, kb: Fp, c: &Cell) -> Result<(), Error> {
        self.gate(a, b, Some(c), [ka, kb, Fp::ZERO, -Fp::ONE, Fp::ZERO]).map(|_| ())
    }

    /// Enforces `a = 0` or `b = 1`: `a - a*b = 0`.
    pub fn implies(&mut self, a: &Cell, b: &Cell) -> Result<(), Error> {
        self.gate(a, b, None, [Fp::ONE, Fp::ZERO, -Fp::ONE, Fp::ZERO, Fp::ZERO]).map(|_| ())
    }

    /// Enforces `x = 1`.
    pub fn is_one(&mut self, x: &Cell) -> Result<(), Error> {
        self.gate(x, x, None, [Fp::ONE, Fp::ZERO, Fp::ZERO, Fp::ZERO, -Fp::ONE]).map(|_| ())
    }

    /// Enforces `x = y` when `cond` is not zero.
    pub fn cond_eq(&mut self, cond: &Cell, x: &Cell, y: &Cell) -> Result<(), Error> {
        let d = self.sub(x, y)?;
        self.zero_product(cond, &d)
    }

    /// `x` when `bit` is 1, `y` when it is 0.
    pub fn select(&mut self, bit: &Cell, x: &Cell, y: &Cell) -> Result<Cell, Error> {
        let d = self.sub(x, y)?;
        let m = self.mul(bit, &d)?;
        self.add(y, &m)
    }

    /// The bit `x == 0`.
    pub fn is_zero(&mut self, x: &Cell) -> Result<Cell, Error> {
        let inverse = self.witness(x.value().map(|x| x.invert().unwrap_or(Fp::ZERO)))?;
        // out = 1 - x*inverse, and x*out = 0.
        let out = self.gate(x, &inverse, None, [Fp::ZERO, Fp::ZERO, Fp::ONE, Fp::ONE, -Fp::ONE])?;
        self.zero_product(x, &out)?;
        Ok(out)
    }

    /// `base*base_scale + sum(bits[i] * 2^i)`.
    pub fn compose(&mut self, base: &Cell, base_scale: Fp, bits: &[Cell]) -> Result<Cell, Error> {
        let mut acc = self.lin(base, base_scale, &bits[0], Fp::ONE)?;
        for (i, bit) in bits.iter().enumerate().skip(1) {
            acc = self.lin(&acc, Fp::ONE, bit, pow2(i as u64))?;
        }
        Ok(acc)
    }

    /// `b0 + 2*b1` for two bits.
    pub fn two_bits(&mut self, bits: &[Cell]) -> Result<Cell, Error> {
        self.lin(&bits[0], Fp::ONE, &bits[1], fe(2))
    }

    // ---- Range checks and comparisons ---------------------------------------

    /// Enforces `x < 2^(4 * nibbles)`.
    pub fn range(&mut self, x: &Cell, nibbles: usize) -> Result<(), Error> {
        let cfg = self.cfg;
        let range = &cfg.range;
        self.range_rows += nibbles + 1;
        self.layouter.assign_region(
            || "range",
            |mut region| {
                let mut acc_value = Value::known(Fp::ZERO);
                let mut acc = region.assign_advice(|| "acc", range.acc, 0, || acc_value)?;
                region.constrain_constant(acc.cell(), Fp::ZERO)?;
                for row in 0..nibbles {
                    range.q_bit.enable(&mut region, row)?;
                    range.q_acc.enable(&mut region, row)?;
                    // Most significant nibble first. A value that does not
                    // fit leaves a running sum that is not `x`.
                    let nib = x.value().map(|v| nibble(v, (nibbles - 1 - row) * 4));
                    for (i, column) in range.bits.iter().enumerate() {
                        region.assign_advice(|| "bit", *column, row, || nib.map(|n| fe((n >> i) & 1)))?;
                    }
                    acc_value = acc_value.zip(nib).map(|(acc, n)| acc * fe(16) + fe(n));
                    acc = region.assign_advice(|| "acc", range.acc, row + 1, || acc_value)?;
                }
                region.constrain_equal(acc.cell(), x.cell())
            },
        )
    }

    /// The bit `a < b`, for `a` and `b` already known to be below
    /// `2^(4 * nibbles)`: `a - b + bit * 2^(4 * nibbles)` must fit the range.
    pub fn lt(&mut self, a: &Cell, b: &Cell, nibbles: usize) -> Result<Cell, Error> {
        let bit = self.bit(a.value().zip(b.value()).map(|(a, b)| less_than(a, b)))?;
        let d = self.sub(a, b)?;
        let w = self.lin(&d, Fp::ONE, &bit, pow2(4 * nibbles as u64))?;
        self.range(&w, nibbles)?;
        Ok(bit)
    }

    /// The bit `a < b` for two integers given as limbs.
    pub fn lt_limbs(&mut self, a: &Limbs, b: &Limbs) -> Result<Cell, Error> {
        let hi_lt = self.lt(&a.hi, &b.hi, 32)?;
        let hi_diff = self.sub(&a.hi, &b.hi)?;
        let hi_eq = self.is_zero(&hi_diff)?;
        let lo_lt = self.lt(&a.lo, &b.lo, 32)?;
        // The two cases exclude each other, so the sum is a bit.
        let both = self.mul(&hi_eq, &lo_lt)?;
        self.add(&hi_lt, &both)
    }

    /// The limbs of `x` as an integer in `[0, p)`. The decomposition is
    /// checked to be below `p`, so `x + p` cannot stand in for `x`.
    pub fn canonical(&mut self, x: &Cell) -> Result<Limbs, Error> {
        let parts = x.value().map(split);
        self.canonical_from(x, parts)
    }

    /// [`Self::canonical`] with the limbs supplied by the prover.
    pub fn canonical_from(&mut self, x: &Cell, parts: Value<(u128, u128)>) -> Result<Limbs, Error> {
        let hi = self.witness(parts.map(|(hi, _)| Fp::from_u128(hi)))?;
        let lo = self.witness(parts.map(|(_, lo)| Fp::from_u128(lo)))?;
        self.range(&hi, 32)?;
        self.range(&lo, 32)?;
        self.lin_is(&lo, Fp::ONE, &hi, pow2(128), x)?;

        // p = max + 1, and the low limb of `max` is not all ones.
        let (max_hi, max_lo) = split(&-Fp::ONE);
        let modulus = Limbs {
            hi: self.constant(Fp::from_u128(max_hi))?,
            lo: self.constant(Fp::from_u128(max_lo + 1))?,
        };
        let limbs = Limbs { hi, lo };
        let below = self.lt_limbs(&limbs, &modulus)?;
        self.is_one(&below)?;
        Ok(limbs)
    }

    // ---- Hashing -------------------------------------------------------------

    fn free_chip(&self) -> usize {
        (0..self.chip_rows.len()).min_by_key(|i| self.chip_rows[*i]).expect("at least one chip")
    }

    fn permute(&mut self, chip: usize, state: [Cell; 3]) -> Result<[Cell; 3], Error> {
        self.chip_rows[chip] += PERMUTATION_ROWS;
        self.cfg.chips[chip].permute(self.layouter.namespace(|| "permute"), state)
    }

    /// The spec sponge from an explicit capacity cell.
    pub fn sponge_from(&mut self, capacity: &Cell, inputs: &[Cell]) -> Result<Cell, Error> {
        assert!(!inputs.is_empty(), "the sponge needs at least one input");
        let mut state: Option<[Cell; 3]> = None;
        for block in inputs.chunks(2) {
            let next = match state {
                // The state starts as [0, 0, capacity], so the first block is
                // the permutation input itself.
                None => {
                    let second = match block.get(1) {
                        Some(second) => second.clone(),
                        None => self.constant(Fp::ZERO)?,
                    };
                    [block[0].clone(), second, capacity.clone()]
                }
                Some([s0, s1, s2]) => {
                    let first = self.add(&s0, &block[0])?;
                    let second = match block.get(1) {
                        Some(second) => self.add(&s1, second)?,
                        None => s1,
                    };
                    [first, second, s2]
                }
            };
            let chip = self.free_chip();
            state = Some(self.permute(chip, next)?);
        }
        let [out, _, _] = state.expect("at least one block");
        Ok(out)
    }

    /// `H_tag(inputs)`.
    pub fn sponge(&mut self, tag: u64, inputs: &[Cell]) -> Result<Cell, Error> {
        let capacity = self.constant(capacity(tag))?;
        self.sponge_from(&capacity, inputs)
    }

    /// The root reached from `leaf` over a path. Returns the root with the
    /// sibling and index-bit cells, so a second pass can reuse the same path.
    /// Each index bit is constrained to 0 or 1.
    pub fn merkle_root(
        &mut self,
        leaf: &Cell,
        siblings: &[Src],
        bits: &[Src],
    ) -> Result<(Cell, Vec<Cell>, Vec<Cell>), Error> {
        let capacity = self.constant(capacity(T_NODE))?;
        let mut cur = leaf.clone();
        let (mut sibling_cells, mut bit_cells) = (Vec::new(), Vec::new());
        for (sibling, bit) in siblings.iter().zip(bits) {
            let index = self.free_chip();
            let cfg = self.cfg;
            let chip = &cfg.chips[index];
            self.chip_rows[index] += 2;
            let (left, right, s, b) = self.layouter.assign_region(
                || "swap",
                |mut region| {
                    chip.q_merkle.enable(&mut region, 0)?;
                    let c = cur.copy_advice(|| "cur", &mut region, chip.state[0], 0)?;
                    let s = match sibling {
                        Src::New(value) => region.assign_advice(|| "sibling", chip.state[1], 0, || *value)?,
                        Src::Old(cell) => cell.copy_advice(|| "sibling", &mut region, chip.state[1], 0)?,
                    };
                    let b = match bit {
                        Src::New(value) => region.assign_advice(|| "bit", chip.bit, 0, || *value)?,
                        Src::Old(cell) => cell.copy_advice(|| "bit", &mut region, chip.bit, 0)?,
                    };
                    let pair = c
                        .value()
                        .zip(s.value())
                        .zip(b.value())
                        .map(|((c, s), b)| (*c + *b * (*s - *c), *s + *b * (*c - *s)));
                    let left = region.assign_advice(|| "left", chip.state[0], 1, || pair.map(|p| p.0))?;
                    let right = region.assign_advice(|| "right", chip.state[1], 1, || pair.map(|p| p.1))?;
                    Ok((left, right, s, b))
                },
            )?;
            let [out, _, _] = self.permute(index, [left, right, capacity.clone()])?;
            cur = out;
            sibling_cells.push(s);
            bit_cells.push(b);
        }
        Ok((cur, sibling_cells, bit_cells))
    }
}

/// A fresh path from witness values.
pub(super) fn fresh<const N: usize>(values: Value<[Fp; N]>) -> Vec<Src> {
    (0..N).map(|i| Src::New(values.map(|v| v[i]))).collect()
}

/// A path already assigned.
pub(super) fn reuse(cells: &[Cell]) -> Vec<Src> {
    cells.iter().cloned().map(Src::Old).collect()
}

/// The low `N` bits of `index`, as field elements.
pub(super) fn index_bits<const N: usize>(index: u64) -> [Fp; N] {
    core::array::from_fn(|level| fe((index >> level) & 1))
}
