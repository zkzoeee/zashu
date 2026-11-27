//! The operation circuit.
//!
//! Public: `[state_before, state_after, liabilities_before, liabilities_after]`.
//!
//! One circuit covers a mint, a swap and a melt, with two nullifier-insert
//! slots and two note-append slots, each switched by a private `active` bit.

use std::sync::atomic::{AtomicUsize, Ordering};

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use zashu_core::spec::hash::{capacity, T_MELT, T_MINT, T_NF_LEAF, T_STATE};
use zashu_core::spec::op::{Kind, OpWitness};
use zashu_core::spec::tree::{NfInsert, NoteAppend};
use zashu_core::spec::DEPTH;

use super::gadgets::{fe, fresh, index_bits, pow2, reuse, Cell, Ctx, Rows, SpecConfig};

/// One nullifier-insert slot.
#[derive(Clone, Debug)]
struct InsertAssign {
    active: bool,
    nf: Fp,
    low_value: Fp,
    next_value: Fp,
    next_index: Fp,
    low_siblings: [Fp; DEPTH],
    low_bits: [Fp; DEPTH],
    new_siblings: [Fp; DEPTH],
    new_bits: [Fp; DEPTH],
    /// The bits of `new_index` above the tree depth.
    new_high: Fp,
}

impl InsertAssign {
    fn new(insert: &Option<NfInsert>) -> Self {
        match insert {
            Some(i) => InsertAssign {
                active: true,
                nf: i.nf,
                low_value: i.low.value,
                next_value: i.low.next_value,
                next_index: fe(i.low.next_index),
                low_siblings: i.low_path,
                low_bits: index_bits(i.low_index),
                new_siblings: i.new_path,
                new_bits: index_bits(i.new_index),
                new_high: fe(i.new_index >> DEPTH),
            },
            None => InsertAssign {
                active: false,
                nf: Fp::ZERO,
                low_value: Fp::ZERO,
                next_value: Fp::ZERO,
                next_index: Fp::ZERO,
                low_siblings: [Fp::ZERO; DEPTH],
                low_bits: [Fp::ZERO; DEPTH],
                new_siblings: [Fp::ZERO; DEPTH],
                new_bits: [Fp::ZERO; DEPTH],
                new_high: Fp::ZERO,
            },
        }
    }
}

/// One note-append slot.
#[derive(Clone, Debug)]
struct AppendAssign {
    active: bool,
    cm: Fp,
    siblings: [Fp; DEPTH],
    bits: [Fp; DEPTH],
}

impl AppendAssign {
    fn new(append: &Option<NoteAppend>) -> Self {
        match append {
            Some(a) => AppendAssign { active: true, cm: a.cm, siblings: a.path, bits: index_bits(a.index) },
            None => AppendAssign {
                active: false,
                cm: Fp::ZERO,
                siblings: [Fp::ZERO; DEPTH],
                bits: [Fp::ZERO; DEPTH],
            },
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct OpAssign {
    /// `epoch, liabilities, nullifier_root, note_root, event_log`.
    before: [Fp; 5],
    /// Mint, swap, melt.
    kind: [bool; 3],
    epoch_after: Fp,
    amount: Fp,
    event: Fp,
    inserts: [InsertAssign; 2],
    appends: [AppendAssign; 2],
}

impl OpAssign {
    pub fn new(w: &OpWitness) -> Self {
        let b = &w.before;
        OpAssign {
            before: [fe(b.epoch), fe(b.liabilities), b.nullifier_root, b.note_root, b.event_log],
            kind: [w.kind == Kind::Mint, w.kind == Kind::Swap, w.kind == Kind::Melt],
            epoch_after: fe(w.epoch_after),
            amount: fe(w.amount),
            event: w.event,
            inserts: [InsertAssign::new(&w.nullifiers[0]), InsertAssign::new(&w.nullifiers[1])],
            appends: [AppendAssign::new(&w.notes[0]), AppendAssign::new(&w.notes[1])],
        }
    }
}

/// The operation circuit over `CHIPS` Poseidon chips.
#[derive(Clone, Debug)]
pub struct OpCircuit<const CHIPS: usize> {
    pub(super) w: Value<OpAssign>,
}

impl<const CHIPS: usize> Default for OpCircuit<CHIPS> {
    fn default() -> Self {
        OpCircuit { w: Value::unknown() }
    }
}

static ROWS: [AtomicUsize; 3] = [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];

/// Rows used by the last synthesis of the operation circuit.
pub(super) fn rows() -> Rows {
    Rows {
        poseidon: ROWS[0].load(Ordering::Relaxed),
        range: ROWS[1].load(Ordering::Relaxed),
        arithmetic: ROWS[2].load(Ordering::Relaxed),
    }
}

impl<const CHIPS: usize> Circuit<Fp> for OpCircuit<CHIPS> {
    type Config = SpecConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> SpecConfig {
        SpecConfig::configure(meta, CHIPS)
    }

    fn synthesize(&self, cfg: SpecConfig, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut cx = Ctx::new(&cfg, layouter);
        let w = self.w.as_ref();
        let one = Fp::ONE;

        // The state before. Epoch and liabilities are 64-bit integers.
        let before = cx.witnesses(w.map(|w| w.before))?;
        let (epoch, liabilities, event_log) = (&before[0], &before[1], &before[4]);
        cx.range(epoch, 16)?;
        cx.range(liabilities, 16)?;
        let state_before = cx.sponge(T_STATE, &before)?;

        // Exactly one kind.
        let kind = cx.bits(w.map(|w| w.kind))?;
        let (is_mint, is_swap, is_melt) = (&kind[0], &kind[1], &kind[2]);
        let mint_or_swap = cx.add(is_mint, is_swap)?;
        cx.sum_is(&mint_or_swap, is_melt, one)?;

        // The epoch does not decrease.
        let epoch_after = cx.witness(w.map(|w| w.epoch_after))?;
        cx.range(&epoch_after, 16)?;
        let elapsed = cx.sub(&epoch_after, epoch)?;
        cx.range(&elapsed, 16)?;

        // Liabilities rise by the amount of a mint and fall by that of a
        // melt. All three are 64-bit, so nothing wraps.
        let amount = cx.witness(w.map(|w| w.amount))?;
        cx.range(&amount, 16)?;
        let sign = cx.sub(is_mint, is_melt)?;
        let change = cx.mul(&sign, &amount)?;
        let liabilities_after = cx.add(liabilities, &change)?;
        cx.range(&liabilities_after, 16)?;
        // A mint or melt moves a positive amount: amount = 0 only in a swap.
        let no_amount = cx.is_zero(&amount)?;
        cx.implies(&no_amount, is_swap)?;

        // The event log absorbs a mint or melt. The two tags differ by one,
        // so the capacity is that of a mint plus the melt flag.
        debug_assert_eq!(capacity(T_MINT) + one, capacity(T_MELT));
        let mint_capacity = cx.constant(capacity(T_MINT))?;
        let event_capacity = cx.add(&mint_capacity, is_melt)?;
        let event = cx.witness(w.map(|w| w.event))?;
        let extended = cx.sponge_from(&event_capacity, &[event_log.clone(), event, amount])?;
        let event_log_after = cx.select(is_swap, event_log, &extended)?;

        let mut nullifier_root = before[2].clone();
        for slot in 0..2 {
            nullifier_root = insert(&mut cx, w.map(|w| &w.inserts[slot]), &nullifier_root)?;
        }
        let mut note_root = before[3].clone();
        for slot in 0..2 {
            note_root = append(&mut cx, w.map(|w| &w.appends[slot]), &note_root)?;
        }

        let after = [epoch_after, liabilities_after.clone(), nullifier_root, note_root, event_log_after];
        let state_after = cx.sponge(T_STATE, &after)?;

        for (row, cell) in [&state_before, &state_after, liabilities, &liabilities_after].into_iter().enumerate() {
            cx.expose(cell, row)?;
        }

        let rows = cx.rows();
        ROWS[0].store(rows.poseidon, Ordering::Relaxed);
        ROWS[1].store(rows.range, Ordering::Relaxed);
        ROWS[2].store(rows.arithmetic, Ordering::Relaxed);
        Ok(())
    }
}

/// `NfInsert::apply`: the nullifier root after one sorted insert, or `root`
/// itself when the slot is not active.
fn insert<L: Layouter<Fp>>(cx: &mut Ctx<'_, L>, s: Value<&InsertAssign>, root: &Cell) -> Result<Cell, Error> {
    let one = Fp::ONE;
    let active = cx.bit(s.map(|s| s.active))?;
    let fields = cx.witnesses(s.map(|s| [s.nf, s.low_value, s.next_value, s.next_index]))?;
    let (nf, low_value, next_value, next_index) = (&fields[0], &fields[1], &fields[2], &fields[3]);
    cx.range(next_index, 16)?;

    // low_value < nf, and nf < next_value unless the low leaf is the last.
    // The order is that of integers in [0, p).
    let low_limbs = cx.canonical(low_value)?;
    let nf_limbs = cx.canonical(nf)?;
    let next_limbs = cx.canonical(next_value)?;
    let above_low = cx.lt_limbs(&low_limbs, &nf_limbs)?;
    cx.implies(&active, &above_low)?;
    let is_last = cx.is_zero(next_value)?;
    let below_next = cx.lt_limbs(&nf_limbs, &next_limbs)?;
    // (1 - is_last) * (1 - below_next)
    let out_of_order = cx.gate(&is_last, &below_next, None, [-one, -one, one, -one, one])?;
    cx.zero_product(&active, &out_of_order)?;

    // The low leaf is in the tree.
    let low_leaf = cx.sponge(T_NF_LEAF, &[low_value.clone(), next_value.clone(), next_index.clone()])?;
    let (low_root, low_siblings, low_bits) =
        cx.merkle_root(&low_leaf, &fresh(s.map(|s| s.low_siblings)), &fresh(s.map(|s| s.low_bits)))?;
    cx.cond_eq(&active, &low_root, root)?;

    // The root of the new leaf's path with the leaf empty. Its index bits,
    // with the bits of the index above the tree depth, make `new_index`.
    let zero = cx.constant(Fp::ZERO)?;
    let (empty_root, new_siblings, new_bits) =
        cx.merkle_root(&zero, &fresh(s.map(|s| s.new_siblings)), &fresh(s.map(|s| s.new_bits)))?;
    let new_high = cx.witness(s.map(|s| s.new_high))?;
    cx.range(&new_high, (64 - DEPTH) / 4)?;
    let new_index = cx.compose(&new_high, pow2(DEPTH as u64), &new_bits)?;

    // The low leaf re-pointed at the new one; the new leaf's slot is empty
    // in that tree.
    let repointed = cx.sponge(T_NF_LEAF, &[low_value.clone(), nf.clone(), new_index])?;
    let (middle_root, _, _) = cx.merkle_root(&repointed, &reuse(&low_siblings), &reuse(&low_bits))?;
    cx.cond_eq(&active, &empty_root, &middle_root)?;

    // The new leaf takes over the low leaf's successor.
    let new_leaf = cx.sponge(T_NF_LEAF, &[nf.clone(), next_value.clone(), next_index.clone()])?;
    let (new_root, _, _) = cx.merkle_root(&new_leaf, &reuse(&new_siblings), &reuse(&new_bits))?;
    cx.select(&active, &new_root, root)
}

/// `NoteAppend::apply`: the note root after writing `cm` into an empty leaf,
/// or `root` itself when the slot is not active.
fn append<L: Layouter<Fp>>(cx: &mut Ctx<'_, L>, s: Value<&AppendAssign>, root: &Cell) -> Result<Cell, Error> {
    let active = cx.bit(s.map(|s| s.active))?;
    let cm = cx.witness(s.map(|s| s.cm))?;
    let zero = cx.constant(Fp::ZERO)?;
    let (empty_root, siblings, bits) =
        cx.merkle_root(&zero, &fresh(s.map(|s| s.siblings)), &fresh(s.map(|s| s.bits)))?;
    cx.cond_eq(&active, &empty_root, root)?;
    let (new_root, _, _) = cx.merkle_root(&cm, &reuse(&siblings), &reuse(&bits))?;
    cx.select(&active, &new_root, root)
}
