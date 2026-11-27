//! The operation and chain statements as Ragu steps.
//!
//! An operation is a short chain of transitions between state hashes:
//!
//! ```text
//!  Value(mint | swap | melt)   epoch, liabilities and event log
//!  NfLow + NfInsert            one sorted nullifier insert, per nullifier
//!  NoteInsert                  one or two note appends
//! ```
//!
//! The value step starts the operation's `Transition`; each insert step
//! extends it and checks it continues from the state the transition ends at.
//! `FoldStep` joins the transitions of consecutive operations into a chain.
//!
//! A tree update walks the old and the new leaf up the same siblings, eight
//! levels a step. Two leaves changed together (a nullifier insert's low leaf
//! and appended leaf, or two note appends) are a *pair*: each climbs on its
//! own only to the level where the paths meet, and the rest is walked once.

use ragu::drivers::{Driver, DriverValue};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::FixedVec;
use ragu::primitives::{decompose, decompose_n, multiadd, Boolean, Element};
use ragu::step::{Encoded, Index, Oracles, Step};
use zashu_core::spec::hash::{T_MELT, T_MINT, T_NF_LEAF, T_STATE};
use zashu_core::spec::op::Kind;
use zashu_core::spec::DEPTH;

use super::gadgets::{
    alloc_u64, constant, enforce_equal, enforce_true, enforce_u64, header, node, or, sponge, values_of, StepOut, V,
};

/// Merkle levels per update step (each level hashes the old and the new node).
pub(super) const UPD_LEVELS: usize = 8;
/// Levels each leaf of a pair can climb inside `PairStart`.
pub(super) const START_LIFT: usize = 3;
/// Levels climbed right after a `PairJoin`.
pub(super) const JOIN_LEVELS: usize = 6;
/// Internal tag of a pair's second leaf: `(leaf, index_delta)`.
const T_PAIR: u64 = 1_000;

header!(
    /// `[state_before, liabilities_before, state_after, liabilities_after, count]`.
    Transition, 5, 5
);
header!(
    /// `[old_node, new_node, old_leaf, new_leaf, index, weight, pair]`:
    /// changing the leaf at `index` from `old_leaf` to `new_leaf` moves its
    /// ancestor `log2(weight)` levels up from `old_node` to `new_node`.
    ///
    /// `pair` is zero for a single leaf. Otherwise a second leaf, `delta` to
    /// the right and previously empty, was filled with `b` in the same
    /// update, and `pair = H_PAIR(b, delta)`.
    Update, 3, 7
);
header!(
    /// `[pre_root, post_root, nf, next_value, next_index, appended]`: a
    /// sorted insertion of `nf`, whose appended leaf hash still has to be
    /// checked against `(nf, next_value, next_index)`.
    NfMid, 4, 6
);

pub(super) const T_START: usize = 0;
pub(super) const T_START_LIAB: usize = 1;
pub(super) const T_END: usize = 2;
pub(super) const T_END_LIAB: usize = 3;
pub(super) const T_COUNT: usize = 4;

const U_OLD: usize = 0;
const U_NEW: usize = 1;
const U_OLD_LEAF: usize = 2;
const U_NEW_LEAF: usize = 3;
const U_INDEX: usize = 4;
const U_WEIGHT: usize = 5;
const U_PAIR: usize = 6;

fn state_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
    liabilities: &Element<'dr, D>,
    nullifier_root: &Element<'dr, D>,
    note_root: &Element<'dr, D>,
    event_log: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    sponge(
        dr,
        T_STATE,
        &[epoch.clone(), liabilities.clone(), nullifier_root.clone(), note_root.clone(), event_log.clone()],
    )
}

// --------------------------------------------------------------------------
// Value steps
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct StateW {
    pub(super) epoch: u64,
    pub(super) liabilities: u64,
    pub(super) nullifier_root: Fp,
    pub(super) note_root: Fp,
    pub(super) event_log: Fp,
}

#[derive(Clone, Copy)]
pub(crate) struct ValueW {
    pub(super) before: StateW,
    pub(super) epoch_after: u64,
    pub(super) liabilities_after: u64,
    pub(super) event: Fp,
}

fn value_step<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    w: DriverValue<D, ValueW>,
    kind: Kind,
) -> ragu::Result<V<'dr, D, 5>> {
    let allocator = &mut Standard::new();
    let epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.before.epoch))?;
    let liab = alloc_u64(dr, allocator, w.as_ref().map(|w| w.before.liabilities))?;
    let nf_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.before.nullifier_root))?;
    let note_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.before.note_root))?;
    let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.before.event_log))?;
    let epoch_after = alloc_u64(dr, allocator, w.as_ref().map(|w| w.epoch_after))?;
    let liab_after = alloc_u64(dr, allocator, w.as_ref().map(|w| w.liabilities_after))?;

    // Epochs never go backwards.
    let elapsed = epoch_after.sub(dr, &epoch);
    enforce_u64(dr, allocator, &elapsed)?;

    let log_after = match kind {
        Kind::Swap => {
            enforce_equal(dr, &liab, &liab_after)?;
            log.clone()
        }
        Kind::Mint | Kind::Melt => {
            // A non-zero amount in the right direction: the wrong direction
            // wraps the field and fails the range check.
            let mint = kind == Kind::Mint;
            let amount = if mint { liab_after.sub(dr, &liab) } else { liab.sub(dr, &liab_after) };
            enforce_u64(dr, allocator, &amount)?;
            amount.clone().enforce_nonzero(dr)?;
            let event = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event))?;
            sponge(dr, if mint { T_MINT } else { T_MELT }, &[log.clone(), event, amount])?
        }
    };

    let before = state_hash(dr, &epoch, &liab, &nf_root, &note_root, &log)?;
    let after = state_hash(dr, &epoch_after, &liab_after, &nf_root, &note_root, &log_after)?;
    FixedVec::new(vec![before, liab, after, liab_after, Element::one()])
}

macro_rules! value {
    ($name:ident, $index:expr, $kind:expr) => {
        pub(crate) struct $name;

        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = ValueW;
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = Transition;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                witness: DriverValue<D, ValueW>,
                _: DriverValue<D, ()>,
                _: DriverValue<D, ()>,
            ) -> StepOut<'dr, D, Self, HS>
            where
                Self: 'dr,
            {
                let out = value_step(dr, witness, $kind)?;
                let data = values_of(&out);
                Ok((
                    (Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)),
                    data,
                    D::unit(),
                ))
            }
        }
    };
}

value!(ValueMint, 9, Kind::Mint);
value!(ValueSwap, 10, Kind::Swap);
value!(ValueMelt, 11, Kind::Melt);

/// Joins two transitions: the left ends exactly where the right begins.
pub(crate) struct FoldStep;

impl Step<Pasta> for FoldStep {
    const INDEX: Index = Index::new(12);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Transition;
    type Right = Transition;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 5]>,
        right: DriverValue<D, [Fp; 5]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let l: &V<'dr, D, 5> = left.as_gadget();
        let r: &V<'dr, D, 5> = right.as_gadget();
        enforce_equal(dr, &l[T_END], &r[T_START])?;
        enforce_equal(dr, &l[T_END_LIAB], &r[T_START_LIAB])?;
        let count = l[T_COUNT].add(dr, &r[T_COUNT]);
        let out: V<'dr, D, 5> = FixedVec::new(vec![
            l[T_START].clone(),
            l[T_START_LIAB].clone(),
            r[T_END].clone(),
            r[T_END_LIAB].clone(),
            count,
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Merkle leaf updates
// --------------------------------------------------------------------------

/// Up to `N` Merkle levels of one climb. Inactive levels are skipped, so a
/// step can stop at any height.
#[derive(Clone, Copy)]
pub(crate) struct Levels<const N: usize> {
    pub(super) siblings: [Fp; N],
    pub(super) bits: [bool; N],
    pub(super) active: [bool; N],
}

/// `(old, new, index, weight)`: a subtree root before and after the change,
/// the changed leaf's index within that subtree and the subtree's leaf count.
type Node<'dr, D> = (Element<'dr, D>, Element<'dr, D>, Element<'dr, D>, Element<'dr, D>);

fn climb<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    start: Node<'dr, D>,
    w: &DriverValue<D, Levels<N>>,
) -> ragu::Result<Node<'dr, D>> {
    let (mut old, mut new, mut index, mut weight) = start;
    for i in 0..N {
        let sibling = Element::alloc(dr, allocator, w.as_ref().map(|w| w.siblings[i]))?;
        let is_right = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.bits[i]))?;
        let active = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.active[i]))?;

        let left = is_right.conditional_select(dr, &old, &sibling)?;
        let right = old.add(dr, &sibling).sub(dr, &left);
        let up = node(dr, &left, &right)?;
        old = active.conditional_select(dr, &old, &up)?;

        let left = is_right.conditional_select(dr, &new, &sibling)?;
        let right = new.add(dr, &sibling).sub(dr, &left);
        let up = node(dr, &left, &right)?;
        new = active.conditional_select(dr, &new, &up)?;

        let counted = active.and(dr, &is_right)?;
        let term = counted.element().mul(dr, &weight)?;
        index = index.add(dr, &term);
        let grow = active.element().mul(dr, &weight)?;
        weight = weight.add(dr, &grow);
    }
    Ok((old, new, index, weight))
}

/// Joins two changed subtrees of equal size that are siblings, `a` on the
/// left. The result is addressed by `a`'s leaf; `b`'s leaf (which must have
/// been empty) is remembered as `pair = H_PAIR(b_new_leaf, b_index - a_index)`.
fn join<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: Node<'dr, D>,
    b: Node<'dr, D>,
    b_new_leaf: &Element<'dr, D>,
) -> ragu::Result<(Node<'dr, D>, Element<'dr, D>)> {
    enforce_equal(dr, &a.3, &b.3)?;
    let old = node(dr, &a.0, &b.0)?;
    let new = node(dr, &a.1, &b.1)?;
    let delta = b.2.add(dr, &a.3).sub(dr, &a.2);
    let pair = sponge(dr, T_PAIR, &[b_new_leaf.clone(), delta])?;
    let weight = a.3.add(dr, &a.3);
    Ok(((old, new, a.2, weight), pair))
}

#[derive(Clone, Copy)]
pub(crate) struct UpdW {
    pub(super) old_leaf: Fp,
    pub(super) new_leaf: Fp,
    pub(super) levels: Levels<UPD_LEVELS>,
}

pub(crate) struct UpdStart;

impl Step<Pasta> for UpdStart {
    const INDEX: Index = Index::new(13);
    type Witness<'source> = UpdW;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, UpdW>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let old_leaf = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.old_leaf))?;
        let new_leaf = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.new_leaf))?;
        let start = (old_leaf.clone(), new_leaf.clone(), Element::zero(dr), Element::one());
        let (old, new, index, weight) = climb(dr, allocator, start, &witness.as_ref().map(|w| w.levels))?;
        let out: V<'dr, D, 7> =
            FixedVec::new(vec![old, new, old_leaf, new_leaf, index, weight, Element::zero(dr)])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

pub(crate) struct UpdExtend;

impl Step<Pasta> for UpdExtend {
    const INDEX: Index = Index::new(14);
    type Witness<'source> = Levels<UPD_LEVELS>;
    type Aux<'source> = ();
    type Left = Update;
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Levels<UPD_LEVELS>>,
        left: DriverValue<D, [Fp; 7]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let u: &V<'dr, D, 7> = left.as_gadget();
        let start = (u[U_OLD].clone(), u[U_NEW].clone(), u[U_INDEX].clone(), u[U_WEIGHT].clone());
        let (old, new, index, weight) = climb(dr, allocator, start, &witness)?;
        let out: V<'dr, D, 7> = FixedVec::new(vec![
            old,
            new,
            u[U_OLD_LEAF].clone(),
            u[U_NEW_LEAF].clone(),
            index,
            weight,
            u[U_PAIR].clone(),
        ])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Two leaves whose paths meet within [`START_LIFT`] levels: `a` changes and
/// `b`, to its right, is filled.
#[derive(Clone, Copy)]
pub(crate) struct PairStartW {
    pub(super) a_old: Fp,
    pub(super) a_new: Fp,
    pub(super) b_new: Fp,
    pub(super) a_levels: Levels<START_LIFT>,
    pub(super) b_levels: Levels<START_LIFT>,
}

pub(crate) struct PairStart;

impl Step<Pasta> for PairStart {
    const INDEX: Index = Index::new(15);
    type Witness<'source> = PairStartW;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, PairStartW>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let a_old = Element::alloc(dr, allocator, w.as_ref().map(|w| w.a_old))?;
        let a_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.a_new))?;
        let b_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b_new))?;

        let a = (a_old.clone(), a_new.clone(), Element::zero(dr), Element::one());
        let a = climb(dr, allocator, a, &w.as_ref().map(|w| w.a_levels))?;
        // `b` fills an empty slot.
        let b = (Element::zero(dr), b_new.clone(), Element::zero(dr), Element::one());
        let b = climb(dr, allocator, b, &w.as_ref().map(|w| w.b_levels))?;
        let ((old, new, index, weight), pair) = join(dr, a, b, &b_new)?;

        let out: V<'dr, D, 7> = FixedVec::new(vec![old, new, a_old, a_new, index, weight, pair])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Joins two single-leaf updates that climbed to the same height, the right
/// one filling an empty slot, and climbs on.
pub(crate) struct PairJoin;

impl Step<Pasta> for PairJoin {
    const INDEX: Index = Index::new(16);
    type Witness<'source> = Levels<JOIN_LEVELS>;
    type Aux<'source> = ();
    type Left = Update;
    type Right = Update;
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Levels<JOIN_LEVELS>>,
        left: DriverValue<D, [Fp; 7]>,
        right: DriverValue<D, [Fp; 7]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let a: &V<'dr, D, 7> = left.as_gadget();
        let b: &V<'dr, D, 7> = right.as_gadget();
        // Each side is a single leaf, and the right one was empty.
        a[U_PAIR].enforce_zero(dr)?;
        b[U_PAIR].enforce_zero(dr)?;
        b[U_OLD_LEAF].enforce_zero(dr)?;

        let side = |u: &V<'dr, D, 7>| (u[U_OLD].clone(), u[U_NEW].clone(), u[U_INDEX].clone(), u[U_WEIGHT].clone());
        let (joined, pair) = join(dr, side(a), side(b), &b[U_NEW_LEAF])?;
        let (old, new, index, weight) = climb(dr, allocator, joined, &witness)?;

        let out: V<'dr, D, 7> =
            FixedVec::new(vec![old, new, a[U_OLD_LEAF].clone(), a[U_NEW_LEAF].clone(), index, weight, pair])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// The update reached the root: its weight is `2^DEPTH`.
fn enforce_full_depth<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, update: &V<'dr, D, 7>) -> ragu::Result<()> {
    let full = constant(dr, 1u64 << DEPTH);
    enforce_equal(dr, &update[U_WEIGHT], &full)
}

// --------------------------------------------------------------------------
// Note appends
// --------------------------------------------------------------------------

/// The state fields a root-changing step does not touch.
#[derive(Clone, Copy)]
pub(crate) struct RestW {
    pub(super) epoch: u64,
    pub(super) liabilities: u64,
    /// `NoteInsert`: the nullifier root. `NfInsert`: the note root.
    pub(super) other_root: Fp,
    pub(super) event_log: Fp,
}

#[derive(Clone, Copy)]
pub(crate) struct NoteInsertW {
    pub(super) rest: RestW,
    /// The second leaf of a pair and how far right of the first it sits.
    pub(super) b_new: Fp,
    pub(super) delta: Fp,
}

/// Extends the running transition with a note-tree update that fills one
/// empty leaf, or two when the update is a pair.
pub(crate) struct NoteInsert;

impl Step<Pasta> for NoteInsert {
    const INDEX: Index = Index::new(17);
    type Witness<'source> = NoteInsertW;
    type Aux<'source> = ();
    type Left = Transition;
    type Right = Update;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, NoteInsertW>,
        left: DriverValue<D, [Fp; 5]>,
        right: DriverValue<D, [Fp; 7]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let t: &V<'dr, D, 5> = left.as_gadget();
        let u: &V<'dr, D, 7> = right.as_gadget();
        enforce_full_depth(dr, u)?;
        // Append-only: the slot was empty (a pair's second slot was checked
        // when it was joined).
        u[U_OLD_LEAF].enforce_zero(dr)?;

        // A pair must be opened, so that it is a pair of this kind.
        let single = u[U_PAIR].is_zero(dr, allocator)?;
        let b_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b_new))?;
        let delta = Element::alloc(dr, allocator, w.as_ref().map(|w| w.delta))?;
        let opened = sponge(dr, T_PAIR, &[b_new, delta])?;
        let paired = single.not(dr);
        opened.sub(dr, &u[U_PAIR]).mul(dr, &paired.element())?.enforce_zero(dr)?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.rest.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.rest.liabilities)))?;
        let nf_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rest.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rest.event_log))?;
        let before = state_hash(dr, &epoch, &liab, &nf_root, &u[U_OLD], &log)?;
        let after = state_hash(dr, &epoch, &liab, &nf_root, &u[U_NEW], &log)?;
        // Continues exactly where the running transition ends.
        enforce_equal(dr, &t[T_END], &before)?;
        enforce_equal(dr, &t[T_END_LIAB], &liab)?;

        let out: V<'dr, D, 5> =
            FixedVec::new(vec![t[T_START].clone(), t[T_START_LIAB].clone(), after, liab, t[T_COUNT].clone()])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Nullifier inserts
// --------------------------------------------------------------------------

fn pow2(e: usize) -> Fp {
    (0..e).fold(Fp::from(1u64), |x, _| x + x)
}

type Key<'dr, D> = (Element<'dr, D>, Element<'dr, D>);

/// A field element as the two halves `(high 127 bits, low 128 bits)` of its
/// canonical integer, which order the same way the integers do.
fn order_key<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    value: &Element<'dr, D>,
) -> ragu::Result<Key<'dr, D>> {
    // Canonical little-endian bits.
    let bits = decompose(dr, allocator, value)?;
    let (mut hi_terms, mut hi_coeffs) = (Vec::new(), Vec::new());
    let (mut lo_terms, mut lo_coeffs) = (Vec::new(), Vec::new());
    for (k, bit) in bits.iter().enumerate() {
        if k < 128 {
            lo_terms.push(bit.element());
            lo_coeffs.push(pow2(k));
        } else {
            hi_terms.push(bit.element());
            hi_coeffs.push(pow2(k - 128));
        }
    }
    Ok((multiadd(dr, &hi_terms, &hi_coeffs), multiadd(dr, &lo_terms, &lo_coeffs)))
}

/// `x < y` for `x, y < 2^128`: bit 128 of `2^128 + y - x - 1`.
fn lt_128<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    x: &Element<'dr, D>,
    y: &Element<'dr, D>,
) -> ragu::Result<Boolean<'dr, D>> {
    let offset = Element::constant(dr, pow2(128) - Fp::from(1u64));
    let z = y.sub(dr, x).add(dr, &offset);
    let bits = decompose_n::<_, 129>(dr, allocator, &z)?;
    Ok(bits[128].clone())
}

fn key_lt<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    a: &Key<'dr, D>,
    b: &Key<'dr, D>,
) -> ragu::Result<Boolean<'dr, D>> {
    let hi_lt = lt_128(dr, allocator, &a.0, &b.0)?;
    let hi_eq = a.0.is_equal(dr, allocator, &b.0)?;
    let lo_lt = lt_128(dr, allocator, &a.1, &b.1)?;
    let tie = hi_eq.and(dr, &lo_lt)?;
    or(dr, &hi_lt, &tie)
}

fn leaf_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    value: &Element<'dr, D>,
    next_value: &Element<'dr, D>,
    next_index: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    sponge(dr, T_NF_LEAF, &[value.clone(), next_value.clone(), next_index.clone()])
}

#[derive(Clone, Copy)]
pub(crate) struct NfLowW {
    /// The low leaf before the insert.
    pub(super) value: Fp,
    pub(super) next_value: Fp,
    pub(super) next_index: u64,
    pub(super) nf: Fp,
    pub(super) new_index: u64,
    /// The appended leaf and how far right of the low leaf it sits.
    pub(super) b_new: Fp,
    pub(super) delta: Fp,
}

/// Checks a paired update against a sorted insertion: `low.value < nf <
/// low.next_value` (or the low leaf is the last), the low leaf is re-pointed
/// at `nf`, and the pair's second leaf landed on `new_index`.
pub(crate) struct NfLow;

impl Step<Pasta> for NfLow {
    const INDEX: Index = Index::new(18);
    type Witness<'source> = NfLowW;
    type Aux<'source> = ();
    type Left = Update;
    type Right = ();
    type Output = NfMid;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, NfLowW>,
        left: DriverValue<D, [Fp; 7]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let u: &V<'dr, D, 7> = left.as_gadget();
        enforce_full_depth(dr, u)?;

        let value = Element::alloc(dr, allocator, w.as_ref().map(|w| w.value))?;
        let nf = Element::alloc(dr, allocator, w.as_ref().map(|w| w.nf))?;
        let next_value = Element::alloc(dr, allocator, w.as_ref().map(|w| w.next_value))?;
        let next_index = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.next_index)))?;
        let new_index = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.new_index)))?;
        let b_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b_new))?;
        let delta = Element::alloc(dr, allocator, w.as_ref().map(|w| w.delta))?;

        // Sorted: the nullifier falls in the gap after the low leaf.
        let k_value = order_key(dr, allocator, &value)?;
        let k_nf = order_key(dr, allocator, &nf)?;
        let k_next = order_key(dr, allocator, &next_value)?;
        let above_low = key_lt(dr, allocator, &k_value, &k_nf)?;
        enforce_true(dr, &above_low)?;
        let below_next = key_lt(dr, allocator, &k_nf, &k_next)?;
        let no_next = next_value.is_zero(dr, allocator)?;
        let in_gap = or(dr, &no_next, &below_next)?;
        enforce_true(dr, &in_gap)?;

        // The pair's second leaf is the one appended at `new_index`.
        let opened = sponge(dr, T_PAIR, &[b_new.clone(), delta.clone()])?;
        enforce_equal(dr, &opened, &u[U_PAIR])?;
        let appended_at = u[U_INDEX].add(dr, &delta);
        enforce_equal(dr, &appended_at, &new_index)?;

        let old_low = leaf_hash(dr, &value, &next_value, &next_index)?;
        enforce_equal(dr, &old_low, &u[U_OLD_LEAF])?;
        let new_low = leaf_hash(dr, &value, &nf, &new_index)?;
        enforce_equal(dr, &new_low, &u[U_NEW_LEAF])?;

        let out: V<'dr, D, 6> =
            FixedVec::new(vec![u[U_OLD].clone(), u[U_NEW].clone(), nf, next_value, next_index, b_new])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Checks the appended leaf is `(nf, next_value, next_index)` and extends the
/// running transition with the whole insertion.
pub(crate) struct NfInsert;

impl Step<Pasta> for NfInsert {
    const INDEX: Index = Index::new(19);
    type Witness<'source> = RestW;
    type Aux<'source> = ();
    type Left = Transition;
    type Right = NfMid;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, RestW>,
        left: DriverValue<D, [Fp; 5]>,
        right: DriverValue<D, [Fp; 6]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let t: &V<'dr, D, 5> = left.as_gadget();
        let m: &V<'dr, D, 6> = right.as_gadget();
        let (pre_root, post_root, nf, next_value, next_index, appended) = (&m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);

        // The new leaf takes over the low leaf's old successor.
        let leaf = leaf_hash(dr, nf, next_value, next_index)?;
        enforce_equal(dr, &leaf, appended)?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.liabilities)))?;
        let note_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event_log))?;
        let before = state_hash(dr, &epoch, &liab, pre_root, &note_root, &log)?;
        let after = state_hash(dr, &epoch, &liab, post_root, &note_root, &log)?;
        // Continues exactly where the running transition ends.
        enforce_equal(dr, &t[T_END], &before)?;
        enforce_equal(dr, &t[T_END_LIAB], &liab)?;

        let out: V<'dr, D, 5> =
            FixedVec::new(vec![t[T_START].clone(), t[T_START_LIAB].clone(), after, liab, t[T_COUNT].clone()])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}
