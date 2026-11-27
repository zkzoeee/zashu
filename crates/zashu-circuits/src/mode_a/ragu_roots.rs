//! Ragu fold for the Mode A solvency proof that also binds how the event log,
//! nullifier root and note root change (`FoldBackend::Ragu`).
//!
//! The simpler fold in [`ragu_backend`](super::ragu_backend) opens each step's
//! state hashes but lets the two roots and the event log move freely. Here a
//! mint operation is proven as a short chain of single-purpose transitions,
//! each between two state hashes that differ in exactly one respect:
//!
//! ```text
//!  Value(mint | melt | swap)      epoch, liabilities and event log
//!  NfInsert   x nullifiers        nullifier root, one indexed-tree insert each
//!  NoteInsert x outputs           note root, one or two appends each
//! ```
//!
//! * **Value** steps require both roots to stay put, and a mint or melt must
//!   extend the event log with `Poseidon4(log, DOMAIN, quote, amount)` where
//!   `amount` is exactly the change in liabilities. A swap leaves it alone.
//! * **NoteInsert** proves the note root changed by writing a commitment into
//!   a previously empty leaf: an `Update` chain (4 levels a step) walks the
//!   old and the new leaf up the same siblings to the old and the new root.
//! * **NfInsert** proves a sorted indexed-Merkle-tree insertion: `NfLow`
//!   checks `low.val < nf < low.next_val` (or `low` is the last leaf) and that
//!   the low leaf was re-pointed at `nf`, and `NfInsert` that the new leaf was
//!   appended into an empty slot. Nullifiers can only ever be added.
//!
//! Two leaves changed together are an `Update` *pair*: each climbs on its own
//! only to the level where their paths meet (`PairStart` when that is within
//! two levels, `PairJoin` otherwise), and the shared path above is walked
//! once. A nullifier insert is always a pair (low leaf and appended leaf);
//! note outputs are paired two at a time.
//!
//! The value step starts an operation's `Transition` and every insert step
//! extends it, checking it continues from the state the transition ends at.
//! Operations are fused with the recursive `FoldStep`, so the published proof
//! attests an unbroken chain from the genesis state to the current one.
//!
//! Not covered: that the inserted nullifiers and notes are the ones the
//! operation's Mode B proof (or BDHKE spend) authorised, and that the amounts
//! match what was paid over Lightning. Those are checked by the mint, and by
//! an auditor replaying the public event log.

use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{decompose, decompose_n, multiadd, Boolean, Element};
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::Pcd;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zashu_acc::{LeafUpdate, NullifierTransitionWitness, ACC_DEPTH};
use zashu_core::field::{bytes_to_fp, hash_bytes_to_fp};
use zashu_core::poseidon::{
    hash_event_melt, hash_event_mint, DOMAIN_ACC, DOMAIN_MELT, DOMAIN_MINT, DOMAIN_STATE,
};
use zashu_core::types::MintState;

use super::ragu_backend::{
    finish_with, ragu_err, verify_with, BackgroundFolder, FoldStep, FolderOps, Payload, Rank, Running,
    StateFields, StepKind, Transition, TransitionPcd, ANCHOR, COUNT, DIGEST, END_LIAB, END_STATE, PAYLOAD,
    START_LIAB, START_STATE,
};
use crate::error::{CircuitError, Result};
use crate::pcd::{FoldedProof, StateTransition, SubcircuitId};
use crate::ragu_gadgets::{
    fp_from_bytes, fp_from_pasta, poseidon_hash, values_of, TAG_NODE, TAG_OUTPUT, TAG_SPEND,
};

type App = crate::ragu_app::WalletApp;

/// Merkle levels proven per update step (each level hashes twice: old and new).
const UPD_LEVELS: usize = 4;
const _: () = assert!(ACC_DEPTH % UPD_LEVELS == 0 && ACC_DEPTH == 32);

macro_rules! header {
    ($(#[$doc:meta])* $name:ident, $suffix:expr, $n:expr) => {
        $(#[$doc])*
        pub(crate) struct $name;

        impl Header<Fp> for $name {
            const SUFFIX: Suffix = Suffix::new($suffix);
            type OnlinePolyCommit = (Padding, Padding);
            type Data = [Fp; $n];
            type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<$n>>];

            fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: DriverValue<D, Self::Data>,
            ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
                FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
            }
        }
    };
}

// `Transition` (suffix 0) comes from `ragu_backend`.
header!(
    /// `[old_node, new_node, old_leaf, new_leaf, index, weight, pair]`:
    /// changing the leaf at `index` from `old_leaf` to `new_leaf` moves its
    /// ancestor `log2(weight)` levels up from `old_node` to `new_node`.
    ///
    /// `pair` is zero for a single leaf. Otherwise a second leaf, `delta` to
    /// the right and previously empty, was filled with `b` in the same
    /// update, and `pair = Poseidon2(b, delta)`.
    Update, 1, 7
);
// Suffix 2 is unused.
header!(
    /// `[pre_root, post_root, nf, next_val, next_idx, appended]`: a sorted
    /// insertion of `nf` moved the nullifier root from `pre_root` to
    /// `post_root`, appending the leaf hash `appended`, which still has to be
    /// checked against `(nf, next_val, next_idx)`.
    NfMid, 3, 6
);

const U_OLD: usize = 0;
const U_NEW: usize = 1;
const U_OLD_LEAF: usize = 2;
const U_NEW_LEAF: usize = 3;
const U_INDEX: usize = 4;
const U_WEIGHT: usize = 5;
const U_PAIR: usize = 6;

type V<'dr, D, const N: usize> = FixedVec<Element<'dr, D>, ConstLen<N>>;

type StepOut<'dr, D, S, const HS: usize> = ragu::Result<(
    (
        Encoded<'dr, D, <S as Step<Pasta>>::Left, HS>,
        Encoded<'dr, D, <S as Step<Pasta>>::Right, HS>,
        Encoded<'dr, D, <S as Step<Pasta>>::Output, HS>,
    ),
    DriverValue<D, <<S as Step<Pasta>>::Output as Header<Fp>>::Data>,
    DriverValue<D, ()>,
)>;

fn constant<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, v: u64) -> Element<'dr, D> {
    Element::constant(dr, Fp::from(v))
}

fn pow2(e: usize) -> Fp {
    (0..e).fold(Fp::from(1u64), |x, _| x + x)
}

fn enforce_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> ragu::Result<()> {
    a.sub(dr, b).enforce_zero(dr)
}

fn enforce_true<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, b: &Boolean<'dr, D>) -> ragu::Result<()> {
    b.element().sub(dr, &Element::one()).enforce_zero(dr)
}

fn or<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Boolean<'dr, D>,
    b: &Boolean<'dr, D>,
) -> ragu::Result<Boolean<'dr, D>> {
    let (na, nb) = (a.not(dr), b.not(dr));
    Ok(na.and(dr, &nb)?.not(dr))
}

fn alloc_u64<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    v: DriverValue<D, u64>,
) -> ragu::Result<Element<'dr, D>> {
    let e = Element::alloc(dr, allocator, v.map(Fp::from))?;
    e.enforce_le::<64>(dr, allocator, Fp::from(u64::MAX))?;
    Ok(e)
}

/// `hash_acc_node(left, right) = Poseidon3(DOMAIN_ACC, left, right)`
fn acc_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    left: &Element<'dr, D>,
    right: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    let domain = constant(dr, DOMAIN_ACC);
    poseidon_hash(dr, &[domain, left.clone(), right.clone()])
}

/// `IndexedLeaf::hash = hash_acc_node(hash_acc_node(val, next_val), next_idx)`
fn indexed_leaf_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    val: &Element<'dr, D>,
    next_val: &Element<'dr, D>,
    next_idx: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    let inner = acc_hash(dr, val, next_val)?;
    acc_hash(dr, &inner, next_idx)
}

/// `Poseidon4(DOMAIN_STATE, epoch, liabilities, nf_root)`, the inner state hash.
fn state_inner<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
    liabilities: &Element<'dr, D>,
    nf_root: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    let domain = constant(dr, DOMAIN_STATE);
    poseidon_hash(dr, &[domain, epoch.clone(), liabilities.clone(), nf_root.clone()])
}

/// `Poseidon3(inner, note_root, event_log)`, the state hash.
fn state_outer<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    inner: &Element<'dr, D>,
    note_root: &Element<'dr, D>,
    event_log: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    poseidon_hash(dr, &[inner.clone(), note_root.clone(), event_log.clone()])
}

// --------------------------------------------------------------------------
// Value steps: epoch, liabilities and event log; roots fixed
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct ValueWitness {
    prev: StateFields,
    next_epoch: u64,
    next_liabilities: u64,
    /// Mint: quote hash. Melt: payout hash. Swap: unused.
    event: Fp,
}

fn value_leaf<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    w: DriverValue<D, ValueWitness>,
    kind: StepKind,
) -> ragu::Result<Payload<'dr, D>> {
    let allocator = &mut Standard::new();
    let max = Fp::from(u64::MAX);

    let epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.prev.epoch))?;
    let liab = alloc_u64(dr, allocator, w.as_ref().map(|w| w.prev.liabilities))?;
    let nf_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.prev.nf_root))?;
    let note_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.prev.note_root))?;
    let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.prev.event_log))?;
    let next_epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.next_epoch))?;
    let next_liab = alloc_u64(dr, allocator, w.as_ref().map(|w| w.next_liabilities))?;

    // Epochs never go backwards.
    next_epoch.sub(dr, &epoch).enforce_le::<64>(dr, allocator, max)?;

    let next_log = match kind {
        StepKind::Swap => {
            enforce_equal(dr, &liab, &next_liab)?;
            log.clone()
        }
        StepKind::Mint | StepKind::Melt => {
            // A non-zero u64 amount in the right direction (a wrong direction
            // wraps the field and fails the range check)...
            let amount = if kind == StepKind::Mint { next_liab.sub(dr, &liab) } else { liab.sub(dr, &next_liab) };
            amount.enforce_le::<64>(dr, allocator, max)?;
            amount.clone().enforce_nonzero(dr)?;
            // ...which is exactly the amount recorded in the event log.
            let event = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event))?;
            let domain = constant(dr, if kind == StepKind::Mint { DOMAIN_MINT } else { DOMAIN_MELT });
            poseidon_hash(dr, &[log.clone(), domain, event, amount])?
        }
    };

    let inner_prev = state_inner(dr, &epoch, &liab, &nf_root)?;
    let inner_next = state_inner(dr, &next_epoch, &next_liab, &nf_root)?;
    let hash_prev = state_outer(dr, &inner_prev, &note_root, &log)?;
    let hash_next = state_outer(dr, &inner_next, &note_root, &next_log)?;
    // No inserts here; the anchor is the note root this operation starts from.
    let digest = Element::zero(dr);
    FixedVec::new(vec![hash_prev, liab, hash_next, next_liab, Element::one(), digest, note_root])
}

macro_rules! value_step {
    ($name:ident, $index:expr, $kind:expr) => {
        pub(crate) struct $name;

        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = ValueWitness;
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = Transition;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                witness: DriverValue<D, ValueWitness>,
                _: DriverValue<D, ()>,
                _: DriverValue<D, ()>,
            ) -> StepOut<'dr, D, Self, HS>
            where
                Self: 'dr,
            {
                let out = value_leaf(dr, witness, $kind)?;
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

value_step!(ValueMint, 0, StepKind::Mint);
value_step!(ValueSwap, 1, StepKind::Swap);
value_step!(ValueMelt, 2, StepKind::Melt);
// Index 3 is `FoldStep`.

// --------------------------------------------------------------------------
// Merkle leaf updates
// --------------------------------------------------------------------------

/// Up to `N` Merkle levels of one climb. Inactive levels are skipped, so a
/// step can stop at any height.
#[derive(Clone, Copy)]
pub(crate) struct Levels<const N: usize> {
    siblings: [Fp; N],
    /// Bit `i` set: the running node is the right child at level `i`.
    bits: [bool; N],
    active: [bool; N],
}

impl<const N: usize> Levels<N> {
    /// The first `N` levels of `siblings`/`index` starting at `from`, clipped
    /// to `until`; the rest are inactive.
    fn of(u: &LeafUpdate, from: usize, until: usize) -> Result<Self> {
        let mut out = Levels { siblings: [Fp::from(0u64); N], bits: [false; N], active: [false; N] };
        for j in 0..N {
            let level = from + j;
            if level < until {
                out.siblings[j] = tree_fp(&u.siblings[level])?;
                out.bits[j] = (u.leaf_index >> level) & 1 == 1;
                out.active[j] = true;
            }
        }
        Ok(out)
    }
}

/// `(old, new, index, weight)`: a subtree root before and after the change,
/// the changed leaf's index within that subtree and the subtree's leaf count.
type Node<'dr, D> = (Element<'dr, D>, Element<'dr, D>, Element<'dr, D>, Element<'dr, D>);

/// Walks the old and the new node up the active levels over shared siblings,
/// accumulating the leaf index. `weight` is `2^levels_so_far`.
fn climb<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    node: Node<'dr, D>,
    w: &DriverValue<D, Levels<N>>,
) -> ragu::Result<Node<'dr, D>> {
    let (mut old, mut new, mut index, mut weight) = node;
    for i in 0..N {
        let sibling = Element::alloc(dr, allocator, w.as_ref().map(|w| w.siblings[i]))?;
        let is_right = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.bits[i]))?;
        let active = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.active[i]))?;

        let left = is_right.conditional_select(dr, &old, &sibling)?;
        let right = old.add(dr, &sibling).sub(dr, &left);
        let up = acc_hash(dr, &left, &right)?;
        old = active.conditional_select(dr, &old, &up)?;

        let left = is_right.conditional_select(dr, &new, &sibling)?;
        let right = new.add(dr, &sibling).sub(dr, &left);
        let up = acc_hash(dr, &left, &right)?;
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
/// been empty) is remembered as `pair = Poseidon2(b_new_leaf, b_index - a_index)`.
fn join<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: Node<'dr, D>,
    b: Node<'dr, D>,
    b_new_leaf: &Element<'dr, D>,
) -> ragu::Result<(Node<'dr, D>, Element<'dr, D>)> {
    enforce_equal(dr, &a.3, &b.3)?;
    let old = acc_hash(dr, &a.0, &b.0)?;
    let new = acc_hash(dr, &a.1, &b.1)?;
    let delta = b.2.add(dr, &a.3).sub(dr, &a.2);
    let pair = poseidon_hash(dr, &[b_new_leaf.clone(), delta])?;
    let weight = a.3.add(dr, &a.3);
    Ok(((old, new, a.2, weight), pair))
}

#[derive(Clone, Copy)]
pub(crate) struct UpdWitness {
    old_leaf: Fp,
    new_leaf: Fp,
    levels: Levels<UPD_LEVELS>,
}

pub(crate) struct UpdStart;

impl Step<Pasta> for UpdStart {
    const INDEX: Index = Index::new(4);
    type Witness<'source> = UpdWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, UpdWitness>,
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
        let levels = witness.as_ref().map(|w| w.levels);
        let (old, new, index, weight) = climb(dr, allocator, start, &levels)?;
        let pair = Element::zero(dr);
        let out: V<'dr, D, 7> = FixedVec::new(vec![old, new, old_leaf, new_leaf, index, weight, pair])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

pub(crate) struct UpdExtend;

impl Step<Pasta> for UpdExtend {
    const INDEX: Index = Index::new(5);
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

/// Two leaves whose paths meet within two levels: `a` changes and `b`, to its
/// right, is filled. With `lift` both climb one level before they are joined.
#[derive(Clone, Copy)]
pub(crate) struct PairStartWitness {
    a_old: Fp,
    a_new: Fp,
    b_new: Fp,
    a_level: Levels<1>,
    b_level: Levels<1>,
}

pub(crate) struct PairStart;

impl Step<Pasta> for PairStart {
    const INDEX: Index = Index::new(7);
    type Witness<'source> = PairStartWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, PairStartWitness>,
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
        let a = climb(dr, allocator, a, &w.as_ref().map(|w| w.a_level))?;
        // `b` fills an empty slot.
        let b = (Element::zero(dr), b_new.clone(), Element::zero(dr), Element::one());
        let b = climb(dr, allocator, b, &w.as_ref().map(|w| w.b_level))?;
        let ((old, new, index, weight), pair) = join(dr, a, b, &b_new)?;

        let out: V<'dr, D, 7> = FixedVec::new(vec![old, new, a_old, a_new, index, weight, pair])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Levels climbed right after a [`PairJoin`].
const JOIN_LEVELS: usize = 2;

/// Joins two single-leaf updates that climbed to the same height, the right
/// one filling an empty slot, and climbs on.
pub(crate) struct PairJoin;

impl Step<Pasta> for PairJoin {
    const INDEX: Index = Index::new(25);
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

        let node = |u: &V<'dr, D, 7>| (u[U_OLD].clone(), u[U_NEW].clone(), u[U_INDEX].clone(), u[U_WEIGHT].clone());
        let (joined, pair) = join(dr, node(a), node(b), &b[U_NEW_LEAF])?;
        let (old, new, index, weight) = climb(dr, allocator, joined, &witness)?;

        let out: V<'dr, D, 7> =
            FixedVec::new(vec![old, new, a[U_OLD_LEAF].clone(), a[U_NEW_LEAF].clone(), index, weight, pair])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// The update reached the root: its weight is `2^ACC_DEPTH`.
fn enforce_full_depth<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, update: &V<'dr, D, 7>) -> ragu::Result<()> {
    let full = constant(dr, 1u64 << ACC_DEPTH);
    enforce_equal(dr, &update[U_WEIGHT], &full)
}

/// Appends `leaf` to a running digest: a zero digest (nothing inserted yet)
/// is replaced, anything else is chained exactly as `FoldStep` would.
fn absorb<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    digest: &Element<'dr, D>,
    leaf: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    let empty = digest.is_zero(dr, allocator)?;
    let tag = constant(dr, TAG_NODE);
    let node = poseidon_hash(dr, &[tag, digest.clone(), leaf.clone()])?;
    empty.conditional_select(dr, &node, leaf)
}

// --------------------------------------------------------------------------
// Note insert: the note root changes by filling one or two empty leaves
// --------------------------------------------------------------------------

/// The state fields a root-changing step does not touch.
#[derive(Clone, Copy)]
pub(crate) struct RestWitness {
    epoch: u64,
    liabilities: u64,
    /// NoteInsert: the nullifier root. NfInsert: the note root.
    other_root: Fp,
    event_log: Fp,
}

#[derive(Clone, Copy)]
pub(crate) struct NoteInsertWitness {
    rest: RestWitness,
    /// The second leaf of a paired update and how far right of the first it
    /// sits; unused for a single leaf.
    b_new: Fp,
    delta: Fp,
}

/// Extends the operation's running transition with a note-tree update that
/// fills one empty leaf, or two when the update is a pair.
pub(crate) struct NoteInsert;

impl Step<Pasta> for NoteInsert {
    const INDEX: Index = Index::new(6);
    type Witness<'source> = NoteInsertWitness;
    type Aux<'source> = ();
    type Left = Transition;
    type Right = Update;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, NoteInsertWitness>,
        left: DriverValue<D, [Fp; PAYLOAD]>,
        right: DriverValue<D, [Fp; 7]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let t: &Payload<'dr, D> = left.as_gadget();
        let u: &V<'dr, D, 7> = right.as_gadget();
        enforce_full_depth(dr, u)?;
        // Append-only: the slot was empty (a pair's second slot was checked
        // when it was joined).
        u[U_OLD_LEAF].enforce_zero(dr)?;

        // A pair commits to its second leaf; a single update has none.
        let single = u[U_PAIR].is_zero(dr, allocator)?;
        let b_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b_new))?;
        let delta = Element::alloc(dr, allocator, w.as_ref().map(|w| w.delta))?;
        let opened = poseidon_hash(dr, &[b_new.clone(), delta])?;
        let paired = single.not(dr);
        opened.sub(dr, &u[U_PAIR]).mul(dr, &paired.element())?.enforce_zero(dr)?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.rest.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.rest.liabilities)))?;
        let nf_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rest.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rest.event_log))?;

        let inner = state_inner(dr, &epoch, &liab, &nf_root)?;
        let hash_prev = state_outer(dr, &inner, &u[U_OLD], &log)?;
        let hash_next = state_outer(dr, &inner, &u[U_NEW], &log)?;
        // Continues exactly where the running transition ends.
        enforce_equal(dr, &t[END_STATE], &hash_prev)?;
        enforce_equal(dr, &t[END_LIAB], &liab)?;

        // The inserted commitments enter the operation's digest as outputs.
        let tag = constant(dr, TAG_OUTPUT);
        let first = poseidon_hash(dr, &[tag.clone(), u[U_NEW_LEAF].clone()])?;
        let second = poseidon_hash(dr, &[tag, b_new])?;
        let one = absorb(dr, allocator, &t[DIGEST], &first)?;
        let node_tag = constant(dr, TAG_NODE);
        let two = poseidon_hash(dr, &[node_tag, one.clone(), second])?;
        let digest = single.conditional_select(dr, &two, &one)?;

        let out: Payload<'dr, D> = FixedVec::new(vec![
            t[START_STATE].clone(),
            t[START_LIAB].clone(),
            hash_next,
            liab,
            t[COUNT].clone(),
            digest,
            t[ANCHOR].clone(),
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Nullifier insert: a sorted indexed-tree insertion
// --------------------------------------------------------------------------

/// The accumulator orders 32-byte values lexicographically, first byte most
/// significant, and the bytes are the little-endian encoding of the field
/// element. This returns that order's key as two 128-bit halves `(hi, lo)`.
fn order_key<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    value: &Element<'dr, D>,
) -> ragu::Result<(Element<'dr, D>, Element<'dr, D>)> {
    // Canonical little-endian bits (unsatisfiable only for the negligible
    // fraction of field elements at or above 2^254).
    let bits = decompose(dr, allocator, value)?;
    let (mut hi_terms, mut hi_coeffs) = (Vec::new(), Vec::new());
    let (mut lo_terms, mut lo_coeffs) = (Vec::new(), Vec::new());
    for (k, bit) in bits.iter().enumerate() {
        let (byte, t) = (k / 8, k % 8);
        if byte < 16 {
            hi_terms.push(bit.element());
            hi_coeffs.push(pow2((15 - byte) * 8 + t));
        } else {
            lo_terms.push(bit.element());
            lo_coeffs.push(pow2((31 - byte) * 8 + t));
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

type Key<'dr, D> = (Element<'dr, D>, Element<'dr, D>);

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

#[derive(Clone, Copy)]
pub(crate) struct NfLowWitness {
    /// The low leaf before the insert: `(val, next_val, next_idx)`.
    val: Fp,
    next_val: Fp,
    next_idx: u64,
    nf: Fp,
    /// Where the new leaf is appended.
    new_idx: u64,
    /// The appended leaf and how far right of the low leaf it sits.
    b_new: Fp,
    delta: Fp,
}

/// Checks a paired update against a sorted insertion: `low.val < nf <
/// low.next_val` (or `low` is the last leaf), the low leaf is re-pointed
/// `(val, next_val, next_idx) -> (val, nf, new_idx)`, and the second leaf of
/// the pair landed on `new_idx`.
pub(crate) struct NfLow;

impl Step<Pasta> for NfLow {
    const INDEX: Index = Index::new(8);
    type Witness<'source> = NfLowWitness;
    type Aux<'source> = ();
    type Left = Update;
    type Right = ();
    type Output = NfMid;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, NfLowWitness>,
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

        let val = Element::alloc(dr, allocator, w.as_ref().map(|w| w.val))?;
        let nf = Element::alloc(dr, allocator, w.as_ref().map(|w| w.nf))?;
        let next_val = Element::alloc(dr, allocator, w.as_ref().map(|w| w.next_val))?;
        let next_idx = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.next_idx)))?;
        let new_idx = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.new_idx)))?;
        let b_new = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b_new))?;
        let delta = Element::alloc(dr, allocator, w.as_ref().map(|w| w.delta))?;

        // Sorted: the nullifier falls in the gap after the low leaf.
        let k_val = order_key(dr, allocator, &val)?;
        let k_nf = order_key(dr, allocator, &nf)?;
        let k_next = order_key(dr, allocator, &next_val)?;
        let above_low = key_lt(dr, allocator, &k_val, &k_nf)?;
        enforce_true(dr, &above_low)?;
        let below_next = key_lt(dr, allocator, &k_nf, &k_next)?;
        let no_next = next_val.is_zero(dr, allocator)?;
        let in_gap = or(dr, &no_next, &below_next)?;
        enforce_true(dr, &in_gap)?;

        // The pair's second leaf is the one appended at `new_idx`.
        let opened = poseidon_hash(dr, &[b_new.clone(), delta.clone()])?;
        enforce_equal(dr, &opened, &u[U_PAIR])?;
        let appended_at = u[U_INDEX].add(dr, &delta);
        enforce_equal(dr, &appended_at, &new_idx)?;

        let old_low = indexed_leaf_hash(dr, &val, &next_val, &next_idx)?;
        enforce_equal(dr, &old_low, &u[U_OLD_LEAF])?;
        let new_low = indexed_leaf_hash(dr, &val, &nf, &new_idx)?;
        enforce_equal(dr, &new_low, &u[U_NEW_LEAF])?;

        let out: V<'dr, D, 6> =
            FixedVec::new(vec![u[U_OLD].clone(), u[U_NEW].clone(), nf, next_val, next_idx, b_new])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Checks the appended leaf is `(nf, next_val, next_idx)` and extends the
/// operation's running transition with the whole insertion.
pub(crate) struct NfInsert;

impl Step<Pasta> for NfInsert {
    const INDEX: Index = Index::new(9);
    type Witness<'source> = RestWitness;
    type Aux<'source> = ();
    type Left = Transition;
    type Right = NfMid;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, RestWitness>,
        left: DriverValue<D, [Fp; PAYLOAD]>,
        right: DriverValue<D, [Fp; 6]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let t: &Payload<'dr, D> = left.as_gadget();
        let m: &V<'dr, D, 6> = right.as_gadget();
        let (pre_root, post_root, nf, next_val, next_idx, appended) = (&m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);

        // The new leaf takes over the low leaf's old successor.
        let new_leaf = indexed_leaf_hash(dr, nf, next_val, next_idx)?;
        enforce_equal(dr, &new_leaf, appended)?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.liabilities)))?;
        let note_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event_log))?;

        let inner_prev = state_inner(dr, &epoch, &liab, pre_root)?;
        let inner_next = state_inner(dr, &epoch, &liab, post_root)?;
        let hash_prev = state_outer(dr, &inner_prev, &note_root, &log)?;
        let hash_next = state_outer(dr, &inner_next, &note_root, &log)?;
        // Continues exactly where the running transition ends.
        enforce_equal(dr, &t[END_STATE], &hash_prev)?;
        enforce_equal(dr, &t[END_LIAB], &liab)?;

        // The inserted nullifier enters the operation's digest as a spend.
        let tag = constant(dr, TAG_SPEND);
        let spend = poseidon_hash(dr, &[tag, nf.clone()])?;
        let digest = absorb(dr, allocator, &t[DIGEST], &spend)?;

        let out: Payload<'dr, D> = FixedVec::new(vec![
            t[START_STATE].clone(),
            t[START_LIAB].clone(),
            hash_next,
            liab,
            t[COUNT].clone(),
            digest,
            t[ANCHOR].clone(),
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Native side
// --------------------------------------------------------------------------

fn app() -> Result<&'static App> {
    crate::ragu_app::wallet()
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn unit(app: &App) -> Pcd<Pasta, Rank, ()> {
    app.bootstrap_proof().clone().carry::<()>(())
}

fn fuse(app: &App, left: TransitionPcd, right: TransitionPcd) -> Result<TransitionPcd> {
    app.fuse(&mut rng(), FoldStep, (), left, right).map(|p| p.0).map_err(|e| ragu_err("fuse", e))
}

/// Accumulator bytes as a field element. Tree values must be canonical so the
/// circuit hashes and orders the same thing the accumulator does.
fn tree_fp(bytes: &[u8; 32]) -> Result<Fp> {
    fp_from_bytes(bytes).map_err(|_| {
        CircuitError::InvalidWitness(
            "accumulator value is not a canonical field element; canonicalise nullifiers before inserting".into(),
        )
    })
}

fn single_start(u: &LeafUpdate, until: usize) -> Result<UpdWitness> {
    Ok(UpdWitness { old_leaf: tree_fp(&u.old_leaf)?, new_leaf: tree_fp(&u.new_leaf)?, levels: Levels::of(u, 0, until)? })
}

/// Climbs `pcd` from level `from` up to (not including) level `until`.
fn climb_to(
    app: &App,
    mut pcd: Pcd<Pasta, Rank, Update>,
    u: &LeafUpdate,
    from: usize,
    until: usize,
) -> Result<Pcd<Pasta, Rank, Update>> {
    let mut level = from;
    while level < until {
        pcd = app
            .fuse(&mut rng(), UpdExtend, Levels::of(u, level, until)?, pcd, unit(app))
            .map_err(|e| ragu_err("update", e))?
            .0;
        level += UPD_LEVELS;
    }
    Ok(pcd)
}

fn check_update(u: &LeafUpdate) -> Result<()> {
    if u.siblings.len() != ACC_DEPTH || u.leaf_index >> ACC_DEPTH != 0 {
        return Err(CircuitError::InvalidWitness("invalid leaf update".into()));
    }
    Ok(())
}

/// One leaf changed: its path from the leaf to the root.
fn prove_update(app: &App, u: &LeafUpdate) -> Result<Pcd<Pasta, Rank, Update>> {
    check_update(u)?;
    let pcd = app.seed(&mut rng(), UpdStart, single_start(u, ACC_DEPTH)?).map_err(|e| ragu_err("update", e))?.0;
    climb_to(app, pcd, u, UPD_LEVELS, ACC_DEPTH)
}

/// Two leaves changed, `a` first and then `b` to its right filling an empty
/// slot. Their paths are proven separately only up to where they meet; the
/// shared part above is proven once.
fn prove_pair(app: &App, a: &LeafUpdate, b: &LeafUpdate) -> Result<Pcd<Pasta, Rank, Update>> {
    check_update(a)?;
    check_update(b)?;
    if a.leaf_index >= b.leaf_index || b.old_leaf != [0u8; 32] || b.pre_root != a.post_root {
        return Err(CircuitError::InvalidWitness("leaf updates cannot be proven as a pair".into()));
    }
    // The level at which the two paths become siblings.
    let meet = (63 - (a.leaf_index ^ b.leaf_index).leading_zeros()) as usize;
    let (pcd, done) = if meet <= 1 {
        let w = PairStartWitness {
            a_old: tree_fp(&a.old_leaf)?,
            a_new: tree_fp(&a.new_leaf)?,
            b_new: tree_fp(&b.new_leaf)?,
            a_level: Levels::of(a, 0, meet)?,
            b_level: Levels::of(b, 0, meet)?,
        };
        (app.seed(&mut rng(), PairStart, w).map_err(|e| ragu_err("pair", e))?.0, meet + 1)
    } else {
        let side = |u: &LeafUpdate| -> Result<Pcd<Pasta, Rank, Update>> {
            let pcd = app.seed(&mut rng(), UpdStart, single_start(u, meet)?).map_err(|e| ragu_err("update", e))?.0;
            climb_to(app, pcd, u, UPD_LEVELS, meet)
        };
        let (left, right) = (side(a)?, side(b)?);
        let after = Levels::of(a, meet + 1, ACC_DEPTH)?;
        let pcd = app.fuse(&mut rng(), PairJoin, after, left, right).map_err(|e| ragu_err("pair", e))?.0;
        (pcd, meet + 1 + JOIN_LEVELS)
    };
    // Above the meeting point both leaves share `a`'s path.
    climb_to(app, pcd, a, done, ACC_DEPTH)
}

fn rest(state: &MintState, other_root: Fp) -> Result<RestWitness> {
    let f = StateFields::of(state)?;
    Ok(RestWitness { epoch: f.epoch, liabilities: f.liabilities, other_root, event_log: f.event_log })
}

fn index_delta(a: &LeafUpdate, b: &LeafUpdate) -> Fp {
    Fp::from(b.leaf_index - a.leaf_index)
}

/// Extends `acc` with one sorted nullifier insertion.
fn prove_nullifier_insert(
    app: &App,
    state: &MintState,
    t: &NullifierTransitionWitness,
    acc: TransitionPcd,
) -> Result<TransitionPcd> {
    let missing = || CircuitError::InvalidWitness("nullifier transition carries no tree updates".into());
    let (low_update, append_update) =
        (t.low_update.as_ref().ok_or_else(missing)?, t.append_update.as_ref().ok_or_else(missing)?);
    let low = &t.non_membership.low_leaf;

    let pair = prove_pair(app, low_update, append_update)?;
    let w = NfLowWitness {
        val: tree_fp(&low.val)?,
        next_val: tree_fp(&low.next_val)?,
        next_idx: low.next_idx,
        nf: tree_fp(&t.nullifier)?,
        new_idx: t.new_leaf_index,
        b_new: tree_fp(&append_update.new_leaf)?,
        delta: index_delta(low_update, append_update),
    };
    let mid = app.fuse(&mut rng(), NfLow, w, pair, unit(app)).map_err(|e| ragu_err("nullifier low leaf", e))?.0;
    let w = rest(state, StateFields::of(state)?.note_root)?;
    app.fuse(&mut rng(), NfInsert, w, acc, mid).map(|p| p.0).map_err(|e| ragu_err("nullifier insert", e))
}

/// Extends `acc` with one note append, or with two proven as a pair.
fn prove_note_insert(
    app: &App,
    state: &MintState,
    first: &LeafUpdate,
    second: Option<&LeafUpdate>,
    acc: TransitionPcd,
) -> Result<TransitionPcd> {
    let rest = rest(state, StateFields::of(state)?.nf_root)?;
    let (upd, w) = match second {
        None => (prove_update(app, first)?, NoteInsertWitness { rest, b_new: Fp::from(0u64), delta: Fp::from(0u64) }),
        Some(second) => (
            prove_pair(app, first, second)?,
            NoteInsertWitness { rest, b_new: tree_fp(&second.new_leaf)?, delta: index_delta(first, second) },
        ),
    };
    app.fuse(&mut rng(), NoteInsert, w, acc, upd).map(|p| p.0).map_err(|e| ragu_err("note insert", e))
}

fn step_parts(step: &FoldedProof) -> Result<(StepKind, &StateTransition)> {
    let kind = match step.subcircuit {
        SubcircuitId::MintStep => StepKind::Mint,
        SubcircuitId::SwapStep => StepKind::Swap,
        SubcircuitId::MeltStep => StepKind::Melt,
        other => return Err(CircuitError::InvalidWitness(format!("cannot fold {other:?} with the Ragu backend"))),
    };
    let t = step.transition.as_deref().ok_or_else(|| {
        CircuitError::InvalidWitness(format!(
            "{:?} step proof carries no state transition; the Ragu backend needs it",
            step.subcircuit
        ))
    })?;
    Ok((kind, t))
}

/// Proves one mint operation as its chain of single-purpose transitions.
pub(super) fn prove_step(app: &App, step: &FoldedProof) -> Result<(TransitionPcd, StateFields, StateFields)> {
    let (kind, t) = step_parts(step)?;
    let (prev, next) = (&t.prev, &t.next);
    let invalid = |msg: &str| CircuitError::InvalidWitness(format!("{:?} step: {msg}", step.subcircuit));

    // 1. Value: epoch, liabilities and event log move; the roots do not.
    let mut cur = prev.clone();
    cur.epoch = next.epoch;
    cur.total_liabilities = next.total_liabilities;
    cur.event_log_hash = next.event_log_hash;
    if cur.epoch < prev.epoch {
        return Err(invalid("epoch went backwards"));
    }
    let event = match kind {
        StepKind::Swap => {
            if cur.total_liabilities != prev.total_liabilities || cur.event_log_hash != prev.event_log_hash {
                return Err(invalid("a swap must not change liabilities or the event log"));
            }
            Fp::from(0u64)
        }
        StepKind::Mint | StepKind::Melt => {
            let mint = kind == StepKind::Mint;
            let amount = if mint {
                cur.total_liabilities.checked_sub(prev.total_liabilities)
            } else {
                prev.total_liabilities.checked_sub(cur.total_liabilities)
            };
            let amount = amount.filter(|a| *a > 0).ok_or(CircuitError::ValueBounds)?;
            let event = t.event.ok_or_else(|| invalid("no quote/payout hash recorded (use `with_event`)"))?;
            let expected = if mint {
                hash_event_mint(&prev.event_log_hash, &event, amount)
            } else {
                hash_event_melt(&prev.event_log_hash, &event, amount)
            };
            if expected != cur.event_log_hash {
                return Err(invalid("event log does not extend with this event and amount"));
            }
            let domain: &[u8] = if mint { b"zashu-q" } else { b"zashu-p" };
            fp_from_pasta(&bytes_to_fp(&event).unwrap_or_else(|_| hash_bytes_to_fp(domain, &event)))
        }
    };
    let w = ValueWitness {
        prev: StateFields::of(prev)?,
        next_epoch: cur.epoch,
        next_liabilities: cur.total_liabilities,
        event,
    };
    let seeded = match kind {
        StepKind::Mint => app.seed(&mut rng(), ValueMint, w).map(|p| p.0),
        StepKind::Swap => app.seed(&mut rng(), ValueSwap, w).map(|p| p.0),
        StepKind::Melt => app.seed(&mut rng(), ValueMelt, w).map(|p| p.0),
    };
    let mut acc = seeded.map_err(|e| ragu_err("value step", e))?;

    // 2. Nullifier inserts, in order.
    for nt in &t.nullifier_updates {
        if cur.nullifier_acc_root != nt.pre_root {
            return Err(invalid("nullifier updates do not chain from the state's nullifier root"));
        }
        acc = prove_nullifier_insert(app, &cur, nt, acc)?;
        cur.nullifier_acc_root = nt.post_root;
    }

    // 3. Note inserts, in order, two at a time where they can share a path.
    for chunk in t.note_updates.chunks(2) {
        if cur.note_acc_root != chunk[0].pre_root {
            return Err(invalid("note updates do not chain from the state's note root"));
        }
        let pairable = chunk.len() == 2
            && chunk[1].pre_root == chunk[0].post_root
            && chunk[0].leaf_index < chunk[1].leaf_index
            && chunk[1].old_leaf == [0u8; 32];
        if pairable {
            acc = prove_note_insert(app, &cur, &chunk[0], Some(&chunk[1]), acc)?;
            cur.note_acc_root = chunk[1].post_root;
        } else {
            for nu in chunk {
                if cur.note_acc_root != nu.pre_root {
                    return Err(invalid("note updates do not chain from the state's note root"));
                }
                acc = prove_note_insert(app, &cur, nu, None, acc)?;
                cur.note_acc_root = nu.post_root;
            }
        }
    }

    if &cur != next {
        return Err(invalid(
            "the recorded event and root updates do not account for the state change \
             (record them with `with_event` / `with_root_updates`)",
        ));
    }
    Ok((acc, StateFields::of(prev)?, StateFields::of(next)?))
}

fn extend(acc: Option<Running>, step: &FoldedProof) -> Result<Running> {
    let app = app()?;
    let (pcd, prev, next) = prove_step(app, step)?;
    match acc {
        None => Ok((pcd, next, 1)),
        Some((root, end, steps)) => {
            if end != prev {
                return Err(CircuitError::InvalidWitness(format!(
                    "step {steps} does not chain onto the folded state"
                )));
            }
            Ok((fuse(app, root, pcd)?, next, steps + 1))
        }
    }
}

fn finish(root: &TransitionPcd, steps: usize) -> Result<FoldedProof> {
    finish_with(app()?, root, steps, SubcircuitId::RaguFoldRoots)
}

/// Folds a contiguous sequence of Mode A step proofs, binding every event-log
/// and root change. The step proofs must carry their events and root updates.
pub fn fold(start_state: &MintState, end_state: &MintState, step_proofs: &[FoldedProof]) -> Result<FoldedProof> {
    if step_proofs.is_empty() {
        return Err(CircuitError::InvalidWitness("cannot fold empty proof batch".into()));
    }
    let first = step_parts(&step_proofs[0])?.1;
    if &first.prev != start_state {
        return Err(CircuitError::InvalidWitness("step proofs do not start at the requested state".into()));
    }
    let mut acc: Option<Running> = None;
    for step in step_proofs {
        acc = Some(extend(acc, step)?);
    }
    let (root, end, steps) = acc.expect("non-empty batch");
    if end != StateFields::of(end_state)? {
        return Err(CircuitError::InvalidWitness("step proofs do not end at the requested state".into()));
    }
    finish(&root, steps)
}

/// A background folder for this application; see [`BackgroundFolder`].
pub fn background() -> BackgroundFolder {
    BackgroundFolder::spawn_with(FolderOps { extend, finish })
}

/// Verifies a root-binding Ragu fold proof against its own public inputs.
pub fn verify(proof: &FoldedProof) -> Result<()> {
    verify_with(app()?, SubcircuitId::RaguFoldRoots, proof)
}
