//! Ragu fold for the Mode A solvency proof that also binds how the event log,
//! nullifier root and note root change (`FoldBackend::Ragu`, the default).
//!
//! The simpler fold in [`ragu_backend`](super::ragu_backend) opens each step's
//! state hashes but lets the two roots and the event log move freely. Here a
//! mint operation is proven as a short chain of single-purpose transitions,
//! each between two state hashes that differ in exactly one respect:
//!
//! ```text
//!  Value(mint | melt | swap)      epoch, liabilities and event log
//!  NfInsert   x nullifiers        nullifier root, one indexed-tree insert each
//!  NoteInsert x outputs           note root, one append each
//! ```
//!
//! * **Value** steps require both roots to stay put, and a mint or melt must
//!   extend the event log with `Poseidon4(log, DOMAIN, quote, amount)` where
//!   `amount` is exactly the change in liabilities. A swap leaves it alone.
//! * **NoteInsert** proves the note root changed by writing a commitment into
//!   a previously empty leaf: an `Update` chain (8 steps of 4 levels) walks the
//!   old and the new leaf up the same siblings to the old and the new root.
//! * **NfInsert** proves a sorted indexed-Merkle-tree insertion: an `Order`
//!   step checks `low.val < nf < low.next_val` (or `low` is the last leaf), one
//!   `Update` chain re-points the low leaf at `nf`, and a second one appends
//!   the new leaf into an empty slot. Nullifiers can only ever be added.
//!
//! All of these are `Transition`s, fused with the same recursive `FoldStep`,
//! so the published proof attests an unbroken chain of them from the genesis
//! state to the current one.
//!
//! Not covered: that the inserted nullifiers and notes are the ones the
//! operation's Mode B proof (or BDHKE spend) authorised, and that the amounts
//! match what was paid over Lightning. Those are checked by the mint, and by
//! an auditor replaying the public event log.

use std::sync::OnceLock;

use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{decompose, decompose_n, multiadd, Boolean, Element};
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::{Application, ApplicationBuilder, Coeff, Pcd};
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
    StateFields, StepKind, Transition, TransitionPcd,
};
use crate::error::{CircuitError, Result};
use crate::pcd::{FoldedProof, StateTransition, SubcircuitId};
use crate::ragu_gadgets::{fp_from_bytes, fp_from_pasta, poseidon_hash, values_of};

/// Largest header payload (6) plus Ragu's suffix slot.
const HEADER_SIZE: usize = 7;
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;

/// Merkle levels proven per update step (each level hashes twice: old and new).
const UPD_LEVELS: usize = 4;
const UPD_STEPS: usize = ACC_DEPTH / UPD_LEVELS;
const _: () = assert!(ACC_DEPTH % UPD_LEVELS == 0 && ACC_DEPTH == 32);

macro_rules! header {
    ($(#[$doc:meta])* $name:ident, $suffix:expr, $n:expr) => {
        $(#[$doc])*
        struct $name;

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
    /// `[old_node, new_node, old_leaf, new_leaf, index, weight]`: changing the
    /// leaf at `index` from `old_leaf` to `new_leaf` moves its ancestor
    /// `log2(weight)` levels up from `old_node` to `new_node`.
    Update, 1, 6
);
header!(
    /// `[val, nf, next_val]` with `val < nf`, and `nf < next_val` unless
    /// `next_val` is zero (no successor), in the accumulator's byte order.
    Order, 2, 3
);
header!(
    /// `[pre_root, mid_root, nf, next_val, next_idx, new_idx]`: the low leaf
    /// was re-pointed at `nf`; the new leaf still has to be appended.
    NfMid, 3, 6
);

const U_OLD: usize = 0;
const U_NEW: usize = 1;
const U_OLD_LEAF: usize = 2;
const U_NEW_LEAF: usize = 3;
const U_INDEX: usize = 4;
const U_WEIGHT: usize = 5;

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
struct ValueWitness {
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
    FixedVec::new(vec![hash_prev, liab, hash_next, next_liab, Element::one()])
}

macro_rules! value_step {
    ($name:ident, $index:expr, $kind:expr) => {
        struct $name;

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

#[derive(Clone, Copy)]
struct UpdWitness {
    old_leaf: Fp,
    new_leaf: Fp,
    siblings: [Fp; UPD_LEVELS],
    /// Bit `i` set: the running node is the right child at level `i`.
    bits: [bool; UPD_LEVELS],
}

/// Walks the old and the new node up [`UPD_LEVELS`] levels over shared
/// siblings, accumulating the leaf index. `weight` is `2^levels_so_far`.
#[allow(clippy::type_complexity)]
fn climb<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    mut old: Element<'dr, D>,
    mut new: Element<'dr, D>,
    mut index: Element<'dr, D>,
    weight: &Element<'dr, D>,
    w: &DriverValue<D, UpdWitness>,
) -> ragu::Result<(Element<'dr, D>, Element<'dr, D>, Element<'dr, D>)> {
    for i in 0..UPD_LEVELS {
        let sibling = Element::alloc(dr, allocator, w.as_ref().map(|w| w.siblings[i]))?;
        let is_right = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.bits[i]))?;

        let left = is_right.conditional_select(dr, &old, &sibling)?;
        let right = old.add(dr, &sibling).sub(dr, &left);
        old = acc_hash(dr, &left, &right)?;

        let left = is_right.conditional_select(dr, &new, &sibling)?;
        let right = new.add(dr, &sibling).sub(dr, &left);
        new = acc_hash(dr, &left, &right)?;

        let bit_weight = weight.scale(dr, Coeff::Arbitrary(Fp::from(1u64 << i)));
        let term = is_right.element().mul(dr, &bit_weight)?;
        index = index.add(dr, &term);
    }
    Ok((old, new, index))
}

fn next_weight<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, weight: &Element<'dr, D>) -> Element<'dr, D> {
    weight.scale(dr, Coeff::Arbitrary(Fp::from(1u64 << UPD_LEVELS)))
}

struct UpdStart;

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
        let one = Element::one();
        let zero = Element::zero(dr);
        let (old, new, index) = climb(dr, allocator, old_leaf.clone(), new_leaf.clone(), zero, &one, &witness)?;
        let weight = next_weight(dr, &one);
        let out: V<'dr, D, 6> = FixedVec::new(vec![old, new, old_leaf, new_leaf, index, weight])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

struct UpdExtend;

impl Step<Pasta> for UpdExtend {
    const INDEX: Index = Index::new(5);
    type Witness<'source> = UpdWitness;
    type Aux<'source> = ();
    type Left = Update;
    type Right = ();
    type Output = Update;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, UpdWitness>,
        left: DriverValue<D, [Fp; 6]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let u: &V<'dr, D, 6> = left.as_gadget();
        let (old, new, index) =
            climb(dr, allocator, u[U_OLD].clone(), u[U_NEW].clone(), u[U_INDEX].clone(), &u[U_WEIGHT], &witness)?;
        let weight = next_weight(dr, &u[U_WEIGHT]);
        let out: V<'dr, D, 6> =
            FixedVec::new(vec![old, new, u[U_OLD_LEAF].clone(), u[U_NEW_LEAF].clone(), index, weight])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// The update reached the root: its weight is `2^ACC_DEPTH`.
fn enforce_full_depth<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, update: &V<'dr, D, 6>) -> ragu::Result<()> {
    let full = constant(dr, 1u64 << ACC_DEPTH);
    enforce_equal(dr, &update[U_WEIGHT], &full)
}

// --------------------------------------------------------------------------
// Note insert: the note root changes by filling an empty leaf
// --------------------------------------------------------------------------

/// The state fields a root-changing step does not touch.
#[derive(Clone, Copy)]
struct RestWitness {
    epoch: u64,
    liabilities: u64,
    /// NoteInsert: the nullifier root. NfInsert: the note root.
    other_root: Fp,
    event_log: Fp,
}

struct NoteInsert;

impl Step<Pasta> for NoteInsert {
    const INDEX: Index = Index::new(6);
    type Witness<'source> = RestWitness;
    type Aux<'source> = ();
    type Left = Update;
    type Right = ();
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, RestWitness>,
        left: DriverValue<D, [Fp; 6]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let u: &V<'dr, D, 6> = left.as_gadget();
        enforce_full_depth(dr, u)?;
        // Append-only: the slot was empty.
        u[U_OLD_LEAF].enforce_zero(dr)?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.liabilities)))?;
        let nf_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event_log))?;

        let inner = state_inner(dr, &epoch, &liab, &nf_root)?;
        let hash_prev = state_outer(dr, &inner, &u[U_OLD], &log)?;
        let hash_next = state_outer(dr, &inner, &u[U_NEW], &log)?;
        let zero = Element::zero(dr);
        let out: Payload<'dr, D> = FixedVec::new(vec![hash_prev, liab.clone(), hash_next, liab, zero])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
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

struct OrderStep;

impl Step<Pasta> for OrderStep {
    const INDEX: Index = Index::new(7);
    /// `[val, nf, next_val]`
    type Witness<'source> = [Fp; 3];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Order;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, [Fp; 3]>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let val = Element::alloc(dr, allocator, w.as_ref().map(|w| w[0]))?;
        let nf = Element::alloc(dr, allocator, w.as_ref().map(|w| w[1]))?;
        let next = Element::alloc(dr, allocator, w.as_ref().map(|w| w[2]))?;

        let k_val = order_key(dr, allocator, &val)?;
        let k_nf = order_key(dr, allocator, &nf)?;
        let k_next = order_key(dr, allocator, &next)?;

        let above_low = key_lt(dr, allocator, &k_val, &k_nf)?;
        enforce_true(dr, &above_low)?;
        let below_next = key_lt(dr, allocator, &k_nf, &k_next)?;
        let no_next = next.is_zero(dr, allocator)?;
        let in_gap = or(dr, &no_next, &below_next)?;
        enforce_true(dr, &in_gap)?;

        let out: V<'dr, D, 3> = FixedVec::new(vec![val, nf, next])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Re-points the low leaf: `(val, next_val, next_idx) -> (val, nf, new_idx)`.
struct NfLow;

impl Step<Pasta> for NfLow {
    const INDEX: Index = Index::new(8);
    /// `(low.next_idx, new_idx)`
    type Witness<'source> = (u64, u64);
    type Aux<'source> = ();
    type Left = Update;
    type Right = Order;
    type Output = NfMid;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, (u64, u64)>,
        left: DriverValue<D, [Fp; 6]>,
        right: DriverValue<D, [Fp; 3]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let u: &V<'dr, D, 6> = left.as_gadget();
        let o: &V<'dr, D, 3> = right.as_gadget();
        let (val, nf, next_val) = (&o[0], &o[1], &o[2]);
        enforce_full_depth(dr, u)?;

        let next_idx = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.0)))?;
        let new_idx = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.1)))?;

        let old_low = indexed_leaf_hash(dr, val, next_val, &next_idx)?;
        enforce_equal(dr, &old_low, &u[U_OLD_LEAF])?;
        let new_low = indexed_leaf_hash(dr, val, nf, &new_idx)?;
        enforce_equal(dr, &new_low, &u[U_NEW_LEAF])?;

        let out: V<'dr, D, 6> = FixedVec::new(vec![
            u[U_OLD].clone(),
            u[U_NEW].clone(),
            nf.clone(),
            next_val.clone(),
            next_idx,
            new_idx,
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Appends the new leaf `(nf, next_val, next_idx)` at `new_idx` and exposes the
/// whole insertion as a state transition.
struct NfInsert;

impl Step<Pasta> for NfInsert {
    const INDEX: Index = Index::new(9);
    type Witness<'source> = RestWitness;
    type Aux<'source> = ();
    type Left = NfMid;
    type Right = Update;
    type Output = Transition;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, RestWitness>,
        left: DriverValue<D, [Fp; 6]>,
        right: DriverValue<D, [Fp; 6]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let m: &V<'dr, D, 6> = left.as_gadget();
        let a: &V<'dr, D, 6> = right.as_gadget();
        let (pre_root, mid_root, nf, next_val, next_idx, new_idx) = (&m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);

        enforce_full_depth(dr, a)?;
        // The append continues from the tree the low-leaf update left, lands
        // on the index the low leaf now points at, and fills an empty slot.
        enforce_equal(dr, &a[U_OLD], mid_root)?;
        enforce_equal(dr, &a[U_INDEX], new_idx)?;
        a[U_OLD_LEAF].enforce_zero(dr)?;
        let new_leaf = indexed_leaf_hash(dr, nf, next_val, next_idx)?;
        enforce_equal(dr, &new_leaf, &a[U_NEW_LEAF])?;

        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.epoch)))?;
        let liab = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.liabilities)))?;
        let note_root = Element::alloc(dr, allocator, w.as_ref().map(|w| w.other_root))?;
        let log = Element::alloc(dr, allocator, w.as_ref().map(|w| w.event_log))?;

        let inner_prev = state_inner(dr, &epoch, &liab, pre_root)?;
        let inner_next = state_inner(dr, &epoch, &liab, &a[U_NEW])?;
        let hash_prev = state_outer(dr, &inner_prev, &note_root, &log)?;
        let hash_next = state_outer(dr, &inner_next, &note_root, &log)?;
        let zero = Element::zero(dr);
        let out: Payload<'dr, D> = FixedVec::new(vec![hash_prev, liab.clone(), hash_next, liab, zero])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Native side
// --------------------------------------------------------------------------

fn app() -> Result<&'static App> {
    static APP: OnceLock<std::result::Result<App, String>> = OnceLock::new();
    APP.get_or_init(|| {
        let pasta = ragu::pcd::pasta::baked();
        ApplicationBuilder::<Pasta, Rank, HEADER_SIZE>::new()
            .register(ValueMint)
            .and_then(|b| b.register(ValueSwap))
            .and_then(|b| b.register(ValueMelt))
            .and_then(|b| b.register(FoldStep))
            .and_then(|b| b.register(UpdStart))
            .and_then(|b| b.register(UpdExtend))
            .and_then(|b| b.register(NoteInsert))
            .and_then(|b| b.register(OrderStep))
            .and_then(|b| b.register(NfLow))
            .and_then(|b| b.register(NfInsert))
            .and_then(|b| b.finalize(pasta))
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| CircuitError::Plonk(format!("ragu root-binding application build: {e}")))
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

fn prove_update(app: &App, u: &LeafUpdate) -> Result<Pcd<Pasta, Rank, Update>> {
    if u.siblings.len() != ACC_DEPTH {
        return Err(CircuitError::InvalidWitness("invalid sibling length".into()));
    }
    let (old_leaf, new_leaf) = (tree_fp(&u.old_leaf)?, tree_fp(&u.new_leaf)?);
    let chunk = |i: usize| -> Result<UpdWitness> {
        let mut siblings = [Fp::from(0u64); UPD_LEVELS];
        for (j, s) in siblings.iter_mut().enumerate() {
            *s = tree_fp(&u.siblings[i * UPD_LEVELS + j])?;
        }
        Ok(UpdWitness {
            old_leaf,
            new_leaf,
            siblings,
            bits: core::array::from_fn(|j| (u.leaf_index >> (i * UPD_LEVELS + j)) & 1 == 1),
        })
    };
    let mut pcd = app.seed(&mut rng(), UpdStart, chunk(0)?).map_err(|e| ragu_err("update", e))?.0;
    for i in 1..UPD_STEPS {
        pcd = app
            .fuse(&mut rng(), UpdExtend, chunk(i)?, pcd, unit(app))
            .map_err(|e| ragu_err("update", e))?
            .0;
    }
    Ok(pcd)
}

fn rest(state: &MintState, other_root: Fp) -> Result<RestWitness> {
    let f = StateFields::of(state)?;
    Ok(RestWitness { epoch: f.epoch, liabilities: f.liabilities, other_root, event_log: f.event_log })
}

fn prove_nullifier_insert(app: &App, state: &MintState, t: &NullifierTransitionWitness) -> Result<TransitionPcd> {
    let missing = || CircuitError::InvalidWitness("nullifier transition carries no tree updates".into());
    let (low_update, append_update) =
        (t.low_update.as_ref().ok_or_else(missing)?, t.append_update.as_ref().ok_or_else(missing)?);
    let low = &t.non_membership.low_leaf;

    let order = [tree_fp(&low.val)?, tree_fp(&t.nullifier)?, tree_fp(&low.next_val)?];
    let order = app.seed(&mut rng(), OrderStep, order).map_err(|e| ragu_err("nullifier order", e))?.0;
    let low_pcd = prove_update(app, low_update)?;
    let mid = app
        .fuse(&mut rng(), NfLow, (low.next_idx, t.new_leaf_index), low_pcd, order)
        .map_err(|e| ragu_err("nullifier low leaf", e))?
        .0;
    let append_pcd = prove_update(app, append_update)?;
    let w = rest(state, StateFields::of(state)?.note_root)?;
    app.fuse(&mut rng(), NfInsert, w, mid, append_pcd).map(|p| p.0).map_err(|e| ragu_err("nullifier insert", e))
}

fn prove_note_insert(app: &App, state: &MintState, u: &LeafUpdate) -> Result<TransitionPcd> {
    let upd = prove_update(app, u)?;
    let w = rest(state, StateFields::of(state)?.nf_root)?;
    app.fuse(&mut rng(), NoteInsert, w, upd, unit(app)).map(|p| p.0).map_err(|e| ragu_err("note insert", e))
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
fn prove_step(app: &App, step: &FoldedProof) -> Result<(TransitionPcd, StateFields, StateFields)> {
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
        let leaf = prove_nullifier_insert(app, &cur, nt)?;
        acc = fuse(app, acc, leaf)?;
        cur.nullifier_acc_root = nt.post_root;
    }

    // 3. Note inserts, in order.
    for nu in &t.note_updates {
        if cur.note_acc_root != nu.pre_root {
            return Err(invalid("note updates do not chain from the state's note root"));
        }
        let leaf = prove_note_insert(app, &cur, nu)?;
        acc = fuse(app, acc, leaf)?;
        cur.note_acc_root = nu.post_root;
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
