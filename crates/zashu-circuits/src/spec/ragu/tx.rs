//! The transaction statement as Ragu steps.
//!
//! ```text
//!  PathStart [-> PathExtend] -> Spend<predicate> --\
//!                                                   Close -> Tx
//!  PathStart [-> PathExtend] -> Spend<predicate> --/
//! ```
//!
//! * `PathStart` walks the first 16 levels of an input's Merkle path.
//! * `SpendKey` and `SpendTimelock` walk the remaining 8 themselves. The HTLC
//!   and multisig spends have no room left, so `PathExtend` walks those 8
//!   first.
//! * Each `Spend*` step opens the note, derives its nullifier, enforces
//!   membership (waived for a zero-value dummy) and one predicate.
//! * `Close` joins the two inputs, opens the two outputs and forms the
//!   statement. `MintClose` is a transaction with no inputs, in one step.
//!
//! The published proof is rerandomized and compressed. Which `Spend*` steps
//! ran is inside the recursion; hiding it relies on Ragu's rerandomisation.

use ragu::drivers::{Driver, DriverValue};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::FixedVec;
use ragu::primitives::{Boolean, Element};
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::Coeff;
use zashu_core::spec::hash::{T_HASHLOCK, T_HTLC, T_KEY, T_MULTISIG, T_NF, T_NOTE, T_PK, T_TIMELOCK};
use zashu_core::spec::note::{PRED_HTLC, PRED_KEY, PRED_MULTISIG, PRED_TIMELOCK};
use zashu_core::spec::DEPTH;

use super::gadgets::{alloc_u64, constant, enforce_equal, enforce_u64, header, node, sponge, values_of, StepOut, V};

/// Levels walked by `PathStart`.
pub(super) const START_LEVELS: usize = 16;
/// Levels walked by `PathExtend`, or by a spend step that has room.
pub(super) const TAIL_LEVELS: usize = DEPTH - START_LEVELS;
const _: () = assert!(TAIL_LEVELS == 8);

header!(
    /// `[leaf, node, levels]`: `node` is the ancestor of `leaf` `levels` up.
    Path, 0, 3
);
header!(
    /// `[anchor, epoch, value, nullifier]` of one spent input.
    Part, 1, 4
);
header!(
    /// `[anchor, epoch, balance, nf_1, nf_2, cm_1, cm_2]`.
    Tx, 2, 7
);

/// A run of Merkle levels: siblings, and whether the running node is the
/// right child at each.
#[derive(Clone, Copy)]
pub(crate) struct Climb<const N: usize> {
    pub(super) siblings: [Fp; N],
    pub(super) bits: [bool; N],
}

fn climb<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    mut cur: Element<'dr, D>,
    w: &DriverValue<D, Climb<N>>,
) -> ragu::Result<Element<'dr, D>> {
    for i in 0..N {
        let sibling = Element::alloc(dr, allocator, w.as_ref().map(|w| w.siblings[i]))?;
        let is_right = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.bits[i]))?;
        let left = is_right.conditional_select(dr, &cur, &sibling)?;
        let right = cur.add(dr, &sibling).sub(dr, &left);
        cur = node(dr, &left, &right)?;
    }
    Ok(cur)
}

pub(crate) struct PathStart;

impl Step<Pasta> for PathStart {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = (Fp, Climb<START_LEVELS>);
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Path;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, (Fp, Climb<START_LEVELS>)>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let leaf = Element::alloc(dr, allocator, w.as_ref().map(|w| w.0))?;
        let top = climb(dr, allocator, leaf.clone(), &w.as_ref().map(|w| w.1))?;
        let out: V<'dr, D, 3> = FixedVec::new(vec![leaf, top, constant(dr, START_LEVELS as u64)])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

pub(crate) struct PathExtend;

impl Step<Pasta> for PathExtend {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = Climb<TAIL_LEVELS>;
    type Aux<'source> = ();
    type Left = Path;
    type Right = ();
    type Output = Path;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, Climb<TAIL_LEVELS>>,
        left: DriverValue<D, [Fp; 3]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let p: &V<'dr, D, 3> = left.as_gadget();
        let top = climb(dr, allocator, p[1].clone(), &w)?;
        let tail = constant(dr, TAIL_LEVELS as u64);
        let levels = p[2].add(dr, &tail);
        let out: V<'dr, D, 3> = FixedVec::new(vec![p[0].clone(), top, levels])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Notes and keys
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct NoteW {
    pub(super) value: u64,
    pub(super) owner: Fp,
    pub(super) predicate: u64,
    pub(super) params: Fp,
    pub(super) rho: Fp,
    pub(super) r: Fp,
}

struct Opened<'dr, D: Driver<'dr, F = Fp>> {
    cm: Element<'dr, D>,
    value: Element<'dr, D>,
    owner: Element<'dr, D>,
    params: Element<'dr, D>,
    rho: Element<'dr, D>,
    r: Element<'dr, D>,
}

/// Opens a note commitment. `predicate` is fixed by the caller for a spend
/// (so a note cannot be spent under another predicate) and free for an output.
fn open_note<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    w: &DriverValue<D, NoteW>,
    predicate: Option<u64>,
) -> ragu::Result<Opened<'dr, D>> {
    let value = alloc_u64(dr, allocator, w.as_ref().map(|w| w.value))?;
    let owner = Element::alloc(dr, allocator, w.as_ref().map(|w| w.owner))?;
    let predicate = match predicate {
        Some(id) => constant(dr, id),
        None => Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.predicate)))?,
    };
    let params = Element::alloc(dr, allocator, w.as_ref().map(|w| w.params))?;
    let rho = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rho))?;
    let r = Element::alloc(dr, allocator, w.as_ref().map(|w| w.r))?;
    let cm = sponge(dr, T_NOTE, &[value.clone(), owner.clone(), predicate, params.clone(), rho.clone(), r.clone()])?;
    Ok(Opened { cm, value, owner, params, rho, r })
}

#[derive(Clone, Copy)]
pub(crate) struct KeyW {
    pub(super) spend_sk: Fp,
    pub(super) tweak: Fp,
}

/// `K = H_KEY(H_PK(spend_sk), tweak)`.
fn key_image<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    w: DriverValue<D, KeyW>,
) -> ragu::Result<Element<'dr, D>> {
    let sk = Element::alloc(dr, allocator, w.as_ref().map(|w| w.spend_sk))?;
    let tweak = Element::alloc(dr, allocator, w.as_ref().map(|w| w.tweak))?;
    let pk = sponge(dr, T_PK, &[sk])?;
    sponge(dr, T_KEY, &[pk, tweak])
}

// --------------------------------------------------------------------------
// Spends
// --------------------------------------------------------------------------

/// What every spend step is given, whatever its predicate.
#[derive(Clone, Copy)]
pub(crate) struct SpendW {
    pub(super) note: NoteW,
    pub(super) anchor: Fp,
    pub(super) epoch: u64,
    /// The last levels of the path, for the steps that walk them.
    pub(super) tail: Climb<TAIL_LEVELS>,
}

struct Spent<'dr, D: Driver<'dr, F = Fp>> {
    note: Opened<'dr, D>,
    epoch: Element<'dr, D>,
    part: V<'dr, D, 4>,
}

/// Opens the note the path starts from, finishes the path (`LEVELS` is 8 or
/// 0) and enforces membership under the anchor unless the value is zero.
fn spend<'dr, D: Driver<'dr, F = Fp>, const LEVELS: usize>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    path: &V<'dr, D, 3>,
    w: &DriverValue<D, SpendW>,
    predicate: u64,
) -> ragu::Result<Spent<'dr, D>> {
    let note = open_note(dr, allocator, &w.as_ref().map(|w| w.note), Some(predicate))?;
    enforce_equal(dr, &path[0], &note.cm)?;
    let walked = constant(dr, (DEPTH - LEVELS) as u64);
    enforce_equal(dr, &path[2], &walked)?;
    let root = if LEVELS == 0 {
        path[1].clone()
    } else {
        climb(dr, allocator, path[1].clone(), &w.as_ref().map(|w| w.tail))?
    };

    let anchor = Element::alloc(dr, allocator, w.as_ref().map(|w| w.anchor))?;
    // In the tree, or a zero-value dummy.
    root.sub(dr, &anchor).mul(dr, &note.value)?.enforce_zero(dr)?;
    let epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.epoch))?;
    let nf = sponge(dr, T_NF, &[note.rho.clone(), note.r.clone()])?;
    let part = FixedVec::new(vec![anchor, epoch.clone(), note.value.clone(), nf])?;
    Ok(Spent { note, epoch, part })
}

macro_rules! spend_step {
    ($(#[$doc:meta])* $name:ident, $index:expr, $levels:expr, $predicate:expr, $extra:ty,
     |$dr:ident, $allocator:ident, $s:ident, $x:ident| $body:block) => {
        $(#[$doc])*
        pub(crate) struct $name;

        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = (SpendW, $extra);
            type Aux<'source> = ();
            type Left = Path;
            type Right = ();
            type Output = Part;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                $dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                w: DriverValue<D, (SpendW, $extra)>,
                left: DriverValue<D, [Fp; 3]>,
                _: DriverValue<D, ()>,
            ) -> StepOut<'dr, D, Self, HS>
            where
                Self: 'dr,
            {
                let $allocator = &mut Standard::new();
                let left = Encoded::new($dr, $allocator, left)?;
                let $s = spend::<D, { $levels }>($dr, $allocator, left.as_gadget(), &w.as_ref().map(|w| w.0), $predicate)?;
                let $x: DriverValue<D, $extra> = w.as_ref().map(|w| w.1);
                $body
                let data = values_of(&$s.part);
                Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget($s.part)), data, D::unit()))
            }
        }
    };
}

spend_step!(
    /// `owner` is the key image; `params` is zero.
    SpendKey, 2, TAIL_LEVELS, PRED_KEY, KeyW,
    |dr, allocator, s, x| {
        let image = key_image(dr, allocator, x)?;
        enforce_equal(dr, &image, &s.note.owner)?;
        s.note.params.enforce_zero(dr)?;
    }
);

#[derive(Clone, Copy)]
pub(crate) struct TimelockW {
    pub(super) key: KeyW,
    pub(super) lock: u64,
}

spend_step!(
    /// As `SpendKey`, from `lock` on: `params = H_TIMELOCK(lock)`.
    SpendTimelock, 3, 0, PRED_TIMELOCK, TimelockW,
    |dr, allocator, s, x| {
        let image = key_image(dr, allocator, x.as_ref().map(|x| x.key))?;
        enforce_equal(dr, &image, &s.note.owner)?;
        let lock = alloc_u64(dr, allocator, x.as_ref().map(|x| x.lock))?;
        let params = sponge(dr, T_TIMELOCK, &[lock.clone()])?;
        enforce_equal(dr, &params, &s.note.params)?;
        // epoch >= lock
        let waited = s.epoch.sub(dr, &lock);
        enforce_u64(dr, allocator, &waited)?;
    }
);

#[derive(Clone, Copy)]
pub(crate) struct HtlcClaimW {
    pub(super) key: KeyW,
    pub(super) preimage: Fp,
    pub(super) refund: Fp,
    pub(super) expiry: u64,
}

spend_step!(
    /// The receiver claims with the preimage while `epoch < expiry`.
    SpendHtlcClaim, 4, 0, PRED_HTLC, HtlcClaimW,
    |dr, allocator, s, x| {
        let receiver = key_image(dr, allocator, x.as_ref().map(|x| x.key))?;
        let preimage = Element::alloc(dr, allocator, x.as_ref().map(|x| x.preimage))?;
        let refund = Element::alloc(dr, allocator, x.as_ref().map(|x| x.refund))?;
        let expiry = alloc_u64(dr, allocator, x.as_ref().map(|x| x.expiry))?;
        let lock = sponge(dr, T_HASHLOCK, &[preimage])?;
        let params = sponge(dr, T_HTLC, &[lock, receiver, refund, expiry.clone()])?;
        enforce_equal(dr, &params, &s.note.params)?;
        // epoch < expiry
        let room = expiry.sub(dr, &s.epoch).sub(dr, &Element::one());
        enforce_u64(dr, allocator, &room)?;
    }
);

#[derive(Clone, Copy)]
pub(crate) struct HtlcRefundW {
    pub(super) key: KeyW,
    pub(super) hashlock: Fp,
    pub(super) receiver: Fp,
    pub(super) expiry: u64,
}

spend_step!(
    /// The refund key spends from `expiry` on.
    SpendHtlcRefund, 5, 0, PRED_HTLC, HtlcRefundW,
    |dr, allocator, s, x| {
        let refund = key_image(dr, allocator, x.as_ref().map(|x| x.key))?;
        let lock = Element::alloc(dr, allocator, x.as_ref().map(|x| x.hashlock))?;
        let receiver = Element::alloc(dr, allocator, x.as_ref().map(|x| x.receiver))?;
        let expiry = alloc_u64(dr, allocator, x.as_ref().map(|x| x.expiry))?;
        let params = sponge(dr, T_HTLC, &[lock, receiver, refund, expiry.clone()])?;
        enforce_equal(dr, &params, &s.note.params)?;
        // epoch >= expiry
        let past = s.epoch.sub(dr, &expiry);
        enforce_u64(dr, allocator, &past)?;
    }
);

pub(super) const KEYS: usize = zashu_core::spec::note::MULTISIG_KEYS;
pub(super) const SIGNERS: usize = zashu_core::spec::note::MULTISIG_SIGNERS;

#[derive(Clone, Copy)]
pub(crate) struct MultisigW {
    pub(super) threshold: u64,
    pub(super) key_count: u64,
    pub(super) keys: [Fp; KEYS],
    pub(super) signers: [KeyW; SIGNERS],
    /// `slots[i][j]`: signer `i` opens key `j`. All false for an unused signer.
    pub(super) slots: [[bool; KEYS]; SIGNERS],
    /// Signer `i` is used. The first always is.
    pub(super) active: [bool; SIGNERS],
}

/// `x` fits two bits: `0 <= x <= 3`.
fn enforce_small<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    x: &Element<'dr, D>,
) -> ragu::Result<()> {
    x.enforce_le::<2>(dr, allocator, Fp::from(3u64))
}

spend_step!(
    /// `t` of the first `n` committed key images, in increasing slot order.
    SpendMultisig, 6, 0, PRED_MULTISIG, MultisigW,
    |dr, allocator, s, x| {
        let t = Element::alloc(dr, allocator, x.as_ref().map(|x| Fp::from(x.threshold)))?;
        let n = Element::alloc(dr, allocator, x.as_ref().map(|x| Fp::from(x.key_count)))?;
        let mut keys = Vec::with_capacity(KEYS);
        for j in 0..KEYS {
            keys.push(Element::alloc(dr, allocator, x.as_ref().map(|x| x.keys[j]))?);
        }
        let mut committed = vec![t.clone(), n.clone()];
        committed.extend(keys.iter().cloned());
        let params = sponge(dr, T_MULTISIG, &committed)?;
        enforce_equal(dr, &params, &s.note.params)?;

        // The first signer is always used; a later one only if the one
        // before it is. The threshold is exactly the number used.
        let second = Boolean::alloc(dr, allocator, x.as_ref().map(|x| x.active[1]))?;
        let third = Boolean::alloc(dr, allocator, x.as_ref().map(|x| x.active[2]))?;
        let no_second = second.not(dr);
        third.and(dr, &no_second)?.element().enforce_zero(dr)?;
        let active = [Element::one(), second.element(), third.element()];
        let used = active[0].add(dr, &active[1]).add(dr, &active[2]);
        enforce_equal(dr, &used, &t)?;
        // t <= n <= 4 (and t >= 1 by construction).
        let spare = n.sub(dr, &t);
        enforce_small(dr, allocator, &spare)?;
        let unused = constant(dr, KEYS as u64).sub(dr, &n);
        enforce_small(dr, allocator, &unused)?;

        let mut previous: Option<Element<'dr, D>> = None;
        for i in 0..SIGNERS {
            let image = key_image(dr, allocator, x.as_ref().map(|x| x.signers[i]))?;
            // One-hot slot choice: exactly one bit for a used signer, none otherwise.
            let (mut count, mut slot, mut chosen) = (Element::zero(dr), Element::zero(dr), Element::zero(dr));
            for (j, key) in keys.iter().enumerate() {
                let bit = Boolean::alloc(dr, allocator, x.as_ref().map(|x| x.slots[i][j]))?;
                count = count.add(dr, &bit.element());
                let weighted = bit.element().scale(dr, Coeff::Arbitrary(Fp::from(j as u64)));
                slot = slot.add(dr, &weighted);
                let picked = bit.element().mul(dr, key)?;
                chosen = chosen.add(dr, &picked);
            }
            enforce_equal(dr, &count, &active[i])?;
            // A used signer holds the key in its slot...
            image.sub(dr, &chosen).mul(dr, &active[i])?.enforce_zero(dr)?;
            // ...the slot is among the first n...
            let below = n.sub(dr, &Element::one()).sub(dr, &slot).mul(dr, &active[i])?;
            enforce_small(dr, allocator, &below)?;
            // ...and above the previous signer's.
            if let Some(previous) = &previous {
                let gap = slot.sub(dr, previous).sub(dr, &Element::one()).mul(dr, &active[i])?;
                enforce_small(dr, allocator, &gap)?;
            }
            previous = Some(slot);
        }
    }
);

// --------------------------------------------------------------------------
// Closing steps
// --------------------------------------------------------------------------

pub(super) type Outputs = [NoteW; 2];

/// Opens both outputs; returns their commitments and the sum of their values.
#[allow(clippy::type_complexity)]
fn open_outputs<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    w: &DriverValue<D, Outputs>,
) -> ragu::Result<(Element<'dr, D>, Element<'dr, D>, Element<'dr, D>)> {
    let first = open_note(dr, allocator, &w.as_ref().map(|w| w[0]), None)?;
    let second = open_note(dr, allocator, &w.as_ref().map(|w| w[1]), None)?;
    let total = first.value.add(dr, &second.value);
    Ok((first.cm, second.cm, total))
}

/// Two inputs and two outputs into the statement.
pub(crate) struct Close;

impl Step<Pasta> for Close {
    const INDEX: Index = Index::new(7);
    type Witness<'source> = Outputs;
    type Aux<'source> = ();
    type Left = Part;
    type Right = Part;
    type Output = Tx;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, Outputs>,
        left: DriverValue<D, [Fp; 4]>,
        right: DriverValue<D, [Fp; 4]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let a: &V<'dr, D, 4> = left.as_gadget();
        let b: &V<'dr, D, 4> = right.as_gadget();
        // Both inputs were spent against the same anchor at the same epoch.
        enforce_equal(dr, &a[0], &b[0])?;
        enforce_equal(dr, &a[1], &b[1])?;

        let (cm_1, cm_2, created) = open_outputs(dr, allocator, &w)?;
        let balance = a[2].add(dr, &b[2]).sub(dr, &created);
        let out: V<'dr, D, 7> =
            FixedVec::new(vec![a[0].clone(), a[1].clone(), balance, a[3].clone(), b[3].clone(), cm_1, cm_2])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// A transaction with no inputs: no anchor, no nullifiers.
pub(crate) struct MintClose;

impl Step<Pasta> for MintClose {
    const INDEX: Index = Index::new(8);
    type Witness<'source> = (u64, Outputs);
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Tx;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, (u64, Outputs)>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.0))?;
        let (cm_1, cm_2, created) = open_outputs(dr, allocator, &w.as_ref().map(|w| w.1))?;
        let zero = Element::zero(dr);
        let out: V<'dr, D, 7> =
            FixedVec::new(vec![zero.clone(), epoch, created.negate(dr), zero.clone(), zero, cm_1, cm_2])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}
