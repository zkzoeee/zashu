//! Ragu proof-carrying-data backend for Mode B shielded transactions and the
//! `NUTZ-4` hidden predicates (`ragu` feature).
//!
//! A full spend does not fit in one Ragu step (about 4,095 gates at rank 14;
//! a 32-level Poseidon Merkle path alone needs far more), so a transaction is
//! a small tree of steps:
//!
//! ```text
//!  PathStart -> PathExtend x3 --\
//!                                 Spend<predicate> --\
//!  Key --------------------------/                    Merge -> ... -> Finalize
//!  Output -------------------------------------------/
//! ```
//!
//! * `PathStart` / `PathExtend`: 8 levels each of the note accumulator's
//!   Merkle path, from a note commitment up to the anchor.
//! * `Key`: knowledge of a secret scalar `sk`, exposing `pk_to_fp([sk] G)`.
//! * `Spend*`: one step circuit per predicate. Opens the note commitment the
//!   path starts from, derives its nullifier, and enforces that predicate
//!   against the key proof.
//! * `Output`: opens an output note commitment and range-checks its value.
//! * `Merge`: combines two parts; anchors and epochs must agree, balances add.
//! * `Finalize`: turns the last part into the transaction statement.
//!
//! The verifier only ever sees the rerandomized, compressed transaction proof
//! and its header `[anchor, epoch, digest, balance]`. Which `Spend*` circuits
//! ran is inside the recursion. Hiding that from the mint relies on Ragu's
//! rerandomization, whose indistinguishability Ragu documents as a goal that
//! is not yet proven; treat predicate privacy as best-effort until it is.
//!
//! `digest` commits to the ordered nullifiers and output commitments; the
//! verifier recomputes it from the public lists (see [`tx_digest`]). `balance`
//! is `sum(inputs) - sum(outputs)` as a field element: zero for a swap, the
//! public amount for a melt/unshield, and its negation for a mint/shield.
//! `epoch` is the epoch the predicates were evaluated at; the mint must reject
//! a proof whose epoch is ahead of its own.
//!
//! Multisig notes are not supported by this backend yet.

use std::sync::OnceLock;

use ragu::circuits::polynomials::R;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{EpAffine, Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{Boolean, Element, FixedBase, GadgetExt};
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::udon::curve::Affine;
use ragu::udon::field::Field;
use ragu::{Application, ApplicationBuilder, CompressedProof, Pcd};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zashu_acc::{InclusionWitness, NoteAccumulator, ACC_DEPTH};
use zashu_core::field::{fp_from_u64, hash_bytes_to_fp};
use zashu_core::poseidon::{
    note_rho_r_fields, pk_to_fp, poseidon_2, poseidon_3, predicate_params_to_fp, DOMAIN_ACC, DOMAIN_NF,
    DOMAIN_NOTE, DOMAIN_PREDICATE, DOMAIN_STEALTH,
};
use zashu_core::types::{Note, NoteCommitment, Nullifier, PredicateId};

use super::bytes_fp;
use crate::error::{CircuitError, Result};
use crate::pcd::{FoldedProof, SubcircuitId};
use crate::predicates::{hashlock_to_fp, sk_to_scalar, verify_predicate, HtlcAction, PredicateWitness};
use crate::ragu_gadgets::{fp_from_pasta, poseidon_hash, values_of};

type Rank = R<14>;
pub const RAGU_RANK: u32 = 14;
/// Largest header payload (4) plus Ragu's suffix slot.
const HEADER_SIZE: usize = 5;
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;

/// Merkle levels proven per path step.
const PATH_LEVELS: usize = 8;
const PATH_STEPS: usize = ACC_DEPTH / PATH_LEVELS;
const _: () = assert!(ACC_DEPTH % PATH_LEVELS == 0);
/// Bits of a secret scalar (Pallas scalar field).
const SK_BITS: usize = 255;

/// Digest domain tags (see [`tx_digest`]).
pub const TAG_SPEND: u64 = 0x21;
pub const TAG_OUTPUT: u64 = 0x22;
pub const TAG_NODE: u64 = 0x23;

fn ragu_err(context: &str, e: impl core::fmt::Display) -> CircuitError {
    CircuitError::Plonk(format!("ragu {context}: {e}"))
}

// --------------------------------------------------------------------------
// Headers
// --------------------------------------------------------------------------

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

header!(
    /// `[leaf, node, levels]`: `node` is the ancestor of `leaf` `levels` up.
    Path, 0, 3
);
header!(
    /// `[pk_fp]`: the prover knows `sk` with `pk_to_fp([sk] G) == pk_fp`.
    Key, 1, 1
);
header!(
    /// `[anchor, epoch, digest, balance]` of a partial transaction.
    Part, 2, 4
);
header!(
    /// `[anchor, epoch, digest, balance]` of a finished transaction.
    Tx, 3, 4
);

const ANCHOR: usize = 0;
const EPOCH: usize = 1;
const DIGEST: usize = 2;
const BALANCE: usize = 3;

type V<'dr, D, const N: usize> = FixedVec<Element<'dr, D>, ConstLen<N>>;

/// The return type of `Step::witness` for steps without auxiliary output.
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

fn enforce_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> ragu::Result<()> {
    a.sub(dr, b).enforce_zero(dr)
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

// --------------------------------------------------------------------------
// Merkle path steps
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct PathWitness {
    leaf: Fp,
    siblings: [Fp; PATH_LEVELS],
    /// Bit `i` set: the running node is the right child at level `i`.
    bits: [bool; PATH_LEVELS],
}

/// Climbs [`PATH_LEVELS`] levels with `hash_acc_node = Poseidon3(DOMAIN_ACC, left, right)`.
fn climb<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    mut cur: Element<'dr, D>,
    w: &DriverValue<D, PathWitness>,
) -> ragu::Result<Element<'dr, D>> {
    let domain = constant(dr, DOMAIN_ACC);
    for i in 0..PATH_LEVELS {
        let sibling = Element::alloc(dr, allocator, w.as_ref().map(|w| w.siblings[i]))?;
        let is_right = Boolean::alloc(dr, allocator, w.as_ref().map(|w| w.bits[i]))?;
        let left = is_right.conditional_select(dr, &cur, &sibling)?;
        let right = cur.add(dr, &sibling).sub(dr, &left);
        cur = poseidon_hash(dr, &[domain.clone(), left, right])?;
    }
    Ok(cur)
}

struct PathStart;

impl Step<Pasta> for PathStart {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = PathWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Path;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, PathWitness>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let leaf = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.leaf))?;
        let node = climb(dr, allocator, leaf.clone(), &witness)?;
        let out: V<'dr, D, 3> = FixedVec::new(vec![leaf, node, constant(dr, PATH_LEVELS as u64)])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

struct PathExtend;

impl Step<Pasta> for PathExtend {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = PathWitness;
    type Aux<'source> = ();
    type Left = Path;
    type Right = ();
    type Output = Path;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, PathWitness>,
        left: DriverValue<D, [Fp; 3]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let l: &V<'dr, D, 3> = left.as_gadget();
        let node = climb(dr, allocator, l[1].clone(), &witness)?;
        let step = constant(dr, PATH_LEVELS as u64);
        let levels = l[2].add(dr, &step);
        let out: V<'dr, D, 3> = FixedVec::new(vec![l[0].clone(), node, levels])?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Key ownership
// --------------------------------------------------------------------------

fn generator_table() -> &'static FixedBase<EpAffine, SK_BITS> {
    static TABLE: OnceLock<FixedBase<EpAffine, SK_BITS>> = OnceLock::new();
    TABLE.get_or_init(|| {
        FixedBase::new(EpAffine::generator(), EpAffine::identity()).expect("Pallas generator table")
    })
}

struct KeyStep;

impl Step<Pasta> for KeyStep {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = [bool; SK_BITS];
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Key;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, [bool; SK_BITS]>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let bits: FixedVec<Boolean<'dr, D>, ConstLen<SK_BITS>> =
            FixedVec::try_from_fn(|i| Boolean::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))?;
        let pk = generator_table().mul(dr, &bits)?;
        let mut xy: Vec<Element<'dr, D>> = Vec::with_capacity(2);
        pk.write(dr, &mut xy)?;
        let pk_fp = poseidon_hash(dr, &xy)?;
        let out: V<'dr, D, 1> = FixedVec::new(vec![pk_fp])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

// --------------------------------------------------------------------------
// Spend steps: one circuit per predicate
// --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpendKind {
    Standard,
    P2pk,
    Timelock,
    HtlcClaim,
    HtlcRefund,
}

#[derive(Clone, Copy)]
struct SpendWitness {
    value: u64,
    owner: Fp,
    params: Fp,
    rho: Fp,
    r: Fp,
    /// Epoch the predicate is evaluated at (public in the final statement).
    epoch: u64,
    /// Timelock: `lock_epoch`. HTLC: `expiry_epoch`. Otherwise unused.
    lock: u64,
    /// HtlcClaim: hash-to-field of the preimage. HtlcRefund: the hashlock.
    a: Fp,
    /// HtlcClaim: refund key image. HtlcRefund: receiver key image.
    b: Fp,
}

fn spend<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    kind: SpendKind,
    w: DriverValue<D, SpendWitness>,
    path: &V<'dr, D, 3>,
    key: &V<'dr, D, 1>,
) -> ragu::Result<V<'dr, D, 4>> {
    let allocator = &mut Standard::new();
    let key = &key[0];

    let value = alloc_u64(dr, allocator, w.as_ref().map(|w| w.value))?;
    let epoch = alloc_u64(dr, allocator, w.as_ref().map(|w| w.epoch))?;
    let owner = Element::alloc(dr, allocator, w.as_ref().map(|w| w.owner))?;
    let params = Element::alloc(dr, allocator, w.as_ref().map(|w| w.params))?;
    let rho = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rho))?;
    let r = Element::alloc(dr, allocator, w.as_ref().map(|w| w.r))?;

    let predicate_id = match kind {
        SpendKind::Standard => PredicateId::StandardSpend,
        SpendKind::P2pk => PredicateId::P2PK,
        SpendKind::Timelock => PredicateId::Timelock,
        SpendKind::HtlcClaim | SpendKind::HtlcRefund => PredicateId::PrivateHTLC,
    } as u8 as u64;
    let predicate_id = constant(dr, predicate_id);

    // The note this spend consumes is the leaf the Merkle path starts from,
    // and the path runs the full depth of the accumulator.
    let domain_note = constant(dr, DOMAIN_NOTE);
    let cm = poseidon_hash(
        dr,
        &[domain_note, value.clone(), owner.clone(), predicate_id.clone(), params.clone(), rho.clone(), r.clone()],
    )?;
    enforce_equal(dr, &cm, &path[0])?;
    let depth = constant(dr, ACC_DEPTH as u64);
    enforce_equal(dr, &path[2], &depth)?;

    let domain_nf = constant(dr, DOMAIN_NF);
    let nf = poseidon_hash(dr, &[domain_nf, r, rho])?;

    // The predicate.
    let domain_pred = constant(dr, DOMAIN_PREDICATE);
    match kind {
        SpendKind::Standard => {
            params.enforce_zero(dr)?;
            enforce_equal(dr, &owner, key)?;
        }
        SpendKind::P2pk => {
            let expected = poseidon_hash(dr, &[domain_pred, predicate_id, key.clone()])?;
            enforce_equal(dr, &params, &expected)?;
        }
        SpendKind::Timelock => {
            enforce_equal(dr, &owner, key)?;
            let lock = alloc_u64(dr, allocator, w.as_ref().map(|w| w.lock))?;
            let expected = poseidon_hash(dr, &[domain_pred, predicate_id, lock.clone(), owner])?;
            enforce_equal(dr, &params, &expected)?;
            // lock <= epoch: the difference is a u64, so it did not wrap.
            epoch.sub(dr, &lock).enforce_le::<64>(dr, allocator, Fp::from(u64::MAX))?;
        }
        SpendKind::HtlcClaim | SpendKind::HtlcRefund => {
            let expiry = alloc_u64(dr, allocator, w.as_ref().map(|w| w.lock))?;
            let a = Element::alloc(dr, allocator, w.as_ref().map(|w| w.a))?;
            let b = Element::alloc(dr, allocator, w.as_ref().map(|w| w.b))?;
            let (hashlock, receiver, refund) = if kind == SpendKind::HtlcClaim {
                // Knows the preimage, and holds the receiver key.
                let domain_stealth = constant(dr, DOMAIN_STEALTH);
                let hashlock = poseidon_hash(dr, &[domain_stealth, a])?;
                (hashlock, key.clone(), b)
            } else {
                // Holds the refund key, and the HTLC has expired.
                epoch.sub(dr, &expiry).enforce_le::<64>(dr, allocator, Fp::from(u64::MAX))?;
                (a, b, key.clone())
            };
            let zero = Element::zero(dr);
            let expected =
                poseidon_hash(dr, &[domain_pred, predicate_id, hashlock, receiver, refund, expiry, zero])?;
            enforce_equal(dr, &params, &expected)?;
        }
    }

    let tag = constant(dr, TAG_SPEND);
    let digest = poseidon_hash(dr, &[tag, nf])?;
    FixedVec::new(vec![path[1].clone(), epoch, digest, value])
}

macro_rules! spend_step {
    ($name:ident, $index:expr, $kind:expr) => {
        struct $name;

        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = SpendWitness;
            type Aux<'source> = ();
            type Left = Path;
            type Right = Key;
            type Output = Part;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                witness: DriverValue<D, SpendWitness>,
                left: DriverValue<D, [Fp; 3]>,
                right: DriverValue<D, [Fp; 1]>,
            ) -> StepOut<'dr, D, Self, HS>
            where
                Self: 'dr,
            {
                let allocator = &mut Standard::new();
                let left = Encoded::new(dr, allocator, left)?;
                let right = Encoded::new(dr, allocator, right)?;
                let out = spend(dr, $kind, witness, left.as_gadget(), right.as_gadget())?;
                let data = values_of(&out);
                Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
            }
        }
    };
}

spend_step!(SpendStandard, 3, SpendKind::Standard);
spend_step!(SpendP2pk, 4, SpendKind::P2pk);
spend_step!(SpendTimelock, 5, SpendKind::Timelock);
spend_step!(SpendHtlcClaim, 6, SpendKind::HtlcClaim);
spend_step!(SpendHtlcRefund, 7, SpendKind::HtlcRefund);

// --------------------------------------------------------------------------
// Output, merge, finalize
// --------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct OutputWitness {
    value: u64,
    owner: Fp,
    predicate_id: u64,
    params: Fp,
    rho: Fp,
    r: Fp,
    /// Passed through so the part can merge with the spends.
    anchor: Fp,
    epoch: u64,
}

struct OutputStep;

impl Step<Pasta> for OutputStep {
    const INDEX: Index = Index::new(8);
    type Witness<'source> = OutputWitness;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Part;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        w: DriverValue<D, OutputWitness>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let value = alloc_u64(dr, allocator, w.as_ref().map(|w| w.value))?;
        let owner = Element::alloc(dr, allocator, w.as_ref().map(|w| w.owner))?;
        let predicate_id = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.predicate_id)))?;
        let params = Element::alloc(dr, allocator, w.as_ref().map(|w| w.params))?;
        let rho = Element::alloc(dr, allocator, w.as_ref().map(|w| w.rho))?;
        let r = Element::alloc(dr, allocator, w.as_ref().map(|w| w.r))?;
        let anchor = Element::alloc(dr, allocator, w.as_ref().map(|w| w.anchor))?;
        let epoch = Element::alloc(dr, allocator, w.as_ref().map(|w| Fp::from(w.epoch)))?;

        let domain_note = constant(dr, DOMAIN_NOTE);
        let cm = poseidon_hash(dr, &[domain_note, value.clone(), owner, predicate_id, params, rho, r])?;
        let tag = constant(dr, TAG_OUTPUT);
        let digest = poseidon_hash(dr, &[tag, cm])?;
        let balance = value.negate(dr);

        let out: V<'dr, D, 4> = FixedVec::new(vec![anchor, epoch, digest, balance])?;
        let data = values_of(&out);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

struct MergeStep;

impl Step<Pasta> for MergeStep {
    const INDEX: Index = Index::new(9);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Part;
    type Right = Part;
    type Output = Part;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 4]>,
        right: DriverValue<D, [Fp; 4]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let l: &V<'dr, D, 4> = left.as_gadget();
        let r: &V<'dr, D, 4> = right.as_gadget();

        enforce_equal(dr, &l[ANCHOR], &r[ANCHOR])?;
        enforce_equal(dr, &l[EPOCH], &r[EPOCH])?;
        let tag = constant(dr, TAG_NODE);
        let digest = poseidon_hash(dr, &[tag, l[DIGEST].clone(), r[DIGEST].clone()])?;
        let balance = l[BALANCE].add(dr, &r[BALANCE]);

        let out: V<'dr, D, 4> = FixedVec::new(vec![l[ANCHOR].clone(), l[EPOCH].clone(), digest, balance])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Re-labels a finished part as a transaction. Every published proof is a
/// `Finalize` proof, so its circuit identity says nothing about the spends.
struct FinalizeStep;

impl Step<Pasta> for FinalizeStep {
    const INDEX: Index = Index::new(10);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Part;
    type Right = ();
    type Output = Tx;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 4]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let l: &V<'dr, D, 4> = left.as_gadget();
        let out: V<'dr, D, 4> = FixedVec::new(l.iter().cloned().collect())?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
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
            .register(PathStart)
            .and_then(|b| b.register(PathExtend))
            .and_then(|b| b.register(KeyStep))
            .and_then(|b| b.register(SpendStandard))
            .and_then(|b| b.register(SpendP2pk))
            .and_then(|b| b.register(SpendTimelock))
            .and_then(|b| b.register(SpendHtlcClaim))
            .and_then(|b| b.register(SpendHtlcRefund))
            .and_then(|b| b.register(OutputStep))
            .and_then(|b| b.register(MergeStep))
            .and_then(|b| b.register(FinalizeStep))
            .and_then(|b| b.finalize(pasta))
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| CircuitError::Plonk(format!("ragu mode B application build: {e}")))
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn unit(app: &App) -> Pcd<Pasta, Rank, ()> {
    app.bootstrap_proof().clone().carry::<()>(())
}

/// The transaction digest: a left-leaning hash chain over tagged leaves,
/// nullifiers first and then output commitments, in the order given.
///
/// `leaf = Poseidon2(TAG_SPEND, nf)` or `Poseidon2(TAG_OUTPUT, cm)`,
/// `node = Poseidon3(TAG_NODE, left, right)`. The tags keep a leaf from being
/// read as a node, so the digest determines the two lists.
pub fn tx_digest(nullifiers: &[Nullifier], out_cms: &[NoteCommitment]) -> Option<zashu_core::field::Fp> {
    let leaves = nullifiers
        .iter()
        .map(|nf| poseidon_2(fp_from_u64(TAG_SPEND), bytes_fp(&nf.0)))
        .chain(out_cms.iter().map(|cm| poseidon_2(fp_from_u64(TAG_OUTPUT), bytes_fp(&cm.0))));
    leaves.reduce(|acc, leaf| poseidon_3(fp_from_u64(TAG_NODE), acc, leaf))
}

/// A note to spend, with its Merkle witness and predicate witness.
pub struct SpendInput<'a> {
    pub note: &'a Note,
    pub witness: &'a InclusionWitness,
    pub predicate: &'a PredicateWitness,
}

struct SpendPlan {
    kind: SpendKind,
    sk: [u8; 32],
    lock: u64,
    a: Fp,
    b: Fp,
}

fn plan_spend(note: &Note, predicate: &PredicateWitness) -> Result<SpendPlan> {
    let zero = Fp::from(0u64);
    let pk = |pk: &[u8; 32]| fp_from_pasta(&pk_to_fp(pk));
    Ok(match predicate {
        PredicateWitness::StandardSpend { sk } => {
            SpendPlan { kind: SpendKind::Standard, sk: *sk, lock: 0, a: zero, b: zero }
        }
        PredicateWitness::P2PK { target_sk, .. } => {
            SpendPlan { kind: SpendKind::P2pk, sk: *target_sk, lock: 0, a: zero, b: zero }
        }
        PredicateWitness::Timelock { lock_epoch, sk, .. } => {
            SpendPlan { kind: SpendKind::Timelock, sk: *sk, lock: *lock_epoch, a: zero, b: zero }
        }
        PredicateWitness::PrivateHTLC { hashlock, pk_receiver, pk_refund, expiry_epoch, action, .. } => {
            match action {
                HtlcAction::Claim { preimage, sk_receiver } => SpendPlan {
                    kind: SpendKind::HtlcClaim,
                    sk: *sk_receiver,
                    lock: *expiry_epoch,
                    a: fp_from_pasta(&hash_bytes_to_fp(b"zashu-stealth-fp", preimage)),
                    b: pk(pk_refund),
                },
                HtlcAction::Refund { sk_refund } => SpendPlan {
                    kind: SpendKind::HtlcRefund,
                    sk: *sk_refund,
                    lock: *expiry_epoch,
                    a: fp_from_pasta(&hashlock_to_fp(hashlock)),
                    b: pk(pk_receiver),
                },
            }
        }
        PredicateWitness::Multisig { .. } => {
            let _ = note;
            return Err(CircuitError::PredicateError(
                "multisig notes are not supported by the Ragu backend yet".into(),
            ));
        }
    })
}

fn prove_path(app: &App, cm: &NoteCommitment, witness: &InclusionWitness) -> Result<Pcd<Pasta, Rank, Path>> {
    if witness.siblings.len() != ACC_DEPTH {
        return Err(CircuitError::InvalidWitness("invalid sibling length".into()));
    }
    let leaf = fp_from_pasta(&bytes_fp(&cm.0));
    let chunk = |i: usize| PathWitness {
        leaf,
        siblings: core::array::from_fn(|j| fp_from_pasta(&bytes_fp(&witness.siblings[i * PATH_LEVELS + j]))),
        bits: core::array::from_fn(|j| (witness.leaf_index >> (i * PATH_LEVELS + j)) & 1 == 1),
    };
    let mut path = app.seed(&mut rng(), PathStart, chunk(0)).map_err(|e| ragu_err("path", e))?.0;
    for i in 1..PATH_STEPS {
        path = app
            .fuse(&mut rng(), PathExtend, chunk(i), path, unit(app))
            .map_err(|e| ragu_err("path", e))?
            .0;
    }
    Ok(path)
}

fn prove_key(app: &App, sk: &[u8; 32]) -> Result<Pcd<Pasta, Rank, Key>> {
    use ff::PrimeField;
    let repr = sk_to_scalar(sk).to_repr();
    let bits: [bool; SK_BITS] = core::array::from_fn(|i| (repr[i / 8] >> (i % 8)) & 1 == 1);
    app.seed(&mut rng(), KeyStep, bits).map(|p| p.0).map_err(|e| ragu_err("key", e))
}

fn prove_spend(app: &App, epoch: u64, input: &SpendInput<'_>) -> Result<Pcd<Pasta, Rank, Part>> {
    let note = input.note;
    let plan = plan_spend(note, input.predicate)?;
    let (rho, r) = note_rho_r_fields(&note.rho, &note.r);
    let w = SpendWitness {
        value: note.value,
        owner: fp_from_pasta(&pk_to_fp(&note.owner_pk)),
        params: fp_from_pasta(&predicate_params_to_fp(&note.predicate_params_hash)),
        rho: fp_from_pasta(&rho),
        r: fp_from_pasta(&r),
        epoch,
        lock: plan.lock,
        a: plan.a,
        b: plan.b,
    };
    let path = prove_path(app, &note.commitment(), input.witness)?;
    let key = prove_key(app, &plan.sk)?;
    let rng = &mut rng();
    let part = match plan.kind {
        SpendKind::Standard => app.fuse(rng, SpendStandard, w, path, key).map(|p| p.0),
        SpendKind::P2pk => app.fuse(rng, SpendP2pk, w, path, key).map(|p| p.0),
        SpendKind::Timelock => app.fuse(rng, SpendTimelock, w, path, key).map(|p| p.0),
        SpendKind::HtlcClaim => app.fuse(rng, SpendHtlcClaim, w, path, key).map(|p| p.0),
        SpendKind::HtlcRefund => app.fuse(rng, SpendHtlcRefund, w, path, key).map(|p| p.0),
    };
    part.map_err(|e| ragu_err("spend", e))
}

fn prove_output(app: &App, anchor: Fp, epoch: u64, note: &Note) -> Result<Pcd<Pasta, Rank, Part>> {
    let (rho, r) = note_rho_r_fields(&note.rho, &note.r);
    let w = OutputWitness {
        value: note.value,
        owner: fp_from_pasta(&pk_to_fp(&note.owner_pk)),
        predicate_id: note.predicate_id as u64,
        params: fp_from_pasta(&predicate_params_to_fp(&note.predicate_params_hash)),
        rho: fp_from_pasta(&rho),
        r: fp_from_pasta(&r),
        anchor,
        epoch,
    };
    app.seed(&mut rng(), OutputStep, w).map(|p| p.0).map_err(|e| ragu_err("output", e))
}

/// Proves a shielded transaction: `inputs` are spent against `anchor_root`
/// with their predicates evaluated at `epoch`, and `outputs` are created.
///
/// The proof's balance is `sum(inputs) - sum(outputs)`; it is the verifier
/// who decides which balance a mint, swap or melt must have.
pub fn prove_tx(
    anchor_root: &[u8; 32],
    epoch: u64,
    inputs: &[SpendInput<'_>],
    outputs: &[&Note],
) -> Result<FoldedProof> {
    // Native pre-checks, so a bad witness fails here with a clear error
    // rather than as an unsatisfiable circuit.
    for input in inputs {
        if !NoteAccumulator::verify_inclusion(anchor_root, &input.note.commitment().0, input.witness) {
            return Err(CircuitError::InvalidWitness("input note not in anchor_root".into()));
        }
        verify_predicate(input.note, input.predicate)?;
    }
    prove_tx_unchecked(anchor_root, epoch, inputs, outputs)
}

/// [`prove_tx`] without the native pre-checks. For tests that need to show a
/// bad witness is rejected by the circuits themselves.
#[doc(hidden)]
pub fn prove_tx_unchecked(
    anchor_root: &[u8; 32],
    epoch: u64,
    inputs: &[SpendInput<'_>],
    outputs: &[&Note],
) -> Result<FoldedProof> {
    if inputs.is_empty() && outputs.is_empty() {
        return Err(CircuitError::InvalidWitness("transaction has no inputs or outputs".into()));
    }

    let app = app()?;
    let anchor = fp_from_pasta(&bytes_fp(anchor_root));
    let mut acc: Option<Pcd<Pasta, Rank, Part>> = None;
    let mut push = |part: Pcd<Pasta, Rank, Part>| -> Result<()> {
        acc = Some(match acc.take() {
            None => part,
            Some(prev) => app
                .fuse(&mut rng(), MergeStep, (), prev, part)
                .map_err(|e| ragu_err("merge", e))?
                .0,
        });
        Ok(())
    };
    for input in inputs {
        push(prove_spend(app, epoch, input)?)?;
    }
    for note in outputs {
        push(prove_output(app, anchor, epoch, note)?)?;
    }
    let root = acc.expect("at least one part");
    let tx = app
        .fuse(&mut rng(), FinalizeStep, (), root, unit(app))
        .map_err(|e| ragu_err("finalize", e))?
        .0;
    // A Ragu proof, compressed or not, is not hiding by itself: its openings
    // are evaluations of witness polynomials, and a fuse stores what it reads
    // of its children. Ragu's `rerandomize` (two more fuses) is what it
    // provides for publishing a proof privately, so the transaction is always
    // rerandomized before it is compressed. Ragu states indistinguishability
    // of rerandomized proofs as a design goal that is not yet proven.
    let tx = app.rerandomize(tx, &mut rng()).map_err(|e| ragu_err("rerandomize", e))?;
    let compressed = app.compress(&tx, &mut rng()).map_err(|e| ragu_err("compress", e))?;
    let (proof, data) = compressed.into_parts();
    let bytes = proof.to_bytes().map_err(|e| ragu_err("encode", format!("{e:?}")))?;
    Ok(FoldedProof {
        subcircuit: SubcircuitId::RaguTx,
        k: RAGU_RANK,
        public_inputs: data.iter().map(|v| v.to_bytes()).collect(),
        ipa_proof: bytes,
        folded_children: inputs.len() + outputs.len(),
        transition: None,
    })
}

/// What `sum(inputs) - sum(outputs)` must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Balance {
    /// Swap: value is conserved.
    Zero,
    /// Melt / unshield: this much leaves the shielded pool.
    Out(u64),
    /// Mint / shield: this much enters the shielded pool.
    In(u64),
}

/// The epoch a Ragu transaction proof's predicates were evaluated at, or
/// `None` for proofs of other backends. A mint must reject a proof whose
/// epoch is greater than its current epoch.
pub fn proof_epoch(proof: &FoldedProof) -> Option<u64> {
    if proof.subcircuit != SubcircuitId::RaguTx {
        return None;
    }
    let bytes = proof.public_inputs.get(EPOCH)?;
    if bytes[8..].iter().any(|b| *b != 0) {
        return Some(u64::MAX);
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")))
}

/// Verifies a Ragu transaction proof against the public nullifiers, output
/// commitments and required balance. `anchor_root` is checked when given
/// (it is meaningless for a transaction without inputs).
///
/// The caller must separately check [`proof_epoch`] against its clock.
pub fn verify_tx(
    proof: &FoldedProof,
    anchor_root: Option<&[u8; 32]>,
    nullifiers: &[Nullifier],
    out_cms: &[NoteCommitment],
    balance: Balance,
) -> Result<()> {
    let fail = |msg: &str| CircuitError::VerificationFailed(format!("ragu tx: {msg}"));
    if proof.subcircuit != SubcircuitId::RaguTx {
        return Err(fail("not a Ragu transaction proof"));
    }
    if proof.public_inputs.len() != 4 {
        return Err(fail("expected 4 public inputs"));
    }
    let mut data = [Fp::from(0u64); 4];
    for (slot, bytes) in data.iter_mut().zip(&proof.public_inputs) {
        *slot = Fp::from_bytes(*bytes).ok_or_else(|| fail("non-canonical public input"))?;
    }

    if let Some(anchor) = anchor_root {
        if data[ANCHOR] != fp_from_pasta(&bytes_fp(anchor)) {
            return Err(fail("anchor mismatch"));
        }
    }
    let digest = tx_digest(nullifiers, out_cms).ok_or_else(|| fail("no nullifiers or outputs"))?;
    if data[DIGEST] != fp_from_pasta(&digest) {
        return Err(fail("nullifiers or output commitments do not match the proof"));
    }
    let expected_balance = match balance {
        Balance::Zero => Fp::from(0u64),
        Balance::Out(v) => Fp::from(v),
        Balance::In(v) => Fp::from(0u64) - Fp::from(v),
    };
    if data[BALANCE] != expected_balance {
        return Err(fail("value balance mismatch"));
    }

    if proof.ipa_proof.len() != CompressedProof::<Pasta>::encoded_len::<Rank>() {
        return Err(fail("unexpected proof length"));
    }
    let compressed =
        CompressedProof::<Pasta>::from_bytes(&proof.ipa_proof).map_err(|e| fail(&format!("decode: {e:?}")))?;
    match app()?.verify_compressed(&compressed.carry::<Tx>(data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail("proof rejected")),
        Err(e) => Err(fail(&e.to_string())),
    }
}
