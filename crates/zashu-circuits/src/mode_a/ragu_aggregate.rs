//! Aggregated Ragu fold (`FoldBackend::RaguAggregated`, opt-in): on top of the
//! root-binding fold, each shielded operation is checked against the
//! transaction proof that authorised it.
//!
//! The root-binding fold proves that an operation's inserts are valid, but
//! not that they are the inserts a wallet asked for. Here every operation's
//! fold proof and (when it has one) its Mode B transaction proof are
//! *decompressed* inside a Ragu aggregator application, and an aggregator
//! step compares them:
//!
//! * `OpTx`: the digest of the nullifiers and notes the operation inserted
//!   equals the transaction's digest, in the same order; the liabilities
//!   moved by exactly the transaction's value balance (zero for a swap, the
//!   amount for a melt, its negation for a mint); and a transaction with
//!   spends used the note root the operation started from as its anchor.
//! * `OpPlain`: an operation with no matching transaction proof. It is
//!   accepted, but counted.
//! * `AggFold`: chains operations, adding up both counts.
//!
//! The published statement is `[start_liab, end_liab, start_state, end_state,
//! ops, unbound_ops]`. `unbound_ops` is the auditor's handle: it is how many
//! operations were *not* backed by a shielded transaction proof. That
//! includes everything a proof cannot cover: legacy BDHKE mints and melts,
//! shield/unshield (half legacy), transactions built on the Halo 2 backend,
//! and transactions whose anchor was not the latest note root. A mint that
//! only runs shielded operations against fresh anchors reaches zero.
//!
//! Costs, on a 10-core laptop: an aggregator step is about 2 s (five times a
//! normal step), a proof in flight is about 172 MB, the application takes
//! about 18 s to build, and verification is about 0.35 s. Ragu marks the
//! aggregator profile unaudited, with a soundness bound still open.

use std::sync::OnceLock;

use ragu::circuits::polynomials::AggregatorRank;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::pcd::profile::{Aggregator, Decompression, Profiled};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::Element;
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::udon::field::Field;
use ragu::{Application, ApplicationBuilder, CompressedProof, Pcd};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zashu_core::types::MintState;

use super::ragu_backend::{
    ragu_err, BackgroundFolder, FolderOps, StateFields, Transition, ANCHOR, DIGEST, END_LIAB, END_STATE,
    START_LIAB, START_STATE,
};
use super::ragu_roots;
use crate::error::{CircuitError, Result};
use crate::mode_b::ragu_backend::Tx;
use crate::pcd::{FoldedProof, SubcircuitId};
use crate::ragu_app::{self, HEADER_SIZE, RAGU_RANK};
use crate::ragu_gadgets::values_of;

type Agg = Profiled<Pasta, Aggregator<HEADER_SIZE>>;
type AggApp = Application<'static, Agg, AggregatorRank, HEADER_SIZE>;
type SealedPcd = Pcd<Agg, AggregatorRank, Sealed>;

const SEALED: usize = 6;
const S_OPS: usize = 4;
const S_UNBOUND: usize = 5;

// Transaction header slots (`mode_b::ragu_backend::Tx`).
const TX_ANCHOR: usize = 0;
const TX_DIGEST: usize = 2;
const TX_BALANCE: usize = 3;

/// `[start_state, start_liab, end_state, end_liab, ops, unbound_ops]`
struct Sealed;

impl Header<Fp> for Sealed {
    const SUFFIX: Suffix = Suffix::new(9);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = [Fp; SEALED];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<SEALED>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

type V<'dr, D, const N: usize> = FixedVec<Element<'dr, D>, ConstLen<N>>;

type StepOut<'dr, D, S, const HS: usize> = ragu::Result<(
    (
        Encoded<'dr, D, <S as Step<Agg>>::Left, HS>,
        Encoded<'dr, D, <S as Step<Agg>>::Right, HS>,
        Encoded<'dr, D, <S as Step<Agg>>::Output, HS>,
    ),
    DriverValue<D, [Fp; SEALED]>,
    DriverValue<D, ()>,
)>;

fn enforce_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> ragu::Result<()> {
    a.sub(dr, b).enforce_zero(dr)
}

fn sealed<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    t: &V<'dr, D, 7>,
    unbound: bool,
) -> ragu::Result<V<'dr, D, SEALED>> {
    let unbound = if unbound { Element::one() } else { Element::zero(dr) };
    FixedVec::new(vec![
        t[START_STATE].clone(),
        t[START_LIAB].clone(),
        t[END_STATE].clone(),
        t[END_LIAB].clone(),
        Element::one(),
        unbound,
    ])
}

/// An operation backed by a shielded transaction proof.
struct OpTx;

impl Step<Agg> for OpTx {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Transition;
    type Right = Tx;
    type Output = Sealed;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Agg, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 7]>,
        right: DriverValue<D, [Fp; 4]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let t: &V<'dr, D, 7> = left.as_gadget();
        let tx: &V<'dr, D, 4> = right.as_gadget();

        // The operation inserted exactly the transaction's nullifiers and
        // outputs, in order, and inserted something.
        enforce_equal(dr, &t[DIGEST], &tx[TX_DIGEST])?;
        t[DIGEST].clone().enforce_nonzero(dr)?;

        // Liabilities moved by the transaction's value balance.
        let moved = t[START_LIAB].sub(dr, &t[END_LIAB]);
        enforce_equal(dr, &moved, &tx[TX_BALANCE])?;

        // A transaction with spends proved membership under the note root the
        // operation started from. A spend-free transaction leaves its anchor
        // zero, which no Merkle path can hash to.
        let off = tx[TX_ANCHOR].sub(dr, &t[ANCHOR]);
        off.mul(dr, &tx[TX_ANCHOR])?.enforce_zero(dr)?;

        let out = sealed(dr, t, false)?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// An operation with no matching transaction proof: accepted and counted.
struct OpPlain;

impl Step<Agg> for OpPlain {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Transition;
    type Right = ();
    type Output = Sealed;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Agg, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; 7]>,
        _: DriverValue<D, ()>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let out = sealed(dr, left.as_gadget(), true)?;
        let data = values_of(&out);
        Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Chains two runs of sealed operations.
struct AggFold;

impl Step<Agg> for AggFold {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Sealed;
    type Right = Sealed;
    type Output = Sealed;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, Agg, Self>,
        _: DriverValue<D, ()>,
        left: DriverValue<D, [Fp; SEALED]>,
        right: DriverValue<D, [Fp; SEALED]>,
    ) -> StepOut<'dr, D, Self, HS>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let l: &V<'dr, D, SEALED> = left.as_gadget();
        let r: &V<'dr, D, SEALED> = right.as_gadget();

        enforce_equal(dr, &l[END_STATE], &r[START_STATE])?;
        enforce_equal(dr, &l[END_LIAB], &r[START_LIAB])?;
        let ops = l[S_OPS].add(dr, &r[S_OPS]);
        let unbound = l[S_UNBOUND].add(dr, &r[S_UNBOUND]);
        let out: V<'dr, D, SEALED> = FixedVec::new(vec![
            l[START_STATE].clone(),
            l[START_LIAB].clone(),
            r[END_STATE].clone(),
            r[END_LIAB].clone(),
            ops,
            unbound,
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

// Ragu requires an aggregator to register every header type its wallet
// application can output, because a decompressed statement is read with the
// wallet's own header type. The fold only consumes `Transition` and `Tx`;
// these pass-through steps declare the rest and are never proven.
macro_rules! declare_header {
    ($name:ident, $index:expr, $header:ty, $n:expr) => {
        struct $name;

        impl Step<Agg> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = ();
            type Aux<'source> = ();
            type Left = $header;
            type Right = ();
            type Output = $header;

            #[allow(clippy::type_complexity)]
            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Agg, Self>,
                _: DriverValue<D, ()>,
                left: DriverValue<D, [Fp; $n]>,
                _: DriverValue<D, ()>,
            ) -> ragu::Result<(
                (
                    Encoded<'dr, D, Self::Left, HS>,
                    Encoded<'dr, D, Self::Right, HS>,
                    Encoded<'dr, D, Self::Output, HS>,
                ),
                DriverValue<D, [Fp; $n]>,
                DriverValue<D, ()>,
            )>
            where
                Self: 'dr,
            {
                let allocator = &mut Standard::new();
                let left = Encoded::new(dr, allocator, left)?;
                let g: &V<'dr, D, $n> = left.as_gadget();
                let out: V<'dr, D, $n> = FixedVec::new(g.iter().cloned().collect())?;
                let data = values_of(&out);
                Ok(((left, Encoded::from_gadget(()), Encoded::from_gadget(out)), data, D::unit()))
            }
        }
    };
}

declare_header!(DeclareUpdate, 3, ragu_roots::Update, 6);
declare_header!(DeclareOrder, 4, ragu_roots::Order, 3);
declare_header!(DeclareNfMid, 5, ragu_roots::NfMid, 6);
declare_header!(DeclarePath, 6, crate::mode_b::ragu_backend::Path, 3);
declare_header!(DeclareKey, 7, crate::mode_b::ragu_backend::Key, 1);
declare_header!(DeclarePart, 8, crate::mode_b::ragu_backend::Part, 4);
declare_header!(DeclareKeys, 9, crate::mode_b::ragu_backend::Keys, 3);

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn build() -> ragu::Result<AggApp> {
    let pasta = ragu::pcd::pasta::baked();
    // The aggregator owns its own instance of the wallet application.
    let wallet = ragu_app::build()?;
    let decompression = Decompression::new(wallet, &mut rng())?;
    ApplicationBuilder::<Agg, AggregatorRank, HEADER_SIZE>::new()
        .register(OpTx)?
        .register(OpPlain)?
        .register(AggFold)?
        .register(DeclareUpdate)?
        .register(DeclareOrder)?
        .register(DeclareNfMid)?
        .register(DeclarePath)?
        .register(DeclareKey)?
        .register(DeclarePart)?
        .register(DeclareKeys)?
        .finalize_with(pasta, decompression)
}

fn app() -> Result<&'static AggApp> {
    static APP: OnceLock<std::result::Result<AggApp, String>> = OnceLock::new();
    APP.get_or_init(|| build().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| CircuitError::Plonk(format!("ragu aggregator application build: {e}")))
}

/// The operation's transaction proof as an aggregator child, if it has one
/// that matches what the operation did. `force` skips the native matching
/// check, so a mismatch has to be rejected by the `OpTx` circuit (tests).
fn tx_child(
    agg: &AggApp,
    step: &FoldedProof,
    chain: &[Fp; 7],
    force: bool,
) -> Result<Option<Pcd<Agg, AggregatorRank, Tx>>> {
    let Some(tx) = step.transition.as_deref().and_then(|t| t.tx_proof.as_deref()) else {
        return Ok(None);
    };
    if tx.subcircuit != SubcircuitId::RaguTx || tx.public_inputs.len() != 4 {
        return Ok(None);
    }
    let mut data = [Fp::from(0u64); 4];
    for (slot, bytes) in data.iter_mut().zip(&tx.public_inputs) {
        match Fp::from_bytes(*bytes) {
            Some(v) => *slot = v,
            None => return Ok(None),
        }
    }
    let zero = Fp::from(0u64);
    let matches = chain[DIGEST] != zero
        && chain[DIGEST] == data[TX_DIGEST]
        && chain[START_LIAB] - chain[END_LIAB] == data[TX_BALANCE]
        && (data[TX_ANCHOR] == zero || data[TX_ANCHOR] == chain[ANCHOR]);
    if !matches && !force {
        return Ok(None);
    }
    let Ok(compressed) = CompressedProof::<Pasta>::from_bytes(&tx.ipa_proof) else {
        return Ok(None);
    };
    // Decompression first runs the wallet verifier on the proof.
    match agg.decompress(&mut rng(), &compressed.carry::<Tx>(data)) {
        Ok(node) => Ok(Some(node)),
        Err(_) if !force => Ok(None),
        Err(e) => Err(ragu_err("decompress transaction", e)),
    }
}

/// Proves one operation: its root-binding chain in the wallet application,
/// decompressed and sealed against its transaction proof in the aggregator.
fn seal_step(agg: &AggApp, step: &FoldedProof, force_tx: bool) -> Result<(SealedPcd, StateFields, StateFields)> {
    let wallet = agg.context().wallet();
    let (chain, prev, next) = ragu_roots::prove_step(wallet, step)?;
    let chain_data = *chain.data();
    let compressed = wallet.compress(&chain, &mut rng()).map_err(|e| ragu_err("compress operation", e))?;
    let node = agg.decompress(&mut rng(), &compressed).map_err(|e| ragu_err("decompress operation", e))?;

    let sealed = match tx_child(agg, step, &chain_data, force_tx)? {
        Some(tx) => agg.fuse(&mut rng(), OpTx, (), node, tx).map(|p| p.0),
        None => {
            let unit = agg.bootstrap_proof().clone().carry::<()>(());
            agg.fuse(&mut rng(), OpPlain, (), node, unit).map(|p| p.0)
        }
    };
    Ok((sealed.map_err(|e| ragu_err("seal operation", e))?, prev, next))
}

type Running = (SealedPcd, StateFields, usize);

fn extend_with(acc: Option<Running>, step: &FoldedProof, force_tx: bool) -> Result<Running> {
    let agg = app()?;
    let (sealed, prev, next) = seal_step(agg, step, force_tx)?;
    match acc {
        None => Ok((sealed, next, 1)),
        Some((root, end, steps)) => {
            if end != prev {
                return Err(CircuitError::InvalidWitness(format!(
                    "step {steps} does not chain onto the folded state"
                )));
            }
            let fused = agg.fuse(&mut rng(), AggFold, (), root, sealed).map_err(|e| ragu_err("fuse", e))?.0;
            Ok((fused, next, steps + 1))
        }
    }
}

fn extend(acc: Option<Running>, step: &FoldedProof) -> Result<Running> {
    extend_with(acc, step, false)
}

fn finish(root: &SealedPcd, steps: usize) -> Result<FoldedProof> {
    let compressed = app()?.compress(root, &mut rng()).map_err(|e| ragu_err("compress", e))?;
    let (proof, data) = compressed.into_parts();
    let bytes = proof.to_bytes().map_err(|e| ragu_err("encode", format!("{e:?}")))?;
    // The first four follow the Halo 2 `FoldBatch` layout.
    let public_inputs = [START_LIAB, END_LIAB, START_STATE, END_STATE, S_OPS, S_UNBOUND]
        .map(|slot| data[slot].to_bytes())
        .to_vec();
    Ok(FoldedProof {
        subcircuit: SubcircuitId::RaguFoldAggregated,
        k: RAGU_RANK,
        public_inputs,
        ipa_proof: bytes,
        folded_children: steps,
        transition: None,
    })
}

fn fold_with(
    start_state: &MintState,
    end_state: &MintState,
    step_proofs: &[FoldedProof],
    force_tx: bool,
) -> Result<FoldedProof> {
    if step_proofs.is_empty() {
        return Err(CircuitError::InvalidWitness("cannot fold empty proof batch".into()));
    }
    let mut acc: Option<Running> = None;
    for step in step_proofs {
        acc = Some(extend_with(acc, step, force_tx)?);
    }
    let (root, end, steps) = acc.expect("non-empty batch");
    let start = step_proofs[0].transition.as_deref().map(|t| &t.prev);
    if start != Some(start_state) || end != StateFields::of(end_state)? {
        return Err(CircuitError::InvalidWitness(
            "step proofs do not span the requested start and end states".into(),
        ));
    }
    finish(&root, steps)
}

/// Folds Mode A step proofs, sealing each operation against its transaction
/// proof where it has a matching one.
pub fn fold(start_state: &MintState, end_state: &MintState, step_proofs: &[FoldedProof]) -> Result<FoldedProof> {
    fold_with(start_state, end_state, step_proofs, false)
}

/// [`fold`], but any attached transaction proof is used even when it does not
/// match the operation. For tests showing the `OpTx` circuit rejects it.
#[doc(hidden)]
pub fn fold_forcing_tx(
    start_state: &MintState,
    end_state: &MintState,
    step_proofs: &[FoldedProof],
) -> Result<FoldedProof> {
    fold_with(start_state, end_state, step_proofs, true)
}

/// A background folder for this application; see [`BackgroundFolder`].
pub fn background() -> BackgroundFolder {
    BackgroundFolder::spawn_with(FolderOps { extend, finish })
}

/// `(ops, unbound_ops)` of an aggregated fold proof: how many operations it
/// covers and how many of them had no matching shielded transaction proof.
pub fn op_counts(proof: &FoldedProof) -> Option<(u64, u64)> {
    if proof.subcircuit != SubcircuitId::RaguFoldAggregated || proof.public_inputs.len() != SEALED {
        return None;
    }
    let small = |b: &[u8; 32]| {
        b[8..].iter().all(|x| *x == 0).then(|| u64::from_le_bytes(b[..8].try_into().expect("8 bytes")))
    };
    Some((small(&proof.public_inputs[4])?, small(&proof.public_inputs[5])?))
}

/// Verifies an aggregated fold proof against its own public inputs.
pub fn verify(proof: &FoldedProof) -> Result<()> {
    let fail = |msg: String| CircuitError::VerificationFailed(format!("ragu aggregated fold: {msg}"));
    if proof.subcircuit != SubcircuitId::RaguFoldAggregated {
        return Err(fail(format!("unexpected subcircuit {:?}", proof.subcircuit)));
    }
    if proof.public_inputs.len() != SEALED {
        return Err(fail(format!("expected {SEALED} public inputs, got {}", proof.public_inputs.len())));
    }
    let pi = proof
        .public_inputs
        .iter()
        .map(|b| Fp::from_bytes(*b).ok_or_else(|| fail("non-canonical public input".into())))
        .collect::<Result<Vec<_>>>()?;
    let mut data = [Fp::from(0u64); SEALED];
    data[START_LIAB] = pi[0];
    data[END_LIAB] = pi[1];
    data[START_STATE] = pi[2];
    data[END_STATE] = pi[3];
    data[S_OPS] = pi[4];
    data[S_UNBOUND] = pi[5];

    let compressed =
        CompressedProof::<Agg>::from_bytes(&proof.ipa_proof).map_err(|e| fail(format!("decode: {e:?}")))?;
    match app()?.verify_compressed(&compressed.carry::<Sealed>(data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail("proof rejected".into())),
        Err(e) => Err(fail(e.to_string())),
    }
}
