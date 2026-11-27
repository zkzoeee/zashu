//! Ragu proof-carrying-data backend for the Mode A solvency fold (`NUTZ-1`).
//!
//! Enabled with the `ragu` cargo feature. Ragu is unreleased and unaudited
//! upstream, so this backend is opt-in and must not be relied on in production.
//!
//! Each Mode A step is re-proven as a Ragu leaf from the state transition its
//! Halo 2 step proof carries, and the leaves are fused left to right into one proof.
//! Unlike the Halo 2 `FoldBatchCircuit`, the fold is recursive: the root proof
//! attests that every step's liabilities arithmetic holds and that state hashes
//! and liabilities chain contiguously from the first step to the last.
//!
//! Every step opens both of its state hashes in-circuit (the same Poseidon
//! construction as `MintState::state_hash`), so the liabilities the circuit
//! does arithmetic on are the liabilities the state hashes commit to. Epochs
//! are checked to be non-decreasing. What a step does not check is how the
//! nullifier root, note root and event log change; those are covered by the
//! Mode B proofs and by replaying the mint's public event log.
//!
//! The compressed root is returned as a [`FoldedProof`] whose public inputs use
//! the same layout as the Halo 2 `FoldBatch` proof:
//! `[start_liabilities, end_liabilities, start_state, end_state, step_count]`.

use std::sync::{mpsc, Mutex, OnceLock};

use ragu::circuits::polynomials::R;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::Element;
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::udon::field::Field;
use ragu::{Application, ApplicationBuilder, CompressedProof, Pcd};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

use zashu_core::poseidon::{mint_state_root_fields, DOMAIN_STATE};
use zashu_core::types::MintState;

use crate::error::{CircuitError, Result};
use crate::pcd::{FoldedProof, SubcircuitId};
use crate::ragu_gadgets::{fp_from_bytes, fp_from_pasta, poseidon_hash, values_of, TAG_NODE};

/// Ragu circuit rank (`2^14` constraints per step circuit).
pub const RAGU_RANK: u32 = 14;

pub(crate) type Rank = R<14>;
pub(crate) const PAYLOAD: usize = 7;
/// Payload plus Ragu's header suffix slot.
const HEADER_SIZE: usize = PAYLOAD + 1;
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;
pub(crate) type TransitionPcd = Pcd<Pasta, Rank, Transition>;
pub(crate) type Payload<'dr, D> = FixedVec<Element<'dr, D>, ConstLen<PAYLOAD>>;

// Header payload slots.
pub(crate) const START_STATE: usize = 0;
pub(crate) const START_LIAB: usize = 1;
pub(crate) const END_STATE: usize = 2;
pub(crate) const END_LIAB: usize = 3;
pub(crate) const COUNT: usize = 4;
/// Digest of the nullifiers and notes inserted (zero if none); see
/// [`TAG_NODE`](crate::ragu_gadgets::TAG_NODE).
pub(crate) const DIGEST: usize = 5;
/// The note root at the start of the leftmost transition.
pub(crate) const ANCHOR: usize = 6;

pub(super) fn ragu_err(context: &str, e: impl core::fmt::Display) -> CircuitError {
    CircuitError::Plonk(format!("ragu {context}: {e}"))
}

/// `[start_state, start_liabilities, end_state, end_liabilities, step_count, digest, anchor]`
pub(crate) struct Transition;

impl Header<Fp> for Transition {
    const SUFFIX: Suffix = Suffix::new(0);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = [Fp; PAYLOAD];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<PAYLOAD>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StepKind {
    Mint,
    Swap,
    Melt,
}

/// The preimage of a `MintState::state_hash`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct StateFields {
    pub(super) epoch: u64,
    pub(super) liabilities: u64,
    pub(super) nf_root: Fp,
    pub(super) note_root: Fp,
    pub(super) event_log: Fp,
    /// Native `state_hash`, used only for pre-checks outside the circuit.
    pub(super) hash: Fp,
}

impl StateFields {
    pub(super) fn of(state: &MintState) -> Result<Self> {
        let [nf, note, ev] =
            mint_state_root_fields(&state.nullifier_acc_root, &state.note_acc_root, &state.event_log_hash);
        Ok(Self {
            epoch: state.epoch,
            liabilities: state.total_liabilities,
            nf_root: fp_from_pasta(&nf),
            note_root: fp_from_pasta(&note),
            event_log: fp_from_pasta(&ev),
            hash: fp_from_bytes(&state.state_hash())?,
        })
    }
}

#[derive(Clone, Copy)]
struct StepWitness {
    prev: StateFields,
    next: StateFields,
}

struct OpenedState<'dr, D: Driver<'dr>> {
    epoch: Element<'dr, D>,
    liabilities: Element<'dr, D>,
    hash: Element<'dr, D>,
}

/// Allocates a state preimage, range-checks its integers and recomputes
/// `Poseidon3(Poseidon4(DOMAIN_STATE, epoch, liabilities, nf_root), note_root, event_log)`.
fn open_state<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    state: DriverValue<D, StateFields>,
) -> ragu::Result<OpenedState<'dr, D>> {
    let max = Fp::from(u64::MAX);
    let epoch = Element::alloc(dr, allocator, state.as_ref().map(|s| Fp::from(s.epoch)))?;
    let liabilities = Element::alloc(dr, allocator, state.as_ref().map(|s| Fp::from(s.liabilities)))?;
    let nf_root = Element::alloc(dr, allocator, state.as_ref().map(|s| s.nf_root))?;
    let note_root = Element::alloc(dr, allocator, state.as_ref().map(|s| s.note_root))?;
    let event_log = Element::alloc(dr, allocator, state.as_ref().map(|s| s.event_log))?;

    epoch.enforce_le::<64>(dr, allocator, max)?;
    liabilities.enforce_le::<64>(dr, allocator, max)?;

    let domain = Element::constant(dr, Fp::from(DOMAIN_STATE));
    let h1 = poseidon_hash(dr, &[domain, epoch.clone(), liabilities.clone(), nf_root])?;
    let hash = poseidon_hash(dr, &[h1, note_root, event_log])?;
    Ok(OpenedState { epoch, liabilities, hash })
}

/// Shared body of the three leaf steps.
fn value_step<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    witness: DriverValue<D, StepWitness>,
    kind: StepKind,
) -> ragu::Result<Payload<'dr, D>> {
    let allocator = &mut Standard::new();
    let max = Fp::from(u64::MAX);

    let prev = open_state(dr, allocator, witness.as_ref().map(|w| w.prev))?;
    let next = open_state(dr, allocator, witness.as_ref().map(|w| w.next))?;

    // Epochs never go backwards: next - prev is a u64, so it did not wrap.
    next.epoch.sub(dr, &prev.epoch).enforce_le::<64>(dr, allocator, max)?;

    match kind {
        StepKind::Swap => prev.liabilities.sub(dr, &next.liabilities).enforce_zero(dr)?,
        StepKind::Mint | StepKind::Melt => {
            // amount = |next - prev| must be a non-zero u64. With both
            // liabilities range-checked, a wrong direction wraps the field and
            // fails the amount range check.
            let amount = if kind == StepKind::Mint {
                next.liabilities.sub(dr, &prev.liabilities)
            } else {
                prev.liabilities.sub(dr, &next.liabilities)
            };
            amount.enforce_le::<64>(dr, allocator, max)?;
            amount.enforce_nonzero(dr)?;
        }
    }

    // Slot order: START_STATE, START_LIAB, END_STATE, END_LIAB, COUNT.
    // This fold does not track inserts: digest and anchor stay zero.
    let (digest, anchor) = (Element::zero(dr), Element::zero(dr));
    FixedVec::new(vec![prev.hash, prev.liabilities, next.hash, next.liabilities, Element::one(), digest, anchor])
}

macro_rules! leaf_step {
    ($name:ident, $index:expr, $kind:expr) => {
        struct $name;

        impl Step<Pasta> for $name {
            const INDEX: Index = Index::new($index);
            type Witness<'source> = StepWitness;
            type Aux<'source> = ();
            type Left = ();
            type Right = ();
            type Output = Transition;

            fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
                &self,
                dr: &mut D,
                _: &mut Oracles<'_, 'dr, D, Pasta, Self>,
                witness: DriverValue<D, Self::Witness<'source>>,
                _: DriverValue<D, ()>,
                _: DriverValue<D, ()>,
            ) -> ragu::Result<(
                (
                    Encoded<'dr, D, Self::Left, HS>,
                    Encoded<'dr, D, Self::Right, HS>,
                    Encoded<'dr, D, Self::Output, HS>,
                ),
                DriverValue<D, [Fp; PAYLOAD]>,
                DriverValue<D, ()>,
            )>
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

leaf_step!(MintLeaf, 0, StepKind::Mint);
leaf_step!(SwapLeaf, 1, StepKind::Swap);
leaf_step!(MeltLeaf, 2, StepKind::Melt);

/// Recursive step: merges two adjacent transitions into one.
pub(crate) struct FoldStep;

impl Step<Pasta> for FoldStep {
    const INDEX: Index = Index::new(3);
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
        left: DriverValue<D, [Fp; PAYLOAD]>,
        right: DriverValue<D, [Fp; PAYLOAD]>,
    ) -> ragu::Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, [Fp; PAYLOAD]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let l: &Payload<'dr, D> = left.as_gadget();
        let r: &Payload<'dr, D> = right.as_gadget();

        // Contiguity: the left transition ends exactly where the right begins.
        l[END_STATE].sub(dr, &r[START_STATE]).enforce_zero(dr)?;
        l[END_LIAB].sub(dr, &r[START_LIAB]).enforce_zero(dr)?;

        let count = l[COUNT].add(dr, &r[COUNT]);

        // Digests chain left to right; a zero digest (no inserts) is neutral.
        let left_empty = l[DIGEST].is_zero(dr, allocator)?;
        let right_empty = r[DIGEST].is_zero(dr, allocator)?;
        let tag = Element::constant(dr, Fp::from(TAG_NODE));
        let node = poseidon_hash(dr, &[tag, l[DIGEST].clone(), r[DIGEST].clone()])?;
        let unless_right_empty = right_empty.conditional_select(dr, &node, &l[DIGEST])?;
        let digest = left_empty.conditional_select(dr, &unless_right_empty, &r[DIGEST])?;

        let out = FixedVec::new(vec![
            l[START_STATE].clone(),
            l[START_LIAB].clone(),
            r[END_STATE].clone(),
            r[END_LIAB].clone(),
            count,
            digest,
            l[ANCHOR].clone(),
        ])?;
        let data = values_of(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

fn app() -> Result<&'static App> {
    static APP: OnceLock<std::result::Result<App, String>> = OnceLock::new();
    APP.get_or_init(|| {
        let pasta = ragu::pcd::pasta::baked();
        ApplicationBuilder::<Pasta, Rank, HEADER_SIZE>::new()
            .register(MintLeaf)
            .and_then(|b| b.register(SwapLeaf))
            .and_then(|b| b.register(MeltLeaf))
            .and_then(|b| b.register(FoldStep))
            .and_then(|b| b.finalize(pasta))
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| CircuitError::Plonk(format!("ragu application build: {e}")))
}

/// Recovers a leaf witness from the state transition a Mode A step proof carries.
fn leaf_from_step(step: &FoldedProof) -> Result<(StepKind, StepWitness)> {
    let kind = match step.subcircuit {
        SubcircuitId::MintStep => StepKind::Mint,
        SubcircuitId::SwapStep => StepKind::Swap,
        SubcircuitId::MeltStep => StepKind::Melt,
        other => {
            return Err(CircuitError::InvalidWitness(format!(
                "cannot fold {other:?} with the Ragu backend"
            )))
        }
    };
    let t = step.transition.as_deref().ok_or_else(|| {
        CircuitError::InvalidWitness(format!(
            "{:?} step proof carries no state transition; the Ragu backend needs it",
            step.subcircuit
        ))
    })?;
    Ok((kind, StepWitness { prev: StateFields::of(&t.prev)?, next: StateFields::of(&t.next)? }))
}

/// Pre-checks a leaf natively so a bad step fails here with a clear error
/// instead of producing a proof that only fails at verification.
fn check_leaf(kind: StepKind, w: &StepWitness) -> Result<()> {
    let (prev, next) = (w.prev.liabilities, w.next.liabilities);
    let ok = w.next.epoch >= w.prev.epoch
        && match kind {
            StepKind::Mint => next > prev,
            StepKind::Melt => next < prev,
            StepKind::Swap => next == prev,
        };
    if ok {
        Ok(())
    } else {
        Err(CircuitError::ValueBounds)
    }
}

fn seed_leaf(app: &App, kind: StepKind, w: StepWitness) -> Result<TransitionPcd> {
    let rng = &mut UnwrapErr(SysRng);
    let pcd = match kind {
        StepKind::Mint => app.seed(rng, MintLeaf, w).map(|p| p.0),
        StepKind::Swap => app.seed(rng, SwapLeaf, w).map(|p| p.0),
        StepKind::Melt => app.seed(rng, MeltLeaf, w).map(|p| p.0),
    };
    pcd.map_err(|e| ragu_err("seed", e))
}

/// Folds a contiguous sequence of Mode A step proofs into one compressed Ragu
/// PCD proof.
///
/// Leaves are proven in parallel chunks (see [`parallel_chunk`]) and the chunks
/// fused left to right.
pub fn fold(start_state: &MintState, end_state: &MintState, step_proofs: &[FoldedProof]) -> Result<FoldedProof> {
    if step_proofs.is_empty() {
        return Err(CircuitError::InvalidWitness("cannot fold empty proof batch".into()));
    }
    let leaves = step_proofs.iter().map(leaf_from_step).collect::<Result<Vec<_>>>()?;
    for (i, (kind, w)) in leaves.iter().enumerate() {
        check_leaf(*kind, w)?;
        if let Some((_, next)) = leaves.get(i + 1) {
            if w.next != next.prev {
                return Err(CircuitError::InvalidWitness(format!(
                    "step {i} does not chain into step {}",
                    i + 1
                )));
            }
        }
    }
    let (first, last) = (&leaves[0].1, &leaves[leaves.len() - 1].1);
    if first.prev != StateFields::of(start_state)? || last.next != StateFields::of(end_state)? {
        return Err(CircuitError::InvalidWitness(
            "step proofs do not span the requested start and end states".into(),
        ));
    }

    let app = app()?;
    let mut acc: Option<TransitionPcd> = None;
    for chunk in leaves.chunks(parallel_chunk()) {
        let part = fold_chunk(app, chunk)?;
        acc = Some(match acc {
            None => part,
            Some(prev) => fuse(app, prev, part)?,
        });
    }
    finish(app, &acc.expect("non-empty batch"), step_proofs.len())
}

/// How many leaves are proven and tree-fused concurrently in a batch fold,
/// set with `ZASHU_RAGU_PARALLEL`. The default is sequential: Ragu already
/// uses every core inside one proof, each in-flight uncompressed proof is
/// about 34 MB at rank 14, and on a 10-core machine 4-way chunks measured only
/// about 1.3x faster while 8-way was several times slower.
fn parallel_chunk() -> usize {
    std::env::var("ZASHU_RAGU_PARALLEL")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_PARALLEL_CHUNK)
}

const DEFAULT_PARALLEL_CHUNK: usize = 1;

fn fuse(app: &App, left: TransitionPcd, right: TransitionPcd) -> Result<TransitionPcd> {
    app.fuse(&mut UnwrapErr(SysRng), FoldStep, (), left, right)
        .map(|p| p.0)
        .map_err(|e| ragu_err("fuse", e))
}

/// Proves a run of adjacent leaves and fuses them into one transition, as a
/// balanced tree whose two halves are proven concurrently.
fn fold_chunk(app: &App, leaves: &[(StepKind, StepWitness)]) -> Result<TransitionPcd> {
    match leaves {
        [] => unreachable!("chunks are never empty"),
        [(kind, w)] => seed_leaf(app, *kind, *w),
        _ => {
            let (l, r) = leaves.split_at(leaves.len() / 2);
            let (l, r) = rayon::join(|| fold_chunk(app, l), || fold_chunk(app, r));
            fuse(app, l?, r?)
        }
    }
}

/// Compresses a folded transition into the wire proof.
fn finish(app: &App, root: &TransitionPcd, steps: usize) -> Result<FoldedProof> {
    finish_with(app, root, steps, SubcircuitId::RaguFold)
}

pub(super) fn finish_with<const HS: usize>(
    app: &Application<'static, Pasta, Rank, HS>,
    root: &TransitionPcd,
    steps: usize,
    subcircuit: SubcircuitId,
) -> Result<FoldedProof> {
    let compressed = app.compress(root, &mut UnwrapErr(SysRng)).map_err(|e| ragu_err("compress", e))?;
    let (proof, data) = compressed.into_parts();
    let bytes = proof.to_bytes().map_err(|e| ragu_err("encode", format!("{e:?}")))?;

    // Same public-input layout as the Halo 2 `FoldBatch` proof.
    let public_inputs = [START_LIAB, END_LIAB, START_STATE, END_STATE, COUNT, DIGEST, ANCHOR]
        .map(|slot| data[slot].to_bytes())
        .to_vec();
    Ok(FoldedProof {
        subcircuit,
        k: RAGU_RANK,
        public_inputs,
        ipa_proof: bytes,
        folded_children: steps,
        transition: None,
    })
}

/// The running fold: the proof so far, the state it ends at, and its step count.
pub(super) type Running = (TransitionPcd, StateFields, usize);

/// How a [`BackgroundFolder`] proves and compresses, so the worker can serve
/// either Ragu fold application.
#[derive(Clone, Copy)]
pub(super) struct FolderOps {
    /// Fuses one more step onto the running proof.
    pub(super) extend: fn(Option<Running>, &FoldedProof) -> Result<Running>,
    /// Compresses the running proof.
    pub(super) finish: fn(&TransitionPcd, usize) -> Result<FoldedProof>,
}

enum FolderMsg {
    Step(Box<FoldedProof>),
    Snapshot(mpsc::Sender<Result<Option<FoldedProof>>>),
}

/// Folds Mode A steps on a worker thread as they happen, so producing the
/// `NUTZ-1` proof only costs one compression once the worker has caught up.
///
/// Steps must be pushed in order. The worker keeps a single running proof;
/// a step that does not extend it poisons the folder and every later
/// [`snapshot`](Self::snapshot) reports that error.
pub struct BackgroundFolder {
    tx: mpsc::Sender<FolderMsg>,
}

impl BackgroundFolder {
    pub fn spawn() -> Self {
        Self::spawn_with(FolderOps {
            extend,
            finish: |root, steps| app().and_then(|app| finish(app, root, steps)),
        })
    }

    pub(super) fn spawn_with(ops: FolderOps) -> Self {
        let (tx, rx) = mpsc::channel::<FolderMsg>();
        std::thread::Builder::new()
            .name("zashu-ragu-fold".into())
            .spawn(move || {
                let mut acc: Option<Running> = None;
                let mut poisoned: Option<String> = None;
                for msg in rx {
                    match msg {
                        FolderMsg::Step(step) => {
                            if poisoned.is_none() {
                                match (ops.extend)(acc.take(), &step) {
                                    Ok(next) => acc = Some(next),
                                    Err(e) => poisoned = Some(e.to_string()),
                                }
                            }
                        }
                        FolderMsg::Snapshot(reply) => {
                            let result = match (&poisoned, &acc) {
                                (Some(e), _) => Err(CircuitError::Plonk(format!("ragu background fold: {e}"))),
                                (None, None) => Ok(None),
                                (None, Some((root, _, steps))) => {
                                    (ops.finish)(root, *steps).map(Some)
                                }
                            };
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .expect("spawn ragu fold worker");
        Self { tx }
    }

    /// Queues a step proof (with its state transition). Never blocks on proving.
    pub fn push(&self, step: FoldedProof) {
        let _ = self.tx.send(FolderMsg::Step(Box::new(step)));
    }

    /// Waits for every queued step to be folded, then compresses the running
    /// proof. Returns `None` if no step was pushed yet.
    pub fn snapshot(&self) -> Result<Option<FoldedProof>> {
        self.request_snapshot().wait()
    }

    /// Asks for a snapshot of everything queued so far, without waiting for
    /// it. Steps pushed afterwards are not part of it.
    pub fn request_snapshot(&self) -> PendingSnapshot {
        let (reply, rx) = mpsc::channel();
        let sent = self.tx.send(FolderMsg::Snapshot(reply)).is_ok();
        PendingSnapshot { rx: sent.then(|| Mutex::new(rx)) }
    }
}

/// A snapshot the background worker has been asked for.
pub struct PendingSnapshot {
    // In a mutex only so the handle is `Sync` and can sit in shared state.
    rx: Option<Mutex<mpsc::Receiver<Result<Option<FoldedProof>>>>>,
}

impl PendingSnapshot {
    fn gone() -> CircuitError {
        CircuitError::Plonk("ragu background fold worker stopped".into())
    }

    /// Blocks until the worker has folded up to the request and compressed.
    pub fn wait(self) -> Result<Option<FoldedProof>> {
        let rx = self.rx.ok_or_else(Self::gone)?.into_inner().map_err(|_| Self::gone())?;
        rx.recv().map_err(|_| Self::gone())?
    }

    /// The snapshot if it is ready; `None` while the worker is still folding.
    pub fn try_take(&mut self) -> Option<Result<Option<FoldedProof>>> {
        let Some(rx) = self.rx.as_mut().and_then(|rx| rx.get_mut().ok()) else {
            return Some(Err(Self::gone()));
        };
        match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(Self::gone())),
        }
    }
}

/// Fuses one more step onto the running proof.
fn extend(acc: Option<Running>, step: &FoldedProof) -> Result<Running> {
    let (kind, w) = leaf_from_step(step)?;
    check_leaf(kind, &w)?;
    let app = app()?;
    match acc {
        None => Ok((seed_leaf(app, kind, w)?, w.next, 1)),
        Some((root, end, steps)) => {
            if end != w.prev {
                return Err(CircuitError::InvalidWitness(format!(
                    "step {steps} does not chain onto the folded state"
                )));
            }
            Ok((fuse(app, root, seed_leaf(app, kind, w)?)?, w.next, steps + 1))
        }
    }
}

/// Verifies a compressed Ragu fold proof against its own public inputs.
/// Callers still have to compare those public inputs with the expected states,
/// which `verify_fold_batch` does for both backends.
pub fn verify(proof: &FoldedProof) -> Result<()> {
    verify_with(app()?, SubcircuitId::RaguFold, proof)
}

pub(super) fn verify_with<const HS: usize>(
    app: &Application<'static, Pasta, Rank, HS>,
    subcircuit: SubcircuitId,
    proof: &FoldedProof,
) -> Result<()> {
    let fail = |msg: String| CircuitError::VerificationFailed(format!("ragu fold: {msg}"));
    if proof.subcircuit != subcircuit {
        return Err(fail(format!("unexpected subcircuit {:?}", proof.subcircuit)));
    }
    if proof.public_inputs.len() != PAYLOAD {
        return Err(fail(format!("expected {PAYLOAD} public inputs, got {}", proof.public_inputs.len())));
    }
    let pi = proof
        .public_inputs
        .iter()
        .map(|b| Fp::from_bytes(*b).ok_or_else(|| fail("non-canonical public input".into())))
        .collect::<Result<Vec<_>>>()?;
    // Public inputs: [start_liab, end_liab, start_state, end_state, count, digest, anchor].
    let mut data = [Fp::from(0u64); PAYLOAD];
    data[START_LIAB] = pi[0];
    data[END_LIAB] = pi[1];
    data[START_STATE] = pi[2];
    data[END_STATE] = pi[3];
    data[COUNT] = pi[4];
    data[DIGEST] = pi[5];
    data[ANCHOR] = pi[6];

    if proof.ipa_proof.len() != CompressedProof::<Pasta>::encoded_len::<Rank>() {
        return Err(fail("unexpected proof length".into()));
    }
    let compressed = CompressedProof::<Pasta>::from_bytes(&proof.ipa_proof)
        .map_err(|e| fail(format!("decode: {e:?}")))?;
    match app.verify_compressed(&compressed.carry::<Transition>(data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail("proof rejected".into())),
        Err(e) => Err(fail(e.to_string())),
    }
}
