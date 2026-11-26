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

use std::sync::OnceLock;

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
use crate::ragu_gadgets::{fp_from_bytes, fp_from_pasta, poseidon_hash, values_of};

/// Ragu circuit rank (`2^14` constraints per step circuit).
pub const RAGU_RANK: u32 = 14;

type Rank = R<14>;
const PAYLOAD: usize = 5;
/// Payload plus Ragu's header suffix slot.
const HEADER_SIZE: usize = PAYLOAD + 1;
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;
type TransitionPcd = Pcd<Pasta, Rank, Transition>;
type Payload<'dr, D> = FixedVec<Element<'dr, D>, ConstLen<PAYLOAD>>;

// Header payload slots.
const START_STATE: usize = 0;
const START_LIAB: usize = 1;
const END_STATE: usize = 2;
const END_LIAB: usize = 3;
const COUNT: usize = 4;

fn ragu_err(context: &str, e: impl core::fmt::Display) -> CircuitError {
    CircuitError::Plonk(format!("ragu {context}: {e}"))
}

/// `[start_state, start_liabilities, end_state, end_liabilities, step_count]`
struct Transition;

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
enum StepKind {
    Mint,
    Swap,
    Melt,
}

/// The preimage of a `MintState::state_hash`.
#[derive(Clone, Copy, PartialEq, Eq)]
struct StateFields {
    epoch: u64,
    liabilities: u64,
    nf_root: Fp,
    note_root: Fp,
    event_log: Fp,
    /// Native `state_hash`, used only for pre-checks outside the circuit.
    hash: Fp,
}

impl StateFields {
    fn of(state: &MintState) -> Result<Self> {
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
    FixedVec::new(vec![prev.hash, prev.liabilities, next.hash, next.liabilities, Element::one()])
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
struct FoldStep;

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
        let out = FixedVec::new(vec![
            l[START_STATE].clone(),
            l[START_LIAB].clone(),
            r[END_STATE].clone(),
            r[END_LIAB].clone(),
            count,
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
/// Leaves are fused left to right, so at most two uncompressed proofs (about
/// 34 MB each at rank 14) are alive at a time.
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
    let rng = &mut UnwrapErr(SysRng);
    let mut acc: Option<TransitionPcd> = None;
    for (kind, w) in leaves {
        let leaf = seed_leaf(app, kind, w)?;
        acc = Some(match acc {
            None => leaf,
            Some(prev) => app.fuse(rng, FoldStep, (), prev, leaf).map_err(|e| ragu_err("fuse", e))?.0,
        });
    }
    let root = acc.expect("non-empty batch");
    let compressed = app.compress(&root, rng).map_err(|e| ragu_err("compress", e))?;
    let (proof, data) = compressed.into_parts();
    let bytes = proof.to_bytes().map_err(|e| ragu_err("encode", format!("{e:?}")))?;

    // Same public-input layout as the Halo 2 `FoldBatch` proof.
    let public_inputs = [START_LIAB, END_LIAB, START_STATE, END_STATE, COUNT]
        .map(|slot| data[slot].to_bytes())
        .to_vec();
    Ok(FoldedProof {
        subcircuit: SubcircuitId::RaguFold,
        k: RAGU_RANK,
        public_inputs,
        ipa_proof: bytes,
        folded_children: step_proofs.len(),
        transition: None,
    })
}

/// Verifies a compressed Ragu fold proof against its own public inputs.
/// Callers still have to compare those public inputs with the expected states,
/// which `verify_fold_batch` does for both backends.
pub fn verify(proof: &FoldedProof) -> Result<()> {
    let fail = |msg: String| CircuitError::VerificationFailed(format!("ragu fold: {msg}"));
    if proof.subcircuit != SubcircuitId::RaguFold {
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
    // Public inputs: [start_liab, end_liab, start_state, end_state, count].
    let mut data = [Fp::from(0u64); PAYLOAD];
    data[START_LIAB] = pi[0];
    data[END_LIAB] = pi[1];
    data[START_STATE] = pi[2];
    data[END_STATE] = pi[3];
    data[COUNT] = pi[4];

    if proof.ipa_proof.len() != CompressedProof::<Pasta>::encoded_len::<Rank>() {
        return Err(fail("unexpected proof length".into()));
    }
    let compressed = CompressedProof::<Pasta>::from_bytes(&proof.ipa_proof)
        .map_err(|e| fail(format!("decode: {e:?}")))?;
    match app()?.verify_compressed(&compressed.carry::<Transition>(data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail("proof rejected".into())),
        Err(e) => Err(fail(e.to_string())),
    }
}
