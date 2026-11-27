//! `main.rs` at rank 15, to time a step against rank 14.
//! Spike: zashu's Mode A solvency fold (NUTZ-1) as real Ragu PCD.
//!
//! Model, simplified from `zashu-circuits::mode_a`:
//!   state      = Poseidon(total_liabilities, nullifier_root)
//!   Transition = header [start_state, end_state, step_count]
//!   MintStep   : liabilities += amount   (seed, no children)
//!   MeltStep   : liabilities -= amount   (seed, no children)
//!   FoldStep   : left.end == right.start, counts add (two children)
//!
//! Unlike the current Halo 2 `FoldBatchCircuit`, FoldStep is a recursive
//! step: the root proof attests that every leaf proof verified and that the
//! state chain is contiguous. The mint is not trusted for either.

use std::time::Instant;

use ragu::circuits::polynomials::R;
use ragu::drivers::emulator::Emulator;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::poseidon::Sponge;
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::Element;
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::{Application, ApplicationBuilder, Cycle, Pcd, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

type Rank = R<15>;
const HEADER_SIZE: usize = 4; // 3 payload elements + Ragu's suffix
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;
type Poseidon = <Pasta as Cycle>::CircuitPoseidon;
type TransitionPcd = Pcd<Pasta, Rank, Transition>;

/// `[start_state, end_state, step_count]`
struct Transition;

impl Header<Fp> for Transition {
    const SUFFIX: Suffix = Suffix::new(0);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = [Fp; 3];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ConstLen<3>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

#[derive(Clone, Copy)]
struct StepWitness {
    prev_liabilities: u64,
    amount: u64,
    nf_root: Fp,
}

fn state_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    params: &'dr Poseidon,
    liabilities: &Element<'dr, D>,
    nf_root: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params);
    sponge.absorb(dr, liabilities)?;
    sponge.absorb(dr, nf_root)?;
    sponge.squeeze(dr)
}

/// Shared body of MintStep / MeltStep. Returns `[start, end, 1]`.
fn value_step<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    params: &'dr Poseidon,
    witness: DriverValue<D, StepWitness>,
    mint: bool,
) -> Result<FixedVec<Element<'dr, D>, ConstLen<3>>> {
    let allocator = &mut Standard::new();
    let max = Fp::from(u64::MAX);

    let prev = Element::alloc(dr, allocator, witness.as_ref().map(|w| Fp::from(w.prev_liabilities)))?;
    let amount = Element::alloc(dr, allocator, witness.as_ref().map(|w| Fp::from(w.amount)))?;
    let nf_root = Element::alloc(dr, allocator, witness.as_ref().map(|w| w.nf_root))?;

    prev.enforce_le::<64>(dr, allocator, max)?;
    amount.enforce_le::<64>(dr, allocator, max)?;
    amount.clone().enforce_nonzero(dr)?;

    let next = if mint { prev.add(dr, &amount) } else { prev.sub(dr, &amount) };
    // Catches u64 overflow on mint and underflow (field wraparound) on melt.
    next.enforce_le::<64>(dr, allocator, max)?;

    let start = state_hash(dr, params, &prev, &nf_root)?;
    let end = state_hash(dr, params, &next, &nf_root)?;
    FixedVec::new(vec![start, end, Element::one()])
}

fn header_value<'dr, D: Driver<'dr, F = Fp>>(
    out: &FixedVec<Element<'dr, D>, ConstLen<3>>,
) -> DriverValue<D, [Fp; 3]> {
    let (a, b, c) = (out[0].value().map(|v| *v), out[1].value().map(|v| *v), out[2].value().map(|v| *v));
    a.and_then(|a| b.and_then(|b| c.map(|c| [a, b, c])))
}

macro_rules! value_step_impl {
    ($name:ident, $index:expr, $mint:expr) => {
        struct $name {
            poseidon: &'static Poseidon,
        }

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
            ) -> Result<(
                (
                    Encoded<'dr, D, Self::Left, HS>,
                    Encoded<'dr, D, Self::Right, HS>,
                    Encoded<'dr, D, Self::Output, HS>,
                ),
                DriverValue<D, [Fp; 3]>,
                DriverValue<D, ()>,
            )>
            where
                Self: 'dr,
            {
                let out = value_step(dr, self.poseidon, witness, $mint)?;
                let data = header_value::<D>(&out);
                Ok((
                    (Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(out)),
                    data,
                    D::unit(),
                ))
            }
        }
    };
}

value_step_impl!(MintStep, 0, true);
value_step_impl!(MeltStep, 1, false);

/// Recursive step: merges two adjacent transitions into one.
struct FoldStep;

impl Step<Pasta> for FoldStep {
    const INDEX: Index = Index::new(2);
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
        left: DriverValue<D, [Fp; 3]>,
        right: DriverValue<D, [Fp; 3]>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HS>,
            Encoded<'dr, D, Self::Right, HS>,
            Encoded<'dr, D, Self::Output, HS>,
        ),
        DriverValue<D, [Fp; 3]>,
        DriverValue<D, ()>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::new(dr, allocator, left)?;
        let right = Encoded::new(dr, allocator, right)?;
        let l: &FixedVec<Element<'dr, D>, ConstLen<3>> = left.as_gadget();
        let r: &FixedVec<Element<'dr, D>, ConstLen<3>> = right.as_gadget();

        // The check the Halo 2 fold only does in a comment: left.end == right.start.
        l[1].sub(dr, &r[0]).enforce_zero(dr)?;

        let count = l[2].add(dr, &r[2]);
        let out = FixedVec::new(vec![l[0].clone(), r[1].clone(), count])?;
        let data = header_value::<D>(&out);
        Ok(((left, right, Encoded::from_gadget(out)), data, D::unit()))
    }
}

/// Same Poseidon as the circuit, run natively (what an auditor would do).
fn native_state_hash(params: &'static Poseidon, liabilities: u64, nf_root: Fp) -> Result<Fp> {
    let dr = &mut Emulator::execute();
    let l = Element::constant(dr, Fp::from(liabilities));
    let n = Element::constant(dr, nf_root);
    let h = state_hash(dr, params, &l, &n)?;
    Ok(*h.value().take())
}

fn seed(app: &App, rng: &mut StdRng, poseidon: &'static Poseidon, mint: bool, w: StepWitness) -> Result<TransitionPcd> {
    Ok(if mint {
        app.seed(rng, MintStep { poseidon }, w)?.0
    } else {
        app.seed(rng, MeltStep { poseidon }, w)?.0
    })
}

fn fold_tree(app: &App, rng: &mut StdRng, mut layer: Vec<TransitionPcd>) -> Result<TransitionPcd> {
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut it = layer.into_iter();
        while let Some(l) = it.next() {
            match it.next() {
                Some(r) => next.push(app.fuse(rng, FoldStep, (), l, r)?.0),
                None => next.push(l),
            }
        }
        layer = next;
    }
    Ok(layer.pop().expect("non-empty"))
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn main() -> Result<()> {
    let batch: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(16);
    let mut rng = StdRng::seed_from_u64(0x7a_5a_5b_00);

    let t = Instant::now();
    let pasta = ragu::pcd::pasta::baked_aggregator();
    let poseidon: &'static Poseidon = Pasta::circuit_poseidon(pasta);
    let app: App = ApplicationBuilder::<Pasta, Rank, HEADER_SIZE>::new()
        .register(MintStep { poseidon })?
        .register(MeltStep { poseidon })?
        .register(FoldStep)?
        .finalize(pasta)?;
    println!("app build (one-time)        {:>9.0} ms", ms(t));

    // A chain of `batch` transitions: mostly mints, every 4th a melt.
    let nf_root = Fp::from(0xACC0_u64);
    let mut liabilities = 0u64;
    let mut witnesses = Vec::with_capacity(batch);
    for i in 0..batch {
        let mint = i % 4 != 3;
        let amount = if mint { 1_000 + i as u64 } else { 500 };
        witnesses.push((mint, StepWitness { prev_liabilities: liabilities, amount, nf_root }));
        liabilities = if mint { liabilities + amount } else { liabilities - amount };
    }

    let t = Instant::now();
    let mut leaves = Vec::with_capacity(batch);
    for (mint, w) in &witnesses {
        leaves.push(seed(&app, &mut rng, poseidon, *mint, *w)?);
    }
    let seed_ms = ms(t);
    println!("step proving ({batch:>3} steps)    {:>9.0} ms  ({:.0} ms/step)", seed_ms, seed_ms / batch as f64);

    // Kept aside for the negative tests below.
    let (leaf0, leaf2) = (leaves[0].clone(), leaves.get(2).cloned());

    let t = Instant::now();
    let root = fold_tree(&app, &mut rng, leaves)?;
    let fold_ms = ms(t);
    let fuses = batch.saturating_sub(1).max(1);
    println!("tree fold ({:>3} fuses)        {:>9.0} ms  ({:.0} ms/fuse)", batch.saturating_sub(1), fold_ms, fold_ms / fuses as f64);

    let t = Instant::now();
    let compressed = app.compress(&root, &mut rng)?;
    println!("compress root               {:>9.0} ms", ms(t));

    let t = Instant::now();
    let ok = app.verify_compressed(&compressed)?;
    println!("verify compressed           {:>9.1} ms  -> {ok}", ms(t));
    assert!(ok, "root proof must verify");

    let bytes = compressed.proof().to_bytes().expect("encodable");
    let unc = root.proof().to_bytes().expect("encodable");
    println!("compressed proof size       {:>9} bytes ({} base64)", bytes.len(), bytes.len().div_ceil(3) * 4);
    println!("uncompressed (foldable)     {:>9} bytes", unc.len());

    // Auditor-side check: the header must match natively recomputed states.
    let [start, end, count] = *compressed.data();
    assert_eq!(start, native_state_hash(poseidon, 0, nf_root)?, "genesis state");
    assert_eq!(end, native_state_hash(poseidon, liabilities, nf_root)?, "end state");
    assert_eq!(count, Fp::from(batch as u64), "step count");
    println!("header binds genesis -> liabilities={liabilities} over {batch} steps: OK");

    // --- Negative tests -----------------------------------------------------
    println!("\nnegative tests");

    // 1. Non-contiguous fold: leaf0 (state 0->1) with leaf2 (state 2->3).
    if let Some(leaf2) = leaf2 {
        let verdict = match app.fuse(&mut rng, FoldStep, (), leaf0.clone(), leaf2) {
            Err(e) => format!("rejected at fuse ({e})"),
            Ok((bad, ())) => match app.compress(&bad, &mut rng).and_then(|c| app.verify_compressed(&c)) {
                Err(e) => format!("rejected at compress/verify ({e})"),
                Ok(false) => "rejected by verifier".into(),
                Ok(true) => "ACCEPTED (soundness bug in spike!)".into(),
            },
        };
        println!("  non-contiguous fold       {verdict}");
        assert!(!verdict.starts_with("ACCEPTED"));
    }

    // 2. Lying about the header: valid proof, forged end state.
    let (proof, mut data) = compressed.clone().into_parts();
    data[1] = native_state_hash(poseidon, liabilities - 1, nf_root)?;
    let forged = app.verify_compressed(&proof.carry::<Transition>(data))?;
    println!("  forged end liabilities    {}", if forged { "ACCEPTED (bug!)" } else { "rejected by verifier" });
    assert!(!forged);

    // 3. Melt more than the liabilities (underflow).
    let w = StepWitness { prev_liabilities: 10, amount: 11, nf_root };
    let verdict = match app.seed(&mut rng, MeltStep { poseidon }, w) {
        Err(e) => format!("rejected at seed ({e})"),
        Ok((bad, ())) => match app.compress(&bad, &mut rng).and_then(|c| app.verify_compressed(&c)) {
            Err(e) => format!("rejected at compress/verify ({e})"),
            Ok(false) => "rejected by verifier".into(),
            Ok(true) => "ACCEPTED (soundness bug in spike!)".into(),
        },
    };
    println!("  melt below zero           {verdict}");
    assert!(!verdict.starts_with("ACCEPTED"));

    Ok(())
}
