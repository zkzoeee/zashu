//! The Ragu backend for the `NUTZ-0` statements.
//!
//! One application holds every step. A transaction is a small tree of steps
//! (see [`tx`]), an operation a short chain of them (see [`op`]), and a chain
//! of operations is one recursive proof. Every published proof is a
//! compressed proof of 6,208 bytes.

use std::sync::OnceLock;

use ragu::circuits::polynomials::R;
use ragu::header::Header;
use ragu::pasta::{Fp, Pasta};
use ragu::{Application, ApplicationBuilder, CompressedProof, Pcd};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zashu_core::spec::hash::{h, T_MELT, T_MINT};
use zashu_core::spec::note::{Auth, Key, Note};
use zashu_core::spec::op::{ChainStatement, Kind, OpStatement, OpWitness, State};
use zashu_core::spec::tree::{IndexedLeaf, NfInsert, Path};
use zashu_core::spec::tx::{Spend, TxStatement, TxWitness};
use zashu_core::spec::{Fp as SpecFp, DEPTH};

use super::Backend;
use crate::error::{CircuitError, Result};

mod gadgets;
mod op;
mod tx;

use gadgets::fp;

type Rank = R<14>;
const HEADER_SIZE: usize = 8;
type App = Application<'static, Pasta, Rank, HEADER_SIZE>;
type Proof<H> = Pcd<Pasta, Rank, H>;

fn err(context: &str, e: impl core::fmt::Display) -> CircuitError {
    CircuitError::Plonk(format!("ragu {context}: {e}"))
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn build() -> ragu::Result<App> {
    ApplicationBuilder::<Pasta, Rank, HEADER_SIZE>::new()
        // Transaction: indices 0..=8
        .register(tx::PathStart)?
        .register(tx::PathExtend)?
        .register(tx::SpendKey)?
        .register(tx::SpendTimelock)?
        .register(tx::SpendHtlcClaim)?
        .register(tx::SpendHtlcRefund)?
        .register(tx::SpendMultisig)?
        .register(tx::Close)?
        .register(tx::MintClose)?
        // Operation and chain: indices 9..=19
        .register(op::ValueMint)?
        .register(op::ValueSwap)?
        .register(op::ValueMelt)?
        .register(op::FoldStep)?
        .register(op::UpdStart)?
        .register(op::UpdExtend)?
        .register(op::PairStart)?
        .register(op::PairJoin)?
        .register(op::NoteInsert)?
        .register(op::NfLow)?
        .register(op::NfInsert)?
        .finalize(ragu::pcd::pasta::baked())
}

fn app() -> Result<&'static App> {
    static APP: OnceLock<std::result::Result<App, String>> = OnceLock::new();
    APP.get_or_init(|| build().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| CircuitError::Plonk(format!("ragu application build: {e}")))
}

fn unit(app: &App) -> Proof<()> {
    app.bootstrap_proof().clone().carry::<()>(())
}

fn compress<H: Header<Fp>>(app: &App, pcd: &Proof<H>) -> Result<Vec<u8>> {
    let compressed = app.compress(pcd, &mut rng()).map_err(|e| err("compress", e))?;
    let (proof, _) = compressed.into_parts();
    proof.to_bytes().map_err(|e| err("encode", format!("{e:?}")))
}

fn verify<H: Header<Fp>>(bytes: &[u8], data: H::Data) -> Result<()> {
    let fail = |msg: String| CircuitError::VerificationFailed(format!("ragu: {msg}"));
    if bytes.len() != CompressedProof::<Pasta>::encoded_len::<Rank>() {
        return Err(fail("unexpected proof length".into()));
    }
    let compressed = CompressedProof::<Pasta>::from_bytes(bytes).map_err(|e| fail(format!("decode: {e:?}")))?;
    match app()?.verify_compressed(&compressed.carry::<H>(data)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(fail("proof rejected".into())),
        Err(e) => Err(fail(e.to_string())),
    }
}

// --------------------------------------------------------------------------
// Transactions
// --------------------------------------------------------------------------

fn note_w(note: &Note) -> tx::NoteW {
    tx::NoteW {
        value: note.value,
        owner: fp(&note.owner),
        predicate: note.predicate,
        params: fp(&note.params),
        rho: fp(&note.rho),
        r: fp(&note.r),
    }
}

fn key_w(key: &Key) -> tx::KeyW {
    tx::KeyW { spend_sk: fp(&key.spend_sk), tweak: fp(&key.tweak) }
}

fn climb_w<const N: usize>(path: &Path, index: u64, from: usize) -> tx::Climb<N> {
    tx::Climb {
        siblings: core::array::from_fn(|j| fp(&path[from + j])),
        bits: core::array::from_fn(|j| (index >> (from + j)) & 1 == 1),
    }
}

fn multisig_w(threshold: u64, key_count: u64, keys: &[SpecFp; tx::KEYS], signers: &[zashu_core::spec::note::Signer]) -> tx::MultisigW {
    let unused = tx::KeyW { spend_sk: Fp::from(0u64), tweak: Fp::from(0u64) };
    let mut w = tx::MultisigW {
        threshold,
        key_count,
        keys: core::array::from_fn(|j| fp(&keys[j])),
        signers: [unused; tx::SIGNERS],
        slots: [[false; tx::KEYS]; tx::SIGNERS],
        active: [false; tx::SIGNERS],
    };
    for (i, signer) in signers.iter().take(tx::SIGNERS).enumerate() {
        w.signers[i] = key_w(&signer.key);
        w.active[i] = true;
        if signer.slot < tx::KEYS {
            w.slots[i][signer.slot] = true;
        }
    }
    w
}

fn prove_spend(app: &App, anchor: &SpecFp, epoch: u64, spend: &Spend) -> Result<Proof<tx::Part>> {
    let e = |e| err("spend", e);
    let leaf = fp(&spend.note.commitment());
    let start = app
        .seed(&mut rng(), tx::PathStart, (leaf, climb_w(&spend.path, spend.index, 0)))
        .map_err(|e| err("path", e))?
        .0;
    let tail: tx::Climb<{ tx::TAIL_LEVELS }> = climb_w(&spend.path, spend.index, tx::START_LEVELS);
    let common = tx::SpendW { note: note_w(&spend.note), anchor: fp(anchor), epoch, tail };
    // Only the key spend has room to walk the last levels itself.
    let full = |start| -> Result<Proof<tx::Path>> {
        Ok(app.fuse(&mut rng(), tx::PathExtend, tail, start, unit(app)).map_err(|e| err("path", e))?.0)
    };
    let u = unit(app);
    let r = &mut rng();
    Ok(match &spend.auth {
        Auth::Key(key) => app.fuse(r, tx::SpendKey, (common, key_w(key)), start, u).map_err(e)?.0,
        Auth::Timelock { key, lock_epoch } => {
            let x = tx::TimelockW { key: key_w(key), lock: *lock_epoch };
            app.fuse(r, tx::SpendTimelock, (common, x), full(start)?, u).map_err(e)?.0
        }
        Auth::HtlcClaim { key, preimage, refund, expiry_epoch } => {
            let x = tx::HtlcClaimW {
                key: key_w(key),
                preimage: fp(preimage),
                refund: fp(refund),
                expiry: *expiry_epoch,
            };
            app.fuse(r, tx::SpendHtlcClaim, (common, x), full(start)?, u).map_err(e)?.0
        }
        Auth::HtlcRefund { key, hashlock, receiver, expiry_epoch } => {
            let x = tx::HtlcRefundW {
                key: key_w(key),
                hashlock: fp(hashlock),
                receiver: fp(receiver),
                expiry: *expiry_epoch,
            };
            app.fuse(r, tx::SpendHtlcRefund, (common, x), full(start)?, u).map_err(e)?.0
        }
        Auth::Multisig { threshold, key_count, keys, signers } => {
            let x = multisig_w(*threshold, *key_count, keys, signers);
            app.fuse(r, tx::SpendMultisig, (common, x), full(start)?, u).map_err(e)?.0
        }
    })
}

fn prove_tx(w: &TxWitness) -> Result<Vec<u8>> {
    let app = app()?;
    let outputs = [note_w(&w.outputs[0]), note_w(&w.outputs[1])];
    let tx = match &w.inputs {
        None => app.seed(&mut rng(), tx::MintClose, (w.epoch, outputs)).map_err(|e| err("close", e))?.0,
        Some([first, second]) => {
            // The two inputs are independent until they are closed.
            let (a, b) = rayon::join(
                || prove_spend(app, &w.anchor, w.epoch, first),
                || prove_spend(app, &w.anchor, w.epoch, second),
            );
            app.fuse(&mut rng(), tx::Close, outputs, a?, b?).map_err(|e| err("close", e))?.0
        }
    };
    // A Ragu proof is only hiding once rerandomized.
    let tx = app.rerandomize(tx, &mut rng()).map_err(|e| err("rerandomize", e))?;
    compress(app, &tx)
}

// --------------------------------------------------------------------------
// Operations
// --------------------------------------------------------------------------

type TransitionPcd = Proof<op::Transition>;
type UpdatePcd = Proof<op::Update>;

/// One leaf change: where, from what to what, and the siblings on the way up.
struct Leaf<'a> {
    index: u64,
    old: Fp,
    new: Fp,
    path: &'a Path,
}

impl Leaf<'_> {
    /// Levels `from..until` of this leaf's path, as the first of `N` slots.
    fn levels<const N: usize>(&self, from: usize, until: usize) -> op::Levels<N> {
        let mut out = op::Levels { siblings: [Fp::from(0u64); N], bits: [false; N], active: [false; N] };
        for j in 0..N {
            let level = from + j;
            if level < until.min(DEPTH) {
                out.siblings[j] = fp(&self.path[level]);
                out.bits[j] = (self.index >> level) & 1 == 1;
                out.active[j] = true;
            }
        }
        out
    }
}

/// Climbs `pcd` from level `from` up to (not including) level `until`.
fn climb_to(app: &App, mut pcd: UpdatePcd, leaf: &Leaf<'_>, from: usize, until: usize) -> Result<UpdatePcd> {
    let mut level = from;
    while level < until {
        pcd = app
            .fuse(&mut rng(), op::UpdExtend, leaf.levels(level, until), pcd, unit(app))
            .map_err(|e| err("update", e))?
            .0;
        level += op::UPD_LEVELS;
    }
    Ok(pcd)
}

fn start_single(app: &App, leaf: &Leaf<'_>, until: usize) -> Result<UpdatePcd> {
    let w = op::UpdW { old_leaf: leaf.old, new_leaf: leaf.new, levels: leaf.levels(0, until) };
    let pcd = app.seed(&mut rng(), op::UpdStart, w).map_err(|e| err("update", e))?.0;
    climb_to(app, pcd, leaf, op::UPD_LEVELS, until)
}

/// Two leaves changed, `a` and then `b` to its right filling an empty slot.
/// Their paths are proven separately only up to where they meet.
fn prove_pair(app: &App, a: &Leaf<'_>, b: &Leaf<'_>) -> Result<UpdatePcd> {
    if a.index >= b.index || b.index >> DEPTH != 0 {
        return Err(CircuitError::InvalidWitness("leaf updates cannot be proven as a pair".into()));
    }
    // The level at which the two paths become siblings.
    let meet = (63 - (a.index ^ b.index).leading_zeros()) as usize;
    let (pcd, done) = if meet <= op::START_LIFT {
        let w = op::PairStartW {
            a_old: a.old,
            a_new: a.new,
            b_new: b.new,
            a_levels: a.levels(0, meet),
            b_levels: b.levels(0, meet),
        };
        (app.seed(&mut rng(), op::PairStart, w).map_err(|e| err("pair", e))?.0, meet + 1)
    } else {
        let (left, right) = (start_single(app, a, meet)?, start_single(app, b, meet)?);
        let after: op::Levels<{ op::JOIN_LEVELS }> = a.levels(meet + 1, DEPTH);
        let pcd = app.fuse(&mut rng(), op::PairJoin, after, left, right).map_err(|e| err("pair", e))?.0;
        (pcd, meet + 1 + op::JOIN_LEVELS)
    };
    // Above the meeting point both leaves share `a`'s path.
    climb_to(app, pcd, a, done, DEPTH)
}

fn state_w(s: &State) -> op::StateW {
    op::StateW {
        epoch: s.epoch,
        liabilities: s.liabilities,
        nullifier_root: fp(&s.nullifier_root),
        note_root: fp(&s.note_root),
        event_log: fp(&s.event_log),
    }
}

fn rest_w(s: &State, other_root: &SpecFp) -> op::RestW {
    op::RestW { epoch: s.epoch, liabilities: s.liabilities, other_root: fp(other_root), event_log: fp(&s.event_log) }
}

fn nullifier_insert(app: &App, state: &State, insert: &NfInsert, acc: TransitionPcd) -> Result<TransitionPcd> {
    let low = &insert.low;
    let repointed = IndexedLeaf { value: low.value, next_value: insert.nf, next_index: insert.new_index };
    let appended = IndexedLeaf { value: insert.nf, next_value: low.next_value, next_index: low.next_index };
    let a = Leaf { index: insert.low_index, old: fp(&low.hash()), new: fp(&repointed.hash()), path: &insert.low_path };
    let b = Leaf { index: insert.new_index, old: Fp::from(0u64), new: fp(&appended.hash()), path: &insert.new_path };
    let pair = prove_pair(app, &a, &b)?;
    let w = op::NfLowW {
        value: fp(&low.value),
        next_value: fp(&low.next_value),
        next_index: low.next_index,
        nf: fp(&insert.nf),
        new_index: insert.new_index,
        b_new: b.new,
        delta: Fp::from(b.index - a.index),
    };
    let mid = app.fuse(&mut rng(), op::NfLow, w, pair, unit(app)).map_err(|e| err("nullifier low leaf", e))?.0;
    let rest = rest_w(state, &state.note_root);
    Ok(app.fuse(&mut rng(), op::NfInsert, rest, acc, mid).map_err(|e| err("nullifier insert", e))?.0)
}

/// Proves one operation as a transition, uncompressed.
fn prove_transition(app: &App, w: &OpWitness) -> Result<TransitionPcd> {
    // 1. Value: epoch, liabilities and event log.
    let mut cur = w.before;
    cur.epoch = w.epoch_after;
    let tag = match w.kind {
        Kind::Swap => None,
        Kind::Mint => {
            cur.liabilities = w.before.liabilities.wrapping_add(w.amount);
            Some(T_MINT)
        }
        Kind::Melt => {
            cur.liabilities = w.before.liabilities.wrapping_sub(w.amount);
            Some(T_MELT)
        }
    };
    if let Some(tag) = tag {
        cur.event_log = h(tag, &[w.before.event_log, w.event, SpecFp::from(w.amount)]);
    }
    let value = op::ValueW {
        before: state_w(&w.before),
        epoch_after: cur.epoch,
        liabilities_after: cur.liabilities,
        event: fp(&w.event),
    };
    let seeded = match w.kind {
        Kind::Mint => app.seed(&mut rng(), op::ValueMint, value).map(|p| p.0),
        Kind::Swap => app.seed(&mut rng(), op::ValueSwap, value).map(|p| p.0),
        Kind::Melt => app.seed(&mut rng(), op::ValueMelt, value).map(|p| p.0),
    };
    let mut acc = seeded.map_err(|e| err("value step", e))?;

    // 2. Nullifier inserts, in order.
    for insert in w.nullifiers.iter().flatten() {
        acc = nullifier_insert(app, &cur, insert, acc)?;
        cur.nullifier_root = insert.claimed_root();
    }

    // 3. Note appends: together when they can share a path.
    let appends: Vec<_> = w.notes.iter().flatten().collect();
    let leaf = |i: usize| Leaf { index: appends[i].index, old: Fp::from(0u64), new: fp(&appends[i].cm), path: &appends[i].path };
    let note_insert = |cur: &State, update, b_new, delta, acc| -> Result<TransitionPcd> {
        let w = op::NoteInsertW { rest: rest_w(cur, &cur.nullifier_root), b_new, delta };
        Ok(app.fuse(&mut rng(), op::NoteInsert, w, acc, update).map_err(|e| err("note insert", e))?.0)
    };
    if appends.len() == 2 && appends[0].index < appends[1].index {
        let (a, b) = (leaf(0), leaf(1));
        let update = prove_pair(app, &a, &b)?;
        acc = note_insert(&cur, update, b.new, Fp::from(b.index - a.index), acc)?;
    } else {
        for i in 0..appends.len() {
            let update = start_single(app, &leaf(i), DEPTH)?;
            acc = note_insert(&cur, update, Fp::from(0u64), Fp::from(0u64), acc)?;
            cur.note_root = appends[i].claimed_root();
        }
    }
    Ok(acc)
}

// --------------------------------------------------------------------------
// Backend
// --------------------------------------------------------------------------

pub struct Ragu;

/// The running recursive proof of a chain under construction.
pub struct RaguChain(Option<TransitionPcd>);

impl Backend for Ragu {
    const NAME: &'static str = "ragu";
    type TxProof = Vec<u8>;
    type OpProof = Vec<u8>;
    type Chain = RaguChain;
    type ChainProof = Vec<u8>;

    fn prove_tx(witness: &TxWitness) -> Result<Self::TxProof> {
        prove_tx(witness)
    }

    fn verify_tx(statement: &TxStatement, proof: &Self::TxProof) -> Result<()> {
        verify::<tx::Tx>(proof, statement.public_inputs().map(|v| fp(&v)))
    }

    fn tx_proof_bytes(proof: &Self::TxProof) -> usize {
        proof.len()
    }

    fn prove_op(witness: &OpWitness) -> Result<Self::OpProof> {
        let app = app()?;
        compress(app, &prove_transition(app, witness)?)
    }

    fn verify_op(s: &OpStatement, proof: &Self::OpProof) -> Result<()> {
        let data = [
            fp(&s.before),
            Fp::from(s.liabilities_before),
            fp(&s.after),
            Fp::from(s.liabilities_after),
            Fp::from(1u64),
        ];
        verify::<op::Transition>(proof, data)
    }

    fn op_proof_bytes(proof: &Self::OpProof) -> usize {
        proof.len()
    }

    fn chain_start() -> Self::Chain {
        RaguChain(None)
    }

    fn chain_extend(chain: &mut Self::Chain, witness: &OpWitness) -> Result<()> {
        let app = app()?;
        let next = prove_transition(app, witness)?;
        chain.0 = Some(match chain.0.take() {
            None => next,
            Some(prev) => app.fuse(&mut rng(), op::FoldStep, (), prev, next).map_err(|e| err("fold", e))?.0,
        });
        Ok(())
    }

    fn chain_finish(chain: Self::Chain) -> Result<Self::ChainProof> {
        let root = chain.0.ok_or_else(|| CircuitError::InvalidWitness("empty chain".into()))?;
        compress(app()?, &root)
    }

    fn verify_chain(s: &ChainStatement, proof: &Self::ChainProof) -> Result<()> {
        let data = [
            fp(&s.start),
            Fp::from(s.liabilities_start),
            fp(&s.end),
            Fp::from(s.liabilities_end),
            Fp::from(s.count),
        ];
        verify::<op::Transition>(proof, data)
    }

    fn chain_proof_bytes(proof: &Self::ChainProof) -> usize {
        proof.len()
    }
}
