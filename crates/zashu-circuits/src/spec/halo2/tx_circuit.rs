//! The transaction circuit.
//!
//! Public: `[anchor, epoch, balance, nf_1, nf_2, cm_1, cm_2]`.
//!
//! One circuit covers every transaction: two outputs, two inputs switched by
//! a private `has_inputs` bit, and one predicate sub-circuit per input whose
//! branch is chosen by private flags.

use std::sync::atomic::{AtomicUsize, Ordering};

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use zashu_core::spec::hash::{T_HASHLOCK, T_HTLC, T_KEY, T_MULTISIG, T_NF, T_NOTE, T_PK, T_TIMELOCK};
use zashu_core::spec::note::{Auth, Key, Note, MULTISIG_KEYS, MULTISIG_SIGNERS};
use zashu_core::spec::tx::{Spend, TxWitness};
use zashu_core::spec::DEPTH;

use super::gadgets::{fe, fresh, index_bits, Cell, Ctx, Rows, SpecConfig};
use crate::error::{CircuitError, Result};

/// The private inputs of one spend, as the circuit lays them out.
#[derive(Clone, Debug)]
pub(super) struct SpendAssign {
    /// `value, owner, predicate, params, rho, r`.
    note: [Fp; 6],
    siblings: [Fp; DEPTH],
    index_bits: [Fp; DEPTH],
    /// Which predicate the authorisation is for: key, timelock, HTLC, multisig.
    flags: [bool; 4],
    /// HTLC: claim (with the preimage) rather than refund.
    claim: bool,
    /// Up to three `(spend_sk, tweak)`. Slot 0 is the spender of a key,
    /// timelock or HTLC note; a multisig uses one slot per signer.
    keys: [[Fp; 2]; MULTISIG_SIGNERS],
    /// The lock epoch of a timelock, or the expiry of an HTLC.
    time: Fp,
    preimage: Fp,
    /// HTLC fields the spender does not open: the hashlock and receiver of a
    /// refund, the refund key of a claim.
    hashlock: Fp,
    receiver: Fp,
    refund: Fp,
    /// Multisig: which signer slots are used.
    active: [bool; MULTISIG_SIGNERS],
    /// `key_count - 1`, as two bits.
    count_bits: [bool; 2],
    /// `key_count - signers`, as two bits.
    spare_bits: [bool; 2],
    committed: [Fp; MULTISIG_KEYS],
    /// The committed slot each signer opens, one-hot.
    slots: [[bool; MULTISIG_KEYS]; MULTISIG_SIGNERS],
    /// `key_count - 1 - slot`, as two bits.
    below_bits: [[bool; 2]; MULTISIG_SIGNERS],
    /// `slot - previous slot - 1`, as two bits.
    gap_bits: [[bool; 2]; MULTISIG_SIGNERS],
}

#[derive(Clone, Debug)]
pub(super) struct TxAssign {
    has_inputs: bool,
    anchor: Fp,
    epoch: Fp,
    inputs: [SpendAssign; 2],
    outputs: [[Fp; 6]; 2],
}

fn note_fields(note: &Note) -> [Fp; 6] {
    [fe(note.value), note.owner, fe(note.predicate), note.params, note.rho, note.r]
}

fn two_bits(v: i64) -> [bool; 2] {
    [v & 1 == 1, v & 2 == 2]
}

fn spend_assign(spend: &Spend) -> Result<SpendAssign> {
    let mut a = SpendAssign {
        note: note_fields(&spend.note),
        siblings: spend.path,
        index_bits: index_bits(spend.index),
        flags: [false; 4],
        claim: false,
        keys: [[Fp::ZERO; 2]; MULTISIG_SIGNERS],
        time: Fp::ZERO,
        preimage: Fp::ZERO,
        hashlock: Fp::ZERO,
        receiver: Fp::ZERO,
        refund: Fp::ZERO,
        // What satisfies the multisig wiring when it is not used: one signer
        // in slot 0 of one key.
        active: [true, false, false],
        count_bits: [false; 2],
        spare_bits: [false; 2],
        committed: [Fp::ZERO; MULTISIG_KEYS],
        slots: [[true, false, false, false]; MULTISIG_SIGNERS],
        below_bits: [[false; 2]; MULTISIG_SIGNERS],
        gap_bits: [[false; 2]; MULTISIG_SIGNERS],
    };
    let pair = |key: &Key| [key.spend_sk, key.tweak];
    match &spend.auth {
        Auth::Key(key) => {
            a.flags[0] = true;
            a.keys[0] = pair(key);
        }
        Auth::Timelock { key, lock_epoch } => {
            a.flags[1] = true;
            a.keys[0] = pair(key);
            a.time = fe(*lock_epoch);
        }
        Auth::HtlcClaim { key, preimage, refund, expiry_epoch } => {
            a.flags[2] = true;
            a.claim = true;
            a.keys[0] = pair(key);
            a.preimage = *preimage;
            a.refund = *refund;
            a.time = fe(*expiry_epoch);
        }
        Auth::HtlcRefund { key, hashlock, receiver, expiry_epoch } => {
            a.flags[2] = true;
            a.keys[0] = pair(key);
            a.hashlock = *hashlock;
            a.receiver = *receiver;
            a.time = fe(*expiry_epoch);
        }
        // The threshold is not a witness: the circuit hashes the number of
        // signers in its place, so the two must agree.
        Auth::Multisig { threshold: _, key_count, keys, signers } => {
            if signers.len() > MULTISIG_SIGNERS {
                return Err(CircuitError::InvalidWitness("more multisig signers than the circuit has slots".into()));
            }
            a.flags[3] = true;
            a.committed = *keys;
            // Everything below is a hint. Values out of range give bits that
            // do not add up, and the constraints reject them.
            let count = 1 + (key_count.wrapping_sub(1) & 3) as i64;
            a.count_bits = two_bits(count - 1);
            a.spare_bits = two_bits(count - signers.len() as i64);
            let mut previous = 0i64;
            for j in 0..MULTISIG_SIGNERS {
                a.active[j] = j < signers.len();
                let Some(signer) = signers.get(j) else { continue };
                a.keys[j] = pair(&signer.key);
                a.slots[j] = core::array::from_fn(|slot| slot == signer.slot);
                let slot = if signer.slot < MULTISIG_KEYS { signer.slot as i64 } else { 0 };
                a.below_bits[j] = two_bits(count - 1 - slot);
                a.gap_bits[j] = two_bits(slot - previous - 1);
                previous = slot;
            }
        }
    }
    Ok(a)
}

impl TxAssign {
    pub fn new(w: &TxWitness) -> Result<Self> {
        let inputs = match &w.inputs {
            Some(inputs) => [spend_assign(&inputs[0])?, spend_assign(&inputs[1])?],
            // A mint has no inputs. Its two slots hold a fixed zero-value
            // note that satisfies the input checks; `has_inputs = 0` keeps
            // it out of the statement.
            None => {
                let key = Key { spend_sk: Fp::ZERO, tweak: Fp::ZERO };
                let spend = Spend {
                    note: Note::dummy(Fp::ZERO, Fp::ZERO, &key),
                    index: 0,
                    path: [Fp::ZERO; DEPTH],
                    auth: Auth::Key(key),
                };
                let assign = spend_assign(&spend)?;
                [assign.clone(), assign]
            }
        };
        Ok(TxAssign {
            has_inputs: w.inputs.is_some(),
            anchor: if w.inputs.is_some() { w.anchor } else { Fp::ZERO },
            epoch: fe(w.epoch),
            inputs,
            outputs: [note_fields(&w.outputs[0]), note_fields(&w.outputs[1])],
        })
    }
}

/// The transaction circuit over `CHIPS` Poseidon chips.
#[derive(Clone, Debug)]
pub struct TxCircuit<const CHIPS: usize> {
    pub(super) w: Value<TxAssign>,
}

impl<const CHIPS: usize> Default for TxCircuit<CHIPS> {
    fn default() -> Self {
        TxCircuit { w: Value::unknown() }
    }
}

static ROWS: [AtomicUsize; 3] = [AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)];

/// Rows used by the last synthesis of the transaction circuit.
pub(super) fn rows() -> Rows {
    Rows {
        poseidon: ROWS[0].load(Ordering::Relaxed),
        range: ROWS[1].load(Ordering::Relaxed),
        arithmetic: ROWS[2].load(Ordering::Relaxed),
    }
}

impl<const CHIPS: usize> Circuit<Fp> for TxCircuit<CHIPS> {
    type Config = SpecConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> SpecConfig {
        SpecConfig::configure(meta, CHIPS)
    }

    fn synthesize(&self, cfg: SpecConfig, layouter: impl Layouter<Fp>) -> core::result::Result<(), Error> {
        let mut cx = Ctx::new(&cfg, layouter);
        let w = self.w.as_ref();

        let anchor = cx.witness(w.map(|w| w.anchor))?;
        let epoch = cx.witness(w.map(|w| w.epoch))?;
        // A verifier builds the public epoch from a `u64`; the comparisons
        // below rely on that, so it is enforced here as well.
        cx.range(&epoch, 16)?;
        let has_inputs = cx.bit(w.map(|w| w.has_inputs))?;
        // A mint has no anchor: anchor - has_inputs * anchor = 0.
        cx.implies(&anchor, &has_inputs)?;

        let mut commitments = Vec::new();
        let mut out_values = Vec::new();
        for j in 0..2 {
            let note = cx.witnesses(w.map(|w| w.outputs[j]))?;
            cx.range(&note[0], 16)?;
            commitments.push(cx.sponge(T_NOTE, &note)?);
            out_values.push(note[0].clone());
        }

        let mut nullifiers = Vec::new();
        let mut in_values = Vec::new();
        for i in 0..2 {
            let s = w.map(|w| &w.inputs[i]);
            let note = cx.witnesses(s.map(|s| s.note))?;
            cx.range(&note[0], 16)?;
            let cm = cx.sponge(T_NOTE, &note)?;
            let nf = cx.sponge(T_NF, &note[4..6])?;

            // In the tree under the anchor, or a zero-value dummy.
            let (root, _, _) =
                cx.merkle_root(&cm, &fresh(s.map(|s| s.siblings)), &fresh(s.map(|s| s.index_bits)))?;
            cx.cond_eq(&note[0], &root, &anchor)?;

            predicate(&mut cx, s, &note, &epoch)?;

            // A mint publishes no nullifiers and its inputs carry no value.
            nullifiers.push(cx.mul(&has_inputs, &nf)?);
            in_values.push(cx.mul(&has_inputs, &note[0])?);
        }

        let value_in = cx.add(&in_values[0], &in_values[1])?;
        let value_out = cx.add(&out_values[0], &out_values[1])?;
        let balance = cx.sub(&value_in, &value_out)?;

        let public = [&anchor, &epoch, &balance, &nullifiers[0], &nullifiers[1], &commitments[0], &commitments[1]];
        for (row, cell) in public.into_iter().enumerate() {
            cx.expose(cell, row)?;
        }

        let rows = cx.rows();
        ROWS[0].store(rows.poseidon, Ordering::Relaxed);
        ROWS[1].store(rows.range, Ordering::Relaxed);
        ROWS[2].store(rows.arithmetic, Ordering::Relaxed);
        Ok(())
    }
}

/// The predicate relation of `zashu_core::spec::note::check_predicate`, with
/// the branch chosen by the private flags.
fn predicate<L: Layouter<Fp>>(
    cx: &mut Ctx<'_, L>,
    s: Value<&SpendAssign>,
    note: &[Cell],
    epoch: &Cell,
) -> core::result::Result<(), Error> {
    let (owner, id, params) = (&note[1], &note[2], &note[3]);
    let one = Fp::ONE;

    // Exactly one flag, and it is the note's predicate id.
    let flags = cx.bits(s.map(|s| s.flags))?;
    let (is_timelock, is_htlc, is_multisig) = (&flags[1], &flags[2], &flags[3]);
    let key_or_timelock = cx.add(&flags[0], is_timelock)?;
    let htlc_or_multisig = cx.add(is_htlc, is_multisig)?;
    cx.sum_is(&key_or_timelock, &htlc_or_multisig, one)?;
    let low_ids = cx.lin(is_timelock, one, is_htlc, fe(2))?;
    cx.lin_is(&low_ids, one, is_multisig, fe(3), id)?;

    // Three key images, each from a secret key the spender holds.
    let mut images = Vec::new();
    for j in 0..MULTISIG_SIGNERS {
        let key = cx.witnesses(s.map(|s| s.keys[j]))?;
        let public = cx.sponge(T_PK, &key[..1])?;
        images.push(cx.sponge(T_KEY, &[public, key[1].clone()])?);
    }

    // The lock or expiry epoch, and whether the transaction is before it.
    let time = cx.witness(s.map(|s| s.time))?;
    cx.range(&time, 16)?;
    let early = cx.lt(epoch, &time, 16)?;

    // Key and timelock: the key opens the owner.
    cx.cond_eq(&key_or_timelock, &images[0], owner)?;

    // Timelock: params commit to the lock, which has passed.
    let timelock_params = cx.sponge(T_TIMELOCK, &[time.clone()])?;
    cx.zero_product(is_timelock, &early)?;

    // HTLC. A claim opens the hashlock and the receiver, before expiry; a
    // refund opens the refund key, from expiry on.
    let claim = cx.bit(s.map(|s| s.claim))?;
    let preimage = cx.witness(s.map(|s| s.preimage))?;
    let opened_hashlock = cx.sponge(T_HASHLOCK, &[preimage])?;
    let given = cx.witnesses(s.map(|s| [s.hashlock, s.receiver, s.refund]))?;
    let hashlock = cx.select(&claim, &opened_hashlock, &given[0])?;
    let receiver = cx.select(&claim, &images[0], &given[1])?;
    let refund = cx.select(&claim, &given[2], &images[0])?;
    let htlc_params = cx.sponge(T_HTLC, &[hashlock, receiver, refund, time.clone()])?;
    // claim <=> early
    let mistimed = cx.sub(&claim, &early)?;
    cx.zero_product(is_htlc, &mistimed)?;

    // Multisig. The threshold is the number of signers: 1 to 3, used in order.
    let active = cx.bits(s.map(|s| s.active))?;
    cx.is_one(&active[0])?;
    cx.implies(&active[2], &active[1])?;
    let first_two = cx.add(&active[0], &active[1])?;
    let threshold = cx.add(&first_two, &active[2])?;
    // key_count = 1 + two bits, so it is 1 to 4, and it is threshold + two
    // bits, so it is at least the threshold.
    let count_bits = cx.bits(s.map(|s| s.count_bits))?;
    let count_less_one = cx.two_bits(&count_bits)?;
    let one_cell = cx.constant(one)?;
    let key_count = cx.add(&count_less_one, &one_cell)?;
    let spare_bits = cx.bits(s.map(|s| s.spare_bits))?;
    let spare = cx.two_bits(&spare_bits)?;
    cx.lin_is(&threshold, one, &spare, one, &key_count)?;

    let committed = cx.witnesses(s.map(|s| s.committed))?;
    let mut inputs = vec![threshold, key_count.clone()];
    inputs.extend(committed.iter().cloned());
    let multisig_params = cx.sponge(T_MULTISIG, &inputs)?;

    let mut previous: Option<Cell> = None;
    for j in 0..MULTISIG_SIGNERS {
        // The slot this signer opens: one-hot, so 0 to 3.
        let hot = cx.bits(s.map(|s| s.slots[j]))?;
        let low = cx.add(&hot[0], &hot[1])?;
        let high = cx.add(&hot[2], &hot[3])?;
        cx.sum_is(&low, &high, one)?;
        let low = cx.lin(&hot[1], one, &hot[2], fe(2))?;
        let slot = cx.lin(&low, one, &hot[3], fe(3))?;

        // The signer's key image is the committed key in that slot.
        let mut chosen = cx.mul(&hot[0], &committed[0])?;
        for i in 1..MULTISIG_KEYS {
            let term = cx.mul(&hot[i], &committed[i])?;
            chosen = cx.add(&chosen, &term)?;
        }
        let signing = cx.mul(is_multisig, &active[j])?;
        cx.cond_eq(&signing, &images[j], &chosen)?;

        // slot < key_count: key_count - 1 - slot is two bits.
        let below_bits = cx.bits(s.map(|s| s.below_bits[j]))?;
        let below = cx.two_bits(&below_bits)?;
        let room = cx.gate(&key_count, &slot, None, [one, -one, Fp::ZERO, -one, -one])?;
        cx.cond_eq(&active[j], &room, &below)?;

        // Slots strictly increase: slot - previous - 1 is two bits.
        if let Some(previous) = &previous {
            let gap_bits = cx.bits(s.map(|s| s.gap_bits[j]))?;
            let gap = cx.two_bits(&gap_bits)?;
            let step = cx.gate(&slot, previous, None, [one, -one, Fp::ZERO, -one, -one])?;
            cx.cond_eq(&active[j], &step, &gap)?;
        }
        previous = Some(slot);
    }

    // The note's params are those of the chosen predicate; zero for a key.
    let t = cx.mul(is_timelock, &timelock_params)?;
    let h = cx.mul(is_htlc, &htlc_params)?;
    let m = cx.mul(is_multisig, &multisig_params)?;
    let th = cx.add(&t, &h)?;
    cx.lin_is(&th, one, &m, one, params)?;
    Ok(())
}
