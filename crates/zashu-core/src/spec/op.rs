//! The operation statement and the chain of operations.
//!
//! Public: `[state_before, state_after, liabilities_before, liabilities_after]`.
//!
//! One operation is a mint, a swap or a melt. It moves the epoch,
//! liabilities and event log by the rule of its kind, then applies up to two
//! sorted nullifier inserts and up to two note appends, in that order.

use super::hash::{h, T_MELT, T_MINT, T_STATE};
use super::tree::{NfInsert, NoteAppend};
use super::{fail, Fp, Result, OP_SLOTS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub epoch: u64,
    pub liabilities: u64,
    pub nullifier_root: Fp,
    pub note_root: Fp,
    pub event_log: Fp,
}

impl State {
    pub fn hash(&self) -> Fp {
        h(
            T_STATE,
            &[
                Fp::from(self.epoch),
                Fp::from(self.liabilities),
                self.nullifier_root,
                self.note_root,
                self.event_log,
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Liabilities rise by `amount > 0`; the log absorbs `(quote, amount)`.
    Mint,
    /// Liabilities and the log stay put.
    Swap,
    /// Liabilities fall by `amount > 0`; the log absorbs `(payout, amount)`.
    Melt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpWitness {
    pub kind: Kind,
    pub before: State,
    pub epoch_after: u64,
    pub amount: u64,
    /// The quote (mint) or payout (melt) hash; unused for a swap.
    pub event: Fp,
    pub nullifiers: [Option<NfInsert>; OP_SLOTS],
    pub notes: [Option<NoteAppend>; OP_SLOTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpStatement {
    pub before: Fp,
    pub after: Fp,
    pub liabilities_before: u64,
    pub liabilities_after: u64,
}

impl OpStatement {
    pub fn public_inputs(&self) -> [Fp; 4] {
        [self.before, self.after, Fp::from(self.liabilities_before), Fp::from(self.liabilities_after)]
    }
}

/// The operation relation. Returns the state after it and its statement.
pub fn check(w: &OpWitness) -> Result<(State, OpStatement)> {
    let mut next = w.before;
    if w.epoch_after < w.before.epoch {
        return fail("epoch went backwards");
    }
    next.epoch = w.epoch_after;
    match w.kind {
        Kind::Swap => {}
        Kind::Mint | Kind::Melt => {
            if w.amount == 0 {
                return fail("mint or melt of zero");
            }
            let (liabilities, tag) = match w.kind {
                Kind::Mint => (w.before.liabilities.checked_add(w.amount), T_MINT),
                _ => (w.before.liabilities.checked_sub(w.amount), T_MELT),
            };
            match liabilities {
                Some(l) => next.liabilities = l,
                None => return fail("liabilities out of range"),
            }
            next.event_log = h(tag, &[w.before.event_log, w.event, Fp::from(w.amount)]);
        }
    }
    for insert in w.nullifiers.iter().flatten() {
        next.nullifier_root = insert.apply(next.nullifier_root)?;
    }
    for append in w.notes.iter().flatten() {
        next.note_root = append.apply(next.note_root)?;
    }
    let statement = OpStatement {
        before: w.before.hash(),
        after: next.hash(),
        liabilities_before: w.before.liabilities,
        liabilities_after: next.liabilities,
    };
    Ok((next, statement))
}

/// The statement a witness claims, computed without checking the relation:
/// what a forger would ask a verifier to accept.
pub fn claimed(w: &OpWitness) -> (State, OpStatement) {
    let mut next = w.before;
    next.epoch = w.epoch_after;
    let tag = match w.kind {
        Kind::Swap => None,
        Kind::Mint => {
            next.liabilities = w.before.liabilities.wrapping_add(w.amount);
            Some(T_MINT)
        }
        Kind::Melt => {
            next.liabilities = w.before.liabilities.wrapping_sub(w.amount);
            Some(T_MELT)
        }
    };
    if let Some(tag) = tag {
        next.event_log = h(tag, &[w.before.event_log, w.event, Fp::from(w.amount)]);
    }
    if let Some(insert) = w.nullifiers.iter().flatten().last() {
        next.nullifier_root = insert.claimed_root();
    }
    if let Some(append) = w.notes.iter().flatten().last() {
        next.note_root = append.claimed_root();
    }
    let statement = OpStatement {
        before: w.before.hash(),
        after: next.hash(),
        liabilities_before: w.before.liabilities,
        liabilities_after: next.liabilities,
    };
    (next, statement)
}

/// A run of operations from `start` to `end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainStatement {
    pub start: Fp,
    pub end: Fp,
    pub liabilities_start: u64,
    pub liabilities_end: u64,
    pub count: u64,
}

/// The chain relation: every operation holds and starts where the last ended.
pub fn check_chain(ops: &[OpWitness]) -> Result<ChainStatement> {
    let first = match ops.first() {
        Some(op) => op.before,
        None => return fail("empty chain"),
    };
    let mut state = first;
    for op in ops {
        if op.before != state {
            return fail("operation does not start where the previous one ended");
        }
        state = check(op)?.0;
    }
    Ok(ChainStatement {
        start: first.hash(),
        end: state.hash(),
        liabilities_start: first.liabilities,
        liabilities_end: state.liabilities,
        count: ops.len() as u64,
    })
}
