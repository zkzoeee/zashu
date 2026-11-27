//! The transaction statement.
//!
//! Public: `[anchor, epoch, balance, nf_1, nf_2, cm_1, cm_2]`.
//!
//! A transaction has exactly two outputs and either two inputs or none (a
//! shielded mint, whose nullifiers are zero). Unused slots hold zero-value
//! dummy notes, so the shape does not reveal how many real notes moved.

use super::note::{check_predicate, Auth, Note};
use super::tree::{root_from, Path};
use super::{fail, Fp, Result, TX_SLOTS};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spend {
    pub note: Note,
    pub index: u64,
    pub path: Path,
    pub auth: Auth,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxWitness {
    pub anchor: Fp,
    pub epoch: u64,
    /// `None` for a shielded mint.
    pub inputs: Option<[Spend; TX_SLOTS]>,
    pub outputs: [Note; TX_SLOTS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxStatement {
    pub anchor: Fp,
    pub epoch: u64,
    /// `sum(inputs) - sum(outputs)` in the field.
    pub balance: Fp,
    pub nullifiers: [Fp; TX_SLOTS],
    pub commitments: [Fp; TX_SLOTS],
}

impl TxStatement {
    pub fn public_inputs(&self) -> [Fp; 7] {
        [
            self.anchor,
            Fp::from(self.epoch),
            self.balance,
            self.nullifiers[0],
            self.nullifiers[1],
            self.commitments[0],
            self.commitments[1],
        ]
    }
}

/// The statement a witness claims, computed without checking the relation.
pub fn statement(w: &TxWitness) -> TxStatement {
    let mut balance = Fp::from(0);
    let mut nullifiers = [Fp::from(0); TX_SLOTS];
    if let Some(inputs) = &w.inputs {
        for (slot, spend) in inputs.iter().enumerate() {
            balance += Fp::from(spend.note.value);
            nullifiers[slot] = spend.note.nullifier();
        }
    }
    for note in &w.outputs {
        balance -= Fp::from(note.value);
    }
    TxStatement {
        // A mint spends nothing, so it has no anchor.
        anchor: if w.inputs.is_some() { w.anchor } else { Fp::from(0) },
        epoch: w.epoch,
        balance,
        nullifiers,
        commitments: [w.outputs[0].commitment(), w.outputs[1].commitment()],
    }
}

/// The transaction relation. Returns the statement the witness proves.
pub fn check(w: &TxWitness) -> Result<TxStatement> {
    if let Some(inputs) = &w.inputs {
        for spend in inputs {
            // A zero-value input is a dummy and need not be in the tree.
            let in_tree = root_from(spend.note.commitment(), spend.index, &spend.path) == w.anchor;
            if spend.note.value != 0 && !in_tree {
                return fail("input note is not under the anchor");
            }
            check_predicate(&spend.note, &spend.auth, w.epoch)?;
        }
    }
    Ok(statement(w))
}
