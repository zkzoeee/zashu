//! The conformance suite: what a backend must accept and reject.
//!
//! Every function panics with the name of the failing vector. Run them from a
//! test per backend.

use zashu_core::spec::op::{self, ChainStatement, OpStatement};
use zashu_core::spec::tx::{self, TxStatement};
use zashu_core::spec::vectors::{fe, forged_ops, valid_chain, OpWorld, TxFixture};
use zashu_core::spec::Fp;

use super::Backend;

fn tampered_tx(s: &TxStatement) -> Vec<(&'static str, TxStatement)> {
    let one = fe(1);
    let mut out = Vec::new();
    let mut push = |name, f: &dyn Fn(&mut TxStatement)| {
        let mut t = *s;
        f(&mut t);
        out.push((name, t));
    };
    push("anchor", &|t| t.anchor += one);
    push("epoch", &|t| t.epoch += 1);
    push("balance", &|t| t.balance += one);
    push("first nullifier", &|t| t.nullifiers[0] += one);
    push("second nullifier", &|t| t.nullifiers[1] += one);
    push("first commitment", &|t| t.commitments[0] += one);
    push("second commitment", &|t| t.commitments[1] += one);
    push("swapped nullifiers", &|t| t.nullifiers.swap(0, 1));
    push("swapped commitments", &|t| t.commitments.swap(0, 1));
    out.retain(|(_, t)| t != s);
    out
}

/// Every valid transaction proves and verifies, and its proof verifies for no
/// other statement.
pub fn tx_accepts<B: Backend>() {
    let fixture = TxFixture::new();
    for (name, w) in fixture.valid() {
        let statement = tx::check(&w).unwrap();
        let proof = B::prove_tx(&w).unwrap_or_else(|e| panic!("{}: {name}: prove: {e}", B::NAME));
        B::verify_tx(&statement, &proof).unwrap_or_else(|e| panic!("{}: {name}: verify: {e}", B::NAME));
        for (field, wrong) in tampered_tx(&statement) {
            assert!(
                B::verify_tx(&wrong, &proof).is_err(),
                "{}: {name}: verified with a different {field}",
                B::NAME
            );
        }
    }
}

/// No forged transaction yields a proof of the statement it claims.
pub fn tx_rejects<B: Backend>() {
    let fixture = TxFixture::new();
    for (name, w) in fixture.forged() {
        assert!(tx::check(&w).is_err(), "{name} is not a forgery");
        if let Ok(proof) = B::prove_tx(&w) {
            assert!(B::verify_tx(&tx::statement(&w), &proof).is_err(), "{}: accepted forgery: {name}", B::NAME);
        }
    }
}

fn tampered_op(s: &OpStatement) -> Vec<(&'static str, OpStatement)> {
    let one = fe(1);
    vec![
        ("state before", OpStatement { before: s.before + one, ..*s }),
        ("state after", OpStatement { after: s.after + one, ..*s }),
        ("liabilities before", OpStatement { liabilities_before: s.liabilities_before + 1, ..*s }),
        ("liabilities after", OpStatement { liabilities_after: s.liabilities_after + 1, ..*s }),
    ]
}

/// Every operation of the valid chain proves and verifies on its own.
pub fn op_accepts<B: Backend>() {
    for (i, w) in valid_chain().iter().enumerate() {
        let (_, statement) = op::check(w).unwrap();
        let proof = B::prove_op(w).unwrap_or_else(|e| panic!("{}: operation {i}: prove: {e}", B::NAME));
        B::verify_op(&statement, &proof).unwrap_or_else(|e| panic!("{}: operation {i}: verify: {e}", B::NAME));
        for (field, wrong) in tampered_op(&statement) {
            assert!(
                B::verify_op(&wrong, &proof).is_err(),
                "{}: operation {i}: verified with a different {field}",
                B::NAME
            );
        }
    }
}

/// No forged operation yields a proof of the statement it claims.
pub fn op_rejects<B: Backend>() {
    for (name, w) in forged_ops() {
        assert!(op::check(&w).is_err(), "{name} is not a forgery");
        if let Ok(proof) = B::prove_op(&w) {
            assert!(B::verify_op(&op::claimed(&w).1, &proof).is_err(), "{}: accepted forgery: {name}", B::NAME);
        }
    }
}

fn chain_of<B: Backend>(ops: &[op::OpWitness]) -> crate::error::Result<B::ChainProof> {
    let mut chain = B::chain_start();
    for w in ops {
        B::chain_extend(&mut chain, w)?;
    }
    B::chain_finish(chain)
}

/// The valid chain proves and verifies; a chain with a gap, or with a forged
/// operation in it, does not.
pub fn chain_accepts_and_rejects<B: Backend>() {
    let ops = valid_chain();
    let statement = op::check_chain(&ops).unwrap();
    let proof = chain_of::<B>(&ops).unwrap_or_else(|e| panic!("{}: chain: prove: {e}", B::NAME));
    B::verify_chain(&statement, &proof).unwrap_or_else(|e| panic!("{}: chain: verify: {e}", B::NAME));

    let one: Fp = fe(1);
    let wrong = [
        ("start", ChainStatement { start: statement.start + one, ..statement }),
        ("end", ChainStatement { end: statement.end + one, ..statement }),
        ("starting liabilities", ChainStatement { liabilities_start: statement.liabilities_start + 1, ..statement }),
        ("final liabilities", ChainStatement { liabilities_end: statement.liabilities_end + 1, ..statement }),
        ("count", ChainStatement { count: statement.count + 1, ..statement }),
    ];
    for (field, wrong) in wrong {
        assert!(B::verify_chain(&wrong, &proof).is_err(), "{}: chain verified with a different {field}", B::NAME);
    }

    // Drop the second operation: the third no longer starts where the first ended.
    let gapped: Vec<_> = ops.iter().enumerate().filter(|(i, _)| *i != 1).map(|(_, w)| w.clone()).collect();
    let claimed = ChainStatement { count: statement.count - 1, ..statement };
    if let Ok(proof) = chain_of::<B>(&gapped) {
        assert!(B::verify_chain(&claimed, &proof).is_err(), "{}: accepted a chain with a gap", B::NAME);
    }

    // A valid operation followed by a forged one.
    let mut world = OpWorld::new();
    let first = world.mint(500, &[fe(31)]);
    let mut forged = world.swap(&[], &[]);
    forged.notes[0] = Some(world.notes.overwrite_unchecked(0, fe(32)));
    let (end, _) = op::claimed(&forged);
    let claimed = ChainStatement {
        start: first.before.hash(),
        end: end.hash(),
        liabilities_start: 0,
        liabilities_end: end.liabilities,
        count: 2,
    };
    if let Ok(proof) = chain_of::<B>(&[first, forged]) {
        assert!(B::verify_chain(&claimed, &proof).is_err(), "{}: accepted a chain with a forged operation", B::NAME);
    }
}
