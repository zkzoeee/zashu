//! Mode A fold through the Ragu PCD backend.
//! Run with: `cargo test --release -p zashu-circuits --features ragu --test ragu_fold`
#![cfg(feature = "ragu")]

use zashu_circuits::mode_a::{
    fold_mode_a_batch_with, prove_melt_step, prove_mint_step, prove_swap_step, verify_fold_batch,
    verify_mode_a_step, FoldBackend,
};
use zashu_circuits::{FoldedProof, SubcircuitId};
use zashu_core::poseidon::{hash_event_melt, hash_event_mint};
use zashu_core::types::MintState;

struct Chain {
    states: [MintState; 4],
    steps: [FoldedProof; 3],
}

/// genesis --mint 1000--> s1 --swap--> s2 --melt 300--> s3
fn chain() -> Chain {
    let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
    let mut s1 = s0.clone();
    s1.epoch = 1;
    s1.total_liabilities = 1000;
    s1.event_log_hash = hash_event_mint(&s0.event_log_hash, &[1u8; 32], 1000);
    let mut s2 = s1.clone();
    s2.nullifier_acc_root = [2u8; 32];
    let mut s3 = s2.clone();
    s3.total_liabilities = 700;
    s3.event_log_hash = hash_event_melt(&s2.event_log_hash, &[3u8; 32], 300);

    let steps = [
        prove_mint_step(&s0, &s1, 1000).unwrap(),
        prove_swap_step(&s1, &s2, 500, 500, &[]).unwrap(),
        prove_melt_step(&s2, &s3, 300).unwrap(),
    ];
    Chain { states: [s0, s1, s2, s3], steps }
}

#[test]
fn ragu_fold_verifies_and_rejects_tampering() {
    let Chain { states: [s0, _, s2, s3], steps } = chain();
    let genesis = s0.state_hash();

    let folded = fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &steps).unwrap();
    assert_eq!(folded.subcircuit, SubcircuitId::RaguFold);
    assert_eq!(folded.folded_children, 3);
    verify_fold_batch(&folded, &genesis, &s3).unwrap();

    // Survives the wire encoding used in the solvency bundle.
    let decoded = FoldedProof::from_base64(&folded.to_base64().unwrap()).unwrap();
    verify_fold_batch(&decoded, &genesis, &s3).unwrap();

    // Auditor expects a different end state.
    let mut bad_end = s3.clone();
    bad_end.total_liabilities = 600;
    assert!(verify_fold_batch(&folded, &genesis, &bad_end).is_err());
    assert!(verify_fold_batch(&folded, &genesis, &s2).is_err());

    // Auditor expects a different genesis.
    assert!(verify_fold_batch(&folded, &s2.state_hash(), &s3).is_err());

    // Public inputs rewritten to claim different end liabilities: the proof itself must fail.
    let mut forged = folded.clone();
    forged.public_inputs[1][0] ^= 1;
    assert!(verify_mode_a_step(&forged).is_err());

    // The claimed step count is part of the statement too.
    let mut forged = folded.clone();
    forged.public_inputs[4][0] ^= 1;
    assert!(verify_mode_a_step(&forged).is_err());

    // Corrupted proof bytes.
    let mut corrupt = folded.clone();
    let mid = corrupt.ipa_proof.len() / 2;
    corrupt.ipa_proof[mid] ^= 0x40;
    assert!(verify_fold_batch(&corrupt, &genesis, &s3).is_err());

    // Truncated proof.
    let mut short = folded;
    short.ipa_proof.truncate(100);
    assert!(verify_fold_batch(&short, &genesis, &s3).is_err());
}

#[test]
fn ragu_fold_rejects_broken_chains() {
    let Chain { states: [s0, s1, _, s3], steps: [p1, p2, p3] } = chain();

    // Missing middle step: mint then melt do not chain.
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[p1.clone(), p3.clone()]).is_err());
    // Steps out of order.
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[p2.clone(), p1.clone(), p3]).is_err());
    // Steps do not reach the requested end state.
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[p1.clone(), p2]).is_err());
    // Steps do not start at the requested start state.
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s1, &s1, &[p1]).is_err());
    // A step whose carried transition was altered no longer chains.
    let Chain { states: [s0, _, _, s3], steps: [mut p1, p2, p3] } = chain();
    p1.transition.as_mut().unwrap().next.total_liabilities = 5_000;
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[p1, p2.clone(), p3.clone()]).is_err());
    // A step proof stripped of its transition cannot be re-proven.
    let mut bare = chain().steps[0].clone();
    bare.transition = None;
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[bare, p2, p3]).is_err());
    // Empty batch.
    assert!(fold_mode_a_batch_with(FoldBackend::Ragu, &s0, &s3, &[]).is_err());
}

#[test]
fn incremental_fold_matches_batch_and_poisons_on_a_gap() {
    use zashu_circuits::mode_a::IncrementalFold;

    let Chain { states: [s0, s1, _, s3], steps: [p1, p2, p3] } = chain();
    let fold = IncrementalFold::new(FoldBackend::Ragu).unwrap();
    assert!(fold.snapshot().unwrap().is_none());

    fold.push(&p1);
    let after_one = fold.snapshot().unwrap().unwrap();
    verify_fold_batch(&after_one, &s0.state_hash(), &s1).unwrap();

    fold.push(&p2);
    fold.push(&p3);
    let all = fold.snapshot().unwrap().unwrap();
    assert_eq!(all.folded_children, 3);
    verify_fold_batch(&all, &s0.state_hash(), &s3).unwrap();

    // Pushing a step that does not continue the chain poisons the folder.
    fold.push(&p1);
    assert!(fold.snapshot().is_err());

    // The Halo 2 backend does not fold incrementally.
    let halo2 = IncrementalFold::new(FoldBackend::Halo2).unwrap();
    halo2.push(&p2);
    assert!(halo2.snapshot().unwrap().is_none());
}
