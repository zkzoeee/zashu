//! The aggregated Ragu fold checks each operation against its transaction proof.
//! Run with: `cargo test --release -p zashu-circuits --test ragu_aggregate`
#![cfg(feature = "ragu")]

use group::Group;
use zashu_acc::{NoteAccumulator, NullifierAccumulator};
use zashu_circuits::mode_a::ragu_aggregate::fold_forcing_tx;
use zashu_circuits::mode_a::{
    fold_mode_a_batch_with, fold_op_counts, prove_melt_step, prove_mint_step, prove_swap_step,
    verify_fold_batch, FoldBackend,
};
use zashu_circuits::mode_b::ragu_backend::{prove_tx, SpendInput};
use zashu_circuits::predicates::PredicateWitness;
use zashu_circuits::{FoldedProof, SubcircuitId};
use zashu_core::field::{fq_to_bytes, hash_bytes_to_fq, PallasPoint};
use zashu_core::poseidon::{hash_event_melt, hash_event_mint};
use zashu_core::stealth::PointBytesExt;
use zashu_core::types::{MintState, Note};

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = hash_bytes_to_fq(b"test-sk", &[seed]);
    (fq_to_bytes(&sk), (PallasPoint::generator() * sk).to_affine_bytes())
}

fn note(value: u64, owner_pk: [u8; 32], tag: u8) -> Note {
    Note { value, owner_pk, predicate_id: 0, predicate_params_hash: [0u8; 32], rho: [tag; 32], r: [tag + 100; 32] }
}

struct Mint {
    state: MintState,
    genesis: MintState,
    notes: NoteAccumulator,
    nfs: NullifierAccumulator,
    steps: Vec<FoldedProof>,
}

impl Mint {
    fn new() -> Self {
        let (notes, nfs) = (NoteAccumulator::new(64), NullifierAccumulator::new());
        let genesis = MintState::genesis(nfs.root(), notes.root());
        Self { state: genesis.clone(), genesis, notes, nfs, steps: Vec::new() }
    }

    /// Shielded mint of `n`, moving liabilities by `credited` and attaching `tx`.
    fn zk_mint(&mut self, n: &Note, credited: u64, tx: FoldedProof) -> u64 {
        let prev = self.state.clone();
        let update = self.notes.insert_recorded(n.commitment().0).unwrap();
        let index = update.leaf_index;
        self.state.epoch += 1;
        self.state.total_liabilities += credited;
        self.state.note_acc_root = self.notes.root();
        self.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &[1u8; 32], credited);
        let step = prove_mint_step(&prev, &self.state, credited)
            .unwrap()
            .with_event([1u8; 32])
            .with_root_updates(Vec::new(), vec![update])
            .with_tx_proof(tx);
        self.steps.push(step);
        index
    }

    fn fold(&self) -> zashu_circuits::Result<FoldedProof> {
        fold_mode_a_batch_with(FoldBackend::RaguAggregated, &self.genesis, &self.state, &self.steps)
    }
}

#[test]
fn shielded_operations_are_bound_to_their_transaction_proofs() {
    let (sk_a, pk_a) = keypair(1);
    let (_, pk_b) = keypair(2);
    let spend_a = PredicateWitness::StandardSpend { sk: sk_a };
    let mut mint = Mint::new();

    // 1. Shielded mint of 1000.
    let n1 = note(1_000, pk_a, 1);
    let tx = prove_tx(&[0u8; 32], 0, &[], &[&n1]).unwrap();
    let i1 = mint.zk_mint(&n1, 1_000, tx);

    // 2. Swap n1 -> 600 + 400, spending against the current note root.
    let (n2, n3) = (note(600, pk_a, 2), note(400, pk_b, 3));
    let anchor = mint.notes.root();
    let w1 = mint.notes.witness(i1).unwrap();
    let tx = prove_tx(&anchor, 0, &[SpendInput { note: &n1, witness: &w1, predicate: &spend_a }], &[&n2, &n3]).unwrap();
    let prev = mint.state.clone();
    let nf = vec![mint.nfs.insert(n1.nullifier().0).unwrap()];
    let out2 = mint.notes.insert_recorded(n2.commitment().0).unwrap();
    let i2 = out2.leaf_index;
    let out3 = mint.notes.insert_recorded(n3.commitment().0).unwrap();
    mint.state.epoch += 1;
    mint.state.nullifier_acc_root = mint.nfs.root();
    mint.state.note_acc_root = mint.notes.root();
    let step = prove_swap_step(&prev, &mint.state, 0, 0, &nf)
        .unwrap()
        .with_root_updates(nf, vec![out2, out3])
        .with_tx_proof(tx);
    mint.steps.push(step);

    // 3. Melt n2: 250 leaves the pool, 350 change.
    let n4 = note(350, pk_a, 4);
    let anchor = mint.notes.root();
    let w2 = mint.notes.witness(i2).unwrap();
    let tx = prove_tx(&anchor, 0, &[SpendInput { note: &n2, witness: &w2, predicate: &spend_a }], &[&n4]).unwrap();
    let prev = mint.state.clone();
    let nf = vec![mint.nfs.insert(n2.nullifier().0).unwrap()];
    let change = mint.notes.insert_recorded(n4.commitment().0).unwrap();
    mint.state.epoch += 1;
    mint.state.total_liabilities -= 250;
    mint.state.nullifier_acc_root = mint.nfs.root();
    mint.state.note_acc_root = mint.notes.root();
    mint.state.event_log_hash = hash_event_melt(&prev.event_log_hash, &[3u8; 32], 250);
    let step = prove_melt_step(&prev, &mint.state, 250)
        .unwrap()
        .with_event([3u8; 32])
        .with_root_updates(nf, vec![change])
        .with_tx_proof(tx);
    mint.steps.push(step);

    // 4. A legacy BDHKE mint: no shielded proof exists for it.
    let prev = mint.state.clone();
    mint.state.epoch += 1;
    mint.state.total_liabilities += 77;
    mint.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &[4u8; 32], 77);
    mint.steps.push(prove_mint_step(&prev, &mint.state, 77).unwrap().with_event([4u8; 32]));

    let folded = mint.fold().unwrap();
    assert_eq!(folded.subcircuit, SubcircuitId::RaguFoldAggregated);
    verify_fold_batch(&folded, &mint.genesis.state_hash(), &mint.state).unwrap();
    // Four operations; only the legacy mint is not backed by a transaction proof.
    assert_eq!(fold_op_counts(&folded), Some((4, 1)));

    // The counts are part of the proven statement.
    let mut forged = folded.clone();
    forged.public_inputs[5] = [0u8; 32];
    assert!(verify_fold_batch(&forged, &mint.genesis.state_hash(), &mint.state).is_err());
    let mut wrong = mint.state.clone();
    wrong.total_liabilities += 1;
    assert!(verify_fold_batch(&folded, &mint.genesis.state_hash(), &wrong).is_err());
}

#[test]
fn a_transaction_proof_that_does_not_match_the_operation_does_not_bind_it() {
    let (_, pk_a) = keypair(1);
    let rejected = |mint: &Mint| match fold_forcing_tx(&mint.genesis, &mint.state, &mint.steps) {
        Err(_) => true,
        Ok(p) => verify_fold_batch(&p, &mint.genesis.state_hash(), &mint.state).is_err(),
    };

    // The mint inserts one note but attaches the proof for another.
    let (inserted, proven) = (note(1_000, pk_a, 1), note(1_000, pk_a, 2));
    let tx = prove_tx(&[0u8; 32], 0, &[], &[&proven]).unwrap();
    let mut mint = Mint::new();
    mint.zk_mint(&inserted, 1_000, tx);
    // Offered honestly, the operation is accepted but counted as unbound...
    let folded = mint.fold().unwrap();
    verify_fold_batch(&folded, &mint.genesis.state_hash(), &mint.state).unwrap();
    assert_eq!(fold_op_counts(&folded), Some((1, 1)));
    // ...and it cannot be passed off as bound.
    assert!(rejected(&mint));

    // The right note, but liabilities credited with less than the note is worth.
    let n = note(1_000, pk_a, 3);
    let tx = prove_tx(&[0u8; 32], 0, &[], &[&n]).unwrap();
    let mut mint = Mint::new();
    mint.zk_mint(&n, 999, tx);
    assert_eq!(fold_op_counts(&mint.fold().unwrap()), Some((1, 1)));
    assert!(rejected(&mint));
}
