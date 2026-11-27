//! The Ragu fold binds event-log, nullifier-root and note-root changes.
//! Run with: `cargo test --release -p zashu-circuits --test ragu_roots`
#![cfg(feature = "ragu")]

use zashu_acc::{
    empty_hashes, IndexedLeaf, InclusionWitness, LeafUpdate, NonMembershipWitness, NoteAccumulator,
    NullifierAccumulator, NullifierTransitionWitness, ACC_DEPTH,
};
use zashu_circuits::mode_a::{
    fold_mode_a_batch_with, prove_melt_step, prove_mint_step, prove_swap_step, verify_fold_batch,
    FoldBackend,
};
use zashu_circuits::{FoldedProof, SubcircuitId};
use zashu_core::field::{fp_from_u64, fp_to_bytes};
use zashu_core::poseidon::{hash_acc_node, hash_event_melt, hash_event_mint};
use zashu_core::types::MintState;

/// A canonical field element as accumulator bytes.
fn fe(v: u64) -> [u8; 32] {
    fp_to_bytes(&fp_from_u64(v))
}

/// The root reached by walking `leaf` up `siblings` from `index`.
fn root_from(leaf: [u8; 32], index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    let (mut cur, mut idx) = (leaf, index);
    for s in siblings {
        cur = if idx % 2 == 0 { hash_acc_node(&cur, s) } else { hash_acc_node(s, &cur) };
        idx >>= 1;
    }
    cur
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

    /// Mint `amount` into one new note.
    fn mint(&mut self, amount: u64, quote: [u8; 32], cm: [u8; 32]) {
        let prev = self.state.clone();
        let note = self.notes.insert_recorded(cm).unwrap();
        self.state.epoch += 1;
        self.state.total_liabilities += amount;
        self.state.note_acc_root = self.notes.root();
        self.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &quote, amount);
        let step = prove_mint_step(&prev, &self.state, amount)
            .unwrap()
            .with_event(quote)
            .with_root_updates(Vec::new(), vec![note]);
        self.steps.push(step);
    }

    /// Spend `nullifiers` into `outputs`; liabilities unchanged.
    fn swap(&mut self, nullifiers: &[[u8; 32]], outputs: &[[u8; 32]]) {
        let prev = self.state.clone();
        let nf_updates: Vec<_> = nullifiers.iter().map(|nf| self.nfs.insert(*nf).unwrap()).collect();
        let note_updates: Vec<_> = outputs.iter().map(|cm| self.notes.insert_recorded(*cm).unwrap()).collect();
        self.state.epoch += 1;
        self.state.nullifier_acc_root = self.nfs.root();
        self.state.note_acc_root = self.notes.root();
        let step = prove_swap_step(&prev, &self.state, 0, 0, &nf_updates)
            .unwrap()
            .with_root_updates(nf_updates, note_updates);
        self.steps.push(step);
    }

    /// Spend one nullifier and pay `amount` out.
    fn melt(&mut self, amount: u64, payout: [u8; 32], nullifier: [u8; 32]) {
        let prev = self.state.clone();
        let nf_update = self.nfs.insert(nullifier).unwrap();
        self.state.epoch += 1;
        self.state.total_liabilities -= amount;
        self.state.nullifier_acc_root = self.nfs.root();
        self.state.event_log_hash = hash_event_melt(&prev.event_log_hash, &payout, amount);
        let step = prove_melt_step(&prev, &self.state, amount)
            .unwrap()
            .with_event(payout)
            .with_root_updates(vec![nf_update], Vec::new());
        self.steps.push(step);
    }

    fn fold(&self) -> zashu_circuits::Result<FoldedProof> {
        fold_mode_a_batch_with(FoldBackend::Ragu, &self.genesis, &self.state, &self.steps)
    }

    /// A fold attempt is "not accepted" if folding fails or the proof does not verify.
    fn not_accepted(&self) -> bool {
        match self.fold() {
            Err(_) => true,
            Ok(p) => verify_fold_batch(&p, &self.genesis.state_hash(), &self.state).is_err(),
        }
    }
}

#[test]
fn mint_swap_melt_chain_with_bound_roots() {
    let mut mint = Mint::new();
    mint.mint(1_000, [1u8; 32], fe(101));
    // The second nullifier sorts between the sentinel and the first, so that
    // insert has a real successor to stay below.
    mint.swap(&[fe(200), fe(100)], &[fe(102), fe(103)]);
    // The accumulator orders by bytes, first byte most significant: 9000
    // (bytes 28 23) sorts before 200 (byte c8) although it is numerically
    // larger. The circuit has to agree with that order.
    assert!(fe(9_000) < fe(200));
    mint.melt(300, [3u8; 32], fe(9_000));

    let folded = mint.fold().unwrap();
    assert_eq!(folded.subcircuit, SubcircuitId::RaguFoldRoots);
    assert_eq!(folded.folded_children, 3);
    verify_fold_batch(&folded, &mint.genesis.state_hash(), &mint.state).unwrap();

    let mut wrong = mint.state.clone();
    wrong.total_liabilities += 1;
    assert!(verify_fold_batch(&folded, &mint.genesis.state_hash(), &wrong).is_err());
    let mut wrong = mint.state.clone();
    wrong.nullifier_acc_root = mint.genesis.nullifier_acc_root;
    assert!(verify_fold_batch(&folded, &mint.genesis.state_hash(), &wrong).is_err());
}

#[test]
fn steps_must_account_for_every_state_change() {
    // A mint step whose note insert is not recorded.
    let mut mint = Mint::new();
    mint.mint(500, [1u8; 32], fe(101));
    mint.steps[0].transition.as_mut().unwrap().note_updates.clear();
    assert!(mint.fold().is_err());

    // A mint step without its quote hash, or with the wrong one.
    let mut mint = Mint::new();
    mint.mint(500, [1u8; 32], fe(101));
    mint.steps[0].transition.as_mut().unwrap().event = None;
    assert!(mint.fold().is_err());
    mint.steps[0].transition.as_mut().unwrap().event = Some([2u8; 32]);
    assert!(mint.fold().is_err());

    // The event log records a different amount than the liabilities moved by.
    let mut mint = Mint::new();
    let prev = mint.state.clone();
    mint.state.epoch += 1;
    mint.state.total_liabilities += 500;
    mint.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &[1u8; 32], 400);
    mint.steps.push(prove_mint_step(&prev, &mint.state, 500).unwrap().with_event([1u8; 32]));
    assert!(mint.fold().is_err());

    // A swap that quietly rewrites the event log.
    let mut mint = Mint::new();
    let prev = mint.state.clone();
    mint.state.epoch += 1;
    mint.state.event_log_hash = [7u8; 32];
    mint.steps.push(prove_swap_step(&prev, &mint.state, 0, 0, &[]).unwrap());
    assert!(mint.fold().is_err());
}

#[test]
fn note_root_can_only_change_by_filling_an_empty_leaf() {
    let mut mint = Mint::new();
    mint.mint(500, [1u8; 32], fe(101));

    // Overwrite the existing note at index 0 with another commitment. The
    // update is internally consistent (same siblings, recomputed root), so
    // only the circuit's "slot was empty" check can reject it.
    let prev = mint.state.clone();
    let siblings = mint.notes.witness(0).unwrap().siblings;
    let forged = LeafUpdate {
        pre_root: prev.note_acc_root,
        post_root: root_from(fe(999), 0, &siblings),
        leaf_index: 0,
        old_leaf: fe(101),
        new_leaf: fe(999),
        siblings,
    };
    mint.state.epoch += 1;
    mint.state.note_acc_root = forged.post_root;
    let step = prove_swap_step(&prev, &mint.state, 0, 0, &[]).unwrap().with_root_updates(Vec::new(), vec![forged]);
    mint.steps.push(step);
    assert!(mint.not_accepted());
}

#[test]
fn nullifier_insert_must_respect_the_sorted_order() {
    // Tree: sentinel (0) -> A. Insert B < A, but claim A as its low leaf.
    // Every hash and root below is consistent; only the order check fails.
    let (a, b) = (fe(200), fe(100));
    assert!(b < a);
    let mut mint = Mint::new();
    mint.swap(&[a], &[]);
    let prev = mint.state.clone();

    let empty = empty_hashes();
    let sentinel = IndexedLeaf { val: [0u8; 32], next_val: a, next_idx: 1 };
    let old_a = IndexedLeaf { val: a, next_val: [0u8; 32], next_idx: 0 };
    let new_a = IndexedLeaf { val: a, next_val: b, next_idx: 2 };
    let new_b = IndexedLeaf { val: b, next_val: [0u8; 32], next_idx: 0 };

    // Leaf 1 (A): sibling is leaf 0 (sentinel), then empty subtrees.
    let mut sib_a = vec![sentinel.hash()];
    sib_a.extend_from_slice(&empty[1..ACC_DEPTH]);
    assert_eq!(root_from(old_a.hash(), 1, &sib_a), prev.nullifier_acc_root, "test tree layout");
    let mid_root = root_from(new_a.hash(), 1, &sib_a);

    // Leaf 2 (new): sibling is empty leaf 3, then the (sentinel, A') pair, then empty subtrees.
    let mut sib_b = vec![empty[0], hash_acc_node(&sentinel.hash(), &new_a.hash())];
    sib_b.extend_from_slice(&empty[2..ACC_DEPTH]);
    assert_eq!(root_from(empty[0], 2, &sib_b), mid_root, "test tree layout");
    let post_root = root_from(new_b.hash(), 2, &sib_b);

    let forged = NullifierTransitionWitness {
        pre_root: prev.nullifier_acc_root,
        post_root,
        non_membership: NonMembershipWitness {
            low_leaf: old_a.clone(),
            low_witness: InclusionWitness { leaf_index: 1, siblings: sib_a.clone() },
        },
        new_leaf_index: 2,
        nullifier: b,
        low_update: Some(LeafUpdate {
            pre_root: prev.nullifier_acc_root,
            post_root: mid_root,
            leaf_index: 1,
            old_leaf: old_a.hash(),
            new_leaf: new_a.hash(),
            siblings: sib_a,
        }),
        append_update: Some(LeafUpdate {
            pre_root: mid_root,
            post_root,
            leaf_index: 2,
            old_leaf: empty[0],
            new_leaf: new_b.hash(),
            siblings: sib_b,
        }),
    };
    mint.state.epoch += 1;
    mint.state.nullifier_acc_root = post_root;
    let step = prove_swap_step(&prev, &mint.state, 0, 0, &[]).unwrap().with_root_updates(vec![forged], Vec::new());
    mint.steps.push(step);
    assert!(mint.not_accepted());
}
