use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zashu_core::poseidon::hash_acc_node;

pub const ACC_DEPTH: usize = 32;

#[derive(Debug, Error)]
pub enum AccError {
    #[error("accumulator is full")]
    AccumulatorFull,

    #[error("leaf index {0} out of bounds")]
    IndexOutOfBounds(u64),

    #[error("nullifier already present")]
    DuplicateNullifier,

    #[error("invalid inclusion witness")]
    InvalidWitness,

    #[error("stale anchor root")]
    StaleAnchor,
}

pub type Result<T> = std::result::Result<T, AccError>;

/// Precomputed empty-subtree hashes for each level `0..=ACC_DEPTH`.
pub fn empty_hashes() -> [[u8; 32]; ACC_DEPTH + 1] {
    let mut hashes = [[0u8; 32]; ACC_DEPTH + 1];
    for level in 0..ACC_DEPTH {
        hashes[level + 1] = hash_acc_node(&hashes[level], &hashes[level]);
    }
    hashes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionWitness {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; 32]>,
}

/// Append-only Poseidon Merkle accumulator for active Mode B note commitments,
/// with a rolling window of recent valid anchor roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteAccumulator {
    next_index: u64,
    nodes: HashMap<(usize, u64), [u8; 32]>,
    #[serde(skip, default = "empty_hashes")]
    empty: [[u8; 32]; ACC_DEPTH + 1],
    root_history: VecDeque<[u8; 32]>,
    max_window: usize,
}

impl Default for NoteAccumulator {
    fn default() -> Self {
        Self::new(64)
    }
}

impl NoteAccumulator {
    pub fn new(max_window: usize) -> Self {
        let empty = empty_hashes();
        let initial_root = empty[ACC_DEPTH];
        let mut root_history = VecDeque::with_capacity(max_window.max(1));
        root_history.push_back(initial_root);
        Self {
            next_index: 0,
            nodes: HashMap::new(),
            empty,
            root_history,
            max_window: max_window.max(1),
        }
    }

    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// The node at `(level, idx)`. Interior nodes are a cache: one that was
    /// pruned is recomputed from the level below, down to the leaves, which
    /// are never pruned.
    fn node(&self, level: usize, idx: u64) -> [u8; 32] {
        if let Some(n) = self.nodes.get(&(level, idx)) {
            return *n;
        }
        // No leaf under this node yet (or a missing leaf): it is empty.
        let first_leaf = idx.checked_shl(level as u32).unwrap_or(u64::MAX);
        if level == 0 || first_leaf >= self.next_index {
            return self.empty[level];
        }
        hash_acc_node(&self.node(level - 1, idx * 2), &self.node(level - 1, idx * 2 + 1))
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    pub fn root(&self) -> [u8; 32] {
        *self
            .nodes
            .get(&(ACC_DEPTH, 0))
            .unwrap_or(&self.empty[ACC_DEPTH])
    }

    pub fn is_valid_anchor(&self, root: &[u8; 32]) -> bool {
        self.root_history.iter().any(|r| r == root)
    }

    pub fn insert(&mut self, cm: [u8; 32]) -> Result<u64> {
        if self.next_index >= (1u64 << ACC_DEPTH) {
            return Err(AccError::AccumulatorFull);
        }
        let idx = self.next_index;
        self.next_index += 1;

        self.nodes.insert((0, idx), cm);
        let mut cur_idx = idx;
        let mut cur_hash = cm;

        for level in 0..ACC_DEPTH {
            let sibling_idx = cur_idx ^ 1;
            let sibling = self.node(level, sibling_idx);
            let parent = if cur_idx % 2 == 0 {
                hash_acc_node(&cur_hash, &sibling)
            } else {
                hash_acc_node(&sibling, &cur_hash)
            };
            cur_idx >>= 1;
            cur_hash = parent;
            self.nodes.insert((level + 1, cur_idx), cur_hash);
        }

        if self.root_history.len() >= self.max_window {
            self.root_history.pop_front();
        }
        self.root_history.push_back(cur_hash);

        Ok(idx)
    }

    pub fn witness(&self, leaf_index: u64) -> Result<InclusionWitness> {
        if leaf_index >= self.next_index {
            return Err(AccError::IndexOutOfBounds(leaf_index));
        }
        let mut siblings = Vec::with_capacity(ACC_DEPTH);
        let mut cur_idx = leaf_index;
        for level in 0..ACC_DEPTH {
            let sibling_idx = cur_idx ^ 1;
            let sibling = self.node(level, sibling_idx);
            siblings.push(sibling);
            cur_idx >>= 1;
        }
        Ok(InclusionWitness {
            leaf_index,
            siblings,
        })
    }

    pub fn verify_inclusion(root: &[u8; 32], leaf: &[u8; 32], witness: &InclusionWitness) -> bool {
        if witness.siblings.len() != ACC_DEPTH {
            return false;
        }
        let mut cur = *leaf;
        let mut idx = witness.leaf_index;
        for sibling in &witness.siblings {
            cur = if idx % 2 == 0 {
                hash_acc_node(&cur, sibling)
            } else {
                hash_acc_node(sibling, &cur)
            };
            idx >>= 1;
        }
        &cur == root
    }
}

/// Indexed Merkle Tree leaf for cryptographic non-membership proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedLeaf {
    pub val: [u8; 32],
    pub next_val: [u8; 32],
    pub next_idx: u64,
}

impl IndexedLeaf {
    pub fn hash(&self) -> [u8; 32] {
        let left = hash_acc_node(&self.val, &self.next_val);
        let mut idx_bytes = [0u8; 32];
        idx_bytes[..8].copy_from_slice(&self.next_idx.to_le_bytes());
        hash_acc_node(&left, &idx_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipWitness {
    pub low_leaf: IndexedLeaf,
    pub low_witness: InclusionWitness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierTransitionWitness {
    pub pre_root: [u8; 32],
    pub post_root: [u8; 32],
    pub non_membership: NonMembershipWitness,
    pub new_leaf_index: u64,
}

/// Tachyon-style prunable indexed nullifier accumulator.
/// Supports cryptographic non-membership proofs, insert-with-transition-witness,
/// and epoch pruning to bound memory footprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierAccumulator {
    tree: NoteAccumulator,
    leaves: Vec<IndexedLeaf>,
    sorted_index: BTreeMap<[u8; 32], u64>,
    epoch: u64,
    pruned_before_epoch: u64,
    epoch_checkpoints: Vec<(u64, [u8; 32], u64)>,
}

impl Default for NullifierAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierAccumulator {
    pub fn new() -> Self {
        let mut tree = NoteAccumulator::new(16);
        let sentinel = IndexedLeaf {
            val: [0u8; 32],
            next_val: [0u8; 32],
            next_idx: 0,
        };
        let _ = tree.insert(sentinel.hash());
        let mut sorted_index = BTreeMap::new();
        sorted_index.insert([0u8; 32], 0);
        Self {
            tree,
            leaves: vec![sentinel],
            sorted_index,
            epoch: 0,
            pruned_before_epoch: 0,
            epoch_checkpoints: Vec::new(),
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn len(&self) -> usize {
        self.sorted_index.len().saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        *nf == [0u8; 32] || self.sorted_index.contains_key(nf)
    }

    pub fn prove_non_membership(&self, nf: &[u8; 32]) -> Result<NonMembershipWitness> {
        if self.contains(nf) {
            return Err(AccError::DuplicateNullifier);
        }
        let (&_low_key, &low_idx) = self
            .sorted_index
            .range(..*nf)
            .next_back()
            .ok_or(AccError::InvalidWitness)?;
        let low_leaf = self.leaves[low_idx as usize].clone();
        let low_witness = self.tree.witness(low_idx)?;
        Ok(NonMembershipWitness {
            low_leaf,
            low_witness,
        })
    }

    pub fn verify_non_membership(root: &[u8; 32], nf: &[u8; 32], witness: &NonMembershipWitness) -> bool {
        if *nf == [0u8; 32] {
            return false;
        }
        let low = &witness.low_leaf;
        let gt_low = *nf > low.val;
        let lt_next = low.next_val == [0u8; 32] || *nf < low.next_val;
        if !gt_low || !lt_next {
            return false;
        }
        NoteAccumulator::verify_inclusion(root, &low.hash(), &witness.low_witness)
    }

    pub fn insert(&mut self, nf: [u8; 32]) -> Result<NullifierTransitionWitness> {
        let pre_root = self.root();
        let non_membership = self.prove_non_membership(&nf)?;

        let (&_low_key, &low_idx) = self
            .sorted_index
            .range(..nf)
            .next_back()
            .ok_or(AccError::InvalidWitness)?;
        let old_low = self.leaves[low_idx as usize].clone();
        let new_idx = self.leaves.len() as u64;

        let new_leaf = IndexedLeaf {
            val: nf,
            next_val: old_low.next_val,
            next_idx: old_low.next_idx,
        };
        let updated_low = IndexedLeaf {
            val: old_low.val,
            next_val: nf,
            next_idx: new_idx,
        };

        // Update low_idx in place in Merkle tree & insert new_idx
        self.leaves[low_idx as usize] = updated_low.clone();
        self.update_leaf_at(low_idx, updated_low.hash());

        self.leaves.push(new_leaf.clone());
        let inserted_idx = self.tree.insert(new_leaf.hash())?;
        debug_assert_eq!(inserted_idx, new_idx);
        self.sorted_index.insert(nf, new_idx);

        Ok(NullifierTransitionWitness {
            pre_root,
            post_root: self.root(),
            non_membership,
            new_leaf_index: new_idx,
        })
    }

    fn update_leaf_at(&mut self, leaf_index: u64, leaf_hash: [u8; 32]) {
        self.tree.nodes.insert((0, leaf_index), leaf_hash);
        let mut cur_idx = leaf_index;
        let mut cur_hash = leaf_hash;
        for level in 0..ACC_DEPTH {
            let sibling_idx = cur_idx ^ 1;
            let sibling = self.tree.node(level, sibling_idx);
            let parent = if cur_idx % 2 == 0 {
                hash_acc_node(&cur_hash, &sibling)
            } else {
                hash_acc_node(&sibling, &cur_hash)
            };
            cur_idx >>= 1;
            cur_hash = parent;
            self.tree.nodes.insert((level + 1, cur_idx), cur_hash);
        }
    }

    /// Seals the current epoch and records a compact checkpoint.
    pub fn seal_epoch(&mut self) -> (u64, [u8; 32]) {
        self.epoch += 1;
        let root = self.root();
        self.epoch_checkpoints
            .push((self.epoch, root, self.leaves.len() as u64));
        (self.epoch, root)
    }

    /// Prunes interior Merkle cache nodes for sealed epochs, retaining only
    /// compact epoch checkpoints and the active frontier needed for new inserts.
    pub fn prune_before_epoch(&mut self, keep_last_epochs: usize) -> usize {
        if self.epoch_checkpoints.len() <= keep_last_epochs {
            return 0;
        }
        let cutoff = self.epoch_checkpoints.len() - keep_last_epochs;
        let (pruned_epoch, _, _) = self.epoch_checkpoints[cutoff - 1];
        self.pruned_before_epoch = pruned_epoch;

        // Drop cached interior nodes below level 8. Leaves and upper levels
        // stay; a dropped node is recomputed from its leaves when next needed
        // (at most 2^7 leaf hashes), so roots and witnesses remain correct.
        let before = self.tree.nodes.len();
        self.tree.nodes.retain(|(level, _), _| *level >= 8 || *level == 0);
        before.saturating_sub(self.tree.nodes.len())
    }

    pub fn checkpoints(&self) -> &[(u64, [u8; 32], u64)] {
        &self.epoch_checkpoints
    }

    pub fn node_count(&self) -> usize {
        self.tree.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_accumulator_insert_and_verify() {
        let mut acc = NoteAccumulator::new(4);
        let cm1 = [1u8; 32];
        let cm2 = [2u8; 32];
        let idx1 = acc.insert(cm1).unwrap();
        let root1 = acc.root();
        let idx2 = acc.insert(cm2).unwrap();
        let root2 = acc.root();

        assert!(acc.is_valid_anchor(&root1));
        assert!(acc.is_valid_anchor(&root2));

        let w1 = acc.witness(idx1).unwrap();
        let w2 = acc.witness(idx2).unwrap();
        assert!(NoteAccumulator::verify_inclusion(&root2, &cm1, &w1));
        assert!(NoteAccumulator::verify_inclusion(&root2, &cm2, &w2));
        assert!(!NoteAccumulator::verify_inclusion(&root2, &[9u8; 32], &w1));
    }

    #[test]
    fn nullifier_accumulator_non_membership_and_duplicate_reject() {
        let mut nf_acc = NullifierAccumulator::new();
        let nf1 = [10u8; 32];
        let nf2 = [20u8; 32];
        let nf_mid = [15u8; 32];

        let root0 = nf_acc.root();
        let w_non = nf_acc.prove_non_membership(&nf1).unwrap();
        assert!(NullifierAccumulator::verify_non_membership(&root0, &nf1, &w_non));

        let t1 = nf_acc.insert(nf1).unwrap();
        assert_eq!(t1.pre_root, root0);
        assert!(nf_acc.contains(&nf1));
        assert!(nf_acc.insert(nf1).is_err());

        nf_acc.insert(nf2).unwrap();
        let root2 = nf_acc.root();
        let w_mid = nf_acc.prove_non_membership(&nf_mid).unwrap();
        assert!(NullifierAccumulator::verify_non_membership(&root2, &nf_mid, &w_mid));
        assert!(!NullifierAccumulator::verify_non_membership(&root2, &nf1, &w_mid));
    }

    #[test]
    fn epoch_pruning_bounds_node_storage() {
        let mut nf_acc = NullifierAccumulator::new();
        for epoch in 0..12u8 {
            for i in 0..20u8 {
                let mut nf = [0u8; 32];
                nf[0] = epoch + 1;
                nf[1] = i + 1;
                nf_acc.insert(nf).unwrap();
            }
            nf_acc.seal_epoch();
        }
        let nodes_before = nf_acc.node_count();
        let pruned = nf_acc.prune_before_epoch(2);
        assert!(pruned > 0);
        assert!(nf_acc.node_count() < nodes_before);
    }

    #[test]
    fn inserts_and_witnesses_stay_correct_after_pruning() {
        let fill = |acc: &mut NullifierAccumulator, prune: bool| {
            for e in 0..12u8 {
                for i in 0..20u8 {
                    let mut nf = [0u8; 32];
                    nf[0] = e + 1;
                    nf[1] = i + 1;
                    let t = acc.insert(nf).unwrap();
                    assert!(NullifierAccumulator::verify_non_membership(&t.pre_root, &nf, &t.non_membership));
                }
                acc.seal_epoch();
                if prune {
                    acc.prune_before_epoch(2);
                }
            }
        };
        let (mut pruned, mut full) = (NullifierAccumulator::new(), NullifierAccumulator::new());
        fill(&mut pruned, true);
        fill(&mut full, false);
        // Pruning is only a cache eviction: same root, fewer stored nodes.
        assert_eq!(pruned.root(), full.root());
        assert!(pruned.node_count() < full.node_count());

        let mut probe = [0u8; 32];
        probe[0] = 5;
        probe[1] = 200;
        let w = pruned.prove_non_membership(&probe).unwrap();
        assert!(NullifierAccumulator::verify_non_membership(&pruned.root(), &probe, &w));
    }
}
