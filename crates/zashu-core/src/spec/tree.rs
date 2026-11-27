//! The two accumulators: an append-only note tree and a sorted nullifier tree.
//!
//! Both are binary Merkle trees of depth [`DEPTH`] with `node = H_NODE(left,
//! right)` and zero as the empty leaf.
//!
//! The nullifier tree is an indexed Merkle tree: leaf `i` holds `(value,
//! next_value, next_index)`, hashed with `H_NF_LEAF`, and the leaves form a
//! linked list sorted by value as integers. Leaf 0 is the sentinel `(0, 0,
//! 0)`. Inserting `nf` re-points the leaf just below it (the *low* leaf) and
//! appends a new leaf.

use std::collections::{BTreeMap, HashMap};

use ff::PrimeField;

use super::hash::{h, node, T_NF_LEAF};
use super::{fail, less_than, Fp, Result, DEPTH};

pub type Path = [Fp; DEPTH];

/// The root reached from `leaf` at `index` over `path`.
pub fn root_from(leaf: Fp, index: u64, path: &Path) -> Fp {
    let mut cur = leaf;
    for (level, sibling) in path.iter().enumerate() {
        cur = if (index >> level) & 1 == 0 { node(cur, *sibling) } else { node(*sibling, cur) };
    }
    cur
}

fn empties() -> [Fp; DEPTH + 1] {
    let mut out = [Fp::from(0); DEPTH + 1];
    for level in 0..DEPTH {
        out[level + 1] = node(out[level], out[level]);
    }
    out
}

/// A sparse Merkle tree of depth [`DEPTH`].
#[derive(Clone, Debug)]
struct Tree {
    nodes: HashMap<(usize, u64), Fp>,
    empty: [Fp; DEPTH + 1],
}

impl Tree {
    fn new() -> Self {
        Tree { nodes: HashMap::new(), empty: empties() }
    }

    fn get(&self, level: usize, index: u64) -> Fp {
        self.nodes.get(&(level, index)).copied().unwrap_or(self.empty[level])
    }

    fn root(&self) -> Fp {
        self.get(DEPTH, 0)
    }

    fn path(&self, index: u64) -> Path {
        core::array::from_fn(|level| self.get(level, (index >> level) ^ 1))
    }

    fn set(&mut self, index: u64, leaf: Fp) {
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        for level in 0..DEPTH {
            let (left, right) = (self.get(level, idx & !1), self.get(level, idx | 1));
            idx >>= 1;
            self.nodes.insert((level + 1, idx), node(left, right));
        }
    }
}

/// A note commitment written into the empty leaf at `index`; `path` is the
/// leaf's sibling path, which the write does not change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteAppend {
    pub cm: Fp,
    pub index: u64,
    pub path: Path,
}

#[derive(Clone, Debug)]
pub struct NoteTree {
    tree: Tree,
    next: u64,
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    pub fn new() -> Self {
        NoteTree { tree: Tree::new(), next: 0 }
    }

    pub fn root(&self) -> Fp {
        self.tree.root()
    }

    pub fn len(&self) -> u64 {
        self.next
    }

    pub fn is_empty(&self) -> bool {
        self.next == 0
    }

    pub fn path(&self, index: u64) -> Path {
        self.tree.path(index)
    }

    /// Writes `cm` over whatever is at `index`, for building forgeries: the
    /// result is internally consistent but not an append.
    #[doc(hidden)]
    pub fn overwrite_unchecked(&mut self, index: u64, cm: Fp) -> NoteAppend {
        let path = self.tree.path(index);
        self.tree.set(index, cm);
        NoteAppend { cm, index, path }
    }

    pub fn append(&mut self, cm: Fp) -> Result<NoteAppend> {
        if self.next >> DEPTH != 0 {
            return fail("note tree is full");
        }
        let index = self.next;
        let path = self.tree.path(index);
        self.tree.set(index, cm);
        self.next += 1;
        Ok(NoteAppend { cm, index, path })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedLeaf {
    pub value: Fp,
    pub next_value: Fp,
    pub next_index: u64,
}

impl IndexedLeaf {
    pub fn hash(&self) -> Fp {
        h(T_NF_LEAF, &[self.value, self.next_value, Fp::from(self.next_index)])
    }
}

/// A sorted insertion of `nf`.
///
/// `low` is the leaf at `low_index` before the insert, with `low_path` its
/// sibling path in the tree before the insert. The new leaf goes to
/// `new_index`; `new_path` is that leaf's sibling path *after* the low leaf
/// was re-pointed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NfInsert {
    pub nf: Fp,
    pub low: IndexedLeaf,
    pub low_index: u64,
    pub low_path: Path,
    pub new_index: u64,
    pub new_path: Path,
}

impl NfInsert {
    /// Checks the insertion against `root` and returns the root after it.
    pub fn apply(&self, root: Fp) -> Result<Fp> {
        if !less_than(&self.low.value, &self.nf) {
            return fail("nullifier is not above its low leaf");
        }
        if self.low.next_value != Fp::from(0) && !less_than(&self.nf, &self.low.next_value) {
            return fail("nullifier is not below the low leaf's successor");
        }
        if root_from(self.low.hash(), self.low_index, &self.low_path) != root {
            return fail("low leaf is not in the nullifier tree");
        }
        let repointed = IndexedLeaf { value: self.low.value, next_value: self.nf, next_index: self.new_index };
        let mid = root_from(repointed.hash(), self.low_index, &self.low_path);
        if root_from(Fp::from(0), self.new_index, &self.new_path) != mid {
            return fail("new nullifier leaf is not an empty slot");
        }
        let leaf = IndexedLeaf { value: self.nf, next_value: self.low.next_value, next_index: self.low.next_index };
        Ok(root_from(leaf.hash(), self.new_index, &self.new_path))
    }
}

impl NfInsert {
    /// The root this insertion claims to produce, without checking it.
    pub fn claimed_root(&self) -> Fp {
        let leaf = IndexedLeaf { value: self.nf, next_value: self.low.next_value, next_index: self.low.next_index };
        root_from(leaf.hash(), self.new_index, &self.new_path)
    }
}

impl NoteAppend {
    /// The root this append claims to produce, without checking it.
    pub fn claimed_root(&self) -> Fp {
        root_from(self.cm, self.index, &self.path)
    }
}

impl NoteAppend {
    /// Checks the append against `root` and returns the root after it.
    pub fn apply(&self, root: Fp) -> Result<Fp> {
        if root_from(Fp::from(0), self.index, &self.path) != root {
            return fail("note leaf is not an empty slot");
        }
        Ok(root_from(self.cm, self.index, &self.path))
    }
}

fn sort_key(value: &Fp) -> [u8; 32] {
    let mut key = value.to_repr();
    key.reverse();
    key
}

#[derive(Clone, Debug)]
pub struct NullifierTree {
    tree: Tree,
    leaves: Vec<IndexedLeaf>,
    sorted: BTreeMap<[u8; 32], u64>,
}

impl Default for NullifierTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierTree {
    pub fn new() -> Self {
        let sentinel = IndexedLeaf { value: Fp::from(0), next_value: Fp::from(0), next_index: 0 };
        let mut tree = Tree::new();
        tree.set(0, sentinel.hash());
        let mut sorted = BTreeMap::new();
        sorted.insert(sort_key(&sentinel.value), 0);
        NullifierTree { tree, leaves: vec![sentinel], sorted }
    }

    pub fn root(&self) -> Fp {
        self.tree.root()
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, nf: &Fp) -> bool {
        self.sorted.contains_key(&sort_key(nf))
    }

    pub fn insert(&mut self, nf: Fp) -> Result<NfInsert> {
        if nf == Fp::from(0) || self.contains(&nf) {
            return fail("nullifier is zero or already spent");
        }
        if self.leaves.len() as u64 >> DEPTH != 0 {
            return fail("nullifier tree is full");
        }
        let (_, &low_index) =
            self.sorted.range(..sort_key(&nf)).next_back().expect("the sentinel is below every nullifier");
        Ok(self.insert_unchecked(nf, low_index))
    }

    /// The index of the leaf holding `value`.
    pub fn index_of(&self, value: &Fp) -> Option<u64> {
        self.sorted.get(&sort_key(value)).copied()
    }

    /// Inserts `nf` behind the leaf at `low_index` whether or not that keeps
    /// the list sorted, for building forgeries: every hash and path of the
    /// result is consistent, only the order may be wrong.
    #[doc(hidden)]
    pub fn insert_unchecked(&mut self, nf: Fp, low_index: u64) -> NfInsert {
        let new_index = self.leaves.len() as u64;
        let low = self.leaves[low_index as usize];
        let low_path = self.tree.path(low_index);

        let repointed = IndexedLeaf { value: low.value, next_value: nf, next_index: new_index };
        self.leaves[low_index as usize] = repointed;
        self.tree.set(low_index, repointed.hash());

        let new_path = self.tree.path(new_index);
        let leaf = IndexedLeaf { value: nf, next_value: low.next_value, next_index: low.next_index };
        self.leaves.push(leaf);
        self.tree.set(new_index, leaf.hash());
        self.sorted.insert(sort_key(&nf), new_index);
        NfInsert { nf, low, low_index, low_path, new_index, new_path }
    }
}
