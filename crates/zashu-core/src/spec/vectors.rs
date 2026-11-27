//! Shared test vectors: witnesses every backend must accept, and forgeries
//! every backend must reject.
//!
//! A forgery is a witness the reference checker rejects. A backend rejects it
//! when proving fails, or when the proof it produces does not verify against
//! the statement the forged witness claims ([`tx::statement`] or the claimed
//! operation statement).

use super::note::{
    hashlock, htlc_params, multisig_params, timelock_params, Auth, Key, Note, Signer, PRED_HTLC, PRED_KEY,
    PRED_MULTISIG, PRED_TIMELOCK,
};
use super::op::{Kind, OpWitness, State};
use super::tree::{NoteTree, NullifierTree};
use super::tx::{Spend, TxWitness};
use super::{Fp, DEPTH};

/// A small deterministic field element.
pub fn fe(v: u64) -> Fp {
    Fp::from(v)
}

/// A pseudo-random field element, as a hash output would be.
pub fn random_fe(seed: u64) -> Fp {
    super::to_field(b"zashu-vector", &seed.to_le_bytes())
}

pub fn key(seed: u64) -> Key {
    Key { spend_sk: random_fe(seed), tweak: random_fe(seed + 500) }
}

fn note(value: u64, owner: Fp, predicate: u64, params: Fp, seed: u64) -> Note {
    Note { value, owner, predicate, params, rho: random_fe(seed + 1_000), r: random_fe(seed + 2_000) }
}

/// A named witness.
pub type Named<W> = (&'static str, W);

/// The notes the transaction vectors spend, in one note tree.
pub struct TxFixture {
    pub tree: NoteTree,
    pub anchor: Fp,
    pub ka: Key,
    pub kb: Key,
    pub kc: Key,
    pub preimage: Fp,
    /// 100, owned by `ka`.
    pub n_key: (Note, u64),
    /// 50, owned by `kb`.
    pub n_key2: (Note, u64),
    /// 70, owned by `ka` from epoch 10.
    pub n_time: (Note, u64),
    /// 80: `kb` claims with the preimage before epoch 20, `kc` refunds after.
    pub n_htlc: (Note, u64),
    /// 90: two of `ka`, `kb`, `kc`.
    pub n_multi: (Note, u64),
}

pub const TIMELOCK_EPOCH: u64 = 10;
pub const HTLC_EXPIRY: u64 = 20;

impl TxFixture {
    pub fn new() -> Self {
        let (ka, kb, kc) = (key(1), key(2), key(3));
        let preimage = random_fe(77);
        let zero = fe(0);
        let keys = [ka.image(), kb.image(), kc.image(), zero];
        let notes = [
            note(100, ka.image(), PRED_KEY, zero, 1),
            note(50, kb.image(), PRED_KEY, zero, 2),
            note(70, ka.image(), PRED_TIMELOCK, timelock_params(TIMELOCK_EPOCH), 3),
            note(80, zero, PRED_HTLC, htlc_params(hashlock(preimage), kb.image(), kc.image(), HTLC_EXPIRY), 4),
            note(90, zero, PRED_MULTISIG, multisig_params(2, 3, &keys), 5),
        ];
        let mut tree = NoteTree::new();
        // A few unrelated notes first, so the paths are not all-empty.
        for i in 0..5 {
            tree.append(random_fe(9_000 + i)).unwrap();
        }
        let placed: Vec<(Note, u64)> =
            notes.iter().map(|n| (*n, tree.append(n.commitment()).unwrap().index)).collect();
        TxFixture {
            anchor: tree.root(),
            tree,
            ka,
            kb,
            kc,
            preimage,
            n_key: placed[0],
            n_key2: placed[1],
            n_time: placed[2],
            n_htlc: placed[3],
            n_multi: placed[4],
        }
    }

    pub fn spend(&self, note: (Note, u64), auth: Auth) -> Spend {
        Spend { note: note.0, index: note.1, path: self.tree.path(note.1), auth }
    }

    /// A zero-value input for an unused slot.
    pub fn dummy_spend(&self, seed: u64) -> Spend {
        let k = key(seed + 40);
        let note = Note::dummy(random_fe(seed + 3_000), random_fe(seed + 4_000), &k);
        Spend { note, index: 0, path: [fe(0); DEPTH], auth: Auth::Key(k) }
    }

    pub fn output(&self, value: u64, seed: u64) -> Note {
        note(value, self.kb.image(), PRED_KEY, fe(0), seed + 100)
    }

    fn tx(&self, epoch: u64, first: Spend, second: Spend, out: [u64; 2]) -> TxWitness {
        TxWitness {
            anchor: self.anchor,
            epoch,
            inputs: Some([first, second]),
            outputs: [self.output(out[0], 1), self.output(out[1], 2)],
        }
    }

    fn multisig(&self, signers: Vec<Signer>) -> Auth {
        Auth::Multisig {
            threshold: 2,
            key_count: 3,
            keys: [self.ka.image(), self.kb.image(), self.kc.image(), fe(0)],
            signers,
        }
    }

    fn claim(&self, key: Key, preimage: Fp) -> Auth {
        Auth::HtlcClaim { key, preimage, refund: self.kc.image(), expiry_epoch: HTLC_EXPIRY }
    }

    fn refund(&self, key: Key) -> Auth {
        Auth::HtlcRefund {
            key,
            hashlock: hashlock(self.preimage),
            receiver: self.kb.image(),
            expiry_epoch: HTLC_EXPIRY,
        }
    }

    /// Transactions that satisfy the relation.
    pub fn valid(&self) -> Vec<Named<TxWitness>> {
        let d = |s| self.dummy_spend(s);
        let signer = |key, slot| Signer { key, slot };
        vec![
            (
                "mint: no inputs, one real output",
                TxWitness {
                    anchor: fe(0),
                    epoch: 5,
                    inputs: None,
                    outputs: [self.output(100, 1), self.output(0, 2)],
                },
            ),
            ("swap: one real input, one dummy", self.tx(5, self.spend(self.n_key, Auth::Key(self.ka)), d(1), [60, 40])),
            (
                "swap: two real inputs",
                self.tx(
                    5,
                    self.spend(self.n_key, Auth::Key(self.ka)),
                    self.spend(self.n_key2, Auth::Key(self.kb)),
                    [150, 0],
                ),
            ),
            ("melt: 70 leaves the pool", self.tx(5, self.spend(self.n_key, Auth::Key(self.ka)), d(2), [30, 0])),
            (
                "timelock at its epoch",
                self.tx(
                    TIMELOCK_EPOCH,
                    self.spend(self.n_time, Auth::Timelock { key: self.ka, lock_epoch: TIMELOCK_EPOCH }),
                    d(3),
                    [70, 0],
                ),
            ),
            (
                "htlc claim before expiry",
                self.tx(HTLC_EXPIRY - 1, self.spend(self.n_htlc, self.claim(self.kb, self.preimage)), d(4), [80, 0]),
            ),
            (
                "htlc refund at expiry",
                self.tx(HTLC_EXPIRY, self.spend(self.n_htlc, self.refund(self.kc)), d(5), [80, 0]),
            ),
            (
                "multisig: first and third key",
                self.tx(
                    5,
                    self.spend(self.n_multi, self.multisig(vec![signer(self.ka, 0), signer(self.kc, 2)])),
                    d(6),
                    [90, 0],
                ),
            ),
        ]
    }

    /// Transactions that must be rejected.
    pub fn forged(&self) -> Vec<Named<TxWitness>> {
        let d = |s| self.dummy_spend(s);
        let signer = |key, slot| Signer { key, slot };
        let one = |epoch, note, auth, out| self.tx(epoch, self.spend(note, auth), d(9), [out, 0]);
        let stranger = note(100, self.ka.image(), PRED_KEY, fe(0), 60);
        let wrong_tweak = Key { spend_sk: self.ka.spend_sk, tweak: random_fe(31) };
        let mut misplaced = self.spend(self.n_key, Auth::Key(self.ka));
        misplaced.index ^= 1;
        vec![
            ("key: another key", one(5, self.n_key, Auth::Key(self.kb), 100)),
            ("key: right secret, wrong tweak", one(5, self.n_key, Auth::Key(wrong_tweak), 100)),
            (
                "membership: note was never appended",
                self.tx(
                    5,
                    Spend { note: stranger, index: 3, path: self.tree.path(3), auth: Auth::Key(self.ka) },
                    d(9),
                    [100, 0],
                ),
            ),
            ("membership: wrong leaf index", self.tx(5, misplaced, d(9), [100, 0])),
            (
                "predicate: timelocked note spent as a plain key note",
                one(TIMELOCK_EPOCH - 1, self.n_time, Auth::Key(self.ka), 70),
            ),
            (
                "timelock: one epoch early",
                one(
                    TIMELOCK_EPOCH - 1,
                    self.n_time,
                    Auth::Timelock { key: self.ka, lock_epoch: TIMELOCK_EPOCH },
                    70,
                ),
            ),
            (
                "timelock: claims an earlier lock",
                one(
                    TIMELOCK_EPOCH - 1,
                    self.n_time,
                    Auth::Timelock { key: self.ka, lock_epoch: TIMELOCK_EPOCH - 1 },
                    70,
                ),
            ),
            ("htlc claim: wrong preimage", one(5, self.n_htlc, self.claim(self.kb, random_fe(78)), 80)),
            ("htlc claim: not the receiver", one(5, self.n_htlc, self.claim(self.ka, self.preimage), 80)),
            ("htlc claim: at expiry", one(HTLC_EXPIRY, self.n_htlc, self.claim(self.kb, self.preimage), 80)),
            ("htlc refund: before expiry", one(HTLC_EXPIRY - 1, self.n_htlc, self.refund(self.kc), 80)),
            ("htlc refund: not the refund key", one(HTLC_EXPIRY, self.n_htlc, self.refund(self.kb), 80)),
            ("multisig: one signer of two", one(5, self.n_multi, self.multisig(vec![signer(self.ka, 0)]), 90)),
            (
                "multisig: the same signer twice",
                one(5, self.n_multi, self.multisig(vec![signer(self.ka, 0), signer(self.ka, 0)]), 90),
            ),
            (
                "multisig: a key that was not committed",
                one(5, self.n_multi, self.multisig(vec![signer(self.ka, 0), signer(key(9), 1)]), 90),
            ),
            (
                "multisig: a slot past the key count",
                one(5, self.n_multi, self.multisig(vec![signer(self.ka, 0), signer(key(9), 3)]), 90),
            ),
        ]
    }
}

impl Default for TxFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// A mint's state and both trees, advanced one operation at a time.
#[derive(Clone)]
pub struct OpWorld {
    pub notes: NoteTree,
    pub nullifiers: NullifierTree,
    pub state: State,
}

impl OpWorld {
    pub fn new() -> Self {
        let (notes, nullifiers) = (NoteTree::new(), NullifierTree::new());
        let state = State {
            epoch: 0,
            liabilities: 0,
            nullifier_root: nullifiers.root(),
            note_root: notes.root(),
            event_log: fe(0),
        };
        OpWorld { notes, nullifiers, state }
    }

    /// A world whose trees already hold `notes` notes and `nullifiers` nullifiers.
    pub fn prefilled(notes: u64, nullifiers: u64) -> Self {
        let mut world = Self::new();
        for i in 0..notes {
            world.notes.append(random_fe(50_000 + i)).unwrap();
        }
        for i in 0..nullifiers {
            world.nullifiers.insert(random_fe(60_000 + i)).unwrap();
        }
        world.state.note_root = world.notes.root();
        world.state.nullifier_root = world.nullifiers.root();
        world
    }

    /// Builds the next operation and advances the world past it.
    pub fn apply(&mut self, kind: Kind, amount: u64, event: Fp, nfs: &[Fp], cms: &[Fp]) -> OpWitness {
        let before = self.state;
        let mut w = OpWitness {
            kind,
            before,
            epoch_after: before.epoch + 1,
            amount,
            event,
            nullifiers: [None, None],
            notes: [None, None],
        };
        for (slot, nf) in nfs.iter().enumerate() {
            w.nullifiers[slot] = Some(self.nullifiers.insert(*nf).unwrap());
        }
        for (slot, cm) in cms.iter().enumerate() {
            w.notes[slot] = Some(self.notes.append(*cm).unwrap());
        }
        self.state = super::op::check(&w).expect("vector operations are valid").0;
        w
    }

    pub fn mint(&mut self, amount: u64, cms: &[Fp]) -> OpWitness {
        self.apply(Kind::Mint, amount, random_fe(amount + 70_000), &[], cms)
    }

    pub fn swap(&mut self, nfs: &[Fp], cms: &[Fp]) -> OpWitness {
        self.apply(Kind::Swap, 0, fe(0), nfs, cms)
    }

    pub fn melt(&mut self, amount: u64, nfs: &[Fp], cms: &[Fp]) -> OpWitness {
        self.apply(Kind::Melt, amount, random_fe(amount + 80_000), nfs, cms)
    }
}

impl Default for OpWorld {
    fn default() -> Self {
        Self::new()
    }
}

/// A chain of operations that satisfies the relation, from an empty mint.
pub fn valid_chain() -> Vec<OpWitness> {
    let mut world = OpWorld::new();
    vec![
        // A shielded mint: one note.
        world.mint(1_000, &[random_fe(1)]),
        // A full swap: two nullifiers, two notes.
        world.swap(&[random_fe(2), random_fe(3)], &[random_fe(4), random_fe(5)]),
        // A melt with change.
        world.melt(300, &[random_fe(6)], &[random_fe(7)]),
        // A legacy mint: liabilities and log only.
        world.mint(77, &[]),
        // A swap with one input and one output.
        world.swap(&[random_fe(8)], &[random_fe(9)]),
    ]
}

/// Operations that must be rejected, each starting from a valid state.
pub fn forged_ops() -> Vec<Named<OpWitness>> {
    let base = || {
        let mut world = OpWorld::prefilled(3, 3);
        world.mint(500, &[random_fe(11)]);
        world
    };
    let blank = |world: &OpWorld, kind| OpWitness {
        kind,
        before: world.state,
        epoch_after: world.state.epoch + 1,
        amount: 0,
        event: fe(0),
        nullifiers: [None, None],
        notes: [None, None],
    };
    let mut out = Vec::new();

    // The nullifier is inserted behind a leaf that is not its predecessor.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let (small, large) = {
        let (a, b) = (random_fe(60_000), random_fe(60_001));
        if super::less_than(&a, &b) { (a, b) } else { (b, a) }
    };
    let below_small = {
        // Any value under `small` that is not in the tree.
        let candidate = fe(12_345);
        assert!(super::less_than(&candidate, &small));
        candidate
    };
    let behind_large = world.nullifiers.index_of(&large).unwrap();
    w.nullifiers[0] = Some(world.nullifiers.insert_unchecked(below_small, behind_large));
    out.push(("nullifier: inserted out of order", w));

    // The same nullifier a second time, behind its own leaf.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let again = random_fe(60_002);
    let own = world.nullifiers.index_of(&again).unwrap();
    w.nullifiers[0] = Some(world.nullifiers.insert_unchecked(again, own));
    out.push(("nullifier: already spent", w));

    // A low leaf that was never in the tree.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let mut insert = world.nullifiers.insert(random_fe(21)).unwrap();
    insert.low.next_index += 1;
    w.nullifiers[0] = Some(insert);
    out.push(("nullifier: low leaf not in the tree", w));

    // A note written over an existing one.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    w.notes[0] = Some(world.notes.overwrite_unchecked(1, random_fe(22)));
    out.push(("note: overwrites an existing leaf", w));

    let world = base();
    let mut w = blank(&world, Kind::Mint);
    w.event = random_fe(23);
    out.push(("mint: zero amount", w));

    let world = base();
    let mut w = blank(&world, Kind::Melt);
    w.amount = world.state.liabilities + 1;
    w.event = random_fe(24);
    out.push(("melt: more than the liabilities", w));

    let mut world = base();
    world.state.epoch = 9;
    let mut w = blank(&world, Kind::Swap);
    w.epoch_after = 8;
    out.push(("epoch: goes backwards", w));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{op, tx};

    #[test]
    fn valid_vectors_satisfy_the_relations() {
        let fixture = TxFixture::new();
        for (name, w) in fixture.valid() {
            let statement = tx::check(&w).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(statement, tx::statement(&w), "{name}");
        }
        let chain = valid_chain();
        let statement = op::check_chain(&chain).unwrap();
        assert_eq!(statement.count, chain.len() as u64);
        assert_eq!(statement.liabilities_end, 1_000 - 300 + 77);
    }

    #[test]
    fn forged_vectors_break_the_relations() {
        let fixture = TxFixture::new();
        for (name, w) in fixture.forged() {
            assert!(tx::check(&w).is_err(), "{name} was accepted");
        }
        for (name, w) in forged_ops() {
            assert!(op::check(&w).is_err(), "{name} was accepted");
        }
    }

    #[test]
    fn shapes_and_orders() {
        let fixture = TxFixture::new();
        // A mint has no nullifiers and no anchor; a swap has two.
        let valid = fixture.valid();
        let mint = tx::statement(&valid[0].1);
        assert_eq!(mint.nullifiers, [fe(0); 2]);
        assert_eq!(mint.anchor, fe(0));
        let swap = tx::statement(&valid[1].1);
        assert!(swap.nullifiers.iter().all(|nf| *nf != fe(0)));
        assert_eq!(swap.balance, fe(0));
        assert_eq!(tx::statement(&valid[3].1).balance, fe(70));
        // The order is numeric, not byte-wise from the low end.
        assert!(crate::spec::less_than(&fe(200), &fe(9_000)));
    }
}
