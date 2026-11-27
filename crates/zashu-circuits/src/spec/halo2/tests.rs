use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{ConstraintSystem, Error};
use zashu_core::spec::hash::{h, node, T_MULTISIG, T_NODE, T_PK, T_STATE};
use zashu_core::spec::less_than;
use zashu_core::spec::note::{
    hashlock, htlc_params, multisig_params, timelock_params, Auth, Key, Note, Signer, PRED_HTLC, PRED_KEY,
    PRED_MULTISIG, PRED_TIMELOCK,
};
use zashu_core::spec::op::Kind;
use zashu_core::spec::tree::{IndexedLeaf, NoteTree};
use zashu_core::spec::tx::Spend;
use zashu_core::spec::vectors::{fe, forged_ops, key, random_fe, valid_chain, OpWorld, TxFixture};

use super::gadgets::{split, Ctx, SpecConfig};
use ff::PrimeField;
use super::*;

/// `H_tag(inputs)` and a few gadget outputs, exposed as public values.
#[derive(Clone, Default)]
struct GadgetCircuit {
    hashes: Vec<(u64, Vec<Fp>)>,
    /// `(a, b)`: exposes `a < b` as integers in `[0, p)`.
    orders: Vec<(Fp, Fp)>,
}

impl Circuit<Fp> for GadgetCircuit {
    type Config = SpecConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> SpecConfig {
        SpecConfig::configure(meta, 2)
    }

    fn synthesize(&self, cfg: SpecConfig, layouter: impl Layouter<Fp>) -> core::result::Result<(), Error> {
        let mut cx = Ctx::new(&cfg, layouter);
        let mut row = 0;
        for (tag, inputs) in &self.hashes {
            let cells =
                inputs.iter().map(|v| cx.witness(Value::known(*v))).collect::<core::result::Result<Vec<_>, _>>()?;
            let out = cx.sponge(*tag, &cells)?;
            cx.expose(&out, row)?;
            row += 1;
        }
        for (a, b) in &self.orders {
            let a = cx.witness(Value::known(*a))?;
            let b = cx.witness(Value::known(*b))?;
            let (a, b) = (cx.canonical(&a)?, cx.canonical(&b)?);
            let out = cx.lt_limbs(&a, &b)?;
            cx.expose(&out, row)?;
            row += 1;
        }
        Ok(())
    }
}

#[test]
fn sponge_matches_the_reference() {
    let x: Vec<Fp> = (1..=6).map(random_fe).collect();
    let hashes = vec![
        (T_PK, x[..1].to_vec()),
        (T_NODE, x[..2].to_vec()),
        (T_STATE, x[..5].to_vec()),
        (T_MULTISIG, x[..6].to_vec()),
    ];
    let mut public: Vec<Fp> = hashes.iter().map(|(tag, inputs)| h(*tag, inputs)).collect();
    let circuit = GadgetCircuit { hashes, orders: vec![] };
    MockProver::run(11, &circuit, vec![public.clone()]).unwrap().assert_satisfied();
    public[2] += Fp::ONE;
    assert!(MockProver::run(11, &circuit, vec![public]).unwrap().verify().is_err());
}

/// Decomposes `x` into the given limbs.
#[derive(Clone)]
struct LimbCircuit {
    x: Fp,
    limbs: (u128, u128),
}

impl Circuit<Fp> for LimbCircuit {
    type Config = SpecConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> SpecConfig {
        SpecConfig::configure(meta, 1)
    }

    fn synthesize(&self, cfg: SpecConfig, layouter: impl Layouter<Fp>) -> core::result::Result<(), Error> {
        let mut cx = Ctx::new(&cfg, layouter);
        let x = cx.witness(Value::known(self.x))?;
        cx.canonical_from(&x, Value::known(self.limbs))?;
        Ok(())
    }
}

/// A prover cannot use the limbs of `x + p` for `x`, which would turn the
/// order of the nullifier tree around.
#[test]
fn limbs_are_canonical() {
    let run = |x: Fp, limbs| MockProver::run(9, &LimbCircuit { x, limbs }, vec![vec![]]).unwrap().verify().is_ok();
    let (max_hi, max_lo) = split(&-Fp::ONE);
    for x in [Fp::ZERO, Fp::from(5), random_fe(1), -Fp::ONE] {
        assert!(run(x, split(&x)));
    }
    // x + p for x = 0 and x = 5: equal to x in the field, and both limbs fit.
    assert!(!run(Fp::ZERO, (max_hi, max_lo + 1)));
    assert!(!run(Fp::from(5), (max_hi, max_lo + 6)));
    // x + p with a carry into the high limb.
    let x = Fp::from_u128(u128::MAX);
    assert!(run(x, (0, u128::MAX)));
    assert!(!run(x, (max_hi + 1, max_lo)));
    // Limbs of another value.
    assert!(!run(Fp::from(5), (0, 6)));
}

#[test]
fn order_matches_the_reference() {
    let max = -Fp::ONE;
    let two_128 = Fp::from(2).pow_vartime([128]);
    let orders = vec![
        (Fp::ZERO, Fp::ONE),
        (Fp::ONE, Fp::ZERO),
        (Fp::ZERO, Fp::ZERO),
        (max, Fp::ZERO),
        (Fp::ZERO, max),
        (max - Fp::ONE, max),
        (two_128, two_128 - Fp::ONE),
        (two_128 - Fp::ONE, two_128),
        (random_fe(1), random_fe(2)),
        (random_fe(2), random_fe(1)),
    ];
    let public: Vec<Fp> =
        orders.iter().map(|(a, b)| Fp::from(zashu_core::spec::less_than(a, b) as u64)).collect();
    let circuit = GadgetCircuit { hashes: vec![], orders };
    MockProver::run(12, &circuit, vec![public]).unwrap().assert_satisfied();
}

/// Whether the transaction circuit is satisfied by `w` with the public
/// inputs `w` claims.
fn tx_mock(w: &TxWitness) -> bool {
    let Ok(assign) = tx_circuit::TxAssign::new(w) else { return false };
    let circuit = TxCircuit { w: Value::known(assign) };
    let public = tx::statement(w).public_inputs().to_vec();
    MockProver::run(TX_K, &circuit, vec![public]).unwrap().verify().is_ok()
}

fn op_mock(w: &OpWitness) -> bool {
    let circuit = OpCircuit { w: Value::known(op_circuit::OpAssign::new(w)) };
    let public = op::claimed(w).1.public_inputs().to_vec();
    MockProver::run(OP_K, &circuit, vec![public]).unwrap().verify().is_ok()
}

#[test]
fn transaction_constraints_follow_the_vectors() {
    let fixture = TxFixture::new();
    for (name, w) in fixture.valid() {
        assert!(tx_mock(&w), "rejected: {name}");
    }
    for (name, w) in fixture.forged() {
        assert!(!tx_mock(&w), "accepted: {name}");
    }
}

#[test]
fn operation_constraints_follow_the_vectors() {
    for (i, w) in valid_chain().iter().enumerate() {
        assert!(op_mock(w), "rejected: operation {i}");
    }
    for (name, w) in forged_ops() {
        assert!(!op_mock(&w), "accepted: {name}");
    }
}

/// A transaction spending one note of `value` under `auth`, from a tree
/// holding just that note.
fn spend_of(value: u64, owner: Fp, predicate: u64, params: Fp, auth: Auth, epoch: u64) -> TxWitness {
    let fixture = TxFixture::new();
    let note = Note { value, owner, predicate, params, rho: random_fe(901), r: random_fe(902) };
    let mut tree = NoteTree::new();
    tree.append(random_fe(903)).unwrap();
    let index = tree.append(note.commitment()).unwrap().index;
    TxWitness {
        anchor: tree.root(),
        epoch,
        inputs: Some([Spend { note, index, path: tree.path(index), auth }, fixture.dummy_spend(7)]),
        outputs: [fixture.output(value, 1), fixture.output(0, 2)],
    }
}

/// Cases beyond the shared vectors: the circuit accepts exactly what the
/// reference checker accepts.
#[test]
fn transaction_constraints_agree_with_the_checker() {
    let k: Vec<Key> = (11..=14).map(key).collect();
    let images: Vec<Fp> = k.iter().map(Key::image).collect();
    let all = [images[0], images[1], images[2], images[3]];
    let zero = Fp::ZERO;
    let signer = |i: usize, slot: usize| Signer { key: k[i], slot };

    // (name, committed threshold, committed count, claimed threshold, signers, accepted)
    let multisigs: Vec<(&str, u64, u64, u64, Vec<Signer>, bool)> = vec![
        ("3 of 4", 3, 4, 3, vec![signer(0, 0), signer(1, 1), signer(3, 3)], true),
        ("1 of 1", 1, 1, 1, vec![signer(0, 0)], true),
        ("1 of 4, last key", 1, 4, 1, vec![signer(3, 3)], true),
        ("2 of 2", 2, 2, 2, vec![signer(0, 0), signer(1, 1)], true),
        ("slots out of order", 2, 4, 2, vec![signer(3, 3), signer(1, 1)], false),
        ("more signers than the threshold", 1, 3, 1, vec![signer(0, 0), signer(1, 1)], false),
        ("claimed threshold is not the committed one", 2, 3, 1, vec![signer(0, 0)], false),
        ("fewer keys than the threshold", 2, 1, 2, vec![signer(0, 0), signer(1, 1)], false),
        ("five keys", 1, 5, 1, vec![signer(0, 0)], false),
        ("threshold zero", 0, 1, 0, vec![], false),
        ("four signers", 4, 4, 4, vec![signer(0, 0), signer(1, 1), signer(2, 2), signer(3, 3)], false),
        ("slot past the count", 2, 3, 2, vec![signer(0, 0), signer(3, 3)], false),
        ("slot past the keys", 1, 4, 1, vec![signer(0, 7)], false),
        ("a key in the wrong slot", 2, 4, 2, vec![signer(0, 0), signer(1, 2)], false),
    ];
    let mut cases: Vec<(String, TxWitness, bool)> = multisigs
        .into_iter()
        .map(|(name, t, n, claimed, signers, ok)| {
            let auth = Auth::Multisig { threshold: claimed, key_count: n, keys: all, signers };
            let w = spend_of(90, zero, PRED_MULTISIG, multisig_params(t, n, &all), auth, 5);
            (format!("multisig: {name}"), w, ok)
        })
        .collect();

    let max = u64::MAX;
    let mut push = |name: &str, w: TxWitness, ok: bool| cases.push((name.to_string(), w, ok));
    push("key: non-zero params", spend_of(5, images[0], PRED_KEY, fe(1), Auth::Key(k[0]), 5), false);
    push("key: the largest value", spend_of(max, images[0], PRED_KEY, zero, Auth::Key(k[0]), 5), true);
    push("key: an unknown predicate id", spend_of(5, images[0], 4, zero, Auth::Key(k[0]), 5), false);
    let lock = |lock_epoch: u64, epoch: u64| {
        let auth = Auth::Timelock { key: k[0], lock_epoch };
        spend_of(5, images[0], PRED_TIMELOCK, timelock_params(lock_epoch), auth, epoch)
    };
    push("timelock: long after", lock(3, max), true);
    push("timelock: the last epoch", lock(max, max), true);
    push("timelock: the last epoch, early", lock(max, max - 1), false);
    push("timelock: lock zero", lock(0, 0), true);
    let preimage = random_fe(905);
    let htlc = |expiry: u64| htlc_params(hashlock(preimage), images[0], images[1], expiry);
    let claim = |refund: Fp, expiry: u64, epoch: u64| {
        let auth = Auth::HtlcClaim { key: k[0], preimage, refund, expiry_epoch: expiry };
        spend_of(5, zero, PRED_HTLC, htlc(expiry), auth, epoch)
    };
    let refund = |key: Key, receiver: Fp, expiry: u64, epoch: u64| {
        let auth = Auth::HtlcRefund { key, hashlock: hashlock(preimage), receiver, expiry_epoch: expiry };
        spend_of(5, zero, PRED_HTLC, htlc(expiry), auth, epoch)
    };
    push("htlc claim: just before the last epoch", claim(images[1], max, max - 1), true);
    push("htlc claim: another refund key", claim(images[2], 20, 5), false);
    push("htlc claim: expiry zero", claim(images[1], 0, 0), false);
    push("htlc refund: expiry zero", refund(k[1], images[0], 0, 0), true);
    push("htlc refund: another receiver", refund(k[1], images[2], 20, 25), false);
    push("htlc refund: by the receiver", refund(k[0], images[0], 20, 25), false);

    // A mint of the largest values: the balance wraps in the field only.
    let fixture = TxFixture::new();
    let mint = TxWitness {
        anchor: fe(9),
        epoch: max,
        inputs: None,
        outputs: [fixture.output(max, 1), fixture.output(max, 2)],
    };
    push("mint: largest outputs, stray anchor", mint, true);

    for (name, w, expected) in cases {
        assert_eq!(tx::check(&w).is_ok(), expected, "the reference disagrees on: {name}");
        assert_eq!(tx_mock(&w), expected, "the circuit disagrees on: {name}");
    }
}

fn blank(world: &OpWorld, kind: Kind) -> OpWitness {
    OpWitness {
        kind,
        before: world.state,
        epoch_after: world.state.epoch,
        amount: 0,
        event: fe(0),
        nullifiers: [None, None],
        notes: [None, None],
    }
}

#[test]
fn operation_constraints_agree_with_the_checker() {
    let base = || {
        let mut world = OpWorld::prefilled(3, 3);
        world.mint(500, &[random_fe(11)]);
        world
    };
    let mut cases: Vec<(&str, OpWitness, bool)> = Vec::new();

    // Only the second slots in use, and the epoch standing still.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    w.nullifiers[1] = Some(world.nullifiers.insert(random_fe(21)).unwrap());
    w.notes[1] = Some(world.notes.append(random_fe(22)).unwrap());
    w.amount = 7;
    cases.push(("swap: second slots only, stray amount", w, true));

    // Below every nullifier (the low leaf is the sentinel) and above every
    // one (the low leaf is the last).
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    w.nullifiers[0] = Some(world.nullifiers.insert(fe(5)).unwrap());
    w.nullifiers[1] = Some(world.nullifiers.insert(-Fp::ONE).unwrap());
    cases.push(("nullifiers: the smallest and the largest", w, true));

    // Above the low leaf's successor.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    w.nullifiers[0] = Some(world.nullifiers.insert_unchecked(-Fp::ONE, 0));
    cases.push(("nullifier: above the successor", w, false));

    // Equal to the low leaf's successor.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let mut values = [random_fe(60_000), random_fe(60_001), random_fe(60_002)];
    values.sort_by(|a, b| if less_than(a, b) { core::cmp::Ordering::Less } else { core::cmp::Ordering::Greater });
    w.nullifiers[0] = Some(world.nullifiers.insert_unchecked(values[0], 0));
    cases.push(("nullifier: equal to the successor", w, false));

    // Zero is the sentinel.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    w.nullifiers[0] = Some(world.nullifiers.insert_unchecked(Fp::ZERO, 0));
    cases.push(("nullifier: zero", w, false));

    // The new leaf lands on one that is taken.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let mut insert = world.nullifiers.insert(random_fe(21)).unwrap();
    insert.new_index = 1;
    w.nullifiers[0] = Some(insert);
    cases.push(("nullifier: new leaf is not empty", w, false));

    // Index bits above the tree depth do not choose a leaf, but those of
    // the new nullifier leaf are hashed into the low leaf.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let mut insert = world.nullifiers.insert(random_fe(21)).unwrap();
    insert.low_index |= 1 << 63;
    insert.new_index |= 1 << 40;
    // The re-pointed low leaf now hashes differently, and it sits under one
    // sibling of the new leaf's path.
    let repointed = IndexedLeaf { value: insert.low.value, next_value: insert.nf, next_index: insert.new_index };
    let meet = (63 - ((insert.low_index ^ insert.new_index) & 0xFF_FFFF).leading_zeros()) as usize;
    let mut subtree = repointed.hash();
    for level in 0..meet {
        let sibling = insert.low_path[level];
        subtree =
            if (insert.low_index >> level) & 1 == 0 { node(subtree, sibling) } else { node(sibling, subtree) };
    }
    insert.new_path[meet] = subtree;
    let mut append = world.notes.append(random_fe(22)).unwrap();
    append.index |= 1 << 24;
    w.nullifiers[0] = Some(insert);
    w.notes[0] = Some(append);
    cases.push(("indices: high bits", w, true));

    // The same, without fixing the path: the low leaf does not point at
    // the index the new leaf claims.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let mut insert = world.nullifiers.insert(random_fe(21)).unwrap();
    insert.new_index |= 1 << 40;
    w.nullifiers[0] = Some(insert);
    cases.push(("nullifier: new index differs above the depth", w, false));

    // The second insert must follow the first.
    let mut world = base();
    let mut w = blank(&world, Kind::Swap);
    let first = world.nullifiers.insert(random_fe(21)).unwrap();
    let second = world.nullifiers.insert(random_fe(23)).unwrap();
    w.nullifiers = [Some(second), Some(first)];
    cases.push(("nullifiers: applied in the wrong order", w, false));

    let mut world = base();
    world.state.liabilities = u64::MAX;
    world.state.epoch = u64::MAX;
    let mut w = blank(&world, Kind::Mint);
    w.amount = 1;
    cases.push(("mint: liabilities overflow", w.clone(), false));
    w.kind = Kind::Melt;
    w.amount = u64::MAX;
    cases.push(("melt: everything, at the last epoch", w.clone(), true));
    w.amount = 0;
    cases.push(("melt: zero amount", w, false));

    for (name, w, expected) in cases {
        assert_eq!(op::check(&w).is_ok(), expected, "the reference disagrees on: {name}");
        assert_eq!(op_mock(&w), expected, "the circuit disagrees on: {name}");
    }
}

/// The documented sizes, and that neither circuit fits one `k` lower.
#[test]
fn sizes_are_as_documented() {
    let (tx, op) = (tx_circuit_rows(), op_circuit_rows());
    println!("transaction: k = {TX_K}, {TX_CHIPS} chips, {tx:?}");
    println!("operation:   k = {OP_K}, {OP_CHIPS} chips, {op:?}");
    assert_eq!(tx, Rows { poseidon: 1982, range: 153, arithmetic: 376 });
    assert_eq!(op, Rows { poseidon: 3476, range: 1214, arithmetic: 289 });
    assert!(MockProver::run(TX_K - 1, &TxCircuit::default(), vec![vec![]]).is_err());
    assert!(MockProver::run(OP_K - 1, &OpCircuit::default(), vec![vec![]]).is_err());
}

fn time_config<C: Circuit<Fp> + Clone>(name: &str, k: u32, empty: &C, circuit: C, public: &[Fp]) {
    use std::time::Instant;
    let t = Instant::now();
    let keys = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| keygen(k, empty))) {
        Ok(keys) => keys,
        Err(_) => return println!("{name} k={k}: does not fit"),
    };
    let keygen_time = t.elapsed();
    let mut best = (std::time::Duration::MAX, std::time::Duration::MAX);
    let mut size = 0;
    for _ in 0..3 {
        let t = Instant::now();
        let proof = prove(&keys, circuit.clone(), public).unwrap();
        let proving = t.elapsed();
        let t = Instant::now();
        verify(&keys, public, &proof).unwrap();
        best = (best.0.min(proving), best.1.min(t.elapsed()));
        size = proof.len();
    }
    println!("{name} k={k}: keygen {keygen_time:?}, prove {:?}, verify {:?}, {size} bytes", best.0, best.1);
}

/// Compares chip counts. Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn compare_layouts() {
    let fixture = TxFixture::new();
    let w = &fixture.valid()[2].1;
    let public = tx::statement(w).public_inputs();
    let assign = tx_circuit::TxAssign::new(w).unwrap();
    macro_rules! tx_layout {
        ($chips:literal, $k:literal) => {
            time_config(
                concat!("tx chips=", $chips),
                $k,
                &tx_circuit::TxCircuit::<$chips>::default(),
                tx_circuit::TxCircuit::<$chips> { w: Value::known(assign.clone()) },
                &public,
            )
        };
    }
    tx_layout!(1, 13);
    tx_layout!(2, 12);
    tx_layout!(3, 11);
    tx_layout!(4, 11);
    tx_layout!(8, 10);

    let w = &valid_chain()[1];
    let public = op::claimed(w).1.public_inputs();
    let assign = op_circuit::OpAssign::new(w);
    macro_rules! op_layout {
        ($chips:literal, $k:literal) => {
            time_config(
                concat!("op chips=", $chips),
                $k,
                &op_circuit::OpCircuit::<$chips>::default(),
                op_circuit::OpCircuit::<$chips> { w: Value::known(assign.clone()) },
                &public,
            )
        };
    }
    op_layout!(1, 15);
    op_layout!(2, 14);
    op_layout!(3, 13);
    op_layout!(6, 12);
    op_layout!(11, 11);
}
