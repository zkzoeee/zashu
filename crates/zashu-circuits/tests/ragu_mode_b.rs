//! Mode B shielded transactions and hidden predicates on the Ragu backend.
//! Run with: `cargo test --release -p zashu-circuits --test ragu_mode_b`
#![cfg(feature = "ragu")]

use group::Group;
use zashu_acc::{InclusionWitness, NoteAccumulator};
use zashu_circuits::mode_b::ragu_backend::{
    proof_epoch, prove_tx, prove_tx_unchecked, verify_tx, Balance, SpendInput,
};
use zashu_circuits::predicates::{
    compute_htlc_params, compute_p2pk_params, compute_timelock_params, htlc_hashlock, HtlcAction,
    PredicateWitness,
};
use zashu_circuits::FoldedProof;
use zashu_core::field::{fq_to_bytes, hash_bytes_to_fq, PallasPoint};
use zashu_core::stealth::PointBytesExt;
use zashu_core::types::{Note, NoteCommitment, Nullifier, PredicateId};

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = hash_bytes_to_fq(b"test-sk", &[seed]);
    let pk = (PallasPoint::generator() * sk).to_affine_bytes();
    (fq_to_bytes(&sk), pk)
}

fn note(value: u64, owner_pk: [u8; 32], id: PredicateId, params: [u8; 32], tag: u8) -> Note {
    Note {
        value,
        owner_pk,
        predicate_id: id as u8,
        predicate_params_hash: params,
        rho: [tag; 32],
        r: [tag.wrapping_add(100); 32],
    }
}

/// A proof attempt is "not accepted" if proving fails or the proof does not verify.
fn not_accepted(
    attempt: zashu_circuits::Result<FoldedProof>,
    anchor: &[u8; 32],
    nfs: &[Nullifier],
    cms: &[NoteCommitment],
    balance: Balance,
) -> bool {
    match attempt {
        Err(_) => true,
        Ok(proof) => verify_tx(&proof, Some(anchor), nfs, cms, balance).is_err(),
    }
}

struct World {
    acc: NoteAccumulator,
    anchor: [u8; 32],
}

impl World {
    fn new(notes: &[&Note]) -> (Self, Vec<InclusionWitness>) {
        let mut acc = NoteAccumulator::new(64);
        let idx: Vec<u64> = notes.iter().map(|n| acc.insert(n.commitment().0).unwrap()).collect();
        let anchor = acc.root();
        let witnesses = idx.iter().map(|i| acc.witness(*i).unwrap()).collect();
        (Self { acc, anchor }, witnesses)
    }
}

#[test]
fn mint_swap_and_melt_bind_notes_nullifiers_and_value() {
    let (sk_a, pk_a) = keypair(1);
    let (_, pk_b) = keypair(2);
    let n_in = note(137, pk_a, PredicateId::StandardSpend, [0u8; 32], 1);

    // Mint: one output, 137 enters the pool.
    let mint = prove_tx(&[0u8; 32], 0, &[], &[&n_in]).unwrap();
    verify_tx(&mint, None, &[], &[n_in.commitment()], Balance::In(137)).unwrap();
    assert!(verify_tx(&mint, None, &[], &[n_in.commitment()], Balance::In(138)).is_err());
    assert!(verify_tx(&mint, None, &[], &[n_in.commitment()], Balance::Zero).is_err());

    let (world, w) = World::new(&[&n_in]);
    assert!(!world.acc.is_empty());
    let anchor = world.anchor;
    let spend = PredicateWitness::StandardSpend { sk: sk_a };
    let input = || SpendInput { note: &n_in, witness: &w[0], predicate: &spend };

    // Swap 137 -> 100 + 37.
    let out1 = note(100, pk_b, PredicateId::StandardSpend, [0u8; 32], 2);
    let out2 = note(37, pk_a, PredicateId::StandardSpend, [0u8; 32], 3);
    let nfs = [n_in.nullifier()];
    let cms = [out1.commitment(), out2.commitment()];
    let swap = prove_tx(&anchor, 0, &[input()], &[&out1, &out2]).unwrap();
    verify_tx(&swap, Some(&anchor), &nfs, &cms, Balance::Zero).unwrap();
    assert_eq!(proof_epoch(&swap), Some(0));

    // Survives the wire encoding.
    let decoded = FoldedProof::from_base64(&swap.to_base64().unwrap()).unwrap();
    verify_tx(&decoded, Some(&anchor), &nfs, &cms, Balance::Zero).unwrap();

    // The statement is exactly these nullifiers, these outputs in this order, this anchor and balance.
    let other_nf = [out1.nullifier()];
    assert!(verify_tx(&swap, Some(&anchor), &other_nf, &cms, Balance::Zero).is_err());
    assert!(verify_tx(&swap, Some(&anchor), &[], &cms, Balance::Zero).is_err());
    assert!(verify_tx(&swap, Some(&anchor), &nfs, &[cms[1], cms[0]], Balance::Zero).is_err());
    assert!(verify_tx(&swap, Some(&anchor), &nfs, &cms[..1], Balance::Zero).is_err());
    assert!(verify_tx(&swap, Some(&[9u8; 32]), &nfs, &cms, Balance::Zero).is_err());
    assert!(verify_tx(&swap, Some(&anchor), &nfs, &cms, Balance::Out(1)).is_err());
    let mut forged = swap.clone();
    forged.public_inputs[3] = [0u8; 32];
    forged.public_inputs[1][0] = 7; // claim a different epoch
    assert!(verify_tx(&forged, Some(&anchor), &nfs, &cms, Balance::Zero).is_err());
    let mut corrupt = swap.clone();
    let mid = corrupt.ipa_proof.len() / 2;
    corrupt.ipa_proof[mid] ^= 1;
    assert!(verify_tx(&corrupt, Some(&anchor), &nfs, &cms, Balance::Zero).is_err());

    // Inflation: outputs worth one more than the input cannot verify as a swap.
    let out2_big = note(38, pk_a, PredicateId::StandardSpend, [0u8; 32], 3);
    let cms_big = [out1.commitment(), out2_big.commitment()];
    let inflate = prove_tx(&anchor, 0, &[input()], &[&out1, &out2_big]);
    assert!(not_accepted(inflate, &anchor, &nfs, &cms_big, Balance::Zero));

    // Melt 137 -> 100 out of the pool + 37 change.
    let melt = prove_tx(&anchor, 0, &[input()], &[&out2]).unwrap();
    verify_tx(&melt, Some(&anchor), &nfs, &[out2.commitment()], Balance::Out(100)).unwrap();
    assert!(verify_tx(&melt, Some(&anchor), &nfs, &[out2.commitment()], Balance::Out(101)).is_err());
}

#[test]
fn spends_are_rejected_by_the_circuits_without_key_membership_or_matching_predicate() {
    let (sk_a, pk_a) = keypair(1);
    let (sk_b, pk_b) = keypair(2);
    let standard = note(50, pk_a, PredicateId::StandardSpend, [0u8; 32], 1);
    // Owned by A but payable only to B's key.
    let p2pk = note(60, pk_a, PredicateId::P2PK, compute_p2pk_params(&pk_b), 2);
    let outsider = note(70, pk_a, PredicateId::StandardSpend, [0u8; 32], 3);
    let (world, w) = World::new(&[&standard, &p2pk]);
    let anchor = world.anchor;
    let out = |v| note(v, pk_b, PredicateId::StandardSpend, [0u8; 32], 9);

    // P2PK spent by the target key.
    let p2pk_ok = PredicateWitness::P2PK { target_sk: sk_b, target_pk: pk_b };
    let o60 = out(60);
    let proof = prove_tx(&anchor, 0, &[SpendInput { note: &p2pk, witness: &w[1], predicate: &p2pk_ok }], &[&o60])
        .unwrap();
    verify_tx(&proof, Some(&anchor), &[p2pk.nullifier()], &[o60.commitment()], Balance::Zero).unwrap();

    // Wrong key for a standard spend.
    let wrong_key = PredicateWitness::StandardSpend { sk: sk_b };
    let o50 = out(50);
    let attempt = prove_tx_unchecked(
        &anchor,
        0,
        &[SpendInput { note: &standard, witness: &w[0], predicate: &wrong_key }],
        &[&o50],
    );
    assert!(not_accepted(attempt, &anchor, &[standard.nullifier()], &[o50.commitment()], Balance::Zero));

    // The note's owner tries to skip the P2PK condition by using the standard-spend circuit.
    let bypass = PredicateWitness::StandardSpend { sk: sk_a };
    let attempt =
        prove_tx_unchecked(&anchor, 0, &[SpendInput { note: &p2pk, witness: &w[1], predicate: &bypass }], &[&o60]);
    assert!(not_accepted(attempt, &anchor, &[p2pk.nullifier()], &[o60.commitment()], Balance::Zero));

    // A note that was never inserted, presented with another note's Merkle path.
    let spend_a = PredicateWitness::StandardSpend { sk: sk_a };
    let o70 = out(70);
    let attempt = prove_tx_unchecked(
        &anchor,
        0,
        &[SpendInput { note: &outsider, witness: &w[0], predicate: &spend_a }],
        &[&o70],
    );
    assert!(not_accepted(attempt, &anchor, &[outsider.nullifier()], &[o70.commitment()], Balance::Zero));
}

#[test]
fn timelock_and_htlc_are_enforced_at_the_proven_epoch() {
    let (sk_a, pk_a) = keypair(1);
    let (sk_b, pk_b) = keypair(2);
    let preimage = [0x42u8; 32];
    let hashlock = htlc_hashlock(&preimage);

    let locked = note(40, pk_a, PredicateId::Timelock, compute_timelock_params(5, &pk_a), 1);
    // B can claim with the preimage; A can refund from epoch 10.
    let htlc = note(80, pk_b, PredicateId::PrivateHTLC, compute_htlc_params(&hashlock, &pk_b, &pk_a, 10), 2);
    let (world, w) = World::new(&[&locked, &htlc]);
    let anchor = world.anchor;
    let o40 = note(40, pk_b, PredicateId::StandardSpend, [0u8; 32], 8);
    let o80 = note(80, pk_a, PredicateId::StandardSpend, [0u8; 32], 9);

    // Timelock: not before epoch 5.
    let tl = PredicateWitness::Timelock { lock_epoch: 5, current_epoch: 5, sk: sk_a };
    let tl_in = || SpendInput { note: &locked, witness: &w[0], predicate: &tl };
    let (nf, cm) = ([locked.nullifier()], [o40.commitment()]);
    let early = prove_tx_unchecked(&anchor, 4, &[tl_in()], &[&o40]);
    assert!(not_accepted(early, &anchor, &nf, &cm, Balance::Zero));
    let on_time = prove_tx(&anchor, 5, &[tl_in()], &[&o40]).unwrap();
    verify_tx(&on_time, Some(&anchor), &nf, &cm, Balance::Zero).unwrap();
    // The mint compares this with its own epoch.
    assert_eq!(proof_epoch(&on_time), Some(5));

    // HTLC claim: receiver key plus preimage, any epoch.
    let htlc_w = |action| PredicateWitness::PrivateHTLC {
        hashlock,
        pk_receiver: pk_b,
        pk_refund: pk_a,
        expiry_epoch: 10,
        current_epoch: 10,
        action,
    };
    let (nf, cm) = ([htlc.nullifier()], [o80.commitment()]);
    let claim = htlc_w(HtlcAction::Claim { preimage, sk_receiver: sk_b });
    let proof = prove_tx(&anchor, 0, &[SpendInput { note: &htlc, witness: &w[1], predicate: &claim }], &[&o80])
        .unwrap();
    verify_tx(&proof, Some(&anchor), &nf, &cm, Balance::Zero).unwrap();

    // Wrong preimage.
    let bad_claim = htlc_w(HtlcAction::Claim { preimage: [0x43u8; 32], sk_receiver: sk_b });
    let attempt =
        prove_tx_unchecked(&anchor, 0, &[SpendInput { note: &htlc, witness: &w[1], predicate: &bad_claim }], &[&o80]);
    assert!(not_accepted(attempt, &anchor, &nf, &cm, Balance::Zero));

    // Refund: refund key, only once expired. Same nullifier as the claim path,
    // so the mint sees a double spend if both are tried.
    let refund = htlc_w(HtlcAction::Refund { sk_refund: sk_a });
    let refund_in = || SpendInput { note: &htlc, witness: &w[1], predicate: &refund };
    let early = prove_tx_unchecked(&anchor, 9, &[refund_in()], &[&o80]);
    assert!(not_accepted(early, &anchor, &nf, &cm, Balance::Zero));
    let proof = prove_tx(&anchor, 10, &[refund_in()], &[&o80]).unwrap();
    verify_tx(&proof, Some(&anchor), &nf, &cm, Balance::Zero).unwrap();
}

#[test]
fn ragu_mint_refuses_halo2_transaction_proofs() {
    use zashu_circuits::mode_b::{prove_zk_mint, verify_zk_mint};
    use zashu_circuits::SubcircuitId;
    use zashu_core::field::Fq;

    // No other test in this binary reads the backend variable.
    let (_, pk) = keypair(1);
    let n = note(21, pk, PredicateId::StandardSpend, [0u8; 32], 1);
    let blind = Fq::from(5u64);

    std::env::set_var("ZASHU_PCD_BACKEND", "halo2");
    let (cm, cv, halo2) = prove_zk_mint(&n, blind, 21).unwrap();
    assert_eq!(halo2.subcircuit, SubcircuitId::ZkMint);
    verify_zk_mint(&halo2, 21, &cm, &cv).unwrap();

    // Ragu is the default backend when nothing is set.
    std::env::remove_var("ZASHU_PCD_BACKEND");
    std::env::remove_var("ZASHU_FOLD_BACKEND");
    assert!(verify_zk_mint(&halo2, 21, &cm, &cv).is_err());
    let (cm, cv, ragu) = prove_zk_mint(&n, blind, 21).unwrap();
    assert_eq!(ragu.subcircuit, SubcircuitId::RaguTx);
    verify_zk_mint(&ragu, 21, &cm, &cv).unwrap();
    assert!(verify_zk_mint(&ragu, 22, &cm, &cv).is_err());
}
