//! Like-for-like timing of the Halo 2 and Ragu backends on the same workloads.
//!
//! `cargo run --release -p zashu-circuits --example bench_backends`
//!
//! Each figure is the best of `RUNS` runs after one warm-up (which also pays
//! key generation or the Ragu application build).

use std::time::Instant;

use ff::Field;
use group::Group;
use zashu_acc::NoteAccumulator;
use zashu_circuits::mode_a::{
    fold_mode_a_batch_with, prove_mint_step, verify_fold_batch, FoldBackend, PCD_BACKEND_ENV,
};
use zashu_circuits::mode_b::{
    balance_blinding, prove_zk_melt, prove_zk_mint, prove_zk_swap, verify_zk_melt, verify_zk_mint,
    verify_zk_swap, InputNoteWitness, OutputNoteWitness,
};
use zashu_circuits::predicates::{compute_htlc_params, htlc_hashlock, HtlcAction, PredicateWitness};
use zashu_circuits::FoldedProof;
use zashu_core::field::{fq_to_bytes, hash_bytes_to_fq, Fq, PallasPoint};
use zashu_core::pedersen::ValueCommitment;
use zashu_core::poseidon::hash_event_mint;
use zashu_core::stealth::PointBytesExt;
use zashu_core::types::{MintState, Note, PredicateId};

const RUNS: usize = 3;

fn best_ms<T>(mut f: impl FnMut() -> T) -> (f64, T) {
    let mut best = f64::MAX;
    let mut out = None;
    for _ in 0..RUNS {
        let t = Instant::now();
        let v = f();
        best = best.min(t.elapsed().as_secs_f64() * 1e3);
        out = Some(v);
    }
    (best, out.unwrap())
}

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = hash_bytes_to_fq(b"bench-sk", &[seed]);
    (fq_to_bytes(&sk), (PallasPoint::generator() * sk).to_affine_bytes())
}

fn note(value: u64, owner_pk: [u8; 32], id: PredicateId, params: [u8; 32], tag: u8) -> Note {
    Note { value, owner_pk, predicate_id: id as u8, predicate_params_hash: params, rho: [tag; 32], r: [tag + 100; 32] }
}

struct Row {
    name: String,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

fn row(name: impl Into<String>, prove_ms: f64, verify_ms: f64, proof: &FoldedProof) -> Row {
    Row { name: name.into(), prove_ms, verify_ms, proof_bytes: proof.ipa_proof.len() }
}

fn mode_a(backend: FoldBackend, batch: usize) -> Row {
    let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
    let mut cur = s0.clone();
    let mut steps = Vec::with_capacity(batch);
    for i in 0..batch {
        let prev = cur.clone();
        cur.epoch += 1;
        cur.total_liabilities += 1_000;
        cur.event_log_hash = hash_event_mint(&prev.event_log_hash, &[i as u8; 32], 1_000);
        steps.push(prove_mint_step(&prev, &cur, 1_000).unwrap().with_event([i as u8; 32]));
    }
    let (prove_ms, folded) = best_ms(|| fold_mode_a_batch_with(backend, &s0, &cur, &steps).unwrap());
    let (verify_ms, ()) = best_ms(|| verify_fold_batch(&folded, &s0.state_hash(), &cur).unwrap());
    row(format!("solvency fold, {batch} steps"), prove_ms, verify_ms, &folded)
}

fn mode_b() -> Vec<Row> {
    let mut rng = rand::rng();
    let (sk_a, pk_a) = keypair(1);
    let (sk_b, pk_b) = keypair(2);
    let std_params = [0u8; 32];
    let mut rows = Vec::new();

    // Mint one note.
    let n1 = note(137, pk_a, PredicateId::StandardSpend, std_params, 1);
    let b1 = Fq::random(&mut rng);
    let (prove_ms, (cm1, cv1, p)) = best_ms(|| prove_zk_mint(&n1, b1, 137).unwrap());
    let (verify_ms, ()) = best_ms(|| verify_zk_mint(&p, 137, &cm1, &cv1).unwrap());
    rows.push(row("shielded mint (1 output)", prove_ms, verify_ms, &p));

    // An HTLC note for B, claimable with the preimage.
    let preimage = [0x42u8; 32];
    let hashlock = htlc_hashlock(&preimage);
    let n_htlc = note(80, pk_b, PredicateId::PrivateHTLC, compute_htlc_params(&hashlock, &pk_b, &pk_a, 10), 2);
    let n2 = note(60, pk_a, PredicateId::StandardSpend, std_params, 3);

    let mut acc = NoteAccumulator::new(64);
    let i1 = acc.insert(cm1.0).unwrap();
    let i2 = acc.insert(n2.commitment().0).unwrap();
    let i3 = acc.insert(n_htlc.commitment().0).unwrap();
    let anchor = acc.root();
    let (w1, w2, w3) = (acc.witness(i1).unwrap(), acc.witness(i2).unwrap(), acc.witness(i3).unwrap());
    let spend_a = PredicateWitness::StandardSpend { sk: sk_a };

    // Swap 1 input -> 2 outputs.
    let o1 = note(100, pk_b, PredicateId::StandardSpend, std_params, 10);
    let o2 = note(37, pk_a, PredicateId::StandardSpend, std_params, 11);
    let bo1 = Fq::random(&mut rng);
    let bo2 = balance_blinding(&[b1], &[bo1]);
    let (prove_ms, (nfs, cms, out_cvs, p)) = best_ms(|| {
        prove_zk_swap(
            &anchor,
            &[InputNoteWitness { note: &n1, blind: b1, witness: &w1, predicate: &spend_a }],
            &[OutputNoteWitness { note: &o1, blind: bo1 }, OutputNoteWitness { note: &o2, blind: bo2 }],
        )
        .unwrap()
    });
    let in_cvs = [cv1];
    let (verify_ms, ()) = best_ms(|| verify_zk_swap(&p, &anchor, &nfs, &cms, &in_cvs, &out_cvs).unwrap());
    rows.push(row("shielded swap, 1 in / 2 out", prove_ms, verify_ms, &p));

    // Swap 2 inputs -> 2 outputs.
    let b2 = Fq::random(&mut rng);
    let cv2 = ValueCommitment::commit(n2.value, b2);
    let o3 = note(150, pk_b, PredicateId::StandardSpend, std_params, 12);
    let o4 = note(47, pk_a, PredicateId::StandardSpend, std_params, 13);
    let bo3 = Fq::random(&mut rng);
    let bo4 = balance_blinding(&[b1, b2], &[bo3]);
    let (prove_ms, (nfs, cms, out_cvs, p)) = best_ms(|| {
        prove_zk_swap(
            &anchor,
            &[
                InputNoteWitness { note: &n1, blind: b1, witness: &w1, predicate: &spend_a },
                InputNoteWitness { note: &n2, blind: b2, witness: &w2, predicate: &spend_a },
            ],
            &[OutputNoteWitness { note: &o3, blind: bo3 }, OutputNoteWitness { note: &o4, blind: bo4 }],
        )
        .unwrap()
    });
    let in_cvs = [cv1, cv2];
    let (verify_ms, ()) = best_ms(|| verify_zk_swap(&p, &anchor, &nfs, &cms, &in_cvs, &out_cvs).unwrap());
    rows.push(row("shielded swap, 2 in / 2 out", prove_ms, verify_ms, &p));

    // HTLC claim: 1 hidden-predicate input -> 1 output.
    let b3 = Fq::random(&mut rng);
    let claim = PredicateWitness::PrivateHTLC {
        hashlock,
        pk_receiver: pk_b,
        pk_refund: pk_a,
        expiry_epoch: 10,
        current_epoch: 0,
        action: HtlcAction::Claim { preimage, sk_receiver: sk_b },
    };
    let o5 = note(80, pk_b, PredicateId::StandardSpend, std_params, 14);
    let (prove_ms, (nfs, cms, out_cvs, p)) = best_ms(|| {
        prove_zk_swap(
            &anchor,
            &[InputNoteWitness { note: &n_htlc, blind: b3, witness: &w3, predicate: &claim }],
            &[OutputNoteWitness { note: &o5, blind: b3 }],
        )
        .unwrap()
    });
    let in_cvs = [ValueCommitment::commit(80, b3)];
    let (verify_ms, ()) = best_ms(|| verify_zk_swap(&p, &anchor, &nfs, &cms, &in_cvs, &out_cvs).unwrap());
    rows.push(row("HTLC claim, 1 in / 1 out", prove_ms, verify_ms, &p));

    // Melt 137 -> 100 out + 37 change.
    let change = note(37, pk_a, PredicateId::StandardSpend, std_params, 15);
    let bc = Fq::random(&mut rng);
    let (prove_ms, (nfs, ch, p)) = best_ms(|| {
        prove_zk_melt(
            &anchor,
            &[InputNoteWitness { note: &n1, blind: b1, witness: &w1, predicate: &spend_a }],
            100,
            Some((&change, bc)),
        )
        .unwrap()
    });
    let ch_cm = ch.map(|c| c.0);
    let (verify_ms, ()) = best_ms(|| verify_zk_melt(&p, &anchor, 100, ch_cm.as_ref(), &nfs).unwrap());
    rows.push(row("shielded melt, 1 in + change", prove_ms, verify_ms, &p));

    rows
}

/// Cost of folding one mint operation with the default, root-binding Ragu
/// fold: each row is a single operation on live accumulators.
fn bound_fold_ops() {
    use zashu_acc::NullifierAccumulator;
    use zashu_circuits::mode_a::{prove_melt_step, prove_swap_step};
    use zashu_core::field::{fp_from_u64, fp_to_bytes};
    use zashu_core::poseidon::hash_event_melt;

    let fe = |v: u64| fp_to_bytes(&fp_from_u64(v));
    let (mut notes, mut nfs) = (NoteAccumulator::new(64), NullifierAccumulator::new());
    let genesis = MintState::genesis(nfs.root(), notes.root());
    let mut state = genesis.clone();
    let time = |name: &str, start: &MintState, end: &MintState, step: FoldedProof| {
        let mut cells = Vec::new();
        for backend in [FoldBackend::Ragu, FoldBackend::RaguAggregated] {
            let t = Instant::now();
            let folded = fold_mode_a_batch_with(backend, start, end, &[step.clone()]).unwrap();
            let fold_ms = t.elapsed().as_secs_f64() * 1e3;
            let t = Instant::now();
            verify_fold_batch(&folded, &start.state_hash(), end).unwrap();
            let verify_ms = t.elapsed().as_secs_f64() * 1e3;
            cells.push(format!("{fold_ms:.0} ms | {verify_ms:.0} ms | {} B", folded.ipa_proof.len()));
        }
        println!("| {name} | {} |", cells.join(" | "));
    };
    println!("\n| One operation | Ragu fold | verify | proof | Aggregated fold | verify | proof |");
    println!("| :--- | ---: | ---: | ---: | ---: | ---: | ---: |");

    // Warm-up builds the application.
    let prev = state.clone();
    state.epoch += 1;
    let warm = prove_swap_step(&prev, &state, 0, 0, &[]).unwrap();
    fold_mode_a_batch_with(FoldBackend::Ragu, &prev, &state, &[warm.clone()]).unwrap();
    let t = Instant::now();
    fold_mode_a_batch_with(FoldBackend::RaguAggregated, &prev, &state, &[warm.clone()]).unwrap();
    eprintln!("[ragu-aggregated] first fold, including application build: {:.1} s", t.elapsed().as_secs_f64());
    time("value step only (epoch advance)", &prev, &state, warm);

    let prev = state.clone();
    let note = notes.insert_recorded(fe(101)).unwrap();
    state.epoch += 1;
    state.total_liabilities += 1_000;
    state.note_acc_root = notes.root();
    state.event_log_hash = hash_event_mint(&prev.event_log_hash, &[1u8; 32], 1_000);
    let step = prove_mint_step(&prev, &state, 1_000).unwrap().with_event([1u8; 32]).with_root_updates(vec![], vec![note]);
    time("shielded mint: value + 1 note insert", &prev, &state, step);

    let prev = state.clone();
    let nf = vec![nfs.insert(fe(200)).unwrap()];
    let outs = vec![notes.insert_recorded(fe(102)).unwrap(), notes.insert_recorded(fe(103)).unwrap()];
    state.epoch += 1;
    state.nullifier_acc_root = nfs.root();
    state.note_acc_root = notes.root();
    let step = prove_swap_step(&prev, &state, 0, 0, &nf).unwrap().with_root_updates(nf, outs);
    time("shielded swap: value + 1 nullifier + 2 note inserts", &prev, &state, step);

    let prev = state.clone();
    let nf = vec![nfs.insert(fe(100)).unwrap()];
    state.epoch += 1;
    state.total_liabilities -= 300;
    state.nullifier_acc_root = nfs.root();
    state.event_log_hash = hash_event_melt(&prev.event_log_hash, &[3u8; 32], 300);
    let step = prove_melt_step(&prev, &state, 300).unwrap().with_event([3u8; 32]).with_root_updates(nf, vec![]);
    time("shielded melt: value + 1 nullifier insert", &prev, &state, step);
}

fn run(backend: FoldBackend, label: &str, batches: &[usize]) -> Vec<Row> {
    std::env::set_var(PCD_BACKEND_ENV, label);
    // Warm-up: key generation / application build is a one-time cost.
    let t = Instant::now();
    let _ = mode_a(backend, 1);
    let _ = mode_b();
    eprintln!("[{label}] warm-up (includes one-time setup): {:.1} s", t.elapsed().as_secs_f64());

    let mut rows: Vec<Row> = batches.iter().map(|b| mode_a(backend, *b)).collect();
    rows.extend(mode_b());
    rows
}

fn main() {
    if std::env::args().any(|a| a == "--bound-fold-only") {
        bound_fold_ops();
        return;
    }
    let halo2 = run(FoldBackend::Halo2, "halo2", &[1, 16, 64]);
    let ragu = run(FoldBackend::Ragu, "ragu", &[1, 16, 64]);

    println!("| Workload | Halo 2 prove | Ragu prove | Slowdown | Halo 2 verify | Ragu verify | Halo 2 proof | Ragu proof |");
    println!("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (h, r) in halo2.iter().zip(&ragu) {
        assert_eq!(h.name, r.name);
        println!(
            "| {} | {:.0} ms | {:.0} ms | {:.0}x | {:.1} ms | {:.1} ms | {} B | {} B |",
            h.name,
            h.prove_ms,
            r.prove_ms,
            r.prove_ms / h.prove_ms,
            h.verify_ms,
            r.verify_ms,
            h.proof_bytes,
            r.proof_bytes
        );
    }
    bound_fold_ops();
}
