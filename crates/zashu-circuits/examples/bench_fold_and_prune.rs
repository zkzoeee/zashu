use std::collections::HashSet;
use std::time::Instant;

use zashu_acc::NullifierAccumulator;
use zashu_circuits::mode_a::{fold_mode_a_batch, prove_mint_step, verify_fold_batch};
use zashu_core::poseidon::hash_event_mint;
use zashu_core::types::MintState;

/// One shielded swap (1 standard input, 2 outputs) on the Ragu backend.
#[cfg(feature = "ragu")]
fn bench_ragu_tx() {
    use group::Group;
    use zashu_acc::NoteAccumulator;
    use zashu_circuits::mode_b::ragu_backend::{prove_tx, verify_tx, Balance, SpendInput};
    use zashu_circuits::predicates::PredicateWitness;
    use zashu_core::field::{fq_to_bytes, hash_bytes_to_fq, PallasPoint};
    use zashu_core::stealth::PointBytesExt;
    use zashu_core::types::Note;

    let sk = hash_bytes_to_fq(b"bench-sk", &[1]);
    let pk = (PallasPoint::generator() * sk).to_affine_bytes();
    let note = |value, tag: u8| Note {
        value,
        owner_pk: pk,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [tag; 32],
        r: [tag + 1; 32],
    };
    let (input, out1, out2) = (note(137, 1), note(100, 3), note(37, 5));
    let mut acc = NoteAccumulator::new(16);
    let idx = acc.insert(input.commitment().0).unwrap();
    let (anchor, witness) = (acc.root(), acc.witness(idx).unwrap());
    let predicate = PredicateWitness::StandardSpend { sk: fq_to_bytes(&sk) };
    let spend = || SpendInput { note: &input, witness: &witness, predicate: &predicate };

    // The first proof also builds the application (one-time).
    let t = Instant::now();
    prove_tx(&anchor, 0, &[spend()], &[&out1, &out2]).unwrap();
    let first_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let proof = prove_tx(&anchor, 0, &[spend()], &[&out1, &out2]).unwrap();
    let prove_ms = t.elapsed().as_millis();
    let t = Instant::now();
    verify_tx(&proof, Some(&anchor), &[input.nullifier()], &[out1.commitment(), out2.commitment()], Balance::Zero)
        .unwrap();
    let verify_ms = t.elapsed().as_millis();
    println!(
        "ragu_tx 1-in 2-out | first_prove={first_ms}ms | prove={prove_ms}ms | verify={verify_ms}ms | proof={} bytes",
        proof.ipa_proof.len()
    );
}

fn main() {
    println!("=== Zashu Task A.5 Benchmarks ===");
    println!(
        "fold backend: {:?}",
        zashu_circuits::mode_a::FoldBackend::from_env().unwrap()
    );
    #[cfg(feature = "ragu")]
    bench_ragu_tx();

    for &batch_size in &[1usize, 16, 64] {
        let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
        let mut cur = s0.clone();
        let mut steps = Vec::with_capacity(batch_size);

        let t_prove = Instant::now();
        for i in 0..batch_size {
            let prev = cur.clone();
            cur.epoch += 1;
            cur.total_liabilities += 1_000;
            cur.event_log_hash = hash_event_mint(&prev.event_log_hash, &[i as u8; 32], 1_000);
            steps.push(prove_mint_step(&prev, &cur, 1_000).unwrap().with_event([i as u8; 32]));
        }
        let step_ms = t_prove.elapsed().as_millis();

        let t_fold = Instant::now();
        let folded = fold_mode_a_batch(&s0, &cur, &steps).unwrap();
        let fold_ms = t_fold.elapsed().as_millis();

        let proof_bytes = folded.to_base64().unwrap().len();

        let t_ver = Instant::now();
        verify_fold_batch(&folded, &s0.state_hash(), &cur).unwrap();
        let ver_ms = t_ver.elapsed().as_millis();

        println!(
            "batch={batch_size:3} | step_prove={step_ms:5}ms | fold={fold_ms:5}ms | verify={ver_ms:3}ms | proof_b64={proof_bytes} bytes"
        );
    }

    // 100k spent secrets pruning benchmark (sampled across 20 epochs)
    let mut raw_set = HashSet::with_capacity(10_000);
    let mut nf_acc = NullifierAccumulator::new();
    let total_spends = 10_000u32;
    let t_acc = Instant::now();
    for epoch in 0..20u32 {
        for i in 0..(total_spends / 20) {
            let mut nf = [0u8; 32];
            nf[..4].copy_from_slice(&epoch.to_le_bytes());
            nf[4..8].copy_from_slice(&i.to_le_bytes());
            nf[8] = 1;
            raw_set.insert(nf);
            nf_acc.insert(nf).unwrap();
        }
        nf_acc.seal_epoch();
    }
    let nodes_before = nf_acc.node_count();
    let pruned = nf_acc.prune_before_epoch(2);
    let nodes_after = nf_acc.node_count();
    println!(
        "pruning_bench ({total_spends} spends, 20 epochs) | elapsed={}ms | raw_entries={} | acc_nodes_before={} | acc_nodes_after={} (pruned={})",
        t_acc.elapsed().as_millis(),
        raw_set.len(),
        nodes_before,
        nodes_after,
        pruned
    );
}
