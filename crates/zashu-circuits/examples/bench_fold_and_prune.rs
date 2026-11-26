use std::collections::HashSet;
use std::time::Instant;

use zashu_acc::NullifierAccumulator;
use zashu_circuits::mode_a::{fold_mode_a_batch, prove_mint_step, verify_fold_batch};
use zashu_core::poseidon::hash_event_mint;
use zashu_core::types::MintState;

fn main() {
    println!("=== Zashu Task A.5 Benchmarks ===");
    println!(
        "fold backend: {:?}",
        zashu_circuits::mode_a::FoldBackend::from_env().unwrap()
    );

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
            steps.push(prove_mint_step(&prev, &cur, 1_000).unwrap());
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
