//! The same `NUTZ-0` workloads on each backend.
//!
//! Run with:
//!   cargo run --release -p zashu-circuits --example bench_spec            # both
//!   cargo run --release -p zashu-circuits --example bench_spec -- halo2   # one
//!
//! Each figure is the best of [`RUNS`] after a warm-up that pays one-time
//! setup (key generation, application build).

use std::time::Instant;

use zashu_circuits::spec::halo2::Halo2;
#[cfg(feature = "ragu")]
use zashu_circuits::spec::ragu::Ragu;
use zashu_circuits::spec::Backend;
use zashu_core::spec::op::{self, OpWitness};
use zashu_core::spec::tx::{self, TxWitness};
use zashu_core::spec::vectors::{random_fe, OpWorld, TxFixture};

const RUNS: usize = 2;

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

struct Row {
    name: String,
    prove_ms: f64,
    verify_ms: f64,
    bytes: usize,
}

fn transactions() -> Vec<(&'static str, TxWitness)> {
    let f = TxFixture::new();
    let valid = f.valid();
    let pick = |i: usize| valid[i].1.clone();
    vec![
        ("tx: shielded mint", pick(0)),
        ("tx: swap, one real input", pick(1)),
        ("tx: swap, two real inputs", pick(2)),
        ("tx: timelock spend", pick(4)),
        ("tx: HTLC claim", pick(5)),
        ("tx: 2-of-3 multisig spend", pick(7)),
    ]
}

/// Operations against trees that already hold 1,000 notes and nullifiers.
fn operations() -> Vec<(&'static str, OpWitness)> {
    let mut world = OpWorld::prefilled(1_000, 1_000);
    vec![
        ("op: legacy mint (value only)", world.mint(50, &[])),
        ("op: shielded mint (1 note)", world.mint(1_000, &[random_fe(1)])),
        ("op: swap (2 nullifiers, 2 notes)", world.swap(&[random_fe(2), random_fe(3)], &[random_fe(4), random_fe(5)])),
        ("op: melt (2 nullifiers, 2 notes)", world.melt(300, &[random_fe(6), random_fe(7)], &[random_fe(8), random_fe(9)])),
    ]
}

fn run<B: Backend>() -> Vec<Row> {
    let mut rows = Vec::new();
    let txs = transactions();
    let ops = operations();

    // Warm-up: one-time setup is not part of any figure.
    let t = Instant::now();
    let proof = B::prove_tx(&txs[0].1).unwrap();
    B::verify_tx(&tx::statement(&txs[0].1), &proof).unwrap();
    let proof = B::prove_op(&ops[0].1).unwrap();
    B::verify_op(&op::check(&ops[0].1).unwrap().1, &proof).unwrap();
    eprintln!("[{}] warm-up including one-time setup: {:.1} s", B::NAME, t.elapsed().as_secs_f64());

    for (name, w) in &txs {
        let statement = tx::check(w).unwrap();
        let (prove_ms, proof) = best_ms(|| B::prove_tx(w).unwrap());
        let (verify_ms, ()) = best_ms(|| B::verify_tx(&statement, &proof).unwrap());
        rows.push(Row { name: name.to_string(), prove_ms, verify_ms, bytes: B::tx_proof_bytes(&proof) });
        eprintln!("[{}] {name}: {prove_ms:.0} ms", B::NAME);
    }
    for (name, w) in &ops {
        let statement = op::check(w).unwrap().1;
        let (prove_ms, proof) = best_ms(|| B::prove_op(w).unwrap());
        let (verify_ms, ()) = best_ms(|| B::verify_op(&statement, &proof).unwrap());
        rows.push(Row { name: name.to_string(), prove_ms, verify_ms, bytes: B::op_proof_bytes(&proof) });
        eprintln!("[{}] {name}: {prove_ms:.0} ms", B::NAME);
    }

    // A chain: the four operations above, then more swaps.
    for len in [4usize, 16] {
        let mut world = OpWorld::prefilled(1_000, 1_000);
        let mut chain_ops = vec![world.mint(50, &[]), world.mint(1_000, &[random_fe(1)])];
        let mut seed = 100;
        while chain_ops.len() < len {
            let mut next = || {
                seed += 1;
                random_fe(seed)
            };
            chain_ops.push(world.swap(&[next(), next()], &[next(), next()]));
        }
        let statement = op::check_chain(&chain_ops).unwrap();
        let t = Instant::now();
        let mut chain = B::chain_start();
        for w in &chain_ops {
            B::chain_extend(&mut chain, w).unwrap();
        }
        let proof = B::chain_finish(chain).unwrap();
        let prove_ms = t.elapsed().as_secs_f64() * 1e3;
        let (verify_ms, ()) = best_ms(|| B::verify_chain(&statement, &proof).unwrap());
        rows.push(Row {
            name: format!("chain of {len} operations"),
            prove_ms,
            verify_ms,
            bytes: B::chain_proof_bytes(&proof),
        });
        eprintln!("[{}] chain of {len}: {prove_ms:.0} ms", B::NAME);
    }
    rows
}

fn print_one(name: &str, rows: &[Row]) {
    println!("| Workload | {name} prove | verify | proof |");
    println!("| :--- | ---: | ---: | ---: |");
    for r in rows {
        println!("| {} | {:.0} ms | {:.1} ms | {} B |", r.name, r.prove_ms, r.verify_ms, r.bytes);
    }
}

fn main() {
    let only = std::env::args().nth(1);
    let want = |name: &str| only.as_deref().is_none_or(|o| o == name);

    let halo2 = want("halo2").then(run::<Halo2>);
    #[cfg(feature = "ragu")]
    let ragu = want("ragu").then(run::<Ragu>);
    #[cfg(not(feature = "ragu"))]
    let ragu: Option<Vec<Row>> = None;

    match (&halo2, &ragu) {
        (Some(h), Some(r)) => {
            println!("| Workload | Halo 2 prove | Ragu prove | Ragu / Halo 2 | Halo 2 verify | Ragu verify | Halo 2 proof | Ragu proof |");
            println!("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
            for (h, r) in h.iter().zip(r) {
                assert_eq!(h.name, r.name);
                println!(
                    "| {} | {:.0} ms | {:.0} ms | {:.1}x | {:.1} ms | {:.1} ms | {} B | {} B |",
                    h.name,
                    h.prove_ms,
                    r.prove_ms,
                    r.prove_ms / h.prove_ms,
                    h.verify_ms,
                    r.verify_ms,
                    h.bytes,
                    r.bytes
                );
            }
        }
        (Some(h), None) => print_one("Halo 2", h),
        (None, Some(r)) => print_one("Ragu", r),
        (None, None) => eprintln!("nothing to run: pass `halo2`, `ragu` or no argument"),
    }
}
