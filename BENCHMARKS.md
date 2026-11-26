# Zashu Benchmarks

Measured in `--release` on Apple Silicon. Ragu is the default backend; the Halo 2 figures in section 1 come from `ZASHU_PCD_BACKEND=halo2 cargo run --release -p zashu-circuits --example bench_fold_and_prune`.

## 1. Mode A Folding, Halo 2 backend (`k = 8`, Pasta/IPA, fallback)

| Batch Size | Step Proving (total) | Tree Fold Time | Verification Time | Folded Proof Size (Base64) |
| :--- | :--- | :--- | :--- | :--- |
| `1` | `135 ms` | `68 ms` | `1 ms` | `16,468 bytes` |
| `16` | `842 ms` | `69 ms` | `1 ms` | `16,516 bytes` |
| `64` | `3,416 ms` | `120 ms` | `1 ms` | `16,480 bytes` |

The Halo 2 fold verifies the step proofs natively and proves only the endpoints, which is why it is fast.

## 1b. Halo 2 vs Ragu, like for like

Measured with `cargo run --release -p zashu-circuits --example bench_backends` on a 10-core Apple Silicon laptop: the same workloads on both backends, best of 3 runs after a warm-up. Proof sizes are raw proof bytes.

| Workload | Halo 2 prove | Ragu prove | Slowdown | Halo 2 verify | Ragu verify | Halo 2 proof | Ragu proof |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| solvency fold, 1 step | 55 ms | 859 ms | 16x | 1.8 ms | 68.9 ms | 3,360 B | 6,208 B |
| solvency fold, 16 steps | 72 ms | 16,588 ms | 230x | 1.8 ms | 68.1 ms | 3,360 B | 6,208 B |
| solvency fold, 64 steps | 116 ms | 67,400 ms | 582x | 1.8 ms | 68.8 ms | 3,360 B | 6,208 B |
| shielded mint (1 output) | 63 ms | 2,373 ms | 38x | 1.8 ms | 69.3 ms | 4,032 B | 6,208 B |
| shielded swap, 1 in / 2 out | 737 ms | 7,322 ms | 10x | 12.8 ms | 72.5 ms | 4,384 B | 6,208 B |
| shielded swap, 2 in / 2 out | 730 ms | 10,791 ms | 15x | 12.9 ms | 70.8 ms | 4,384 B | 6,208 B |
| HTLC claim, 1 in / 1 out | 742 ms | 6,509 ms | 9x | 12.9 ms | 71.1 ms | 4,384 B | 6,208 B |
| shielded melt, 1 in + change | 738 ms | 6,010 ms | 8x | 13.3 ms | 69.0 ms | 4,384 B | 6,208 B |

How to read it:

* **The backends do not prove the same thing.** The Halo 2 fold proves only the endpoints and its transaction proofs do not bind note openings, nullifiers or predicates. Ragu re-proves and recursively verifies everything, which is where the time goes.
* **The fold rows exclude the per-request Halo 2 step proofs** (about 57 ms each), which both backends still produce. Ragu's fold costs about 1.05 s per step, linear in the number of steps. The mint pays it in the background as steps happen, not in the solvency call.
* **Ragu transaction time grows with inputs** (each input adds four Merkle-path steps, a key step and a spend step); Halo 2's is flat because one fixed circuit covers up to four inputs.
* **Ragu verification and proof size are constant** (about 70 ms, 6,208 bytes) for every workload.
* One-time setup per process: about 14 s of Halo 2 key generation across all circuits in this run, and about 1.5 s per Ragu application.
* An uncompressed, still-foldable Ragu proof is about 34 MB; only the compressed root is small.
* Proving leaves in parallel (`ZASHU_RAGU_PARALLEL=4`) was about 1.3x faster in the best run and several times slower at 8, so batch folding is sequential by default.
* On the wire, proofs are embedded in JSON as a base64-encoded byte array, about 4.8x the raw size. That is where the "~16 KB" in section 1 comes from.

## 2. Tachyon Nullifier Accumulator & Epoch Pruning

* **Workload:** 10,000 spent secrets across 20 sealed epochs (`keep_last_epochs = 2`).
* **Accumulator Merkle nodes before prune:** `20,028`
* **Accumulator Merkle nodes after prune:** `10,100` (`9,928` interior nodes pruned, ~49.6% reduction).
