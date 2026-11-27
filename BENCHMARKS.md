# Zashu Benchmarks

Measured in `--release` on Apple Silicon. Halo 2 is the default backend; the figures in section 1 come from `cargo run --release -p zashu-circuits --example bench_fold_and_prune`.

## 1. Mode A Folding, Halo 2 backend (`k = 8`, Pasta/IPA, default)

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
* On the wire, proof bytes are base64 and public inputs hex inside the JSON bundle, which is base64 again: about 1.9x the raw size (a Ragu solvency proof is about 11.6 KB). The "~16 KB" in section 1 predates this and used a JSON array of numbers.

### Root-binding and aggregated folds, per operation

The Ragu fold (`ZASHU_PCD_BACKEND=ragu`) also proves how the event log and both roots change; the opt-in aggregated fold additionally checks each operation against its transaction proof. Folding one operation on live accumulators (`bench_backends --bound-fold-only`):

| One operation | Ragu fold | verify | proof | Aggregated fold | verify | proof |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| value step only (epoch advance) | 891 ms | 76 ms | 6,208 B | 6,288 ms | 358 ms | 19,392 B |
| shielded mint: value + 1 note insert | 5,983 ms | 74 ms | 6,208 B | 11,254 ms | 360 ms | 19,392 B |
| shielded swap: value + 1 nullifier + 2 note inserts | 21,432 ms | 74 ms | 6,208 B | 26,809 ms | 333 ms | 19,392 B |
| shielded melt: value + 1 nullifier insert | 11,116 ms | 76 ms | 6,208 B | 16,522 ms | 334 ms | 19,392 B |

* **Root-binding fold:** about 1 s for the value step, 5 to 6 s per note insert (8 Merkle-update steps and the insert) and about 10 s per nullifier insert (two Merkle updates, an order check and the insert).
* **Aggregated fold:** about 5.4 s on top per operation (compress, decompress and two aggregator steps), plus about 2.4 s to decompress a transaction proof when the operation has one. The aggregator application takes about 25 s to build on first use, a proof in flight is about 172 MB, and the mint's shielded end-to-end test peaked at 3.1 GB.
* The mint folds on its background worker, so this bounds how fast the solvency proof can keep up, not how fast requests are answered; it does compete with transaction proving for CPU. The solvency-fold rows in the table above use value-only steps. `ZASHU_PCD_BACKEND=ragu-unbound` skips the root bindings.
* The mint's shielded end-to-end test takes about 8 s on Halo 2, 52 s on `ragu-unbound`, 142 s on `ragu` and 226 s on `ragu-aggregated`.

## 2. Tachyon Nullifier Accumulator & Epoch Pruning

* **Workload:** 10,000 spent secrets across 20 sealed epochs (`keep_last_epochs = 2`).
* **Accumulator Merkle nodes before prune:** `20,028`
* Pruning evicts cached interior nodes; a pruned node is recomputed from its leaves when next needed, so roots and witnesses stay correct. (Earlier builds treated pruned nodes as empty, which broke witnesses after a prune.)
* **Accumulator Merkle nodes after prune:** `10,100` (`9,928` interior nodes pruned, ~49.6% reduction).
