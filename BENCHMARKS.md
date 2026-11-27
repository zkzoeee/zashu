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
| shielded mint (1 output) | 65 ms | 1,960 ms | 30x | 1.7 ms | 84.4 ms | 4,032 B | 6,208 B |
| shielded swap, 1 in / 2 out | 737 ms | 4,865 ms | 7x | 12.2 ms | 81.8 ms | 4,384 B | 6,208 B |
| shielded swap, 2 in / 2 out | 739 ms | 7,010 ms | 9x | 13.4 ms | 81.7 ms | 4,384 B | 6,208 B |
| HTLC claim, 1 in / 1 out | 731 ms | 4,809 ms | 7x | 13.4 ms | 96.2 ms | 4,384 B | 6,208 B |
| shielded melt, 1 in + change | 713 ms | 4,763 ms | 7x | 13.3 ms | 82.1 ms | 4,384 B | 6,208 B |

How to read it:

* **The backends do not prove the same thing.** The Halo 2 fold proves only the endpoints and its transaction proofs do not bind note openings, nullifiers or predicates. Ragu re-proves and recursively verifies everything, which is where the time goes.
* **The fold rows exclude the per-request Halo 2 step proofs** (about 57 ms each), which both backends still produce. Ragu's fold costs about 1.05 s per step, linear in the number of steps. The mint pays it in the background as steps happen, not in the solvency call.
* **Ragu transaction time grows with inputs** (each input adds four Merkle-path steps, a key step and a spend step); Halo 2's is flat because one fixed circuit covers up to four inputs. A transaction's last two outputs and its final statement are one closing step, and a mint is that step alone; inputs are proven in parallel. Before that the five transaction rows were 2.4 s, 7.3 s, 10.8 s, 6.5 s and 6.0 s.
* The transaction rows were re-measured (`bench_backends --tx-only`) on a machine busy with other work, which is why their verify times read 10 to 25 ms higher than the fold rows; the fold rows are from the earlier run.
* **Ragu verification and proof size are constant** (70 to 85 ms, 6,208 bytes) for every workload.
* One-time setup per process: about 14 s of Halo 2 key generation across all circuits in this run, and about 1.5 s per Ragu application.
* An uncompressed, still-foldable Ragu proof is about 34 MB; only the compressed root is small.
* Proving leaves in parallel (`ZASHU_RAGU_PARALLEL=4`) was about 1.3x faster in the best run and several times slower at 8, so batch folding is sequential by default.
* On the wire, proof bytes are base64 and public inputs hex inside the JSON bundle, which is base64 again: about 1.9x the raw size (a Ragu solvency proof is about 11.6 KB). The "~16 KB" in section 1 predates this and used a JSON array of numbers.

### Root-binding and aggregated folds, per operation

The Ragu fold (`ZASHU_PCD_BACKEND=ragu`) also proves how the event log and both roots change; the opt-in aggregated fold additionally checks each operation against its transaction proof. Folding one operation on live accumulators (`bench_backends --bound-fold-only`):

| One operation | Ragu fold | verify | proof | Aggregated fold | verify | proof |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| value step only (epoch advance) | 914 ms | 86 ms | 6,208 B | 7,007 ms | 521 ms | 19,392 B |
| shielded mint: value + 1 note insert | 6,057 ms | 82 ms | 6,208 B | 12,142 ms | 382 ms | 19,392 B |
| shielded swap: value + 1 nullifier + 2 note inserts | 13,181 ms | 84 ms | 6,208 B | 18,985 ms | 368 ms | 19,392 B |
| shielded melt: value + 1 nullifier insert | 7,269 ms | 89 ms | 6,208 B | 13,848 ms | 472 ms | 19,392 B |

* **Root-binding fold:** about 1 s for the value step, about 5 s for one note insert (8 Merkle-update steps and the insert), about 6 s for two note inserts proven as a pair, and about 6.5 s per nullifier insert in a small tree.
* **Shared paths.** Two leaves changed together are proven separately only up to the level where their paths meet, and once above it. Two outputs of one operation are neighbours, so the second costs about one extra step. A nullifier insert changes the low leaf and appends a new one; those meet at about `log2(tree size)`, so the saving shrinks as the tree grows: 12 steps in the small trees measured here, an estimated 16 at a million nullifiers (about 8.5 s, not measured), against 20 before this change.
* Before paths were shared and the insert steps also did the fusing, the swap row was 21.4 s and the melt row 11.1 s.
* **Aggregated fold:** about 5.4 s on top per operation (compress, decompress and two aggregator steps), plus about 2.4 s to decompress a transaction proof when the operation has one. The aggregator application takes about 25 s to build on first use, a proof in flight is about 172 MB, and the mint's shielded end-to-end test peaked at 3.1 GB.
* The mint folds on its background worker, so this bounds how fast the solvency proof can keep up, not how fast requests are answered; it does compete with transaction proving for CPU. The solvency-fold rows in the table above use value-only steps. `ZASHU_PCD_BACKEND=ragu-unbound` skips the root bindings.
* The mint's shielded end-to-end test takes about 8 s on Halo 2, 52 s on `ragu-unbound`, 112 s on `ragu` and 226 s on `ragu-aggregated` (the last measured before insert paths were shared).

## 2. Tachyon Nullifier Accumulator & Epoch Pruning

* **Workload:** 10,000 spent secrets across 20 sealed epochs (`keep_last_epochs = 2`).
* **Accumulator Merkle nodes before prune:** `20,028`
* Pruning evicts cached interior nodes; a pruned node is recomputed from its leaves when next needed, so roots and witnesses stay correct. (Earlier builds treated pruned nodes as empty, which broke witnesses after a prune.)
* **Accumulator Merkle nodes after prune:** `10,100` (`9,928` interior nodes pruned, ~49.6% reduction).
