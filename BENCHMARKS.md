# Zashu Benchmarks

Measured in `--release` on Apple Silicon. Ragu is the default backend; the Halo 2 figures in section 1 come from `ZASHU_PCD_BACKEND=halo2 cargo run --release -p zashu-circuits --example bench_fold_and_prune`.

## 1. Mode A Folding, Halo 2 backend (`k = 8`, Pasta/IPA, fallback)

| Batch Size | Step Proving (total) | Tree Fold Time | Verification Time | Folded Proof Size (Base64) |
| :--- | :--- | :--- | :--- | :--- |
| `1` | `135 ms` | `68 ms` | `1 ms` | `16,468 bytes` |
| `16` | `842 ms` | `69 ms` | `1 ms` | `16,516 bytes` |
| `64` | `3,416 ms` | `120 ms` | `1 ms` | `16,480 bytes` |

The Halo 2 fold verifies the step proofs natively and proves only the endpoints, which is why it is fast.

## 1b. Ragu PCD backend (default, rank 14)

Measured with `cargo run --release -p zashu-circuits --example bench_fold_and_prune` on a 10-core Apple Silicon laptop. Timings vary a lot from run to run; treat them as scale, not as reproducible figures.

| Workload | Proving | Verification | Proof Size |
| :--- | :--- | :--- | :--- |
| Mode A fold, 16 steps (recursive, state hashes opened in-circuit) | `~16.7 s` (about 1 s per step) | `~70 ms` | `6,208 bytes` |
| Mode B shielded swap, 1 input and 2 outputs (10 step proofs) | `~6.5 s` | `~71 ms` | `6,208 bytes` |

* Building a Ragu application takes about 1.5 s once per process.
* An uncompressed, still-foldable Ragu proof is about 34 MB; only the compressed root is small.
* Proving leaves in parallel (`ZASHU_RAGU_PARALLEL=4`) was about 1.3x faster in the best run and several times slower at 8, so batch folding is sequential by default. The mint folds in the background instead.

## 2. Tachyon Nullifier Accumulator & Epoch Pruning

* **Workload:** 10,000 spent secrets across 20 sealed epochs (`keep_last_epochs = 2`).
* **Accumulator Merkle nodes before prune:** `20,028`
* **Accumulator Merkle nodes after prune:** `10,100` (`9,928` interior nodes pruned, ~49.6% reduction).
