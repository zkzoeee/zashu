# Zashu Benchmarks

Measured in `--release` on Apple Silicon using `cargo run --release -p zashu-circuits --example bench_fold_and_prune --offline`.

## 1. Mode A Recursive Folding (`k = 8` Halo 2 Pasta/IPA)

| Batch Size | Step Proving (total) | Tree Fold Time | Verification Time | Folded Proof Size (Base64) |
| :--- | :--- | :--- | :--- | :--- |
| `1` | `135 ms` | `68 ms` | `1 ms` | `16,468 bytes` |
| `16` | `842 ms` | `69 ms` | `1 ms` | `16,516 bytes` |
| `64` | `3,416 ms` | `120 ms` | `1 ms` | `16,480 bytes` |

## 2. Tachyon Nullifier Accumulator & Epoch Pruning

* **Workload:** 10,000 spent secrets across 20 sealed epochs (`keep_last_epochs = 2`).
* **Accumulator Merkle nodes before prune:** `20,028`
* **Accumulator Merkle nodes after prune:** `10,100` (`9,928` interior nodes pruned, ~49.6% reduction).
