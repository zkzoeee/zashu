<p align="center">
  <img src="./assets/zashi-mascot.jpg" alt="Zashi — Zashu Mascot" width="160" style="border-radius: 16px;" />
</p>

# Zashu

**Zero-Knowledge Solvency & Shielded Ecash for Cashu**

**Live demo:** [zashu.fly.dev](https://zashu.fly.dev) · **Try it:** [Glass-Box Playground](https://zashu.fly.dev/playground)

**Zashu** *(ZK + Cashu)* is a zero-knowledge extension to the **Cashu** Chaumian ecash protocol, bringing **Ragu** (non-uniform Proof-Carrying Data / recursive folding, the default proof backend; a Halo 2 backend remains as a fallback) and **Tachyon** (prunable nullifier accumulators + oblivious synchronization) to Cashu mints and wallets.

> **Built for Cashu, not against it.** Cashu's BDHKE blind signatures remain unbeatable for instant, sub-50ms mobile micropayments. Zashu runs **side-by-side inside the exact same Cashu mint**—sharing one Lightning backend and one unified Proof-of-Solvency.

---

## What Zashu Contributes to the Cashu Ecosystem

Cashu excels at fast, private digital cash, but has four well-known structural trade-offs. Zashu addresses each via four modular `NUTZ` extensions:

| Extension | What It Adds to Cashu | Works with Existing Cashu Wallets? |
| :--- | :--- | :--- |
| **[`NUTZ-1`](./NUTZ/NUTZ-1.md)** | **Verifiable Mint Solvency & Prunable Storage** — Folds `mint`/`swap`/`melt` accounting into one constant-size proof (`total_liabilities <= L1 Bitcoin reserves`). The fold is recursive Ragu PCD (6.2 KB, verified in ~70 ms); the fallback Halo 2 fold is a smaller and much faster batch proof (3.4 KB, ~2 ms) that does not re-check the steps. Prunes old spent-secret storage via Tachyon accumulators. | **Yes (100% drop-in)** via CDK sidecar (`GET /v1/solvency`) |
| **[`NUTZ-2`](./NUTZ/NUTZ-2.md)** | **Arbitrary-Amount Shielded Notes** — Replaces power-of-2 splits (`128 + 8 + 1`) with 1 single shielded note (`137 sats`). One proof per transaction covers 32-level Poseidon Merkle inclusion, 64-bit ranges and value balance; the default Ragu backend also binds every note opening and nullifier (see [Proof backends](#proof-backends)). | **Coexists** via zero-fee `/v1/zk/shield` & `/v1/zk/unshield` |
| **[`NUTZ-3`](./NUTZ/NUTZ-3.md)** | **Offline-Safe Stealth Receives & Oblivious Sync** — Pay a friend's `zsp1...` stealth address while they are offline (double-spend-proof once confirmed). Wallets refresh witnesses via `GET /v1/zk/sync` without revealing which notes they own. | Opt-in Zashu wallet feature |
| **[`NUTZ-4`](./NUTZ/NUTZ-4.md)** | **Hidden Programmable Policies & Cross-Mint Swaps** — Hides `P2PK`, `Multisig`, `Timelock` and `PrivateHTLC` conditions inside Ragu non-uniform step circuits so the mint never sees your spending policy or hashlocks (the fallback Halo 2 backend checks the policy in the wallet only). | Opt-in Zashu wallet feature |

---

## How Cashu & Zashu Work Together

1. **Everyday Spending (Standard Cashu):** Keep small balances in fast BDHKE tokens for <50ms coffee payments.
2. **Zero-Fee Shielding (`/v1/zk/shield`):** Merge power-of-2 Cashu proofs (`128 + 8 + 1`) into **1 shielded Zashu note (`137 sats`)** inside the same mint with zero Lightning fees.
3. **Private Transfers & Swaps:** Send arbitrary amounts, pay offline recipients via `zsp1...` stealth keys, or execute private cross-mint atomic swaps (`PrivateHTLC`).
4. **Unshield Anywhere (`/v1/zk/unshield`):** Convert back to legacy Cashu tokens or melt over Lightning to pay any existing Cashu or Lightning wallet.
5. **Continuous Public Audit (`GET /v1/solvency`):** One unified `NUTZ-1` proof audits *both* standard BDHKE and Zashu shielded liabilities against the mint's Bitcoin Taproot reserves.

---

## Key Use Cases

* **Public Mint Accountability:** Anyone (or any wallet) can run `zashu-auditor` against a Cashu mint + Esplora (`mempool.space`) to verify in milliseconds that the mint is not running a fractional reserve.
* **Larger / Savings Ecash Balances:** Hold arbitrary satoshi amounts without power-of-2 denomination fingerprinting.
* **Async P2P Payments:** Send ecash over Nostr or QR to offline recipients without the online `/v1/swap` double-spend race.
* **Private Cross-Mint Liquidity:** Atomic swaps across independent Cashu mints via hidden HTLCs (`0x04`) without leaking amounts or linking identities.

---

## Quickstart: Interactive Web Playground & CLI

No install needed to try it: the playground runs live at **[zashu.fly.dev/playground](https://zashu.fly.dev/playground)**. To run it locally:

```bash
# 1. Start the unified Cashu + Zashu mint server & Web Playground
cargo run --release -p zashu-mint
# Landing Page:           http://127.0.0.1:8080/
# Interactive Playground: http://127.0.0.1:8080/playground

# 2. Audit mint solvency from the CLI (dev mode or Bitcoin Signet via Esplora)
cargo run --release -p zashu-auditor -- --allow-unverified-utxos verify http://127.0.0.1:8080
# Signet Esplora verification:
# cargo run --release -p zashu-auditor -- --esplora https://mempool.space/signet/api verify http://127.0.0.1:8080

# 3. Use the Zashu CLI wallet
cargo run --release -p zashu-wallet -- init
cargo run --release -p zashu-wallet -- mint 137
cargo run --release -p zashu-wallet -- balance
cargo run --release -p zashu-wallet -- send-token 37
```

Or run the automated end-to-end HTTP demo:
```bash
./scripts/demo.sh
```

---

## Architecture & Workspace

```text
crates/
├── zashu-core/         # Pasta/Poseidon, Pedersen commitments, Note/Nullifier, Taproot reserves, zashuA & zsp1 codecs
├── zashu-acc/          # Tachyon-style NoteAccumulator & prunable NullifierAccumulator
├── zashu-circuits/     # Halo 2 (Pasta/IPA) circuits, plus Ragu PCD backends for the NUTZ-1 fold and NUTZ-2/4 transactions
├── zashu-mint/         # Unified Cashu + Zashu mint server, REST API, Landing Page & Glass-Box Playground
├── zashu-cdk-sidecar/  # Drop-in NUTZ-1 solvency sidecar for Cashu Development Kit (CDK)
├── zashu-auditor/      # CLI & library verifier (native + Esplora on-chain UTXO verification)
└── zashu-wallet/       # CLI wallet for shielded notes, stealth sends, and private HTLCs
```

* **Specs:** [`NUTZ/README.md`](./NUTZ/README.md) (`NUTZ-1` through `NUTZ-4`)
* **Benchmarks:** [`BENCHMARKS.md`](./BENCHMARKS.md) (both proof backends, and ~49.6% accumulator pruning over 10k spends)
* **Design Roadmap:** [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md)

## Proof backends

Zashu has two proof backends. Ragu PCD is the default; Halo 2 is a fallback.

```bash
# Default: Ragu
cargo build --release -p zashu-mint

# Same binary, heaviest fold: also checks each operation against its transaction proof
ZASHU_PCD_BACKEND=ragu-aggregated ./target/release/zashu-mint

# Same binary, cheaper fold without root bindings
ZASHU_PCD_BACKEND=ragu-unbound ./target/release/zashu-mint

# Same binary, Halo 2 selected at runtime
ZASHU_PCD_BACKEND=halo2 ./target/release/zashu-mint

# Halo 2 only, without the Ragu dependency
cargo build --release -p zashu-mint --no-default-features
```

| | Ragu PCD (default) | Halo 2 (`ZASHU_PCD_BACKEND=halo2` or `--no-default-features`) |
| :--- | :--- | :--- |
| **`NUTZ-1` solvency fold** | Recursive: the proof attests every step from genesis, opens each state hash in-circuit, and binds how liabilities, the event log, the nullifier root (sorted inserts only) and the note root (appends only) change. Folded in the background as steps happen. | The folder verifies step proofs itself; the folded proof exposes only the start and end state. |
| **`NUTZ-2` shielded transactions** | Every input's note opening, Merkle membership and nullifier, every output's opening, and the value balance are enforced in-circuit. | Proves Merkle membership of one input, 64-bit ranges and value balance. Note openings and nullifiers are not bound by the proof. |
| **`NUTZ-4` predicates** | One step circuit per predicate (`StandardSpend`, `P2PK`, `Multisig` up to 4 keys and 3 signers, `Timelock`, `PrivateHTLC` claim and refund), enforced in-circuit and hidden from the mint. | Checked by the wallet when it builds the proof; not part of the proof. |
| **Solvency proof, 64 steps** | 67 s to fold, 69 ms to verify, 6,208 bytes | 0.12 s to fold, 1.8 ms to verify, 3,360 bytes |
| **Shielded swap (1 in, 2 out)** | 7.3 s to prove, 72 ms to verify, 6,208 bytes | 0.74 s to prove, 13 ms to verify, 4,384 bytes |

* Binding the roots is the expensive part of the fold: about 1 s for an operation's value change, about 6 s per note insert and about 11 s per nullifier insert, so a shielded swap costs about 24 s of background folding. `ZASHU_PCD_BACKEND=ragu-unbound` keeps the recursive fold and Ragu transactions but lets the roots and event log move freely (about 1 s per operation); the auditor reports which kind it verified.
* Ragu costs roughly 10x the proving time of Halo 2 per shielded transaction and far more for the solvency fold, because it actually re-proves and recursively verifies every step; see [`BENCHMARKS.md`](./BENCHMARKS.md) for the full comparison.
* **Aggregated fold (opt-in).** `ZASHU_PCD_BACKEND=ragu-aggregated` adds a Ragu aggregator on top of the default fold. It decompresses each operation's fold proof and its shielded transaction proof and checks that the operation inserted exactly the transaction's nullifiers and outputs, moved liabilities by exactly its value balance, and (for spends) used the note root the operation started from. Operations without a matching transaction proof are accepted but counted, and the auditor reports `unbound_ops` out of `ops`. Legacy BDHKE operations, shield/unshield and spends against an older anchor always count as unbound. It costs about 5 to 8 s more per operation, about 0.34 s to verify, a 19.4 KB proof, about 25 s to start, and proofs of about 172 MB in flight (3 GB peak in the mint's end-to-end test). Ragu marks the aggregator unaudited with a soundness bound still open.
* Proof sizes above are raw proof bytes. In a JSON bundle proofs are base64 and hex strings (the old number-array form is still read), so a Ragu solvency proof is about 11.6 KB on the wire.
* Predicate privacy is best-effort: transaction proofs are rerandomized before they are published, which is the mechanism Ragu provides for this, but Ragu documents the indistinguishability of rerandomized proofs as a goal that is not yet proven.
* A mint running the Ragu backend rejects Halo 2 transaction proofs, and rejects any proof whose predicates were evaluated at an epoch ahead of the mint's.
* The mint, sidecar, auditor and wallet all enable the `ragu` feature by default. A Halo 2-only build of any of them cannot verify or produce Ragu proofs.
* A Ragu shielded swap holds proofs of about 34 MB each in memory while proving; size mint and wallet machines accordingly.
* [Ragu](https://github.com/tachyon-zcash/ragu) is unreleased and still being audited upstream. It is pinned to a git commit, needs Rust 1.97.1+, and is fetched from GitHub at build time.
* Timings are from one 10-core Apple Silicon laptop; see [`BENCHMARKS.md`](./BENCHMARKS.md).
* The sidecar can seal epochs without waiting for proofs (`begin_epoch` / `poll_epochs`); bundles appear as the background fold catches up.
* Code: `crates/zashu-circuits/src/mode_a/` (`ragu_roots.rs`, `ragu_aggregate.rs`, `ragu_backend.rs`), `crates/zashu-circuits/src/mode_b/ragu_backend.rs`, `crates/zashu-circuits/src/ragu_app.rs`; the original spike and the aggregator probe are in `spikes/ragu-pcd`.

## License

[MIT](./LICENSE)
