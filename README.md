<p align="center">
  <img src="./assets/zashi-mascot.jpg" alt="Zashi — Zashu Mascot" width="160" style="border-radius: 16px;" />
</p>

# Zashu

**Zero-Knowledge Solvency & Shielded Ecash for Cashu**

**Live demo:** [zashu.fly.dev](https://zashu.fly.dev) · **Try it:** [Glass-Box Playground](https://zashu.fly.dev/playground)

**Zashu** *(ZK + Cashu)* is a zero-knowledge extension to the **Cashu** Chaumian ecash protocol, bringing **Ragu** (non-uniform Proof-Carrying Data / recursive folding) and **Tachyon** (prunable nullifier accumulators + oblivious synchronization) to Cashu mints and wallets.

> **Built for Cashu, not against it.** Cashu's BDHKE blind signatures remain unbeatable for instant, sub-50ms mobile micropayments. Zashu runs **side-by-side inside the exact same Cashu mint**—sharing one Lightning backend and one unified Proof-of-Solvency.

---

## What Zashu Contributes to the Cashu Ecosystem

Cashu excels at fast, private digital cash, but has four well-known structural trade-offs. Zashu addresses each via four modular `NUTZ` extensions:

| Extension | What It Adds to Cashu | Works with Existing Cashu Wallets? |
| :--- | :--- | :--- |
| **[`NUTZ-1`](./NUTZ/NUTZ-1.md)** | **Verifiable Mint Solvency & Prunable Storage** — Continuously folds `mint`/`swap`/`melt` accounting into a constant-size ~16 KB ZK proof (`total_liabilities <= L1 Bitcoin reserves`), verified in **~1 ms**. Prunes old spent-secret storage via Tachyon accumulators. | **Yes (100% drop-in)** via CDK sidecar (`GET /v1/solvency`) |
| **[`NUTZ-2`](./NUTZ/NUTZ-2.md)** | **Arbitrary-Amount Shielded Notes** — Replaces power-of-2 splits (`128 + 8 + 1`) with 1 single Pedersen-committed note (`137 sats`). Unified `k=13` Halo 2 proof verifies 32-level Poseidon Merkle inclusion + 64-bit range + value balance. | **Coexists** via zero-fee `/v1/zk/shield` & `/v1/zk/unshield` |
| **[`NUTZ-3`](./NUTZ/NUTZ-3.md)** | **Offline-Safe Stealth Receives & Oblivious Sync** — Pay a friend's `zsp1...` stealth address while they are offline (double-spend-proof once confirmed). Wallets refresh witnesses via `GET /v1/zk/sync` without revealing which notes they own. | Opt-in Zashu wallet feature |
| **[`NUTZ-4`](./NUTZ/NUTZ-4.md)** | **Hidden Programmable Policies & Cross-Mint Swaps** — Hides `P2PK`, `Multisig`, `Timelock`, and `PrivateHTLC` conditions inside Ragu non-uniform subcircuits so the mint never sees your spending policy or hashlocks. | Opt-in Zashu wallet feature |

---

## How Cashu & Zashu Work Together

1. **Everyday Spending (Standard Cashu):** Keep small balances in fast BDHKE tokens for <50ms coffee payments.
2. **Zero-Fee Shielding (`/v1/zk/shield`):** Merge power-of-2 Cashu proofs (`128 + 8 + 1`) into **1 shielded Zashu note (`137 sats`)** inside the same mint with zero Lightning fees.
3. **Private Transfers & Swaps:** Send arbitrary amounts, pay offline recipients via `zsp1...` stealth keys, or execute private cross-mint atomic swaps (`PrivateHTLC`).
4. **Unshield Anywhere (`/v1/zk/unshield`):** Convert back to legacy Cashu tokens or melt over Lightning to pay any existing Cashu or Lightning wallet.
5. **Continuous Public Audit (`GET /v1/solvency`):** One unified `NUTZ-1` proof audits *both* standard BDHKE and Zashu shielded liabilities against the mint's Bitcoin Taproot reserves.

---

## Key Use Cases

* **Public Mint Accountability:** Anyone (or any wallet) can run `zashu-auditor` against a Cashu mint + Esplora (`mempool.space`) to verify in ~1 ms that the mint is not running a fractional reserve.
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
├── zashu-circuits/     # Halo 2 (Pasta/IPA) non-uniform PCD, unified k=13 Merkle+Range circuits, NUTZ-4 predicates
├── zashu-mint/         # Unified Cashu + Zashu mint server, REST API, Landing Page & Glass-Box Playground
├── zashu-cdk-sidecar/  # Drop-in NUTZ-1 solvency sidecar for Cashu Development Kit (CDK)
├── zashu-auditor/      # CLI & library verifier (native + Esplora on-chain UTXO verification)
└── zashu-wallet/       # CLI wallet for shielded notes, stealth sends, and private HTLCs
```

* **Specs:** [`NUTZ/README.md`](./NUTZ/README.md) (`NUTZ-1` through `NUTZ-4`)
* **Benchmarks:** [`BENCHMARKS.md`](./BENCHMARKS.md) (1 ms verification, ~16 KB folded solvency proof, ~49.6% accumulator pruning over 10k spends)
* **Design Roadmap:** [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md)

## Experimental: Ragu PCD fold backend

The `NUTZ-1` fold defaults to Halo 2, where the folder verifies step proofs natively and the folded proof only exposes the endpoints. An opt-in backend re-proves the steps and folds them with upstream [Ragu](https://github.com/tachyon-zcash/ragu) recursive PCD, so the final proof itself attests every step and the chaining between them.

```bash
cargo build --release -p zashu-mint --features ragu
ZASHU_FOLD_BACKEND=ragu ./target/release/zashu-mint
```

* Ragu is unreleased and unaudited upstream; it is pinned to a git commit and needs Rust 1.97.1+. Do not use it in production.
* Auditors need the `ragu` feature too (`-p zashu-auditor --features ragu`) to verify these bundles.
* Folding costs roughly 0.9 s per step and verification about 65 ms, against about 1 ms for the Halo 2 fold. The proof is about 6 KB.
* Code: `crates/zashu-circuits/src/mode_a/ragu_backend.rs`; standalone spike: `spikes/ragu-pcd`.

## License

[MIT](./LICENSE)
