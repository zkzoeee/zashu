# Zashu Implementation Plan (Mode A & Mode B)

> **Target Implementer:** Gemini 4 Hydrogen  
> **Specifications:** See [`./NUTZ/NUTZ-1.md`](./NUTZ/NUTZ-1.md) through [`./NUTZ/NUTZ-4.md`](./NUTZ/NUTZ-4.md).  
> **Execution Rule:** Complete tasks strictly in order. Do not skip unit tests, negative/tamper tests, or benchmarks. Every task must leave `cargo test --workspace` green before moving on.

---

## Architecture & Engineering Contracts

### 1. Workspace Layout
```text
zashu/
├── Cargo.toml                  # Workspace root (Rust edition = "2021", MSRV >= 1.80)
├── NUTZ/                       # Protocol specifications (NUTZ-1..NUTZ-4)
├── crates/
│   ├── zashu-core/             # Pasta/Poseidon primitives, Pedersen commitments, Note, Nullifier, MintState, codecs
│   ├── zashu-acc/              # Tachyon-style prunable epoch accumulators (NoteAccumulator, NullifierAccumulator)
│   ├── zashu-circuits/         # Non-uniform PCD / folding trait + Pasta/Halo2-IPA backend + Mode A & Mode B circuits
│   ├── zashu-mint/             # Unified mint engine (BDHKE mock/adapter + Mode A folder + Mode B REST API)
│   ├── zashu-cdk-sidecar/      # Drop-in Mode A solvency sidecar for Cashu Development Kit (CDK)
│   ├── zashu-auditor/          # CLI + library verifier for NUTZ-1 solvency bundles
│   └── zashu-wallet/           # CLI wallet for Mode B (mint, swap, melt, shield, unshield, stealth send, HTLC)
└── benches/                    # Folding latency & 100k-spend accumulator pruning benchmarks
```

### 2. Cryptographic & Backend Contract
* **Curve / Field:** Pasta curves (`pasta_curves`: Pallas `Fp` / Vesta `Fq`) + Poseidon algebraic hash + Pedersen value commitments $C_v = v \cdot G + r_v \cdot H$.
* **Proving Backend Abstraction:** Define a clean `PcdBackend` / `FoldingScheme` trait in `zashu-circuits` implementing Ragu-style **non-uniform PCD** (partitioned subcircuits folding into a shared accumulator).
  * **Default concrete backend:** Implement using `halo2_proofs` (Pasta / IPA, no trusted setup) with explicit folding/accumulation verification so the workspace compiles cleanly from crates.io without blocking on unreleased upstream `ragu` git snapshots.
  * Keep circuit synthesis isolated behind a minimal `CircuitSynthesizer` trait so swapping in upstream `ragu` later requires changing only the backend adapter.
* **Value Bounds:** All note values $v$ are strictly 64-bit unsigned integers (`u64`, $0 \le v < 2^{64}$) enforced by in-circuit range checks to prevent modular wrap-around inflation.
* **Bitcoin Boundary:** Use `bitcoin` + `secp256k1` in `zashu-core` / `zashu-mint` for L1 UTXO reserve proofs (BIP-322 / Taproot Schnorr ownership proofs) and BOLT11/Signet quote handling.

---

## Phase 0: Workspace & Core Primitives

### Task 0.1 — Initialize Rust Cargo Workspace
* **Deliverables:**
  * Root `Cargo.toml` declaring all 7 crates in `crates/*`, shared workspace dependencies (`pasta_curves`, `ff`, `group`, `halo2_proofs`, `serde`, `serde_json`, `ciborium`, `base64`, `axum`, `tokio`, `clap`, `thiserror`, `tracing`, `bitcoin`, `secp256k1`, `proptest`, `criterion`), and strict clippy lints.
  * Skeleton `Cargo.toml` and `src/lib.rs` / `src/main.rs` for each crate.
* **Acceptance Criteria:** `cargo check --workspace` succeeds with zero warnings.

### Task 0.2 — Implement Core Types & Cryptography (`zashu-core`)
* **Deliverables:**
  * `field.rs`: Re-exports & serialization helpers (canonical 32-byte little-endian hex/bytes) for Pasta `Fp` / `Fq`.
  * `poseidon.rs`: Domain-separated Poseidon hash functions (`hash_note`, `hash_nullifier`, `hash_state`, `hash_acc_node`, `hash_predicate`).
  * `pedersen.rs`: Generator derivation (hash-to-curve with nothing-up-my-sleeve domain tags) and Pedersen value commitments `ValueCommitment::commit(value: u64, blind: Fq)` + homomorphic addition/subtraction.
  * `types.rs`:
    * `Note { value: u64, owner_pk: [u8; 32], predicate_id: u8, predicate_params_hash: [u8; 32], rho: [u8; 32], r: [u8; 32] }`
    * `NoteCommitment([u8; 32])`, `Nullifier([u8; 32])`
    * `MintState { epoch: u64, total_liabilities: u64, nullifier_acc_root: [u8; 32], note_acc_root: [u8; 32], event_log_hash: [u8; 32] }`
    * `SolvencyBundle` (matching `NUTZ-1` schema).
* **Acceptance Criteria:** Unit tests verifying commitment determinism, Pedersen homomorphic balance (`commit(a, r1) + commit(b, r2) == commit(a+b, r1+r2)`), and canonical JSON/CBOR round-trips.

### Task 0.3 — Implement Prunable Epoch Accumulators (`zashu-acc`)
* **Deliverables:**
  * `NoteAccumulator`: Append-only Poseidon Merkle/MMR accumulator supporting `insert(cm) -> LeafIndex`, `root() -> [u8; 32]`, `witness(index) -> InclusionWitness`, `verify_inclusion(root, cm, witness) -> bool`, and rolling anchor root history (`is_valid_anchor(root, max_window)`).
  * `NullifierAccumulator`: Indexed Poseidon Merkle tree (or sorted accumulator) supporting **non-membership proofs** (`prove_non_membership(nf) -> NonMembershipWitness`, `verify_non_membership(root, nf, witness)`) and **insert-with-proof** (`insert(nf) -> TransitionWitness`).
  * **Epoch Pruning:** `EpochPruner` that seals epoch $E$, produces a compact frontier/checkpoint, and drops historical raw leaves from memory/disk while preserving verification of new spends.
* **Acceptance Criteria:**
  * Unit tests for inclusion, non-membership (both before and after insertion), duplicate rejection, and epoch pruning.
  * Proof that pruned memory footprint stays bounded across 10+ epochs.

### Task 0.4 — Define Non-Uniform PCD / Folding Abstraction (`zashu-circuits`)
* **Deliverables:**
  * `pcd.rs`: Define `SubcircuitId` enum (`MintStep`, `SwapStep`, `MeltStep`, `FoldBatch`, `ZkMint`, `ZkSwap`, `ZkMelt`, `ZkShield`, `ZkUnshield`, `Predicate(u8)`), `FoldedProof`, `PcdProver`, and `PcdVerifier` traits.
  * Concrete Halo 2 (Pasta/IPA) proving & verification engine with deterministic parameter caching (`params_k` configurable for fast tests vs. production).
  * Tree-folding helper `fold_tree(proofs: &[FoldedProof]) -> Result<FoldedProof>` using parallel `rayon` execution.
* **Acceptance Criteria:** Minimal dummy 2-step fold test passes end-to-end (`prove` $\to$ `fold` $\to$ `verify`) and rejects mutated public inputs.

---

## Mode A: Verifiable Mint Solvency & Prunable State (`NUTZ-1`)

### Task A.1 — Mode A Accounting Subcircuits (`zashu-circuits/src/mode_a/`)
* **Deliverables:**
  * `mint_step.rs`: Proves `state_next.total_liabilities == state_prev.total_liabilities + amount`, `event_log_hash` updated with `quote_hash`, and `amount > 0` without u64 overflow.
  * `swap_step.rs`: Proves all input nullifiers (`Y` secrets hashed into Pasta field) were absent from `state_prev.nullifier_acc_root`, inserted into `state_next.nullifier_acc_root`, `sum(in) == sum(out)`, and `total_liabilities` is unchanged.
  * `melt_step.rs`: Proves input nullifiers consumed, `state_next.total_liabilities == state_prev.total_liabilities - amount` (no underflow), and `event_log_hash` updated with payout hash.
  * `fold_batch.rs`: Recursively folds $N$ Mode A step proofs into a single epoch `FoldedProof` linking `state_start` $\to$ `state_end`.
* **Acceptance Criteria:**
  * Valid sequences of `mint`, `swap`, and `melt` produce verifying folded proofs.
  * Negative tests confirm prover/verifier rejects: (1) mint without liability increment, (2) melt exceeding liabilities, (3) duplicate nullifier replay, (4) mismatched `sum(in) != sum(out)`.

### Task A.2 — L1 Bitcoin Reserves Proof Module (`zashu-core/src/reserves.rs` & `zashu-circuits/src/reserves.rs`)
* **Deliverables:**
  * `ReserveUtxo { txid, vout, value_sats, script_pubkey }` and `ReservesAttestation` (BIP-322 / Taproot Schnorr signatures over challenge `Hash("zashu-reserves-v1" || mint_id || epoch || state_hash)`).
  * Verifier checking all UTXO signatures, optional Electrum/Bitcoin Core RPC UTXO existence check (with mock UTXO set provider for offline tests), and asserting `sum(utxo.value_sats) >= state.total_liabilities`.
  * `SolvencyBundle` builder & serializer matching `NUTZ-1` JSON format.
* **Acceptance Criteria:** Unit tests pass for solvent mint (`reserves >= liabilities`) and fail with explicit error on fractional reserve (`reserves < liabilities`) or forged UTXO signature.

### Task A.3 — Mode A CDK Sidecar & HTTP API (`zashu-cdk-sidecar`)
* **Deliverables:**
  * `MintEventSource` trait with two implementations:
    1. `InMemoryEventSource` (for tests & standalone demo).
    2. `CdkSqliteEventSource` (reads mint/swap/melt records from a CDK SQLite DB or webhook stream).
  * Background `EpochFolder` service that batches events, updates `NullifierAccumulator`, runs `fold_batch`, attaches `ReservesAttestation`, and caches the latest `SolvencyBundle`.
  * `axum` HTTP server exposing:
    * `GET /v1/solvency` — returns latest `NUTZ-1` `SolvencyBundle`.
    * `GET /v1/solvency/epoch/:epoch` — returns historical epoch bundle.
* **Acceptance Criteria:** Sidecar starts cleanly, ingests a stream of mint/swap/melt events, and serves valid `NUTZ-1` JSON over HTTP.

### Task A.4 — Solvency Auditor CLI & Library (`zashu-auditor`)
* **Deliverables:**
  * `verify_solvency_bundle(bundle: &SolvencyBundle, utxo_provider: &dyn UtxoProvider) -> Result<AuditReport>` (designed to compile cleanly to both native and `wasm32-unknown-unknown`).
  * CLI binary `zashu-auditor`:
    * `zashu-auditor verify <mint_url>` — fetches `GET /v1/solvency`, verifies Ragu/PCD proof + reserves attestation, prints human-readable audit summary (`SOLVENT` / `FAILED`) and verification latency in ms.
    * `zashu-auditor verify-file <bundle.json>` — offline bundle verification.
* **Acceptance Criteria:** Verification completes in <50ms for a cached bundle (excluding network RTT) and exits with non-zero status code on any tamper.

### Task A.5 — Mode A Simulation & Pruning Benchmarks (`benches/`)
* **Deliverables:**
  * `benches/folding_bench.rs`: Benchmarks 1, 16, 64, and 256 folded transitions (proving time, folding time, proof byte size, verification time).
  * `benches/pruning_bench.rs`: Simulates 100,000 spent secrets comparing raw `HashSet`/SQLite growth vs. `NullifierAccumulator` + `EpochPruner` memory/disk footprint.
* **Acceptance Criteria:** `cargo test --workspace` runs fast smoke versions; `cargo bench` outputs reproducible Markdown-ready numbers.

### Task A.6 — End-to-End Mode A Integration Test Suite
* **Deliverables:**
  * `crates/zashu-cdk-sidecar/tests/mode_a_e2e.rs`: Spins up mock CDK mint + `zashu-cdk-sidecar` + `zashu-auditor`, runs 100 randomized mint/swap/melt ops, verifies solvency via HTTP, then runs 4 tamper scenarios (under-reported liability, double-spend secret, insufficient L1 reserves, tampered proof bytes) and asserts all 4 are rejected.
* **Acceptance Criteria:** `cargo test -p zashu-cdk-sidecar --test mode_a_e2e` passes 100%.

---

## Mode B: Full ZK-Ecash, Oblivious Sync & Private Predicates (`NUTZ-2`, `NUTZ-3`, `NUTZ-4`)

### Task B.1 — Mode B Shielded Note Circuits (`zashu-circuits/src/mode_b/`)
* **Deliverables:**
  * `range_check.rs`: 64-bit unsigned range-check gadget preventing field wrap-around attacks.
  * `zk_mint.rs` (`NUTZ-2`): Proves `cm` opens to `(v, pk_owner, predicate_id, predicate_params_hash, rho, r)` with `v == public_mint_amount` and valid 64-bit range.
  * `zk_swap.rs` (`NUTZ-2`): Supports $k \in \{1..4\}$ inputs and $m \in \{1..4\}$ outputs (with dummy zero-value padding):
    * Input note membership in `note_acc_root_anchor`.
    * Correct nullifier derivation `nf_i = Poseidon(sk_or_auth, rho_i)`.
    * Pedersen value conservation: $\sum C_{v,\text{in}} == \sum C_{v,\text{out}}$ (amounts stay completely private).
    * 64-bit range checks on all output values.
    * Non-uniform predicate hook for `predicate_id`.
  * `zk_melt.rs` (`NUTZ-2`): Consumes inputs, exposes only `public_melt_amount` (invoice + fee), keeps optional `cm_change` hidden, enforces $\sum v_{\text{in}} == v_{\text{public\_melt}} + v_{\text{change}}$.
  * `zk_shield.rs` & `zk_unshield.rs` (`NUTZ-2`): Intra-mint bridge between standard Cashu BDHKE proofs and Mode B shielded notes conserving `total_liabilities`.
* **Acceptance Criteria:** All 5 circuits pass valid proof tests and reject overflow values ($2^{64}$), unbalanced sums, wrong anchors, and invalid nullifiers.

### Task B.2 — Unified Mode A + Mode B Mint Engine & REST API (`zashu-mint`)
* **Deliverables:**
  * Unified `ZashuMint` state manager holding both legacy BDHKE keyset state (for intra-mint interop) and Mode B `NoteAccumulator` + `NullifierAccumulator` under **one shared `MintState`** and **one `NUTZ-1` solvency proof**.
  * Rolling anchor window (configurable, default last 64 roots) so clients aren't invalidated by concurrent swaps.
  * `axum` REST endpoints per `NUTZ-2`:
    * `GET /v1/zk/info` (mint vk, current `MintState`, supported `predicate_id`s, rolling window size)
    * `POST /v1/zk/mint`
    * `POST /v1/zk/swap`
    * `POST /v1/zk/melt`
    * `POST /v1/zk/shield`
    * `POST /v1/zk/unshield`
    * `GET /v1/solvency` (unified Mode A + Mode B solvency bundle)
* **Acceptance Criteria:** Concurrent swap tests succeed without race-condition witness invalidation; double-spend attempts return HTTP `400` with `ZASHU_NULLIFIER_SPENT`.

### Task B.3 — Oblivious Witness Sync (`NUTZ-3`)
* **Deliverables:**
  * `GET /v1/zk/sync?from_epoch=<E>&bucket=<B>` endpoint serving compact epoch delta bundles (new note commitments + frontier updates + signed `MintState` headers) grouped into fixed-size privacy buckets so the mint cannot infer which specific note index a wallet is tracking.
  * Client-side `ObliviousSyncClient` in `zashu-wallet` that downloads compact deltas and updates all local `InclusionWitness`es incrementally in $O(\text{new\_notes})$ without sending note commitments or indices to the server.
* **Acceptance Criteria:** Wallet created at epoch 1 successfully updates its witness after 500 unrelated swaps by other users and spends its note at epoch 10 without ever revealing its note index during sync.

### Task B.4 — `zashuA...` Bearer Token Codec & Stealth Async Receives (`NUTZ-3`)
* **Deliverables:**
  * `zashu-core/src/token.rs`: CBOR + base64url encoder/decoder for `zashuA...` bearer tokens.
  * `zashu-core/src/stealth.rs`: ECDH stealth address derivation (`zsp1...` address format) + AEAD (ChaCha20-Poly1305) encrypted out-of-band note memo so Alice can execute `/v1/zk/swap` directly to Bob's stealth pubkey and deliver the encrypted memo via JSON/QR/Nostr relay.
* **Acceptance Criteria:**
  * `zashuA...` round-trip tests pass.
  * Stealth async receive test: Alice swaps to Bob's stealth key while Bob is offline; Alice attempts to double-spend the same note and fails; Bob later comes online, scans the encrypted memo, syncs witness, and spends the note cleanly.

### Task B.5 — Private Programmable Predicates (`NUTZ-4`)
* **Deliverables:**
  * Implement non-uniform predicate subcircuits in `zashu-circuits/src/predicates/`:
    * `0x00` — `StandardSpend` (single owner signature).
    * `0x01` — `P2PK` (hidden public key check).
    * `0x02` — `Multisig` ($t$-of-$n$ threshold authorization without revealing $t, n,$ or signers to the mint).
    * `0x03` — `Timelock` (verifies `current_epoch >= lock_epoch` publicly or via range check without leaking policy details).
    * `0x04` — `PrivateHTLC` / `CrossMintSwap` (verifies `Poseidon(preimage) == hashlock` for claim path OR `owner_refund` after `expiry_epoch` for refund path—mint never sees hashlock, preimage, or refund policy).
* **Acceptance Criteria:** Unit tests prove each predicate's happy path and failure path (wrong preimage, early timelock, insufficient multisig threshold), confirming mint API sees identical opaque swap payloads across all predicates.

### Task B.6 — Mode B Wallet CLI (`zashu-wallet`)
* **Deliverables:**
  * Local encrypted wallet store (SQLite or JSON file with seed derivation).
  * Commands:
    * `zashu-wallet init` / `zashu-wallet address` (prints stealth address `zsp1...`)
    * `zashu-wallet mint <amount_sats>`
    * `zashu-wallet balance` & `zashu-wallet sync`
    * `zashu-wallet send-token <amount_sats>` (outputs `zashuA...` bearer token)
    * `zashu-wallet send-stealth <zsp1_addr> <amount_sats>` (double-spend-proof async send)
    * `zashu-wallet receive <zashuA_or_memo>`
    * `zashu-wallet shield <cashu_token>` / `zashu-wallet unshield <amount_sats>`
    * `zashu-wallet melt <bolt11_or_mock_invoice>`
    * `zashu-wallet htlc-lock` / `zashu-wallet htlc-claim` (cross-mint atomic swap)
* **Acceptance Criteria:** CLI smoke script runs every subcommand against a local `zashu-mint` instance with exit code 0.

### Task B.7 — End-to-End Mode B Integration & Interop Test Suite
* **Deliverables:**
  * `crates/zashu-mint/tests/mode_b_e2e.rs` covering:
    1. **Arbitrary amount lifecycle:** Mint 137 sats in 1 note $\to$ split into 100 + 37 $\to$ melt 37 with hidden 100 change.
    2. **Intra-mint interop:** Mint legacy BDHKE tokens (`128 + 8 + 1`) $\to$ `/v1/zk/shield` into 1 Zashu note (137 sats) $\to$ `/v1/zk/unshield` back to legacy BDHKE $\to$ verify unified `NUTZ-1` solvency proof stays valid throughout.
    3. **Offline stealth receive:** Alice swaps to Bob's stealth key; Bob syncs via `/v1/zk/sync` and spends.
    4. **Private cross-mint atomic swap:** Spin up Mint A and Mint B; Alice & Bob execute a `PrivateHTLC` (`0x04`) atomic swap across both mints with neither mint seeing the hashlock or amount.
* **Acceptance Criteria:** `cargo test -p zashu-mint --test mode_b_e2e` passes 100%.

### Task B.8 — Security & Property-Based Invariant Suite
* **Deliverables:**
  * `proptest` suites verifying:
    * **Conservation of value** across arbitrary random sequences of mint/swap/melt/shield/unshield.
    * **64-bit overflow/underflow immunity** (attempting `u64::MAX + 1` or negative wrap in field arithmetic always fails circuit constraints).
    * **Nullifier replay & anchor expiry** rejection.
    * **Predicate isolation** (cannot satisfy `0x04` note using `0x00` subcircuit).
* **Acceptance Criteria:** `cargo test --workspace --release` passes with zero failures and `cargo clippy --workspace --all-targets -- -D warnings` passes cleanly.

---

## Final Verification Checklist (Definition of Done)

Before committing final implementation:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --release -- --ignored   # heavy e2e + proptest suites
```
All four commands must exit with code `0`.
