# Zashu

**Zashu** *(ZK + Cashu)* brings **Ragu non-uniform PCD / recursive folding** and **Tachyon prunable accumulators + oblivious sync** to Chaumian ecash (**Cashu** and **Fedimint**).

## Two Complementary Modes

* **Mode A (`NUTZ-1`) — Verifiable Mint Solvency:** Drop-in sidecar for existing Cashu (CDK) and Fedimint mints. Continuously folds `mint`/`swap`/`melt` accounting into a constant-size ZK proof that `total_liabilities <= reserves`, with prunable nullifier accumulators and zero changes to legacy Cashu wallets.
* **Mode B (`NUTZ-2`, `NUTZ-3`, `NUTZ-4`) — Full ZK-Ecash:** Arbitrary hidden amounts (no power-of-2 splitting), hidden programmable spending conditions (`P2PK`, `Multisig`, `Timelock`, `PrivateHTLC`, `CrossMintSwap`), oblivious mobile witness sync, and double-spend-proof stealth async P2P receives—interoperating zero-fee with standard Cashu inside the same mint via `/v1/zk/shield` and `/v1/zk/unshield`.

## Documentation

* [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) — Numbered task-by-task implementation plan for both Mode A and Mode B.
* [NUTZ Specifications](./NUTZ/README.md):
  * [NUTZ-1](./NUTZ/NUTZ-1.md) — Verifiable ZK Mint Solvency (Mode A)
  * [NUTZ-2](./NUTZ/NUTZ-2.md) — Shielded Ecash Notes & Mint API (Mode B Core)
  * [NUTZ-3](./NUTZ/NUTZ-3.md) — Oblivious Witness Sync & Stealth Async Receives
  * [NUTZ-4](./NUTZ/NUTZ-4.md) — Private Programmable Predicates & Cross-Mint Atomic Swaps
