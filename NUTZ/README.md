# NUTZ — Zashu Protocol Specifications

**NUTZ** *(Notation, Usage, and Terminology for Zashu)* extends Cashu's **NUT** specifications with zero-knowledge solvency proofs, arbitrary-amount shielded ecash notes, oblivious witness synchronization, and private programmable predicates.

| Spec | Mode | Title | Status |
| :--- | :--- | :--- | :--- |
| [NUTZ-1](./NUTZ-1.md) | Mode A | Verifiable ZK Mint Solvency & Prunable Nullifiers | Draft |
| [NUTZ-2](./NUTZ-2.md) | Mode B | Arbitrary-Amount Shielded Ecash Notes & Mint API | Draft |
| [NUTZ-3](./NUTZ-3.md) | Mode B | Oblivious Witness Sync, `zashuA` Tokens & Stealth Async Receives | Draft |
| [NUTZ-4](./NUTZ-4.md) | Mode B | Private Programmable Predicates & Cross-Mint Atomic Swaps | Draft |

## Compatibility with Cashu NUTs
* **NUTZ-1 (Mode A)** is 100% backward-compatible with existing Cashu (`NUT-00`–`NUT-14`) and Fedimint deployments—no wallet changes are required.
* **NUTZ-2 / NUTZ-3 / NUTZ-4 (Mode B)** coexist alongside standard Cashu endpoints (`/v1/*`) inside the same mint under a single unified `NUTZ-1` solvency proof, bridged via zero-fee `/v1/zk/shield` and `/v1/zk/unshield`.
