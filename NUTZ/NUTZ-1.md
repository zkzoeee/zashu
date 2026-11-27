# NUTZ-1: Verifiable ZK Mint Solvency & Prunable Nullifiers (Mode A)

* **Status:** Draft
* **Mode:** Mode A (Backward-compatible with standard Cashu & Fedimint; also audits Mode B)

---

## 1. Motivation
In standard Chaumian ecash, blind signatures prevent a mint from linking users, but give users **no cryptographic assurance** that the mint is not running a fractional reserve (printing unbacked ecash). Additionally, mints must retain every spent token secret forever, causing unbounded storage growth.

`NUTZ-1` defines a verifiable, constant-size **ZK Solvency Bundle** (`Proof of Liabilities <= Proof of Reserves`) produced by folding the mint's step proofs (as a batch proof with the default Halo 2 backend, recursively with the opt-in Ragu backend; see §2.1) alongside a prunable epoch nullifier accumulator.

---

## 2. Canonical Mint State

At the end of every epoch $E$, the mint commits to a deterministic `MintState`:

```json
{
  "epoch": 42,
  "total_liabilities": 12500000,
  "nullifier_acc_root": "0x...",
  "note_acc_root": "0x...",
  "event_log_hash": "0x..."
}
```

* `epoch` (`u64`): Monotonically increasing epoch counter.
* `total_liabilities` (`u64`): Exact sum (in satoshis) of all unspent ecash across the mint (legacy BDHKE + Mode B shielded notes).
* `nullifier_acc_root` (32-byte hex): Root of the Tachyon-style prunable accumulator over all spent secrets/nullifiers.
* `note_acc_root` (32-byte hex): Root of active Mode B notes (zero bytes if Mode A only).
* `event_log_hash` (32-byte hex): Rolling Poseidon hash of all mint/melt external quote commitments.

### 2.1 What the folded proof attests

`state_hash = Poseidon3(Poseidon4(DOMAIN_STATE, epoch, total_liabilities, nullifier_acc_root), note_acc_root, event_log_hash)`.

* **Ragu backend** (`ZASHU_PCD_BACKEND=ragu`): a mint operation is proven as a chain of single-purpose transitions between state hashes, each opened in-circuit, and a recursive fold step enforces that consecutive transitions chain on state hash and liabilities. The published proof attests the whole chain from the genesis state to the current one.
  * **Value** (one per operation): the epoch does not decrease; liabilities follow the operation's kind (mint adds, melt subtracts, swap conserves); a mint or melt extends the event log with `Poseidon4(log, DOMAIN, quote_hash, amount)` where `amount` is exactly the change in liabilities, and a swap leaves the log alone. Both roots stay fixed.
  * **Note insert** (one per output, or one per two outputs): the note root changes by writing a commitment into a previously empty leaf. Notes can only be appended. Two outputs are proven together: their Merkle paths are walked separately up to where they meet and once from there to the root.
  * **Nullifier insert** (one per nullifier): a sorted indexed-Merkle-tree insertion. The low leaf satisfies `low.val < nf < low.next_val` (or has no successor) in the accumulator's byte order, is re-pointed at `nf`, and the new leaf is appended into an empty slot. The two leaf changes are proven as one paired update, sharing the path above the point where they meet. Nullifiers can only be added, never removed or reordered.
  * Not attested: that the inserted nullifiers and notes are the ones the operation's shielded proof or BDHKE spend authorised, and that amounts match Lightning payments. The mint checks the former; an auditor replays the public event log for the latter.
  * Accumulator keys must be canonical field elements; legacy secrets and externally supplied nullifiers are mapped to the field before insertion.
* **Aggregated Ragu backend** (`ZASHU_PCD_BACKEND=ragu-aggregated`): everything above, plus a Ragu aggregator that decompresses each operation's fold proof together with the shielded transaction proof that authorised it. The published statement is `[start_liab, end_liab, start_state, end_state, ops, unbound_ops]`.
  * A **bound** operation inserted exactly its transaction's nullifiers and outputs, in order; moved liabilities by exactly the transaction's value balance (zero for a swap, the amount for a melt, its negation for a mint); and, if it spends, proved membership under the note root the operation started from.
  * Every other operation is accepted and counted in `unbound_ops`: legacy BDHKE mints and melts, shield and unshield, transactions built on the Halo 2 backend, and spends against an older anchor. An auditor decides how many unbound operations it tolerates; a shielded-only mint can reach zero.
  * The anchor rule is strict because the state does not yet commit to a history of note roots.
* **Ragu backend without root bindings** (`ZASHU_PCD_BACKEND=ragu-unbound`): the same recursive fold, but each operation is a single step that checks liabilities and lets the roots and event log move freely. About 1 s per operation instead of tens of seconds.
* **Halo 2 backend** (default): the folder verifies the step proofs itself and emits one proof whose public inputs are the start and end state hashes and liabilities. An auditor trusts the folder for the steps in between.

---

## 3. State Transition Rules (Proved in ZK)

Each epoch transition `MintState(E-1) -> MintState(E)` is folded from individual step proofs:
1. **`mint_step(amount, quote_hash)`:**
   * `total_liabilities' = total_liabilities + amount` (no `u64` overflow).
   * `event_log_hash' = Poseidon(event_log_hash, DOMAIN_MINT, quote_hash, amount)`.
2. **`swap_step(nullifiers[], sum_in, sum_out)`:**
   * Every `nf` in `nullifiers` is proven **absent** from `nullifier_acc_root` and **inserted** into `nullifier_acc_root'`.
   * `sum_in == sum_out` (plaintext for BDHKE; Pedersen commitment balance for Mode B).
   * `total_liabilities' == total_liabilities`.
3. **`melt_step(nullifiers[], amount, payout_hash)`:**
   * Input nullifiers absent from `nullifier_acc_root` and inserted into `nullifier_acc_root'`.
   * `total_liabilities' = total_liabilities - amount` (no underflow).
   * `event_log_hash' = Poseidon(event_log_hash, DOMAIN_MELT, payout_hash, amount)`.

---

## 4. Reserves Attestation

To prove `reserves >= total_liabilities`, the mint signs a challenge bound to the epoch:
```text
challenge = SHA256("zashu-reserves-v1" || mint_id || epoch_le_u64 || MintState_hash)
```
For each reserve UTXO on Bitcoin L1 (or Fedimint federation multisig), the mint provides a BIP-322 / Taproot Schnorr signature over `challenge`. Auditors verify:
1. Each UTXO is unspent on Bitcoin L1 (via full node / Electrum / UTXO accumulator).
2. Each signature is valid for the UTXO's `scriptPubKey`.
3. $\sum \text{utxo.value\_sats} \ge \text{state.total\_liabilities}$.

---

## 5. HTTP API

### `GET /v1/solvency` (and `GET /v1/solvency/epoch/{epoch}`)

**Response (`200 OK`):**
```json
{
  "version": "NUTZ-1",
  "mint_id": "0x...",
  "genesis_state_hash": "0x...",
  "state": {
    "epoch": 42,
    "total_liabilities": 12500000,
    "nullifier_acc_root": "0x...",
    "note_acc_root": "0x...",
    "event_log_hash": "0x..."
  },
  "pcd_proof": "<base64_folded_proof>",
  "reserves": {
    "challenge": "0x...",
    "utxos": [
      {
        "txid": "...",
        "vout": 0,
        "value_sats": 15000000,
        "script_pubkey": "...",
        "signature": "..."
      }
    ]
  },
  "mint_signature": "0x..."
}
```

---

## 6. Client Verification Algorithm
1. Check `version == "NUTZ-1"` and `mint_signature` over `state`.
2. Verify `pcd_proof` against `(genesis_state_hash, state)`.
3. Recompute `challenge` and verify every UTXO signature + L1 unspent status.
4. Assert `sum(utxos.value_sats) >= state.total_liabilities`.
5. Return `SOLVENT` iff all checks pass.
