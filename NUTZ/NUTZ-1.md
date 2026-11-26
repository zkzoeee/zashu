# NUTZ-1: Verifiable ZK Mint Solvency & Prunable Nullifiers (Mode A)

* **Status:** Draft
* **Mode:** Mode A (Backward-compatible with standard Cashu & Fedimint; also audits Mode B)

---

## 1. Motivation
In standard Chaumian ecash, blind signatures prevent a mint from linking users, but give users **no cryptographic assurance** that the mint is not running a fractional reserve (printing unbacked ecash). Additionally, mints must retain every spent token secret forever, causing unbounded storage growth.

`NUTZ-1` defines a verifiable, constant-size **ZK Solvency Bundle** (`Proof of Liabilities <= Proof of Reserves`) produced via recursive folding (Ragu/PCD) alongside a prunable epoch nullifier accumulator.

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
