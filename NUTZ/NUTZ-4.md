# NUTZ-4: Private Programmable Predicates & Cross-Mint Atomic Swaps

* **Status:** Draft
* **Mode:** Mode B (Non-Uniform Ragu Subcircuits)

---

## 1. Motivation
In standard Cashu (`NUT-10`, `NUT-11`, `NUT-14`), P2PK keys, timelocks, and HTLC hashlocks are stored in plaintext JSON inside `secret`, allowing the mint to observe every spending policy.

`NUTZ-4` uses **Ragu’s non-uniform PCD** to hide spending predicates inside the note commitment (`predicate_id`, `predicate_params_hash`). When spending a note, the client proves satisfaction of the predicate’s dedicated subcircuit—the mint verifies only the opaque `zk_swap`/`zk_melt` proof and **never learns which predicate was used**.

---

## 2. Predicate Registry (`predicate_id`)

| `predicate_id` | Name | `predicate_params_hash` Preimage | Witness Required to Spend |
| :--- | :--- | :--- | :--- |
| `0x00` | `StandardSpend` | `0x00..00` | Knowledge of `sk` matching `pk_owner`. |
| `0x01` | `P2PK` | `Poseidon(target_pk)` | Signature / Schnorr proof under `target_pk`. |
| `0x02` | `Multisig` | `Poseidon(t, n, pk_1..pk_n)` | $t$ valid distinct signatures from `{pk_1..pk_n}` (hidden $t, n,$ and signers). |
| `0x03` | `Timelock` | `Poseidon(lock_epoch, pk_owner)` | Valid spend proof AND `anchor_epoch >= lock_epoch`. |
| `0x04` | `PrivateHTLC` | `Poseidon(hashlock, pk_receiver, pk_refund, expiry_epoch)` | **Claim path:** `preimage` s.t. `Poseidon(preimage) == hashlock` + `sk_receiver`.<br>**Refund path:** `sk_refund` AND `anchor_epoch >= expiry_epoch`. |

---

## 3. Private Cross-Mint & Lightning / CMYK Atomic Swaps (`0x04`)

### Flow (Mint A $\leftrightarrow$ Mint B Atomic Swap)
1. **Setup:** Alice wants to swap $V$ sats on Mint A for $V$ sats on Mint B with Bob (a liquidity provider).
2. **Secret:** Alice samples random 32-byte `preimage` and computes `hashlock = Poseidon(preimage)`.
3. **Lock on Mint A:** Alice calls `POST /v1/zk/swap` on Mint A creating a `0x04` (`PrivateHTLC`) note payable to Bob (`hashlock`, `expiry = E_A + 20`) and sends Bob the encrypted note memo (`NUTZ-3`).
4. **Lock on Mint B:** Bob verifies the note exists in Mint A's `note_acc_root`, then calls `POST /v1/zk/swap` on Mint B creating a matching `0x04` note payable to Alice (`hashlock`, `expiry = E_B + 10`).
5. **Claim on Mint B:** Alice claims Bob's note on Mint B using `preimage` (revealing `preimage` to Bob out-of-band, or via encrypted swap receipt—**Mint B still never sees the hashlock or preimage**).
6. **Claim on Mint A:** Bob uses `preimage` to claim Alice's note on Mint A.

### Interoperability with CMYK / Satachy / Zark
Because `CMYK`, `Satachy`, and `Zark` share the exact same `Pasta/Poseidon` `PrivateHTLC` (`0x04`) subcircuit, the identical flow enables **custodial Zashu $\leftrightarrow$ self-custodial shielded Bitcoin UTXO** atomic swaps with zero on-chain linkage.

---

## 4. Security Requirements
* **Predicate Isolation:** The `zk_swap` / `zk_melt` router circuit MUST enforce that the executed non-uniform subcircuit matches the input note's committed `predicate_id` and `predicate_params_hash`.
* **Indistinguishability:** API payloads for `0x00`..`0x04` MUST have identical field structure and byte sizes so mints cannot fingerprint predicate types.
