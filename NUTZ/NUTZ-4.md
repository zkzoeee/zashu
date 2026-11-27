# NUTZ-4: Private Programmable Predicates & Cross-Mint Atomic Swaps

* **Status:** Draft
* **Mode:** Mode B (Non-Uniform Ragu Subcircuits)
* **Implementation:** enforced in-circuit by the default Ragu backend for all five predicates (`0x02` for up to 4 keys and 3 signers). The fallback Halo 2 backend (`ZASHU_PCD_BACKEND=halo2`) checks the predicate in the wallet only.

---

## 1. Motivation
In standard Cashu (`NUT-10`, `NUT-11`, `NUT-14`), P2PK keys, timelocks, and HTLC hashlocks are stored in plaintext JSON inside `secret`, allowing the mint to observe every spending policy.

`NUTZ-4` uses **Ragu’s non-uniform PCD** to hide spending predicates inside the note commitment (`predicate_id`, `predicate_params_hash`). When spending a note, the client proves satisfaction of the predicate’s dedicated subcircuit—the mint verifies only the opaque `zk_swap`/`zk_melt` proof and **never learns which predicate was used**.

---

## 2. Predicate Registry (`predicate_id`)

| `predicate_id` | Name | `predicate_params_hash` | Witness Required to Spend |
| :--- | :--- | :--- | :--- |
| `0x00` | `StandardSpend` | `0x00..00` | `sk` with `[sk]G == pk_owner`. |
| `0x01` | `P2PK` | `Poseidon3(DOMAIN_PREDICATE, 0x01, K(target_pk))` | `sk` with `[sk]G == target_pk`. |
| `0x02` | `Multisig` | `Poseidon7(DOMAIN_PREDICATE, 0x02 + 256 t + 65536 n, K(pk_1), K(pk_2), K(pk_3), K(pk_4), 0)`, absent keys as zero | Secret keys for $t$ distinct keys of the list ($n \le 4$, at most 3 signers proven). Larger key sets use a byte-oriented hash and are Halo 2 only. |
| `0x03` | `Timelock` | `Poseidon4(DOMAIN_PREDICATE, 0x03, lock_epoch, K(pk_owner))` | `sk` for `pk_owner` AND `epoch >= lock_epoch`. |
| `0x04` | `PrivateHTLC` | `Poseidon7(DOMAIN_PREDICATE, 0x04, hashlock, K(pk_receiver), K(pk_refund), expiry_epoch, 0)` | **Claim path:** `preimage` with `H(preimage) == hashlock`, and `sk_receiver`.<br>**Refund path:** `sk_refund` AND `epoch >= expiry_epoch`. |

`K(pk) = Poseidon2(x, y)` is the image of a Pallas public key by its affine coordinates; it is also how `pk_owner` enters the note commitment. `epoch` is the epoch the proof was evaluated at. It is public, and the mint rejects a proof whose `epoch` is ahead of its own.

### 2.1 How the Ragu backend proves a spend

A spend does not fit in one Ragu step, so a transaction is a small tree of steps fused into one proof:

1. **Path** (4 steps of 8 levels): the note commitment is a leaf under `anchor_root`.
2. **Key**: knowledge of `sk`, exposing `K([sk]G)`.
3. **Spend** (one circuit per predicate and branch): opens the note commitment, derives the nullifier, and enforces the predicate against the key proof. For `Multisig`, up to three key proofs are first gathered into a key set; the spend checks each is a distinct member of the committed list and that there are at least $t$.
4. **Output**: opens each output commitment and range-checks its value.
5. **Merge / Finalize**: anchors and epochs must agree and values add up; the final statement is `[anchor, epoch, digest, balance]`.

`digest` commits to the ordered nullifiers and output commitments and is recomputed by the mint. `balance` is `sum(inputs) - sum(outputs)`: zero for a swap, the public amount for a melt, its negation for a mint. The transaction proof is rerandomized before it is published, and the mint sees only that proof, so which spend circuits ran stays inside the recursion. This relies on Ragu's rerandomization, whose indistinguishability Ragu documents as a design goal that is not yet proven; predicate privacy is best-effort until it is. What is checked here: published proofs for all five predicates have the same length, the same envelope and circuit index, and the same public-input shape (`published_proofs_have_the_same_shape_for_every_predicate`).

### 2.2 Nullifiers

`nf = Poseidon3(DOMAIN_NF, r, rho)`. A note has exactly one nullifier, whichever key or branch spends it; otherwise the claim and refund paths of an HTLC would produce different nullifiers and the note could be spent twice. The trade-off is that whoever created a note knows its opening and can tell when it is spent.

---

## 3. Private Cross-Mint & Lightning / CMYK Atomic Swaps (`0x04`)

### Flow (Mint A $\leftrightarrow$ Mint B Atomic Swap)
1. **Setup:** Alice wants to swap $V$ sats on Mint A for $V$ sats on Mint B with Bob (a liquidity provider).
2. **Secret:** Alice samples random 32-byte `preimage` and computes `hashlock = Poseidon2(DOMAIN_STEALTH, hash_to_field(preimage))`.
3. **Lock on Mint A:** Alice calls `POST /v1/zk/swap` on Mint A creating a `0x04` (`PrivateHTLC`) note payable to Bob (`hashlock`, `expiry = E_A + 20`) and sends Bob the encrypted note memo (`NUTZ-3`).
4. **Lock on Mint B:** Bob verifies the note exists in Mint A's `note_acc_root`, then calls `POST /v1/zk/swap` on Mint B creating a matching `0x04` note payable to Alice (`hashlock`, `expiry = E_B + 10`).
5. **Claim on Mint B:** Alice claims Bob's note on Mint B using `preimage` (revealing `preimage` to Bob out-of-band, or via encrypted swap receipt—**Mint B still never sees the hashlock or preimage**).
6. **Claim on Mint A:** Bob uses `preimage` to claim Alice's note on Mint A.

### Interoperability with CMYK / Satachy / Zark
Because `CMYK`, `Satachy`, and `Zark` share the exact same `Pasta/Poseidon` `PrivateHTLC` (`0x04`) subcircuit, the identical flow enables **custodial Zashu $\leftrightarrow$ self-custodial shielded Bitcoin UTXO** atomic swaps with zero on-chain linkage.

---

## 4. Security Requirements
* **Predicate Isolation:** The `zk_swap` / `zk_melt` router circuit MUST enforce that the executed non-uniform subcircuit matches the input note's committed `predicate_id` and `predicate_params_hash`.
* **Epoch bound:** The mint MUST reject a proof evaluated at an epoch greater than its current epoch.
* **Indistinguishability:** API payloads for `0x00`..`0x04` MUST have identical field structure and byte sizes so mints cannot fingerprint predicate types.
