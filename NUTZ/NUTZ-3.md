# NUTZ-3: Oblivious Witness Sync, `zashuA` Tokens & Stealth Async Receives

* **Status:** Draft
* **Mode:** Mode B (Companion to `NUTZ-2`)
* **Keys under `NUTZ-0`:** [`NUTZ-0`](./NUTZ-0.md) §3 replaces the curve-point spend key with `spend_pk = H(spend_sk)` and locks a note to `K = H(spend_pk, tweak)`. The scan key stays a Pallas point and the Diffie-Hellman exchange below is unchanged, but its result becomes the `tweak` instead of a point added to the spend key. This document describes what the wallet runs today.

---

## 1. Motivation
Unlike stateless BDHKE Cashu proofs, shielded `NUTZ-2` notes require a fresh `NoteAccumulator` inclusion witness to spend. `NUTZ-3` defines:
1. **Oblivious Witness Sync (`GET /v1/zk/sync`)** so wallets refresh witnesses without revealing which notes they own.
2. **Bearer Token Format (`zashuA...`)** for direct P2P token handoff.
3. **Stealth Async Receives (`zsp1...`)** for double-spend-proof P2P payments when the receiver is offline.

---

## 2. Oblivious Witness Sync (`GET /v1/zk/sync`)

### Endpoint
`GET /v1/zk/sync?from_epoch={E}&to_epoch={E_end}&bucket={B}`

* **Privacy Rule:** Clients MUST NEVER send their note commitments (`cm`) or `leaf_index` to the mint when syncing.
* **Response (`200 OK`):**
  ```json
  {
    "from_epoch": 10,
    "to_epoch": 15,
    "new_commitments": ["0x...", "..."],
    "frontier_nodes": ["0x..."],
    "latest_state": { "...": "..." },
    "mint_signature": "0x..."
  }
  ```
* **Client Behavior:** The wallet applies `new_commitments` and `frontier_nodes` locally to update all owned `InclusionWitness`es to `latest_state.note_acc_root`. Sync bandwidth scales only with epochs missed, and the mint learns nothing about which notes belong to the wallet.

---

## 3. Bearer Token Format (`zashuA...`)

For quick P2P handoff (analogous to `cashuB...`), a Zashu bearer token encodes:
```text
"zashuA" || base64url_nopad(CBOR({
  "mint": "https://mint.example.com",
  "epoch": 42,
  "notes": [
    {
      "v": 137,
      "spend_sk": "<32-byte temp secret key>",
      "predicate_id": 0,
      "predicate_params_hash": "<32 bytes>",
      "rho": "<32 bytes>",
      "r": "<32 bytes>",
      "leaf_index": 123,
      "witness": "<serialized InclusionWitness>"
    }
  ]
}))
```
*Note: Just like standard Cashu bearer tokens, a receiver of `zashuA...` should call `/v1/zk/swap` to claim exclusive ownership.*

---

## 4. Stealth Async Receives (`zsp1...`) — Double-Spend-Proof P2P

To eliminate the online double-spend race of bearer tokens:
1. **Receiver Static Address:** Bob publishes `zsp1...` encoding `(scan_pk, spend_pk)` on Pallas.
2. **Sender Swap:** Alice derives a one-time stealth owner key via ECDH:
   * Picks ephemeral scalar $e$, computes $E = e \cdot G$ and shared secret $S = \text{Poseidon}(e \cdot \text{scan\_pk})$.
   * Computes one-time `pk_owner = spend_pk + S * G`.
   * Executes `POST /v1/zk/swap` creating a note locked to `pk_owner`.
3. **Out-of-Band Encrypted Memo:** Alice encrypts `(v, rho, r, predicate_id, predicate_params_hash, leaf_index)` under `ChaCha20-Poly1305(key = SHA256(S))` and sends `(E, ciphertext)` to Bob via QR, Nostr (NIP-59), or messenger.
4. **Security Property:** Once the mint accepts Alice's `/v1/zk/swap`, **Alice cannot double-spend the note**, even if Bob remains offline indefinitely. When Bob comes online, he decrypts the memo, runs `/v1/zk/sync`, and owns the note exclusively.
