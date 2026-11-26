# NUTZ-2: Arbitrary-Amount Shielded Ecash Notes & Mint API (Mode B Core)

* **Status:** Draft
* **Mode:** Mode B (Requires `NUTZ-1` unified `MintState`)

---

## 1. Motivation
Standard Cashu requires power-of-2 denominations (`1, 2, 4, 8, ...`) and exposes plaintext amounts during `/v1/swap`. `NUTZ-2` introduces **Shielded Ecash Notes** backed by a Poseidon accumulator and Pedersen value commitments so users can transact arbitrary hidden amounts (e.g., 137 sats in 1 note) while the mint verifies zero-knowledge proofs instead of blind signatures.

---

## 2. Cryptographic Objects (Pasta Curves / Poseidon)

* **Note Preimage:**
  `Note = (v: u64, pk_owner: Fp, predicate_id: u8, predicate_params_hash: Fp, rho: Fp, r: Fp)`
* **Value Commitment (Pedersen on Pallas):**
  $$C_v = v \cdot G_{\text{val}} + r_v \cdot H_{\text{blind}}$$
* **Note Commitment:**
  $$\text{cm} = \text{Poseidon}(\text{DOMAIN\_NOTE}, v, \text{pk\_owner}, \text{predicate\_id}, \text{predicate\_params\_hash}, \rho, r)$$
* **Nullifier:**
  $$\text{nf} = \text{Poseidon}(\text{DOMAIN\_NF}, \text{sk\_auth}, \rho)$$
* **Range Constraint:** Every note value $v$ MUST be constrained to $0 \le v < 2^{64}$ inside every mint/swap/melt/shield circuit.

---

## 3. Rolling Anchor Window
To avoid invalidating client proofs during concurrent mint activity, the mint MUST maintain a rolling window of the last $W$ valid `note_acc_root` values (default $W = 64$). Any `zk_swap`, `zk_melt`, or `zk_unshield` proof anchored to a root within this window is accepted.

---

## 4. HTTP Endpoints

### `GET /v1/zk/info`
Returns mint verifying key hash, current `MintState`, rolling anchor window size $W$, and list of supported `NUTZ-4` `predicate_id`s.

### `POST /v1/zk/mint`
Mints a single arbitrary-amount shielded note against a paid quote (e.g., BOLT11 invoice).
* **Request:** `{ "quote_id": "...", "cm": "0x...", "cv": "0x...", "proof": "<base64>" }`
* **Circuit Checks:** `cm` opens to `v == quote.amount`, `0 <= v < 2^64`, `cv` matches `v`.
* **Response:** `{ "leaf_index": 123, "witness": {...}, "state": {...}, "mint_signature": "0x..." }`

### `POST /v1/zk/swap`
Consumes $k \in \{1..4\}$ shielded notes and produces $m \in \{1..4\}$ new shielded notes.
* **Request:**
  ```json
  {
    "anchor_root": "0x...",
    "nullifiers": ["0x..."],
    "output_commitments": ["0x..."],
    "output_value_commitments": ["0x..."],
    "proof": "<base64>"
  }
  ```
* **Circuit Checks:**
  1. Each input note exists in `anchor_root`.
  2. Each `nf_i` is validly derived and satisfies the input note's `predicate_id` (`NUTZ-4`).
  3. $\sum C_{v,\text{in}} == \sum C_{v,\text{out}}$ (mint learns zero amounts).
  4. All output values satisfy $0 \le v < 2^{64}$.
* **Mint Checks:** `anchor_root` is in the rolling window; no `nf_i` exists in `nullifier_acc_root`.
* **Error Codes:** `ZASHU_NULLIFIER_SPENT` (`400`), `ZASHU_STALE_ANCHOR` (`409`), `ZASHU_INVALID_PROOF` (`400`).

### `POST /v1/zk/melt`
Burns shielded notes to pay an external Lightning invoice / L1 payout, keeping optional change shielded.
* **Request:** `{ "quote_id": "...", "anchor_root": "0x...", "nullifiers": [...], "change_cm": "0x..." | null, "change_cv": "0x..." | null, "proof": "<base64>" }`
* **Circuit Checks:** $\sum v_{\text{in}} == v_{\text{quote\_total}} + v_{\text{change}}$.

### `POST /v1/zk/shield` & `POST /v1/zk/unshield` (Intra-Mint Cashu Interop)
* **`/v1/zk/shield`:** Accepts legacy Cashu BDHKE `Proof[]` + target `cm` + `zk_shield` proof proving `v_note == sum(bdhke_proofs.amount)`. Zero Lightning fee; `total_liabilities` unchanged.
* **`/v1/zk/unshield`:** Burns Zashu note(s) + optional shielded change `cm_change` + blinded BDHKE outputs `B_[]` totaling `v_unshield`. Zero Lightning fee; `total_liabilities` unchanged.
