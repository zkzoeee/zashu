# NUTZ-0: Proof Statements

* **Status:** Draft
* **Reference:** `crates/zashu-core/src/spec` (plain Rust, no proving)
* **Backends:** `crates/zashu-circuits/src/spec` (`ragu`, `halo2`), tested by `spec::conformance`
* **Scope today:** the statements, the reference checker, the test vectors and the two backends. The mint, wallet and sidecar still run the older per-backend circuits described in `NUTZ-1`, `NUTZ-2` and `NUTZ-4`; moving them onto these statements is a separate step.

## 1. Purpose

A proof backend is a way of proving a statement, not a definition of one. This document fixes what is proven, so that every backend proves the same thing and their costs can be compared like for like.

It defines three statements:

| Statement | Says | Public values |
| :--- | :--- | :--- |
| **Transaction** | Notes were spent by someone entitled to, and notes of the same total value were created. | `anchor, epoch, balance, nf_1, nf_2, cm_1, cm_2` |
| **Operation** | The mint's state moved by one valid mint, swap or melt. | `state_before, state_after, liabilities_before, liabilities_after` |
| **Chain** | A run of operations, each starting where the last ended. | `start, end, liabilities_start, liabilities_end, count` |

A backend conforms when it accepts every valid vector, and when no forged vector yields a proof of the statement the forgery claims (§7).

## 2. Primitives

**Field.** Every value inside a statement is a canonical element of the Pallas base field. Bytes from outside (quote hashes, preimages, seeds) are mapped to the field once, at the boundary, with BLAKE2b-512 reduced modulo the field order. No hash inside a statement has a fallback.

**Hash.** One function is used throughout: a Poseidon sponge (`P128Pow5T3`: width 3, rate 2, 8 full and 56 partial rounds of `x^5`) whose capacity element carries a domain tag.

`H_tag(x_1, ..., x_n)`:

1. Start from the state `[0, 0, 2^128 + tag]`.
2. Take the inputs two at a time. Add the first of each pair to state element 0 and the second to state element 1 (a final lone input is added to element 0 only), then apply the permutation.
3. Return state element 0.

So two inputs cost one permutation and `n` inputs cost `ceil(n / 2)`. The capacity `2^128 + tag` can never equal `L * 2^64`, the capacity of halo2's `ConstantLength<L>`, so these hashes cannot collide with those of the older Zashu code. Each tag has one fixed arity:

| Tag | Name | Inputs |
| ---: | :--- | :--- |
| 1 | `NODE` | `left, right` |
| 2 | `NOTE` | `value, owner, predicate, params, rho, r` |
| 3 | `NF` | `rho, r` |
| 4 | `PK` | `spend_sk` |
| 5 | `KEY` | `spend_pk, tweak` |
| 6 | `NF_LEAF` | `value, next_value, next_index` |
| 7 | `STATE` | `epoch, liabilities, nullifier_root, note_root, event_log` |
| 8 | `MINT` | `event_log, quote, amount` |
| 9 | `MELT` | `event_log, payout, amount` |
| 10 | `TIMELOCK` | `lock_epoch` |
| 11 | `HTLC` | `hashlock, receiver, refund, expiry_epoch` |
| 12 | `HASHLOCK` | `preimage` |
| 13 | `MULTISIG` | `threshold, key_count, k_1, k_2, k_3, k_4` |

**Trees.** The note tree and the nullifier tree are binary Merkle trees of depth 24 with `node = H_NODE(left, right)` and zero as the empty leaf.

* The **note tree** is append-only. A leaf is a note commitment.
* The **nullifier tree** is an indexed Merkle tree. Leaf `i` holds `(value, next_value, next_index)` and hashes to `H_NF_LEAF` of them. The leaves form a linked list sorted by `value`, compared as integers in `[0, p)`. Leaf 0 is the sentinel `(0, 0, 0)`; `next_value = 0` means "no successor".

## 3. Notes and keys

A note is `(value, owner, predicate, params, rho, r)` with `value < 2^64`.

* Commitment: `cm = H_NOTE(value, owner, predicate, params, rho, r)`.
* Nullifier: `nf = H_NF(rho, r)`.

**Keys.** A spend key is a field element `spend_sk`. Its public key is `spend_pk = H_PK(spend_sk)`, and the key a note is locked to is the *key image* `K = H_KEY(spend_pk, tweak)`.

* A sender who knows `spend_pk` can lock a note to a fresh, unlinkable image by choosing `tweak`, but cannot spend it.
* For a stealth payment (`NUTZ-3`), `tweak` is derived from a Diffie-Hellman secret on Pallas. That exchange happens outside any proof; no curve arithmetic is ever proven.
* With `tweak = 0` the image is a public function of `spend_pk`, for keys named in a contract.

Two consequences are deliberate and should be understood:

* **There are no signatures.** A spend is authorised by proving knowledge of `spend_sk` inside the transaction proof. The secret must be in the prover, which rules out hardware signers and multisig signers who prove independently.
* **The sender can see the spend.** The nullifier depends on the note alone, because several parties may be entitled to spend one note (HTLC, multisig) and all must reveal the same nullifier. Whoever created the note knows `rho` and `r`.

## 4. Predicates

`predicate` selects the rule; `epoch` is the transaction's public epoch.

| Id | Name | Note fields | Satisfied by |
| ---: | :--- | :--- | :--- |
| 0 | Key | `owner = K`, `params = 0` | `(spend_sk, tweak)` opening `owner` |
| 1 | Timelock | `owner = K`, `params = H_TIMELOCK(lock)` | a key opening `owner`, and `epoch >= lock` |
| 2 | HTLC | `params = H_HTLC(hashlock, receiver, refund, expiry)` | **claim:** `preimage` with `H_HASHLOCK(preimage) = hashlock`, a key opening `receiver`, and `epoch < expiry`; or **refund:** a key opening `refund`, and `epoch >= expiry` |
| 3 | Multisig | `params = H_MULTISIG(t, n, k_1..k_4)` | exactly `t` keys opening `t` distinct slots among the first `n`, in increasing slot order; `1 <= t <= 3`, `t <= n <= 4` |

`owner` is not used by HTLC and Multisig. A note spent under the wrong predicate id is rejected even if a key opens its `owner`.

## 5. The transaction statement

**Public:** `[anchor, epoch, balance, nf_1, nf_2, cm_1, cm_2]`.

**Shape.** A transaction has exactly two outputs and either two inputs or none.

* Unused slots hold zero-value dummy notes, so the proof does not reveal how many real notes moved.
* A transaction with no inputs is a shielded mint. It is publicly a mint anyway, so it is not padded: `nf_1 = nf_2 = 0` and `anchor = 0`.

**Relation.** There exist notes and authorisations such that:

1. For each output `j`: `cm_j` is the commitment of a note with `value < 2^64`.
2. If there are inputs, for each input `i`:
   * `nf_i` is the nullifier of the note;
   * the note's commitment is in the tree with root `anchor`, **or** the note's value is zero (a dummy);
   * the note's predicate is satisfied at `epoch` (§4).
3. `balance = sum(input values) - sum(output values)`, in the field.

**Verifier rules** (the mint, outside the proof):

* `nf_1 != nf_2`, and neither is already in the nullifier tree. A dummy input has a real, random nullifier and is inserted like any other.
* `anchor` is a recent note root; `epoch` is not ahead of the mint's.
* `balance` is `0` for a swap, the amount for a melt, and its negation for a mint.

## 6. The operation and chain statements

**State.** `(epoch, liabilities, nullifier_root, note_root, event_log)`, hashed with `H_STATE`.

**Public:** `[state_before, state_after, liabilities_before, liabilities_after]`, the two states as hashes.

**Relation.** One operation, in this order:

1. **Value.** `epoch` does not decrease. Then by kind:
   * *mint*: liabilities rise by `amount > 0`, and `event_log' = H_MINT(event_log, quote, amount)`;
   * *melt*: liabilities fall by `amount > 0` (never below zero), and `event_log' = H_MELT(event_log, payout, amount)`;
   * *swap*: liabilities and the event log do not change.
2. **Up to two nullifier inserts.** For each, with low leaf `(v, next_v, next_i)` at `low_index`:
   * `v < nf`, and `nf < next_v` unless `next_v = 0`;
   * the low leaf is in the tree;
   * it is replaced by `(v, nf, new_index)`;
   * the leaf at `new_index` was empty and becomes `(nf, next_v, next_i)`.
3. **Up to two note appends.** For each, the leaf at `index` was empty and becomes `cm`.

An unused insert or append slot changes nothing. A legacy operation that only moves liabilities uses none.

**Chain.** `[start, end, liabilities_start, liabilities_end, count]`: there are `count >= 1` operations, each satisfying the relation, the first starting at `start`, each next one starting at the state the previous ended at, the last ending at `end`.

What these statements do **not** say: that the nullifiers and notes an operation inserts are the ones a transaction proof authorised. The mint checks that. Binding the two inside a proof needs one proof to verify another, which only a recursive backend can do; it is outside the shared statements.

## 7. Conformance

The reference checker is `zashu_core::spec::{tx, op}::check`. The vectors are `zashu_core::spec::vectors`:

* **Valid:** a mint; swaps with one and with two real inputs; a melt; a timelock at its epoch; an HTLC claim and refund; a multisig; and a five-operation chain (shielded mint, full swap, melt with change, legacy mint, small swap).
* **Forged transactions:** wrong key; right secret with the wrong tweak; a note that was never appended; a wrong leaf index; a timelocked note spent as a plain key note; a timelock one epoch early; a timelock claiming an earlier lock; HTLC with the wrong preimage, the wrong claimant, a claim at expiry, an early refund and the wrong refund key; multisig with too few signers, a repeated signer, an uncommitted key and a slot past the key count.
* **Forged operations:** a nullifier inserted out of order; a nullifier inserted twice; a low leaf that is not in the tree; a note written over an existing leaf; a mint of zero; a melt of more than the liabilities; an epoch that goes backwards.

A backend must:

1. prove every valid vector and verify it against the statement the checker returns;
2. refuse to verify that proof against any statement that differs in one public value;
3. for every forgery, either fail to prove or produce a proof that does not verify against the statement the forgery claims;
4. reject a chain with a missing operation or with a forged operation in it.

Point 3 is tested without native pre-checks, because some proof systems only report an unsatisfied witness at verification.

## 8. Backends

Both implement `zashu_circuits::spec::Backend`.

| | Ragu | Halo 2 |
| :--- | :--- | :--- |
| Transaction | A small tree of step circuits, one spend circuit per predicate | One fixed circuit; the predicate is a selected branch |
| Operation | A chain of single-purpose steps | One fixed circuit with two insert and two append slots |
| Chain | One recursive proof of constant size | One operation proof per operation, verified in sequence; size and verify time grow with the chain |
| Which predicate ran | Inside the recursion; hiding rests on Ragu's rerandomisation, which is not yet proven | Hidden by the proof's zero-knowledge property: there is only one circuit |

The chain row is the one place the two cannot be equal: this Halo 2 has no recursion. A Halo 2 chain proof also has to carry each operation's statement, so that the verifier can check the proofs link up.

Measured costs of both on the same workloads are in [`BENCHMARKS.md`](../BENCHMARKS.md), section 4.

## 9. Open points

* **Index width.** Leaf indices are 64-bit values of which only the low 24 bits select a leaf. The high bits of a nullifier leaf's `next_index` are hashed into the tree. The statements should require every index to be below `2^24`; today neither the reference nor the backends do.
* **Nullifiers are visible to the sender** (§3). Keying them for single-owner notes and binding them to the leaf position is the planned next revision.
* **Unused fields.** A swap's `amount` and `event`, and a mint's witness anchor, are ignored.
