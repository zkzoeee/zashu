//! The one hash of the spec: a Poseidon sponge (`P128Pow5T3`, width 3, rate
//! 2) whose capacity element carries a domain tag.
//!
//! `H_tag(x_1, ..., x_n)` starts from the state `[0, 0, 2^128 + tag]`, adds
//! the inputs two at a time into the first two state elements (a final lone
//! input is added to the first) with one permutation after each block, and
//! returns the first state element. So two inputs cost one permutation, and
//! `n` inputs cost `ceil(n / 2)`.
//!
//! Every tag has one fixed arity. The capacity `2^128 + tag` can never equal
//! `L * 2^64`, the capacity of halo2's `ConstantLength<L>`, so no value here
//! collides with a hash computed by the older Zashu code.

use std::sync::OnceLock;

use ff::{Field, PrimeField};
use halo2_poseidon::{P128Pow5T3, Spec};

use super::Fp;

/// Tree node: `(left, right)`.
pub const T_NODE: u64 = 1;
/// Note commitment: `(value, owner, predicate, params, rho, r)`.
pub const T_NOTE: u64 = 2;
/// Nullifier: `(rho, r)`.
pub const T_NF: u64 = 3;
/// Spend public key: `(spend_sk)`.
pub const T_PK: u64 = 4;
/// Key image: `(spend_pk, tweak)`.
pub const T_KEY: u64 = 5;
/// Nullifier-tree leaf: `(value, next_value, next_index)`.
pub const T_NF_LEAF: u64 = 6;
/// Mint state: `(epoch, liabilities, nullifier_root, note_root, event_log)`.
pub const T_STATE: u64 = 7;
/// Event log after a mint: `(log, quote, amount)`.
pub const T_MINT: u64 = 8;
/// Event log after a melt: `(log, payout, amount)`.
pub const T_MELT: u64 = 9;
/// Timelock parameters: `(lock_epoch)`.
pub const T_TIMELOCK: u64 = 10;
/// HTLC parameters: `(hashlock, receiver, refund, expiry_epoch)`.
pub const T_HTLC: u64 = 11;
/// Hashlock: `(preimage)`.
pub const T_HASHLOCK: u64 = 12;
/// Multisig parameters: `(threshold, key_count, k1, k2, k3, k4)`.
pub const T_MULTISIG: u64 = 13;

type Constants = (Vec<[Fp; 3]>, [[Fp; 3]; 3]);

fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| {
        let (rc, mds, _) = <P128Pow5T3 as Spec<Fp, 3, 2>>::constants();
        (rc, mds)
    })
}

/// The Poseidon permutation: 8 full and 56 partial rounds of `x^5`.
pub fn permute(state: &mut [Fp; 3]) {
    let (rc, mds) = constants();
    let half_full = <P128Pow5T3 as Spec<Fp, 3, 2>>::full_rounds() / 2;
    let partial = <P128Pow5T3 as Spec<Fp, 3, 2>>::partial_rounds();
    for (r, rcs) in rc.iter().enumerate() {
        let full = r < half_full || r >= half_full + partial;
        let mut s = [state[0] + rcs[0], state[1] + rcs[1], state[2] + rcs[2]];
        s[0] = s[0].pow_vartime([5]);
        if full {
            s[1] = s[1].pow_vartime([5]);
            s[2] = s[2].pow_vartime([5]);
        }
        for (i, out) in state.iter_mut().enumerate() {
            *out = mds[i][0] * s[0] + mds[i][1] * s[1] + mds[i][2] * s[2];
        }
    }
}

/// The capacity element for `tag`: `2^128 + tag`.
pub fn capacity(tag: u64) -> Fp {
    let two_64 = Fp::from_u128(1u128 << 64);
    two_64 * two_64 + Fp::from(tag)
}

/// The sponge from an explicit capacity element.
pub fn sponge(capacity: Fp, inputs: &[Fp]) -> Fp {
    assert!(!inputs.is_empty(), "the sponge needs at least one input");
    let mut state = [Fp::ZERO, Fp::ZERO, capacity];
    for block in inputs.chunks(2) {
        state[0] += block[0];
        if let Some(second) = block.get(1) {
            state[1] += second;
        }
        permute(&mut state);
    }
    state[0]
}

/// `H_tag(inputs)`.
pub fn h(tag: u64, inputs: &[Fp]) -> Fp {
    sponge(capacity(tag), inputs)
}

/// A tree node from its two children: one permutation.
pub fn node(left: Fp, right: Fp) -> Fp {
    h(T_NODE, &[left, right])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{poseidon_2, poseidon_3, poseidon_4, poseidon_7};

    #[test]
    fn sponge_is_the_halo2_sponge_with_another_capacity() {
        let x: Vec<Fp> = (1..=7u64).map(|i| Fp::from(i * 0x9e37_79b9 + 11)).collect();
        let cap = |l: u128| Fp::from_u128(l << 64);
        assert_eq!(sponge(cap(2), &x[..2]), poseidon_2(x[0], x[1]));
        assert_eq!(sponge(cap(3), &x[..3]), poseidon_3(x[0], x[1], x[2]));
        assert_eq!(sponge(cap(4), &x[..4]), poseidon_4(x[0], x[1], x[2], x[3]));
        let seven: [Fp; 7] = core::array::from_fn(|i| x[i]);
        assert_eq!(sponge(cap(7), &x), poseidon_7(seven));
        // The tagged hashes are different functions.
        assert_ne!(h(T_NODE, &x[..2]), poseidon_2(x[0], x[1]));
        assert_ne!(h(T_NODE, &x[..2]), h(T_NF, &x[..2]));
    }
}
