//! Notes, keys and spending predicates.
//!
//! **Keys.** A spend key is a field element `spend_sk`. Its public key is
//! `spend_pk = H_PK(spend_sk)`, and the key a note is locked to is the *key
//! image* `K = H_KEY(spend_pk, tweak)`. A sender who knows only `spend_pk`
//! can lock a note to a fresh, unlinkable image by choosing `tweak` (for a
//! stealth payment, from a Diffie-Hellman secret agreed outside any proof),
//! but cannot spend it: spending needs `spend_sk`. With `tweak = 0` the image
//! is a public function of `spend_pk`.
//!
//! There are no signatures: a spend is authorised by proving knowledge of
//! `spend_sk` inside the transaction proof.
//!
//! **Nullifiers** are `H_NF(rho, r)`, a function of the note alone, because
//! several parties may be able to spend one note (HTLC, multisig) and all of
//! them must reveal the same nullifier. The sender of a note knows `rho` and
//! `r`, and can therefore tell when it is spent.

use super::hash::{h, T_HASHLOCK, T_HTLC, T_KEY, T_MULTISIG, T_NF, T_NOTE, T_PK, T_TIMELOCK};
use super::{fail, Fp, Result};

/// `owner` is a key image; `params` is zero.
pub const PRED_KEY: u64 = 0;
/// As [`PRED_KEY`], spendable once `epoch >= lock`; `params = H_TIMELOCK(lock)`.
pub const PRED_TIMELOCK: u64 = 1;
/// `params = H_HTLC(hashlock, receiver, refund, expiry)`. The receiver claims
/// with the preimage while `epoch < expiry`; the refund key spends from
/// `expiry` on. `owner` is not used.
pub const PRED_HTLC: u64 = 2;
/// `params = H_MULTISIG(t, n, k1, k2, k3, k4)`: `t` of the first `n` key
/// images. `owner` is not used.
pub const PRED_MULTISIG: u64 = 3;

pub const MULTISIG_KEYS: usize = 4;
pub const MULTISIG_SIGNERS: usize = 3;

pub fn spend_pk(spend_sk: Fp) -> Fp {
    h(T_PK, &[spend_sk])
}

pub fn key_image(spend_pk: Fp, tweak: Fp) -> Fp {
    h(T_KEY, &[spend_pk, tweak])
}

/// A secret key with the tweak of the image it must open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub spend_sk: Fp,
    pub tweak: Fp,
}

impl Key {
    pub fn image(&self) -> Fp {
        key_image(spend_pk(self.spend_sk), self.tweak)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub value: u64,
    pub owner: Fp,
    pub predicate: u64,
    pub params: Fp,
    pub rho: Fp,
    pub r: Fp,
}

impl Note {
    pub fn commitment(&self) -> Fp {
        h(
            T_NOTE,
            &[Fp::from(self.value), self.owner, Fp::from(self.predicate), self.params, self.rho, self.r],
        )
    }

    pub fn nullifier(&self) -> Fp {
        h(T_NF, &[self.rho, self.r])
    }

    /// A zero-value note for an unused slot.
    pub fn dummy(rho: Fp, r: Fp, key: &Key) -> Self {
        Note { value: 0, owner: key.image(), predicate: PRED_KEY, params: Fp::from(0), rho, r }
    }
}

pub fn timelock_params(lock_epoch: u64) -> Fp {
    h(T_TIMELOCK, &[Fp::from(lock_epoch)])
}

pub fn hashlock(preimage: Fp) -> Fp {
    h(T_HASHLOCK, &[preimage])
}

pub fn htlc_params(hashlock: Fp, receiver: Fp, refund: Fp, expiry_epoch: u64) -> Fp {
    h(T_HTLC, &[hashlock, receiver, refund, Fp::from(expiry_epoch)])
}

pub fn multisig_params(threshold: u64, key_count: u64, keys: &[Fp; MULTISIG_KEYS]) -> Fp {
    h(T_MULTISIG, &[Fp::from(threshold), Fp::from(key_count), keys[0], keys[1], keys[2], keys[3]])
}

/// One multisig signer: the key and which committed slot it opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signer {
    pub key: Key,
    pub slot: usize,
}

/// What the spender shows to satisfy a note's predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    Key(Key),
    Timelock { key: Key, lock_epoch: u64 },
    HtlcClaim { key: Key, preimage: Fp, refund: Fp, expiry_epoch: u64 },
    HtlcRefund { key: Key, hashlock: Fp, receiver: Fp, expiry_epoch: u64 },
    Multisig { threshold: u64, key_count: u64, keys: [Fp; MULTISIG_KEYS], signers: Vec<Signer> },
}

impl Auth {
    /// The predicate id this authorisation is for.
    pub fn predicate(&self) -> u64 {
        match self {
            Auth::Key(_) => PRED_KEY,
            Auth::Timelock { .. } => PRED_TIMELOCK,
            Auth::HtlcClaim { .. } | Auth::HtlcRefund { .. } => PRED_HTLC,
            Auth::Multisig { .. } => PRED_MULTISIG,
        }
    }
}

/// The predicate relation: `auth` authorises spending `note` at `epoch`.
pub fn check_predicate(note: &Note, auth: &Auth, epoch: u64) -> Result<()> {
    if note.predicate != auth.predicate() {
        return fail("authorisation is for another predicate");
    }
    match auth {
        Auth::Key(key) => {
            if key.image() != note.owner || note.params != Fp::from(0) {
                return fail("key does not open the note's owner");
            }
        }
        Auth::Timelock { key, lock_epoch } => {
            if key.image() != note.owner || note.params != timelock_params(*lock_epoch) {
                return fail("timelock key or parameters do not match the note");
            }
            if epoch < *lock_epoch {
                return fail("timelock has not passed");
            }
        }
        Auth::HtlcClaim { key, preimage, refund, expiry_epoch } => {
            let params = htlc_params(hashlock(*preimage), key.image(), *refund, *expiry_epoch);
            if params != note.params {
                return fail("htlc claim does not match the note");
            }
            if epoch >= *expiry_epoch {
                return fail("htlc has expired");
            }
        }
        Auth::HtlcRefund { key, hashlock, receiver, expiry_epoch } => {
            let params = htlc_params(*hashlock, *receiver, key.image(), *expiry_epoch);
            if params != note.params {
                return fail("htlc refund does not match the note");
            }
            if epoch < *expiry_epoch {
                return fail("htlc has not expired");
            }
        }
        Auth::Multisig { threshold, key_count, keys, signers } => {
            let (t, n) = (*threshold as usize, *key_count as usize);
            if t == 0 || t > MULTISIG_SIGNERS || n < t || n > MULTISIG_KEYS {
                return fail("multisig threshold or key count out of range");
            }
            if multisig_params(*threshold, *key_count, keys) != note.params {
                return fail("multisig parameters do not match the note");
            }
            // Exactly `t` signers, in strictly increasing slot order.
            if signers.len() != t {
                return fail("multisig needs exactly threshold signers");
            }
            let mut previous: Option<usize> = None;
            for signer in signers {
                if signer.slot >= n || previous.is_some_and(|p| signer.slot <= p) {
                    return fail("multisig signer slots must be distinct, increasing and committed");
                }
                if signer.key.image() != keys[signer.slot] {
                    return fail("multisig signer does not hold the committed key");
                }
                previous = Some(signer.slot);
            }
        }
    }
    Ok(())
}
