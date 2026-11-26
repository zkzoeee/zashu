use serde::{Deserialize, Serialize};
use zashu_core::field::{bytes_to_fq, hash_bytes_to_fq, PallasPoint};
use zashu_core::poseidon::{hash_bytes_to_fp_stealth, hash_predicate_params};
use zashu_core::stealth::PointBytesExt;
use zashu_core::types::{Note, PredicateId};

use crate::error::{CircuitError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateWitness {
    /// `0x00`: StandardSpend — knowledge of `sk` deriving `owner_pk`.
    StandardSpend { sk: [u8; 32] },
    /// `0x01`: P2PK — knowledge of `target_sk` matching `Poseidon(target_pk)`.
    P2PK { target_sk: [u8; 32], target_pk: [u8; 32] },
    /// `0x02`: Multisig — `t`-of-`n` distinct valid keys.
    Multisig {
        threshold: u8,
        pubkeys: Vec<[u8; 32]>,
        signer_indices: Vec<usize>,
        signer_sks: Vec<[u8; 32]>,
    },
    /// `0x03`: Timelock — valid `sk` AND `current_epoch >= lock_epoch`.
    Timelock {
        lock_epoch: u64,
        current_epoch: u64,
        sk: [u8; 32],
    },
    /// `0x04`: PrivateHTLC — either Claim (`preimage` + `sk_receiver`) or Refund (`sk_refund` after `expiry_epoch`).
    PrivateHTLC {
        hashlock: [u8; 32],
        pk_receiver: [u8; 32],
        pk_refund: [u8; 32],
        expiry_epoch: u64,
        current_epoch: u64,
        action: HtlcAction,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HtlcAction {
    Claim {
        preimage: [u8; 32],
        sk_receiver: [u8; 32],
    },
    Refund {
        sk_refund: [u8; 32],
    },
}

pub fn htlc_hashlock(preimage: &[u8; 32]) -> [u8; 32] {
    hash_bytes_to_fp_stealth(preimage)
}

pub fn compute_p2pk_params(target_pk: &[u8; 32]) -> [u8; 32] {
    hash_predicate_params(&[b"p2pk", target_pk])
}

pub fn compute_multisig_params(threshold: u8, pubkeys: &[[u8; 32]]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(pubkeys.len() + 2);
    let t_slice = [threshold];
    let n_slice = [pubkeys.len() as u8];
    parts.push(b"multisig");
    parts.push(&t_slice);
    parts.push(&n_slice);
    for pk in pubkeys {
        parts.push(pk);
    }
    hash_predicate_params(&parts)
}

pub fn compute_timelock_params(lock_epoch: u64, owner_pk: &[u8; 32]) -> [u8; 32] {
    let epoch_bytes = lock_epoch.to_le_bytes();
    hash_predicate_params(&[b"timelock", &epoch_bytes, owner_pk])
}

pub fn compute_htlc_params(
    hashlock: &[u8; 32],
    pk_receiver: &[u8; 32],
    pk_refund: &[u8; 32],
    expiry_epoch: u64,
) -> [u8; 32] {
    let exp_bytes = expiry_epoch.to_le_bytes();
    hash_predicate_params(&[b"htlc", hashlock, pk_receiver, pk_refund, &exp_bytes])
}

fn check_sk_matches_pk(sk_bytes: &[u8; 32], expected_pk: &[u8; 32]) -> bool {
    use group::Group;
    let sk_fq = bytes_to_fq(sk_bytes)
        .unwrap_or_else(|_| hash_bytes_to_fq(b"zashu-sk-fq", sk_bytes));
    let derived = (PallasPoint::generator() * sk_fq).to_affine_bytes();
    &derived == expected_pk
}

/// Verifies predicate isolation (subcircuit matches `note.predicate_id` and `predicate_params_hash`)
/// and evaluates the predicate authorization witness.
pub fn verify_predicate(note: &Note, witness: &PredicateWitness) -> Result<[u8; 32]> {
    let pid = PredicateId::try_from(note.predicate_id)
        .map_err(|e| CircuitError::PredicateError(e.to_string()))?;

    match (pid, witness) {
        (PredicateId::StandardSpend, PredicateWitness::StandardSpend { sk }) => {
            if note.predicate_params_hash != [0u8; 32] {
                return Err(CircuitError::PredicateError("non-zero params for StandardSpend".into()));
            }
            if !check_sk_matches_pk(sk, &note.owner_pk) && sk == &[0u8; 32] {
                return Err(CircuitError::PredicateError("invalid standard spend key".into()));
            }
            if !check_sk_matches_pk(sk, &note.owner_pk) {
                return Err(CircuitError::PredicateError("owner_pk mismatch".into()));
            }
            Ok(*sk)
        }
        (PredicateId::P2PK, PredicateWitness::P2PK { target_sk, target_pk }) => {
            if compute_p2pk_params(target_pk) != note.predicate_params_hash {
                return Err(CircuitError::PredicateError("p2pk params hash mismatch".into()));
            }
            if !check_sk_matches_pk(target_sk, target_pk) {
                return Err(CircuitError::PredicateError("p2pk signature/key invalid".into()));
            }
            Ok(*target_sk)
        }
        (
            PredicateId::Multisig,
            PredicateWitness::Multisig {
                threshold,
                pubkeys,
                signer_indices,
                signer_sks,
            },
        ) => {
            if compute_multisig_params(*threshold, pubkeys) != note.predicate_params_hash {
                return Err(CircuitError::PredicateError("multisig params hash mismatch".into()));
            }
            if signer_sks.len() < *threshold as usize || signer_sks.len() != signer_indices.len() {
                return Err(CircuitError::PredicateError("insufficient multisig signers".into()));
            }
            let mut seen = std::collections::HashSet::new();
            for (&idx, sk) in signer_indices.iter().zip(signer_sks.iter()) {
                if idx >= pubkeys.len() || !seen.insert(idx) {
                    return Err(CircuitError::PredicateError("duplicate or invalid signer index".into()));
                }
                if !check_sk_matches_pk(sk, &pubkeys[idx]) {
                    return Err(CircuitError::PredicateError("multisig key mismatch".into()));
                }
            }
            Ok(signer_sks[0])
        }
        (
            PredicateId::Timelock,
            PredicateWitness::Timelock {
                lock_epoch,
                current_epoch,
                sk,
            },
        ) => {
            if compute_timelock_params(*lock_epoch, &note.owner_pk) != note.predicate_params_hash {
                return Err(CircuitError::PredicateError("timelock params hash mismatch".into()));
            }
            if *current_epoch < *lock_epoch {
                return Err(CircuitError::PredicateError("timelock not yet expired".into()));
            }
            if !check_sk_matches_pk(sk, &note.owner_pk) {
                return Err(CircuitError::PredicateError("timelock owner_pk mismatch".into()));
            }
            Ok(*sk)
        }
        (
            PredicateId::PrivateHTLC,
            PredicateWitness::PrivateHTLC {
                hashlock,
                pk_receiver,
                pk_refund,
                expiry_epoch,
                current_epoch,
                action,
            },
        ) => {
            if compute_htlc_params(hashlock, pk_receiver, pk_refund, *expiry_epoch)
                != note.predicate_params_hash
            {
                return Err(CircuitError::PredicateError("htlc params hash mismatch".into()));
            }
            match action {
                HtlcAction::Claim {
                    preimage,
                    sk_receiver,
                } => {
                    if &htlc_hashlock(preimage) != hashlock {
                        return Err(CircuitError::PredicateError("htlc preimage mismatch".into()));
                    }
                    if !check_sk_matches_pk(sk_receiver, pk_receiver) {
                        return Err(CircuitError::PredicateError("htlc receiver key mismatch".into()));
                    }
                    Ok(*sk_receiver)
                }
                HtlcAction::Refund { sk_refund } => {
                    if *current_epoch < *expiry_epoch {
                        return Err(CircuitError::PredicateError("htlc refund before expiry".into()));
                    }
                    if !check_sk_matches_pk(sk_refund, pk_refund) {
                        return Err(CircuitError::PredicateError("htlc refund key mismatch".into()));
                    }
                    Ok(*sk_refund)
                }
            }
        }
        _ => Err(CircuitError::PredicateError(
            "predicate isolation violation: witness does not match note.predicate_id".into(),
        )),
    }
}
