use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};

use crate::field::{bytes_to_fp, fp_from_u64, fp_to_bytes, hash_bytes_to_fp, Fp};

pub const DOMAIN_NOTE: u64 = 0x01;
pub const DOMAIN_NF: u64 = 0x02;
pub const DOMAIN_STATE: u64 = 0x03;
pub const DOMAIN_ACC: u64 = 0x04;
pub const DOMAIN_MINT: u64 = 0x05;
pub const DOMAIN_MELT: u64 = 0x06;
pub const DOMAIN_PREDICATE: u64 = 0x07;
pub const DOMAIN_STEALTH: u64 = 0x08;

pub fn poseidon_2(a: Fp, b: Fp) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

pub fn poseidon_3(a: Fp, b: Fp, c: Fp) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([a, b, c])
}

pub fn poseidon_4(a: Fp, b: Fp, c: Fp, d: Fp) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([a, b, c, d])
}

pub fn poseidon_7(inputs: [Fp; 7]) -> Fp {
    Hash::<Fp, P128Pow5T3, ConstantLength<7>, 3, 2>::init().hash(inputs)
}

pub fn hash_acc_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l = bytes_to_fp(left).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-acc-l", left));
    let r = bytes_to_fp(right).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-acc-r", right));
    fp_to_bytes(&poseidon_3(fp_from_u64(DOMAIN_ACC), l, r))
}

#[allow(clippy::too_many_arguments)]
pub fn hash_note(
    value: u64,
    owner_pk: &[u8; 32],
    predicate_id: u8,
    predicate_params_hash: &[u8; 32],
    rho: &[u8; 32],
    r: &[u8; 32],
) -> [u8; 32] {
    let pk_fp = hash_bytes_to_fp(b"zashu-pk", owner_pk);
    let pred_fp = bytes_to_fp(predicate_params_hash)
        .unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-pred", predicate_params_hash));
    let rho_fp = bytes_to_fp(rho).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-rho", rho));
    let r_fp = bytes_to_fp(r).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-r", r));

    let cm = poseidon_7([
        fp_from_u64(DOMAIN_NOTE),
        fp_from_u64(value),
        pk_fp,
        fp_from_u64(predicate_id as u64),
        pred_fp,
        rho_fp,
        r_fp,
    ]);
    fp_to_bytes(&cm)
}

pub fn hash_nullifier(sk_or_auth: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    let sk_fp = hash_bytes_to_fp(b"zashu-sk", sk_or_auth);
    let rho_fp = bytes_to_fp(rho).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-rho", rho));
    fp_to_bytes(&poseidon_3(fp_from_u64(DOMAIN_NF), sk_fp, rho_fp))
}

pub fn hash_mint_state(
    epoch: u64,
    total_liabilities: u64,
    nullifier_acc_root: &[u8; 32],
    note_acc_root: &[u8; 32],
    event_log_hash: &[u8; 32],
) -> [u8; 32] {
    let nf_fp = bytes_to_fp(nullifier_acc_root)
        .unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-nf-root", nullifier_acc_root));
    let note_fp = bytes_to_fp(note_acc_root)
        .unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-note-root", note_acc_root));
    let ev_fp = bytes_to_fp(event_log_hash)
        .unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-ev", event_log_hash));

    let h1 = poseidon_4(
        fp_from_u64(DOMAIN_STATE),
        fp_from_u64(epoch),
        fp_from_u64(total_liabilities),
        nf_fp,
    );
    let h2 = poseidon_3(h1, note_fp, ev_fp);
    fp_to_bytes(&h2)
}

pub fn hash_event_mint(prev_log: &[u8; 32], quote_hash: &[u8; 32], amount: u64) -> [u8; 32] {
    let prev_fp = bytes_to_fp(prev_log).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-ev", prev_log));
    let q_fp = bytes_to_fp(quote_hash).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-q", quote_hash));
    fp_to_bytes(&poseidon_4(
        prev_fp,
        fp_from_u64(DOMAIN_MINT),
        q_fp,
        fp_from_u64(amount),
    ))
}

pub fn hash_event_melt(prev_log: &[u8; 32], payout_hash: &[u8; 32], amount: u64) -> [u8; 32] {
    let prev_fp = bytes_to_fp(prev_log).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-ev", prev_log));
    let p_fp =
        bytes_to_fp(payout_hash).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-p", payout_hash));
    fp_to_bytes(&poseidon_4(
        prev_fp,
        fp_from_u64(DOMAIN_MELT),
        p_fp,
        fp_from_u64(amount),
    ))
}

pub fn hash_predicate_params(parts: &[&[u8]]) -> [u8; 32] {
    let mut acc = fp_from_u64(DOMAIN_PREDICATE);
    for p in parts {
        let p_fp = hash_bytes_to_fp(b"zashu-pred-part", p);
        acc = poseidon_2(acc, p_fp);
    }
    fp_to_bytes(&acc)
}

pub fn hash_bytes_to_fp_stealth(data: &[u8]) -> [u8; 32] {
    let fp = hash_bytes_to_fp(b"zashu-stealth-fp", data);
    fp_to_bytes(&poseidon_2(fp_from_u64(DOMAIN_STEALTH), fp))
}
