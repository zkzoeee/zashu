use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ff::Field;
use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand_core::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, ZashuError};
use crate::field::{fq_to_bytes, hash_bytes_to_fq, hex32, Fq, PallasPoint};
use crate::poseidon::hash_bytes_to_fp_stealth;

const STEALTH_PREFIX: &str = "zsp1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress {
    #[serde(with = "hex32")]
    pub scan_pk: [u8; 32],
    #[serde(with = "hex32")]
    pub spend_pk: [u8; 32],
}

impl StealthAddress {
    pub fn encode(&self) -> String {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.scan_pk);
        buf[32..].copy_from_slice(&self.spend_pk);
        format!("{STEALTH_PREFIX}{}", hex::encode(buf))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let body = s
            .strip_prefix(STEALTH_PREFIX)
            .ok_or_else(|| ZashuError::InvalidStealthAddress("missing zsp1 prefix".into()))?;
        let raw = hex::decode(body)
            .map_err(|e| ZashuError::InvalidStealthAddress(format!("hex error: {e}")))?;
        if raw.len() != 64 {
            return Err(ZashuError::InvalidStealthAddress("expected 64 bytes".into()));
        }
        let mut scan_pk = [0u8; 32];
        let mut spend_pk = [0u8; 32];
        scan_pk.copy_from_slice(&raw[..32]);
        spend_pk.copy_from_slice(&raw[32..]);
        Ok(Self { scan_pk, spend_pk })
    }
}

#[derive(Debug, Clone)]
pub struct StealthKeypair {
    pub scan_sk: Fq,
    pub spend_sk: Fq,
    pub address: StealthAddress,
}

impl StealthKeypair {
    pub fn random(rng: &mut impl Rng) -> Self {
        let scan_sk = Fq::random(&mut *rng);
        let spend_sk = Fq::random(&mut *rng);
        Self::from_scalars(scan_sk, spend_sk)
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let scan_sk = hash_bytes_to_fq(b"zashu-stealth-scan", seed);
        let spend_sk = hash_bytes_to_fq(b"zashu-stealth-spend", seed);
        Self::from_scalars(scan_sk, spend_sk)
    }

    pub fn from_scalars(scan_sk: Fq, spend_sk: Fq) -> Self {
        let g = PallasPoint::generator();
        let scan_pk = (g * scan_sk).to_affine_bytes();
        let spend_pk = (g * spend_sk).to_affine_bytes();
        Self {
            scan_sk,
            spend_sk,
            address: StealthAddress { scan_pk, spend_pk },
        }
    }

    pub fn recover_one_time_sk(&self, ephemeral_pk: &[u8; 32]) -> Result<[u8; 32]> {
        let eph_pt = point_from_bytes(ephemeral_pk)?;
        let shared_pt = eph_pt * self.scan_sk;
        let tweak = shared_secret_scalar(&shared_pt);
        let one_time_sk = self.spend_sk + tweak;
        Ok(fq_to_bytes(&one_time_sk))
    }
}

pub trait PointBytesExt {
    fn to_affine_bytes(&self) -> [u8; 32];
}

impl PointBytesExt for PallasPoint {
    fn to_affine_bytes(&self) -> [u8; 32] {
        use group::Curve;
        self.to_affine().to_bytes()
    }
}

pub fn point_from_bytes(bytes: &[u8; 32]) -> Result<PallasPoint> {
    let affine: Option<pallas::Affine> = Option::from(pallas::Affine::from_bytes(bytes));
    affine
        .map(PallasPoint::from)
        .ok_or(ZashuError::InvalidPointEncoding)
}

fn shared_secret_scalar(shared_pt: &PallasPoint) -> Fq {
    let bytes = shared_pt.to_affine_bytes();
    hash_bytes_to_fq(b"zashu-stealth-ecdh", &bytes)
}

fn aead_key_from_shared(shared_pt: &PallasPoint) -> [u8; 32] {
    let fp_tag = hash_bytes_to_fp_stealth(&shared_pt.to_affine_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"zashu-stealth-aead-v1");
    hasher.update(fp_tag);
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthMemoPayload {
    pub value: u64,
    pub predicate_id: u8,
    #[serde(with = "hex32")]
    pub predicate_params_hash: [u8; 32],
    #[serde(with = "hex32")]
    pub rho: [u8; 32],
    #[serde(with = "hex32")]
    pub r: [u8; 32],
    pub leaf_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStealthMemo {
    #[serde(with = "hex32")]
    pub ephemeral_pk: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn create_stealth_output(
    recipient: &StealthAddress,
    payload: &StealthMemoPayload,
    rng: &mut impl Rng,
) -> Result<([u8; 32], EncryptedStealthMemo)> {
    let e = Fq::random(&mut *rng);
    let g = PallasPoint::generator();
    let eph_pt = g * e;
    let scan_pt = point_from_bytes(&recipient.scan_pk)?;
    let spend_pt = point_from_bytes(&recipient.spend_pk)?;

    let shared_pt = scan_pt * e;
    let tweak = shared_secret_scalar(&shared_pt);
    let one_time_pk = (spend_pt + g * tweak).to_affine_bytes();

    let key = aead_key_from_shared(&shared_pt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| ZashuError::CryptoError(format!("aead init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let plaintext = serde_cbor::to_vec(payload)
        .map_err(|e| ZashuError::Serialization(format!("memo cbor: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|e| ZashuError::CryptoError(format!("aead encrypt: {e}")))?;

    Ok((
        one_time_pk,
        EncryptedStealthMemo {
            ephemeral_pk: eph_pt.to_affine_bytes(),
            nonce: nonce_bytes,
            ciphertext,
        },
    ))
}

pub fn decrypt_stealth_memo(
    keys: &StealthKeypair,
    memo: &EncryptedStealthMemo,
) -> Result<(StealthMemoPayload, [u8; 32])> {
    let eph_pt = point_from_bytes(&memo.ephemeral_pk)?;
    let shared_pt = eph_pt * keys.scan_sk;
    let key = aead_key_from_shared(&shared_pt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| ZashuError::CryptoError(format!("aead init: {e}")))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&memo.nonce), memo.ciphertext.as_ref())
        .map_err(|_| ZashuError::CryptoError("stealth memo decryption failed".into()))?;
    let payload: StealthMemoPayload = serde_cbor::from_slice(&plaintext)
        .map_err(|e| ZashuError::Serialization(format!("memo cbor decode: {e}")))?;
    let one_time_sk = keys.recover_one_time_sk(&memo.ephemeral_pk)?;
    Ok((payload, one_time_sk))
}
