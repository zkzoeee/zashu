use ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;

use crate::error::{Result, ZashuError};

pub type Fp = pallas::Base;
pub type Fq = pallas::Scalar;
pub type PallasPoint = pallas::Point;
pub type PallasAffine = pallas::Affine;

pub fn fp_to_bytes(f: &Fp) -> [u8; 32] {
    f.to_repr()
}

pub fn bytes_to_fp(bytes: &[u8; 32]) -> Result<Fp> {
    Option::from(Fp::from_repr(*bytes)).ok_or(ZashuError::InvalidFieldEncoding)
}

pub fn fq_to_bytes(f: &Fq) -> [u8; 32] {
    f.to_repr()
}

pub fn bytes_to_fq(bytes: &[u8; 32]) -> Result<Fq> {
    Option::from(Fq::from_repr(*bytes)).ok_or(ZashuError::InvalidFieldEncoding)
}

/// Deterministically maps arbitrary bytes into `Fp` via BLAKE2b-512 uniform reduction.
pub fn hash_bytes_to_fp(domain: &[u8], data: &[u8]) -> Fp {
    let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
    state.update(domain);
    state.update(data);
    let hash = state.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    Fp::from_uniform_bytes(&wide)
}

/// Deterministically maps arbitrary bytes into `Fq` via BLAKE2b-512 uniform reduction.
pub fn hash_bytes_to_fq(domain: &[u8], data: &[u8]) -> Fq {
    let mut state = blake2b_simd::Params::new().hash_length(64).to_state();
    state.update(domain);
    state.update(data);
    let hash = state.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(hash.as_bytes());
    Fq::from_uniform_bytes(&wide)
}

pub fn fp_from_u64(v: u64) -> Fp {
    Fp::from(v)
}

pub fn fq_from_u64(v: u64) -> Fq {
    Fq::from(v)
}

pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(stripped).map_err(serde::de::Error::custom)?;
        if raw.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex string"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}
