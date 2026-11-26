use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ZashuError};
use crate::field::hex32;

pub const TOKEN_PREFIX: &str = "zashuA";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZashuTokenNote {
    pub v: u64,
    #[serde(with = "hex32")]
    pub spend_sk: [u8; 32],
    pub predicate_id: u8,
    #[serde(with = "hex32")]
    pub predicate_params_hash: [u8; 32],
    #[serde(with = "hex32")]
    pub rho: [u8; 32],
    #[serde(with = "hex32")]
    pub r: [u8; 32],
    pub leaf_index: u64,
    pub witness_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZashuToken {
    pub mint: String,
    pub epoch: u64,
    pub notes: Vec<ZashuTokenNote>,
}

impl ZashuToken {
    pub fn encode(&self) -> Result<String> {
        let cbor = serde_cbor::to_vec(self)
            .map_err(|e| ZashuError::Serialization(format!("cbor encode failed: {e}")))?;
        Ok(format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(cbor)))
    }

    pub fn decode(token: &str) -> Result<Self> {
        let payload = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| ZashuError::InvalidToken("missing zashuA prefix".into()))?;
        let raw = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| ZashuError::InvalidToken(format!("base64url decode failed: {e}")))?;
        serde_cbor::from_slice(&raw)
            .map_err(|e| ZashuError::InvalidToken(format!("cbor decode failed: {e}")))
    }
}
