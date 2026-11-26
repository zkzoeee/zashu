use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZashuError {
    #[error("invalid field encoding")]
    InvalidFieldEncoding,

    #[error("invalid curve point encoding")]
    InvalidPointEncoding,

    #[error("invalid hex encoding: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid token format: {0}")]
    InvalidToken(String),

    #[error("invalid stealth address: {0}")]
    InvalidStealthAddress(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("reserves error: {0}")]
    ReservesError(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, ZashuError>;
