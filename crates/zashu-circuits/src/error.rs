use thiserror::Error;

#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("halo2 plonk error: {0}")]
    Plonk(String),

    #[error("proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid witness: {0}")]
    InvalidWitness(String),

    #[error("value overflow or underflow")]
    ValueBounds,

    #[error("predicate mismatch or unsatisfied: {0}")]
    PredicateError(String),

    #[error("core error: {0}")]
    Core(#[from] zashu_core::ZashuError),
}

pub type Result<T> = std::result::Result<T, CircuitError>;
