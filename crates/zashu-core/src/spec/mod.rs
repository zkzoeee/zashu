//! `NUTZ-0`: the proof statements every Zashu proof backend implements.
//!
//! This module is the reference: plain Rust, no proving. It defines the
//! primitives, the witnesses, the public statements and a checker for each
//! relation. A backend is correct when it accepts exactly the witnesses the
//! checkers here accept, for the statements [`tx::statement`] and
//! [`op::statement`] derive.
//!
//! Everything inside the statements is a canonical element of the Pallas base
//! field. Bytes from outside (quote hashes, preimages, seeds) are mapped to
//! the field once, at the boundary, with [`to_field`].

pub mod hash;
pub mod note;
pub mod op;
pub mod tree;
pub mod tx;
pub mod vectors;

pub use crate::field::Fp;

/// Depth of the note tree and the nullifier tree: `2^24` leaves each.
pub const DEPTH: usize = 24;

/// Inputs and outputs of a transaction. Unused slots hold dummy notes.
pub const TX_SLOTS: usize = 2;
/// Nullifier inserts and note appends of an operation. Unused slots are off.
pub const OP_SLOTS: usize = 2;

/// Why a witness does not satisfy a relation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("spec: {0}")]
pub struct SpecError(pub String);

pub type Result<T> = core::result::Result<T, SpecError>;

pub(crate) fn fail<T>(msg: &str) -> Result<T> {
    Err(SpecError(msg.into()))
}

/// Maps bytes from outside the spec to a field element (BLAKE2b-512, reduced).
pub fn to_field(domain: &[u8], bytes: &[u8]) -> Fp {
    crate::field::hash_bytes_to_fp(domain, bytes)
}

/// `a < b` as integers in `[0, p)`: the order of the nullifier tree.
pub fn less_than(a: &Fp, b: &Fp) -> bool {
    use ff::PrimeField;
    let (mut x, mut y) = (a.to_repr(), b.to_repr());
    x.reverse();
    y.reverse();
    x < y
}
