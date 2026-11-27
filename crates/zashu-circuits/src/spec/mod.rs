//! Proof backends for the `NUTZ-0` statements (`zashu_core::spec`).
//!
//! Each backend proves the same three statements (transaction, operation and
//! chain of operations) and is tested against the same vectors, so their
//! costs can be compared like for like. See [`conformance`].

use zashu_core::spec::op::{ChainStatement, OpStatement, OpWitness};
use zashu_core::spec::tx::{TxStatement, TxWitness};

use crate::error::Result;

pub mod conformance;
pub mod halo2;
#[cfg(feature = "ragu")]
pub mod ragu;

/// A proof system for the `NUTZ-0` statements.
///
/// The `prove_*` functions do **not** check the witness against the reference
/// relation first: a witness that does not satisfy it must either fail to
/// prove or yield a proof that does not verify. Callers that want an early,
/// readable error run `zashu_core::spec::{tx, op}::check` themselves.
pub trait Backend {
    const NAME: &'static str;

    type TxProof;
    type OpProof;
    /// A chain under construction.
    type Chain;
    type ChainProof;

    fn prove_tx(witness: &TxWitness) -> Result<Self::TxProof>;
    fn verify_tx(statement: &TxStatement, proof: &Self::TxProof) -> Result<()>;
    fn tx_proof_bytes(proof: &Self::TxProof) -> usize;

    /// One operation as a proof of its own.
    fn prove_op(witness: &OpWitness) -> Result<Self::OpProof>;
    fn verify_op(statement: &OpStatement, proof: &Self::OpProof) -> Result<()>;
    fn op_proof_bytes(proof: &Self::OpProof) -> usize;

    fn chain_start() -> Self::Chain;
    /// Appends the next operation. The backend decides what to keep: a
    /// recursive backend folds it into one running proof, a non-recursive one
    /// keeps a proof per operation.
    fn chain_extend(chain: &mut Self::Chain, witness: &OpWitness) -> Result<()>;
    fn chain_finish(chain: Self::Chain) -> Result<Self::ChainProof>;
    fn verify_chain(statement: &ChainStatement, proof: &Self::ChainProof) -> Result<()>;
    fn chain_proof_bytes(proof: &Self::ChainProof) -> usize;
}
