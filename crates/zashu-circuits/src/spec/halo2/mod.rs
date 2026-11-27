//! The Halo 2 backend for the `NUTZ-0` statements.
//!
//! Two fixed circuits over the Pallas base field, proven with the IPA of
//! `halo2_proofs` (no trusted setup, no recursion):
//!
//! * the **transaction** circuit ([`tx`]): one circuit for every shape and
//!   every predicate;
//! * the **operation** circuit ([`op`]): one circuit for a mint, swap or
//!   melt with two nullifier-insert and two note-append slots.
//!
//! A chain is one operation proof per operation, with each operation's
//! statement; the verifier checks every proof and that the statements link.
//!
//! # Size
//!
//! Poseidon dominates both circuits: a permutation is 65 rows of one chip,
//! and a Merkle level 2 more. The chips sit side by side, so the height is
//! that of the tallest chip. Range checks and the generic arithmetic gate
//! have columns of their own and are much shorter. Measured, and pinned by
//! the test `sizes_are_as_documented`:
//!
//! | Circuit | Permutations | Chips | Tallest chip | Range rows | Arithmetic rows | `k` |
//! | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
//! | Transaction | 88 | 3 | 1982 | 153 | 376 | 11 |
//! | Operation | 308 | 6 | 3476 | 1214 | 289 | 12 |
//!
//! Each `k` is the smallest for its chip count. The chip count trades proof
//! size for time: more chips make a shorter, wider circuit that proves and
//! verifies faster with a larger proof. On one machine (10 cores, release),
//! for chips/`k`, proving, verifying and proof bytes:
//!
//! * transaction: 1/13 0.89 s, 18 ms, 3296; 2/12 0.64 s, 13 ms, 4000;
//!   **3/11 0.43 s, 6 ms, 4736**; 4/11 0.45 s, 8 ms, 5568; 8/10 0.41 s, 6 ms, 8704;
//! * operation: 1/15 2.6 s, 47 ms, 3456; 2/14 1.8 s, 26 ms, 4160;
//!   3/13 1.1 s, 18 ms, 4928; **6/12 0.85 s, 11 ms, 7264**; 11/11 0.54 s, 6 ms, 11104.
//!
//! The test `compare_layouts` (ignored by default) reproduces these.

use std::sync::OnceLock;

use halo2_proofs::circuit::Value;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, BatchVerifier, Circuit, ProvingKey, SingleVerifier,
    VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zashu_core::spec::op::{self, ChainStatement, OpStatement, OpWitness};
use zashu_core::spec::tx::{self, TxStatement, TxWitness};

use super::Backend;
use crate::error::{CircuitError, Result};

mod gadgets;
pub mod op_circuit;
pub mod tx_circuit;

pub use gadgets::Rows;

/// Poseidon chips side by side in the transaction circuit.
pub const TX_CHIPS: usize = 3;
const TX_K: u32 = 11;
/// Poseidon chips side by side in the operation circuit.
pub const OP_CHIPS: usize = 6;
const OP_K: u32 = 12;

type TxCircuit = tx_circuit::TxCircuit<TX_CHIPS>;
type OpCircuit = op_circuit::OpCircuit<OP_CHIPS>;

/// `log2` of the rows of the transaction circuit.
pub fn tx_circuit_k() -> u32 {
    TX_K
}

/// `log2` of the rows of the operation circuit.
pub fn op_circuit_k() -> u32 {
    OP_K
}

/// Rows the transaction circuit uses, per column group.
pub fn tx_circuit_rows() -> Rows {
    tx_keys();
    tx_circuit::rows()
}

/// Rows the operation circuit uses, per column group.
pub fn op_circuit_rows() -> Rows {
    op_keys();
    op_circuit::rows()
}

struct Keys {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

fn keygen<C: Circuit<Fp>>(k: u32, empty: &C) -> Keys {
    let params = Params::<EqAffine>::new(k);
    let vk = keygen_vk(&params, empty).expect("the spec circuits are fixed and fit their k");
    let pk = keygen_pk(&params, vk.clone(), empty).expect("the spec circuits are fixed and fit their k");
    Keys { params, pk, vk }
}

fn tx_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| keygen(TX_K, &TxCircuit::default()))
}

fn op_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| keygen(OP_K, &OpCircuit::default()))
}

/// Generates the keys of both circuits now rather than at first use.
pub fn warm_up() {
    tx_keys();
    op_keys();
}

fn prove<C: Circuit<Fp>>(keys: &Keys, circuit: C, public: &[Fp]) -> Result<Vec<u8>> {
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(&keys.params, &keys.pk, &[circuit], &[&[public]], UnwrapErr(SysRng), &mut transcript)
        .map_err(|e| CircuitError::Plonk(format!("create_proof: {e:?}")))?;
    Ok(transcript.finalize())
}

fn verify(keys: &Keys, public: &[Fp], proof: &[u8]) -> Result<()> {
    let strategy = SingleVerifier::new(&keys.params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    verify_proof(&keys.params, &keys.vk, strategy, &[&[public]], &mut transcript)
        .map_err(|e| CircuitError::VerificationFailed(format!("verify_proof: {e:?}")))
}

/// One operation of a chain: its statement and its proof.
#[derive(Clone, Debug)]
pub struct ChainLink {
    pub statement: OpStatement,
    pub proof: Vec<u8>,
}

pub struct Halo2;

impl Backend for Halo2 {
    const NAME: &'static str = "halo2";
    type TxProof = Vec<u8>;
    type OpProof = Vec<u8>;
    type Chain = Vec<ChainLink>;
    type ChainProof = Vec<ChainLink>;

    fn prove_tx(witness: &TxWitness) -> Result<Self::TxProof> {
        // The public inputs are those the witness claims; if it does not
        // satisfy the relation the proof will not verify against them.
        let public = tx::statement(witness).public_inputs();
        let circuit = TxCircuit { w: Value::known(tx_circuit::TxAssign::new(witness)?) };
        prove(tx_keys(), circuit, &public)
    }

    fn verify_tx(statement: &TxStatement, proof: &Self::TxProof) -> Result<()> {
        verify(tx_keys(), &statement.public_inputs(), proof)
    }

    fn tx_proof_bytes(proof: &Self::TxProof) -> usize {
        proof.len()
    }

    fn prove_op(witness: &OpWitness) -> Result<Self::OpProof> {
        let public = op::claimed(witness).1.public_inputs();
        let circuit = OpCircuit { w: Value::known(op_circuit::OpAssign::new(witness)) };
        prove(op_keys(), circuit, &public)
    }

    fn verify_op(statement: &OpStatement, proof: &Self::OpProof) -> Result<()> {
        verify(op_keys(), &statement.public_inputs(), proof)
    }

    fn op_proof_bytes(proof: &Self::OpProof) -> usize {
        proof.len()
    }

    fn chain_start() -> Self::Chain {
        Vec::new()
    }

    fn chain_extend(chain: &mut Self::Chain, witness: &OpWitness) -> Result<()> {
        let statement = op::claimed(witness).1;
        let proof = Self::prove_op(witness)?;
        chain.push(ChainLink { statement, proof });
        Ok(())
    }

    fn chain_finish(chain: Self::Chain) -> Result<Self::ChainProof> {
        if chain.is_empty() {
            return Err(CircuitError::InvalidWitness("empty chain".into()));
        }
        Ok(chain)
    }

    fn verify_chain(statement: &ChainStatement, proof: &Self::ChainProof) -> Result<()> {
        let fail = |why: &str| Err(CircuitError::VerificationFailed(format!("chain: {why}")));
        let (Some(first), Some(last)) = (proof.first(), proof.last()) else {
            return fail("no operations");
        };
        if proof.len() as u64 != statement.count {
            return fail("wrong number of operations");
        }
        if first.statement.before != statement.start
            || first.statement.liabilities_before != statement.liabilities_start
        {
            return fail("does not start at the stated state");
        }
        if last.statement.after != statement.end || last.statement.liabilities_after != statement.liabilities_end {
            return fail("does not end at the stated state");
        }
        for pair in proof.windows(2) {
            let (previous, next) = (&pair[0].statement, &pair[1].statement);
            if next.before != previous.after || next.liabilities_before != previous.liabilities_after {
                return fail("an operation does not start where the previous one ended");
            }
        }
        let keys = op_keys();
        let mut batch = BatchVerifier::new();
        for link in proof {
            batch.add_proof(vec![vec![link.statement.public_inputs().to_vec()]], link.proof.clone());
        }
        if !batch.finalize(&keys.params, &keys.vk) {
            return fail("an operation proof does not verify");
        }
        Ok(())
    }

    /// The proofs alone. A verifier also needs each operation's statement
    /// (two field elements and two integers).
    fn chain_proof_bytes(proof: &Self::ChainProof) -> usize {
        proof.iter().map(|link| link.proof.len()).sum()
    }
}

#[cfg(test)]
mod tests;
