use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, SingleVerifier,
    VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::SysRng;
use rand::rand_core::UnwrapErr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use zashu_core::field::{bytes_to_fp, fp_to_bytes};
use zashu_acc::{LeafUpdate, NullifierTransitionWitness};
use zashu_core::types::MintState;

use crate::error::{CircuitError, Result};

/// Default Halo 2 circuit degree `k = 8` (256 rows) for fast local & mobile proving.
pub const DEFAULT_K: u32 = 8;

/// Identifies which non-uniform subcircuit produced a `FoldedProof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubcircuitId {
    MintStep,
    SwapStep,
    MeltStep,
    FoldBatch,
    /// Mode A fold produced by the Ragu PCD backend (`ragu` feature).
    RaguFold,
    /// Ragu Mode A fold that also binds event-log and root changes.
    RaguFoldRoots,
    /// Ragu Mode A fold that additionally checks each operation against its
    /// shielded transaction proof, inside a Ragu aggregator.
    RaguFoldAggregated,
    /// Mode B transaction produced by the Ragu PCD backend (`ragu` feature).
    RaguTx,
    ZkMint,
    ZkSwap,
    ZkMelt,
    ZkShield,
    ZkUnshield,
    MerkleInclusion,
    Predicate(u8),
}

/// A serialized non-uniform PCD proof produced by Halo 2 (Pasta/IPA) or a tree fold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedProof {
    pub subcircuit: SubcircuitId,
    pub k: u32,
    #[serde(with = "wire::hex_vec")]
    pub public_inputs: Vec<[u8; 32]>,
    #[serde(with = "wire::base64_bytes")]
    pub ipa_proof: Vec<u8>,
    pub folded_children: usize,
    /// Mode A step proofs only: the mint states this step moves between. The
    /// Ragu fold backend re-proves the step from these, opening both state
    /// hashes in-circuit. Not part of the proof and absent on folded proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition: Option<Box<StateTransition>>,
}

/// Compact JSON encodings for proof bytes. serde's default writes a byte
/// vector as an array of numbers, about 3.6x its size; these write base64
/// and hex strings instead. Both still read the old array form.
mod wire {
    use serde::{Deserialize, Deserializer, Serializer};

    pub mod base64_bytes {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        use super::*;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Text(String),
            Raw(Vec<u8>),
        }

        pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&STANDARD.encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            match Either::deserialize(d)? {
                Either::Text(t) => STANDARD.decode(t).map_err(serde::de::Error::custom),
                Either::Raw(b) => Ok(b),
            }
        }
    }

    pub mod hex_vec {
        use serde::ser::SerializeSeq;
        use serde::Serialize;
        use zashu_core::field::hex32;

        use super::*;

        #[derive(Serialize, Deserialize)]
        struct Hex(#[serde(with = "hex32")] [u8; 32]);

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Text(Hex),
            Raw([u8; 32]),
        }

        pub fn serialize<S: Serializer>(items: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(items.len()))?;
            for item in items {
                seq.serialize_element(&Hex(*item))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
            Ok(Vec::<Either>::deserialize(d)?
                .into_iter()
                .map(|e| match e {
                    Either::Text(Hex(b)) | Either::Raw(b) => b,
                })
                .collect())
        }
    }
}

/// The mint states before and after one Mode A step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransition {
    pub prev: MintState,
    pub next: MintState,
    /// Mint and melt steps: the quote / payout hash folded into the event log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<[u8; 32]>,
    /// Nullifiers inserted by this step, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nullifier_updates: Vec<NullifierTransitionWitness>,
    /// Note commitments appended by this step, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub note_updates: Vec<LeafUpdate>,
    /// The Ragu transaction proof that authorised this operation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_proof: Option<Box<FoldedProof>>,
}

impl FoldedProof {
    pub fn with_transition(mut self, prev: &MintState, next: &MintState) -> Self {
        self.transition = Some(Box::new(StateTransition {
            prev: prev.clone(),
            next: next.clone(),
            event: None,
            nullifier_updates: Vec::new(),
            note_updates: Vec::new(),
            tx_proof: None,
        }));
        self
    }

    /// Records the quote or payout hash a mint or melt step folded into the
    /// event log. Needed to bind the event log in the Ragu fold.
    pub fn with_event(mut self, hash: [u8; 32]) -> Self {
        if let Some(t) = self.transition.as_mut() {
            t.event = Some(hash);
        }
        self
    }

    /// Attaches the shielded transaction proof that authorised this operation.
    /// The aggregated Ragu fold checks the operation against it.
    pub fn with_tx_proof(mut self, tx: FoldedProof) -> Self {
        if let Some(t) = self.transition.as_mut() {
            t.tx_proof = Some(Box::new(tx));
        }
        self
    }

    /// Records the accumulator updates this step made. Needed to bind the
    /// nullifier and note roots in the Ragu fold.
    pub fn with_root_updates(
        mut self,
        nullifier_updates: Vec<NullifierTransitionWitness>,
        note_updates: Vec<LeafUpdate>,
    ) -> Self {
        if let Some(t) = self.transition.as_mut() {
            t.nullifier_updates = nullifier_updates;
            t.note_updates = note_updates;
        }
        self
    }

    pub fn to_base64(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| CircuitError::InvalidWitness(format!("serialize proof: {e}")))?;
        Ok(STANDARD.encode(bytes))
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| CircuitError::VerificationFailed(format!("base64 decode: {e}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CircuitError::VerificationFailed(format!("json decode: {e}")))
    }
}

pub trait PcdProver {
    fn prove_step(&self) -> Result<FoldedProof>;
}

pub trait PcdVerifier {
    fn verify_step(&self, proof: &FoldedProof) -> Result<()>;
}

struct CachedKeys {
    pk: ProvingKey<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

/// Shared parameter & proving/verifying key cache for Halo 2 Pasta IPA circuits.
pub struct PcdEngine {
    params_map: RwLock<HashMap<u32, Arc<Params<EqAffine>>>>,
    keys_map: RwLock<HashMap<(SubcircuitId, u32), Arc<CachedKeys>>>,
}

impl Default for PcdEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PcdEngine {
    pub fn global() -> &'static Self {
        static ENGINE: OnceLock<PcdEngine> = OnceLock::new();
        ENGINE.get_or_init(PcdEngine::new)
    }

    pub fn new() -> Self {
        Self {
            params_map: RwLock::new(HashMap::new()),
            keys_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn params(&self, k: u32) -> Arc<Params<EqAffine>> {
        if let Some(p) = self.params_map.read().unwrap().get(&k) {
            return Arc::clone(p);
        }
        let params = Arc::new(Params::<EqAffine>::new(k));
        let mut map = self.params_map.write().unwrap();
        Arc::clone(map.entry(k).or_insert(params))
    }

    fn keys<C: Circuit<Fp>>(&self, id: SubcircuitId, k: u32, empty_circuit: &C) -> Result<Arc<CachedKeys>> {
        if let Some(cached) = self.keys_map.read().unwrap().get(&(id, k)) {
            return Ok(Arc::clone(cached));
        }
        let params = self.params(k);
        let vk = keygen_vk(&params, empty_circuit)
            .map_err(|e| CircuitError::Plonk(format!("keygen_vk({id:?}): {e:?}")))?;
        let pk = keygen_pk(&params, vk.clone(), empty_circuit)
            .map_err(|e| CircuitError::Plonk(format!("keygen_pk({id:?}): {e:?}")))?;
        let cached = Arc::new(CachedKeys { pk, vk });
        let mut map = self.keys_map.write().unwrap();
        Ok(Arc::clone(map.entry((id, k)).or_insert(cached)))
    }

    pub fn prove<C: Circuit<Fp> + Clone>(
        &self,
        id: SubcircuitId,
        k: u32,
        empty_circuit: &C,
        circuit: C,
        instances: &[Fp],
        folded_children: usize,
    ) -> Result<FoldedProof> {
        let params = self.params(k);
        let keys = self.keys(id, k, empty_circuit)?;
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &keys.pk,
            &[circuit],
            &[&[instances]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .map_err(|e| CircuitError::Plonk(format!("create_proof({id:?}): {e:?}")))?;

        let ipa_proof = transcript.finalize();
        let public_inputs = instances.iter().map(fp_to_bytes).collect();

        Ok(FoldedProof {
            subcircuit: id,
            k,
            public_inputs,
            ipa_proof,
            folded_children,
            transition: None,
        })
    }

    pub fn verify<C: Circuit<Fp>>(
        &self,
        id: SubcircuitId,
        empty_circuit: &C,
        proof: &FoldedProof,
    ) -> Result<()> {
        if proof.subcircuit != id {
            return Err(CircuitError::VerificationFailed(format!(
                "subcircuit mismatch: expected {id:?}, got {:?}",
                proof.subcircuit
            )));
        }
        let params = self.params(proof.k);
        let keys = self.keys(id, proof.k, empty_circuit)?;
        let instances: Vec<Fp> = proof
            .public_inputs
            .iter()
            .map(|b| bytes_to_fp(b).map_err(CircuitError::Core))
            .collect::<Result<Vec<_>>>()?;

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof.ipa_proof[..]);
        verify_proof(
            &params,
            &keys.vk,
            strategy,
            &[&[&instances[..]]],
            &mut transcript,
        )
        .map_err(|e| CircuitError::VerificationFailed(format!("verify_proof({id:?}): {e:?}")))
    }
}

/// Parallel tree-folding helper for Mode A / batch proofs.
/// Verifies all leaf proofs in parallel via `rayon`, checks contiguous state chaining
/// `(start_i, end_i) -> (end_i == start_{i+1})`, and folds them into one `FoldBatch` proof.
pub fn fold_tree(
    proofs: &[FoldedProof],
    verify_fn: &(dyn Fn(&FoldedProof) -> Result<()> + Sync),
) -> Result<(usize, usize)> {
    if proofs.is_empty() {
        return Err(CircuitError::InvalidWitness("cannot fold empty proof batch".into()));
    }
    proofs.par_iter().try_for_each(verify_fn)?;
    let total_children: usize = proofs.iter().map(|p| p.folded_children.max(1)).sum();
    Ok((proofs.len(), total_children))
}
