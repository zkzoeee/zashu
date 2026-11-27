pub mod playground;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zashu_acc::{
    InclusionWitness, LeafUpdate, NoteAccumulator, NullifierAccumulator, NullifierTransitionWitness,
};
use zashu_circuits::mode_a::{
    fold_mode_a_batch, prove_melt_step, prove_mint_step, prove_swap_step, verify_fold_batch,
    IncrementalFold,
};
use zashu_circuits::mode_b::{
    proof_epoch, verify_zk_melt, verify_zk_mint, verify_zk_shield, verify_zk_swap, verify_zk_unshield,
};
use zashu_circuits::FoldedProof;
use zashu_core::field::{bytes_to_fp, canonical_fp_bytes, hex32};
use zashu_core::pedersen::ValueCommitment;
use zashu_core::poseidon::{hash_event_melt, hash_event_mint};
use zashu_core::reserves::{compute_reserves_challenge, sign_taproot_reserve_utxo};
use zashu_core::stealth::EncryptedStealthMemo;
use zashu_core::types::{
    MintState, NoteCommitment, Nullifier, ReservesAttestation, SolvencyBundle,
};

#[derive(Debug, Error)]
pub enum MintError {
    #[error("ZASHU_NULLIFIER_SPENT")]
    NullifierSpent,

    #[error("ZASHU_STALE_ANCHOR")]
    StaleAnchor,

    #[error("ZASHU_INVALID_PROOF: {0}")]
    InvalidProof(String),

    #[error("invalid quote or legacy token: {0}")]
    InvalidRequest(String),

    #[error("accumulator error: {0}")]
    Acc(#[from] zashu_acc::AccError),

    #[error("circuit error: {0}")]
    Circuit(#[from] zashu_circuits::CircuitError),
}

impl IntoResponse for MintError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            MintError::NullifierSpent => (StatusCode::BAD_REQUEST, "ZASHU_NULLIFIER_SPENT"),
            MintError::StaleAnchor => (StatusCode::CONFLICT, "ZASHU_STALE_ANCHOR"),
            MintError::InvalidProof(_) => (StatusCode::BAD_REQUEST, "ZASHU_INVALID_PROOF"),
            MintError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "ZASHU_INVALID_REQUEST"),
            MintError::Acc(_) | MintError::Circuit(_) => {
                (StatusCode::BAD_REQUEST, "ZASHU_INTERNAL_ERROR")
            }
        };
        let body = serde_json::json!({
            "error": code,
            "detail": self.to_string(),
        });
        (status, Json(body)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, MintError>;

#[derive(Debug, Clone)]
pub struct MintReserveKey {
    pub secret_key: SecretKey,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkInfoResponse {
    #[serde(with = "hex32")]
    pub mint_id: [u8; 32],
    pub state: MintState,
    pub rolling_window: usize,
    pub supported_predicates: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMintRequest {
    pub quote_id: String,
    pub amount: u64,
    pub cm: NoteCommitment,
    pub cv: ValueCommitment,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMintResponse {
    pub leaf_index: u64,
    pub witness: InclusionWitness,
    pub state: MintState,
    pub mint_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSwapRequest {
    #[serde(with = "hex32")]
    pub anchor_root: [u8; 32],
    pub nullifiers: Vec<Nullifier>,
    pub output_commitments: Vec<NoteCommitment>,
    pub output_value_commitments: Vec<ValueCommitment>,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSwapResponse {
    pub leaf_indices: Vec<u64>,
    pub witnesses: Vec<InclusionWitness>,
    pub state: MintState,
    pub mint_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMeltRequest {
    pub quote_id: String,
    pub amount: u64,
    #[serde(with = "hex32")]
    pub anchor_root: [u8; 32],
    pub nullifiers: Vec<Nullifier>,
    pub change_cm: Option<NoteCommitment>,
    pub change_cv: Option<ValueCommitment>,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkMeltResponse {
    pub paid: bool,
    pub change_leaf_index: Option<u64>,
    pub change_witness: Option<InclusionWitness>,
    pub state: MintState,
    pub mint_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCashuProof {
    pub secret: String,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkShieldRequest {
    pub bdhke_proofs: Vec<LegacyCashuProof>,
    pub cm: NoteCommitment,
    pub cv: ValueCommitment,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkUnshieldRequest {
    #[serde(with = "hex32")]
    pub anchor_root: [u8; 32],
    pub nullifiers: Vec<Nullifier>,
    pub unshield_amount: u64,
    pub change_cm: Option<NoteCommitment>,
    pub change_cv: Option<ValueCommitment>,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkUnshieldResponse {
    pub bdhke_proofs: Vec<LegacyCashuProof>,
    pub change_leaf_index: Option<u64>,
    pub change_witness: Option<InclusionWitness>,
    pub state: MintState,
    pub mint_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncQuery {
    pub from_epoch: u64,
    #[serde(default)]
    pub bucket: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub new_commitments: Vec<(u64, NoteCommitment)>,
    pub latest_state: MintState,
    pub mint_signature: String,
}

pub struct ZashuMint {
    mint_sk: SecretKey,
    mint_id: [u8; 32],
    genesis_state: MintState,
    state: MintState,
    note_acc: NoteAccumulator,
    nf_acc: NullifierAccumulator,
    rolling_window: usize,
    reserves: Vec<MintReserveKey>,
    step_proofs: Vec<FoldedProof>,
    /// Accumulator updates made since the last recorded step; the next step
    /// proof carries them so the fold can bind the root changes.
    pending_nullifier_updates: Vec<NullifierTransitionWitness>,
    pending_note_updates: Vec<LeafUpdate>,
    /// Folds steps in the background when the Ragu backend is selected.
    incremental_fold: IncrementalFold,
    epoch_commitments: Vec<(u64, u64, NoteCommitment)>,
    legacy_spent_secrets: HashSet<String>,
    legacy_issued_secrets: HashMap<String, u64>,
    stealth_memos: Vec<EncryptedStealthMemo>,
}

impl ZashuMint {
    pub fn new(mint_sk: SecretKey, reserves: Vec<MintReserveKey>, rolling_window: usize) -> Self {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &mint_sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        let mint_id = xonly.serialize();

        let note_acc = NoteAccumulator::new(rolling_window);
        let nf_acc = NullifierAccumulator::new();
        let genesis = MintState::genesis(nf_acc.root(), note_acc.root());

        Self {
            mint_sk,
            mint_id,
            genesis_state: genesis.clone(),
            state: genesis,
            note_acc,
            nf_acc,
            rolling_window,
            reserves,
            step_proofs: Vec::new(),
            pending_nullifier_updates: Vec::new(),
            pending_note_updates: Vec::new(),
            incremental_fold: IncrementalFold::from_env()
                .expect("invalid ZASHU_FOLD_BACKEND or backend not compiled in"),
            epoch_commitments: Vec::new(),
            legacy_spent_secrets: HashSet::new(),
            legacy_issued_secrets: HashMap::new(),
            stealth_memos: Vec::new(),
        }
    }

    pub fn info(&self) -> ZkInfoResponse {
        ZkInfoResponse {
            mint_id: self.mint_id,
            state: self.state.clone(),
            rolling_window: self.rolling_window,
            supported_predicates: vec![0x00, 0x01, 0x02, 0x03, 0x04],
        }
    }

    /// Issues mock legacy BDHKE proofs for intra-mint interop tests and increments unified liabilities.
    pub fn mint_legacy_bdhke(&mut self, amounts: &[u64]) -> Result<Vec<LegacyCashuProof>> {
        let mut out = Vec::with_capacity(amounts.len());
        for (i, &amt) in amounts.iter().enumerate() {
            let prev = self.state.clone();
            let secret = format!("bdhke_{}_{}_{}", self.state.epoch, i, amt);
            self.legacy_issued_secrets.insert(secret.clone(), amt);
            self.state.epoch += 1;
            self.state.total_liabilities += amt;
            let qh = blake2b_hash(secret.as_bytes());
            self.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &qh, amt);
            self.record_step(prove_mint_step(&prev, &self.state, amt)?.with_event(qh));
            out.push(LegacyCashuProof {
                secret,
                amount: amt,
            });
        }
        Ok(out)
    }

    pub fn zk_mint(&mut self, req: ZkMintRequest) -> Result<ZkMintResponse> {
        let proof = FoldedProof::from_base64(&req.proof)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;
        self.check_proof_epoch(&proof)?;
        verify_zk_mint(&proof, req.amount, &req.cm, &req.cv)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;

        let prev = self.state.clone();
        let leaf_index = self.insert_note(req.cm.0)?;
        self.state.epoch += 1;
        self.state.total_liabilities = self
            .state
            .total_liabilities
            .checked_add(req.amount)
            .ok_or_else(|| MintError::InvalidRequest("liability overflow".into()))?;
        self.state.note_acc_root = self.note_acc.root();
        let qh = blake2b_hash(req.quote_id.as_bytes());
        self.state.event_log_hash = hash_event_mint(&prev.event_log_hash, &qh, req.amount);
        self.record_step(prove_mint_step(&prev, &self.state, req.amount)?.with_event(qh));
        self.epoch_commitments
            .push((self.state.epoch, leaf_index, req.cm));

        let witness = self.note_acc.witness(leaf_index)?;
        let sig = self.sign_state(&self.state);
        Ok(ZkMintResponse {
            leaf_index,
            witness,
            state: self.state.clone(),
            mint_signature: sig,
        })
    }

    pub fn zk_swap(&mut self, req: ZkSwapRequest) -> Result<ZkSwapResponse> {
        if !self.note_acc.is_valid_anchor(&req.anchor_root) {
            return Err(MintError::StaleAnchor);
        }
        for nf in &req.nullifiers {
            if self.nf_acc.contains(&nf.0) {
                return Err(MintError::NullifierSpent);
            }
        }
        let proof = FoldedProof::from_base64(&req.proof)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;
        self.check_proof_epoch(&proof)?;
        verify_zk_swap(
            &proof,
            &req.anchor_root,
            &req.nullifiers,
            &req.output_commitments,
            &[],
            &req.output_value_commitments,
        )
        .map_err(|e| MintError::InvalidProof(e.to_string()))?;

        let prev = self.state.clone();
        let mut transitions = Vec::with_capacity(req.nullifiers.len());
        for nf in &req.nullifiers {
            transitions.push(self.insert_nullifier(nf.0)?);
        }

        let mut leaf_indices = Vec::with_capacity(req.output_commitments.len());
        let mut witnesses = Vec::with_capacity(req.output_commitments.len());
        self.state.epoch += 1;
        for cm in &req.output_commitments {
            let idx = self.insert_note(cm.0)?;
            leaf_indices.push(idx);
            self.epoch_commitments.push((self.state.epoch, idx, *cm));
        }
        for &idx in &leaf_indices {
            witnesses.push(self.note_acc.witness(idx)?);
        }

        self.state.nullifier_acc_root = self.nf_acc.root();
        self.state.note_acc_root = self.note_acc.root();
        self.record_step(prove_swap_step(&prev, &self.state, 0, 0, &transitions)?);

        let sig = self.sign_state(&self.state);
        Ok(ZkSwapResponse {
            leaf_indices,
            witnesses,
            state: self.state.clone(),
            mint_signature: sig,
        })
    }

    pub fn zk_melt(&mut self, req: ZkMeltRequest) -> Result<ZkMeltResponse> {
        if !self.note_acc.is_valid_anchor(&req.anchor_root) {
            return Err(MintError::StaleAnchor);
        }
        for nf in &req.nullifiers {
            if self.nf_acc.contains(&nf.0) {
                return Err(MintError::NullifierSpent);
            }
        }
        let proof = FoldedProof::from_base64(&req.proof)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;
        self.check_proof_epoch(&proof)?;
        verify_zk_melt(
            &proof,
            &req.anchor_root,
            req.amount,
            req.change_cm.as_ref(),
            &req.nullifiers,
        )
        .map_err(|e| MintError::InvalidProof(e.to_string()))?;

        let prev = self.state.clone();
        for nf in &req.nullifiers {
            self.insert_nullifier(nf.0)?;
        }
        self.state.epoch += 1;
        let (change_leaf_index, change_witness) = if let Some(cm) = req.change_cm {
            let idx = self.insert_note(cm.0)?;
            self.epoch_commitments.push((self.state.epoch, idx, cm));
            (Some(idx), Some(self.note_acc.witness(idx)?))
        } else {
            (None, None)
        };

        self.state.nullifier_acc_root = self.nf_acc.root();
        self.state.note_acc_root = self.note_acc.root();
        self.state.total_liabilities = self
            .state
            .total_liabilities
            .checked_sub(req.amount)
            .ok_or_else(|| MintError::InvalidRequest("melt exceeds liabilities".into()))?;
        let ph = blake2b_hash(req.quote_id.as_bytes());
        self.state.event_log_hash = hash_event_melt(&prev.event_log_hash, &ph, req.amount);
        self.record_step(prove_melt_step(&prev, &self.state, req.amount)?.with_event(ph));

        let sig = self.sign_state(&self.state);
        Ok(ZkMeltResponse {
            paid: true,
            change_leaf_index,
            change_witness,
            state: self.state.clone(),
            mint_signature: sig,
        })
    }

    pub fn zk_shield(&mut self, req: ZkShieldRequest) -> Result<ZkMintResponse> {
        let mut sum = 0u64;
        for bp in &req.bdhke_proofs {
            if self.legacy_spent_secrets.contains(&bp.secret) {
                return Err(MintError::NullifierSpent);
            }
            let expected = self
                .legacy_issued_secrets
                .get(&bp.secret)
                .ok_or_else(|| MintError::InvalidRequest("unknown legacy BDHKE secret".into()))?;
            if *expected != bp.amount {
                return Err(MintError::InvalidRequest("BDHKE amount mismatch".into()));
            }
            sum += bp.amount;
        }

        let proof = FoldedProof::from_base64(&req.proof)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;
        self.check_proof_epoch(&proof)?;
        verify_zk_shield(&proof, sum, &req.cm, &req.cv)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;

        let prev = self.state.clone();
        let mut transitions = Vec::with_capacity(req.bdhke_proofs.len());
        for bp in &req.bdhke_proofs {
            self.legacy_spent_secrets.insert(bp.secret.clone());
            // Accumulator keys must be canonical field elements.
            let nf = canonical_fp_bytes(b"zashu-legacy-nf", &blake2b_hash(bp.secret.as_bytes()));
            transitions.push(self.insert_nullifier(nf)?);
        }

        self.state.epoch += 1;
        let leaf_index = self.insert_note(req.cm.0)?;
        self.epoch_commitments
            .push((self.state.epoch, leaf_index, req.cm));
        self.state.nullifier_acc_root = self.nf_acc.root();
        self.state.note_acc_root = self.note_acc.root();
        // Liabilities unchanged!
        self.record_step(prove_swap_step(&prev, &self.state, sum, sum, &transitions)?);

        let witness = self.note_acc.witness(leaf_index)?;
        let sig = self.sign_state(&self.state);
        Ok(ZkMintResponse {
            leaf_index,
            witness,
            state: self.state.clone(),
            mint_signature: sig,
        })
    }

    pub fn zk_unshield(&mut self, req: ZkUnshieldRequest) -> Result<ZkUnshieldResponse> {
        if !self.note_acc.is_valid_anchor(&req.anchor_root) {
            return Err(MintError::StaleAnchor);
        }
        for nf in &req.nullifiers {
            if self.nf_acc.contains(&nf.0) {
                return Err(MintError::NullifierSpent);
            }
        }
        let proof = FoldedProof::from_base64(&req.proof)
            .map_err(|e| MintError::InvalidProof(e.to_string()))?;
        self.check_proof_epoch(&proof)?;
        verify_zk_unshield(
            &proof,
            &req.anchor_root,
            req.unshield_amount,
            req.change_cm.as_ref(),
            &req.nullifiers,
        )
        .map_err(|e| MintError::InvalidProof(e.to_string()))?;

        let prev = self.state.clone();
        let mut transitions = Vec::with_capacity(req.nullifiers.len());
        for nf in &req.nullifiers {
            transitions.push(self.insert_nullifier(nf.0)?);
        }

        self.state.epoch += 1;
        let (change_leaf_index, change_witness) = if let Some(cm) = req.change_cm {
            let idx = self.insert_note(cm.0)?;
            self.epoch_commitments.push((self.state.epoch, idx, cm));
            (Some(idx), Some(self.note_acc.witness(idx)?))
        } else {
            (None, None)
        };

        // Issue power-of-2 legacy BDHKE proofs summing to unshield_amount
        let mut bdhke_proofs = Vec::new();
        let mut rem = req.unshield_amount;
        let mut bit = 0u32;
        while rem > 0 {
            if rem & 1 == 1 {
                let amt = 1u64 << bit;
                let secret = format!("unshield_{}_{}_{}", self.state.epoch, bit, amt);
                self.legacy_issued_secrets.insert(secret.clone(), amt);
                bdhke_proofs.push(LegacyCashuProof {
                    secret,
                    amount: amt,
                });
            }
            rem >>= 1;
            bit += 1;
        }

        self.state.nullifier_acc_root = self.nf_acc.root();
        self.state.note_acc_root = self.note_acc.root();
        // Liabilities unchanged!
        self.record_step(prove_swap_step(
            &prev,
            &self.state,
            req.unshield_amount,
            req.unshield_amount,
            &transitions,
        )?);

        let sig = self.sign_state(&self.state);
        Ok(ZkUnshieldResponse {
            bdhke_proofs,
            change_leaf_index,
            change_witness,
            state: self.state.clone(),
            mint_signature: sig,
        })
    }

    pub fn sync_from_epoch(&self, from_epoch: u64) -> SyncResponse {
        let new_commitments = self
            .epoch_commitments
            .iter()
            .filter(|(ep, _, _)| *ep > from_epoch)
            .map(|(_, idx, cm)| (*idx, *cm))
            .collect();
        SyncResponse {
            from_epoch,
            to_epoch: self.state.epoch,
            new_commitments,
            latest_state: self.state.clone(),
            mint_signature: self.sign_state(&self.state),
        }
    }

    /// A Ragu transaction proof states the epoch its predicates (timelocks,
    /// HTLC expiry) were evaluated at; it must not be ahead of this mint.
    fn check_proof_epoch(&self, proof: &FoldedProof) -> Result<()> {
        match proof_epoch(proof) {
            Some(epoch) if epoch > self.state.epoch => Err(zashu_circuits::CircuitError::VerificationFailed(
                format!("proof evaluated at epoch {epoch}, mint is at epoch {}", self.state.epoch),
            )
            .into()),
            _ => Ok(()),
        }
    }

    /// Appends a note commitment, remembering the update for the fold proof.
    fn insert_note(&mut self, cm: [u8; 32]) -> Result<u64> {
        if bytes_to_fp(&cm).is_err() {
            return Err(MintError::InvalidRequest("note commitment is not a canonical field element".into()));
        }
        let update = self.note_acc.insert_recorded(cm)?;
        let index = update.leaf_index;
        self.pending_note_updates.push(update);
        Ok(index)
    }

    /// Inserts a nullifier, remembering the update for the fold proof.
    fn insert_nullifier(&mut self, nf: [u8; 32]) -> Result<NullifierTransitionWitness> {
        if bytes_to_fp(&nf).is_err() {
            return Err(MintError::InvalidRequest("nullifier is not a canonical field element".into()));
        }
        let transition = self.nf_acc.insert(nf)?;
        self.pending_nullifier_updates.push(transition.clone());
        Ok(transition)
    }

    /// Records a Mode A step proof, attaching the accumulator updates made
    /// since the previous step, and queues it for background folding.
    fn record_step(&mut self, step: FoldedProof) {
        let step = step.with_root_updates(
            std::mem::take(&mut self.pending_nullifier_updates),
            std::mem::take(&mut self.pending_note_updates),
        );
        self.incremental_fold.push(&step);
        self.step_proofs.push(step);
    }

    pub fn solvency_bundle(&self) -> Result<SolvencyBundle> {
        let folded = match self.incremental_fold.snapshot()? {
            // Folded in the background as the steps happened. Check it spans
            // genesis to the current state before signing it into a bundle.
            Some(folded) => {
                verify_fold_batch(&folded, &self.genesis_state.state_hash(), &self.state)?;
                folded
            }
            None => {
                let steps = if self.step_proofs.is_empty() {
                    vec![prove_swap_step(&self.genesis_state, &self.state, 0, 0, &[])?]
                } else {
                    self.step_proofs.clone()
                };
                fold_mode_a_batch(&self.genesis_state, &self.state, &steps)?
            }
        };
        let challenge = compute_reserves_challenge(&self.mint_id, &self.state);
        let utxos = self
            .reserves
            .iter()
            .map(|r| {
                sign_taproot_reserve_utxo(
                    &r.secret_key,
                    &r.txid,
                    r.vout,
                    r.value_sats,
                    &challenge,
                )
            })
            .collect();

        Ok(SolvencyBundle {
            version: "NUTZ-1".to_string(),
            mint_id: self.mint_id,
            genesis_state_hash: self.genesis_state.state_hash(),
            state: self.state.clone(),
            pcd_proof: folded.to_base64()?,
            reserves: ReservesAttestation { challenge, utxos },
            mint_signature: self.sign_state(&self.state),
        })
    }

    fn sign_state(&self, state: &MintState) -> String {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &self.mint_sk);
        let msg = Message::from_digest(state.state_hash());
        hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &kp).serialize())
    }
}

fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let h = sha2::Sha256::digest(data);
    out.copy_from_slice(&h);
    out
}

use sha2::Digest;

pub type SharedMintState = Arc<RwLock<ZashuMint>>;

pub fn mint_router(state: SharedMintState) -> Router {
    Router::new()
        .route("/v1/zk/info", get(handle_info))
        .route("/v1/zk/mint", post(handle_mint))
        .route("/v1/zk/swap", post(handle_swap))
        .route("/v1/zk/melt", post(handle_melt))
        .route("/v1/zk/shield", post(handle_shield))
        .route("/v1/zk/unshield", post(handle_unshield))
        .route("/v1/zk/sync", get(handle_sync))
        .route("/v1/zk/memos", post(handle_post_memo).get(handle_get_memos))
        .route("/v1/solvency", get(handle_solvency))
        .with_state(state)
}

async fn handle_info(State(s): State<SharedMintState>) -> Json<ZkInfoResponse> {
    Json(s.read().unwrap().info())
}

async fn handle_mint(
    State(s): State<SharedMintState>,
    Json(req): Json<ZkMintRequest>,
) -> Result<Json<ZkMintResponse>> {
    s.write().unwrap().zk_mint(req).map(Json)
}

async fn handle_swap(
    State(s): State<SharedMintState>,
    Json(req): Json<ZkSwapRequest>,
) -> Result<Json<ZkSwapResponse>> {
    s.write().unwrap().zk_swap(req).map(Json)
}

async fn handle_melt(
    State(s): State<SharedMintState>,
    Json(req): Json<ZkMeltRequest>,
) -> Result<Json<ZkMeltResponse>> {
    s.write().unwrap().zk_melt(req).map(Json)
}

async fn handle_shield(
    State(s): State<SharedMintState>,
    Json(req): Json<ZkShieldRequest>,
) -> Result<Json<ZkMintResponse>> {
    s.write().unwrap().zk_shield(req).map(Json)
}

async fn handle_unshield(
    State(s): State<SharedMintState>,
    Json(req): Json<ZkUnshieldRequest>,
) -> Result<Json<ZkUnshieldResponse>> {
    s.write().unwrap().zk_unshield(req).map(Json)
}

async fn handle_sync(
    State(s): State<SharedMintState>,
    Query(q): Query<SyncQuery>,
) -> Json<SyncResponse> {
    let _ = q.bucket;
    Json(s.read().unwrap().sync_from_epoch(q.from_epoch))
}

async fn handle_post_memo(
    State(s): State<SharedMintState>,
    Json(memo): Json<EncryptedStealthMemo>,
) -> StatusCode {
    s.write().unwrap().stealth_memos.push(memo);
    StatusCode::CREATED
}

async fn handle_get_memos(State(s): State<SharedMintState>) -> Json<Vec<EncryptedStealthMemo>> {
    Json(s.read().unwrap().stealth_memos.clone())
}

async fn handle_solvency(State(s): State<SharedMintState>) -> Result<Json<SolvencyBundle>> {
    s.read().unwrap().solvency_bundle().map(Json)
}
