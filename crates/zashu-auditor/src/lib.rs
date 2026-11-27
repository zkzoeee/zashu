pub mod esplora;

use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zashu_circuits::mode_a::verify_fold_batch;
use zashu_circuits::{FoldedProof, SubcircuitId};
use zashu_core::reserves::{verify_reserves_attestation, UtxoProvider};
use zashu_core::types::SolvencyBundle;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("unsupported bundle version: {0}")]
    UnsupportedVersion(String),

    #[error("invalid mint signature")]
    InvalidMintSignature,

    #[error("PCD proof verification failed: {0}")]
    InvalidPcdProof(String),

    #[error("reserves verification failed: {0}")]
    ReservesFailed(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub solvent: bool,
    pub epoch: u64,
    pub total_liabilities: u64,
    pub total_reserves: u64,
    pub verify_ms: u128,
    /// Which fold proof was verified, e.g. `RaguFoldRoots` or `FoldBatch`.
    #[serde(default)]
    pub fold_proof: String,
    /// The proof attests every step from genesis (any Ragu fold). A Halo 2
    /// `FoldBatch` only shows the endpoints.
    #[serde(default)]
    pub steps_proven: bool,
    /// The proof also attests how the event log, nullifier root and note root
    /// changed (`RaguFoldRoots`).
    #[serde(default)]
    pub roots_bound: bool,
    /// Aggregated fold only: how many operations the proof covers, and how
    /// many of them had no matching shielded transaction proof (legacy
    /// BDHKE operations, shield/unshield, stale anchors).
    #[serde(default)]
    pub ops: Option<u64>,
    #[serde(default)]
    pub unbound_ops: Option<u64>,
}

/// Computes the deterministic mint signature tag over `(mint_id, state_hash)`.
/// In production this can be a Schnorr/Ed25519 signature; here we bind with SHA-256d/X-only Schnorr or HMAC-style pubkey check.
pub fn verify_mint_signature(bundle: &SolvencyBundle) -> bool {
    if bundle.mint_signature.is_empty() {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(&bundle.mint_signature) else {
        return false;
    };
    let Ok(xonly) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bundle.mint_id) else {
        return false;
    };
    let Ok(sig) = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let msg = bitcoin::secp256k1::Message::from_digest(bundle.state.state_hash());
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    secp.verify_schnorr(&sig, &msg, &xonly).is_ok()
}

pub fn verify_solvency_bundle(
    bundle: &SolvencyBundle,
    utxo_provider: &dyn UtxoProvider,
) -> Result<AuditReport> {
    let start = Instant::now();
    if bundle.version != "NUTZ-1" {
        return Err(AuditError::UnsupportedVersion(bundle.version.clone()));
    }
    if !verify_mint_signature(bundle) {
        return Err(AuditError::InvalidMintSignature);
    }

    let proof = FoldedProof::from_base64(&bundle.pcd_proof)
        .map_err(|e| AuditError::InvalidPcdProof(e.to_string()))?;
    verify_fold_batch(&proof, &bundle.genesis_state_hash, &bundle.state)
        .map_err(|e| AuditError::InvalidPcdProof(e.to_string()))?;

    let counts = zashu_circuits::mode_a::fold_op_counts(&proof);
    let total_reserves =
        verify_reserves_attestation(&bundle.mint_id, &bundle.state, &bundle.reserves, utxo_provider)
            .map_err(|e| AuditError::ReservesFailed(e.to_string()))?;

    Ok(AuditReport {
        solvent: true,
        epoch: bundle.state.epoch,
        total_liabilities: bundle.state.total_liabilities,
        total_reserves,
        verify_ms: start.elapsed().as_millis(),
        fold_proof: format!("{:?}", proof.subcircuit),
        steps_proven: matches!(
            proof.subcircuit,
            SubcircuitId::RaguFold | SubcircuitId::RaguFoldRoots | SubcircuitId::RaguFoldAggregated
        ),
        roots_bound: matches!(proof.subcircuit, SubcircuitId::RaguFoldRoots | SubcircuitId::RaguFoldAggregated),
        ops: counts.map(|c| c.0),
        unbound_ops: counts.map(|c| c.1),
    })
}
