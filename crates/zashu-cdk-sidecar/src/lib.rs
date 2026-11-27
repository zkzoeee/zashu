use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zashu_acc::NullifierAccumulator;
use zashu_circuits::mode_a::{
    fold_mode_a_batch, prove_melt_step, prove_mint_step, prove_swap_step, IncrementalFold, SnapshotHandle,
};
use zashu_circuits::FoldedProof;
use zashu_core::field::canonical_fp_bytes;
use zashu_core::poseidon::{hash_event_melt, hash_event_mint};
use zashu_core::reserves::{compute_reserves_challenge, sign_taproot_reserve_utxo};
use zashu_core::types::{MintState, ReservesAttestation, SolvencyBundle};

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("accumulator error: {0}")]
    Acc(#[from] zashu_acc::AccError),

    #[error("circuit error: {0}")]
    Circuit(#[from] zashu_circuits::CircuitError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("no solvency bundle available yet")]
    NoBundle,
}

pub type Result<T> = std::result::Result<T, SidecarError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MintEvent {
    Mint {
        amount: u64,
        quote_hash: [u8; 32],
    },
    Swap {
        input_nullifiers: Vec<[u8; 32]>,
        sum_in: u64,
        sum_out: u64,
    },
    Melt {
        input_nullifiers: Vec<[u8; 32]>,
        amount: u64,
        payout_hash: [u8; 32],
    },
}

pub trait MintEventSource: Send + Sync {
    fn drain_pending_events(&self) -> Result<Vec<MintEvent>>;
}

#[derive(Debug, Default)]
pub struct InMemoryEventSource {
    events: RwLock<Vec<MintEvent>>,
}

impl InMemoryEventSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, ev: MintEvent) {
        self.events.write().unwrap().push(ev);
    }
}

impl MintEventSource for InMemoryEventSource {
    fn drain_pending_events(&self) -> Result<Vec<MintEvent>> {
        let mut guard = self.events.write().unwrap();
        Ok(std::mem::take(&mut *guard))
    }
}

/// Reads mint/swap/melt events from a Cashu Development Kit (CDK) SQLite database table `zashu_events`.
pub struct CdkSqliteEventSource {
    db_path: std::path::PathBuf,
    last_id: RwLock<i64>,
}

impl CdkSqliteEventSource {
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(db_path.as_ref())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS zashu_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_json TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            db_path: db_path.as_ref().to_path_buf(),
            last_id: RwLock::new(0),
        })
    }

    pub fn append_event(&self, ev: &MintEvent) -> Result<()> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let json = serde_json::to_string(ev).unwrap();
        conn.execute("INSERT INTO zashu_events (payload_json) VALUES (?1)", [json])?;
        Ok(())
    }
}

impl MintEventSource for CdkSqliteEventSource {
    fn drain_pending_events(&self) -> Result<Vec<MintEvent>> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let last = *self.last_id.read().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload_json FROM zashu_events WHERE id > ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([last], |row| {
            let id: i64 = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((id, json))
        })?;

        let mut events = Vec::new();
        let mut max_id = last;
        for item in rows {
            let (id, json) = item?;
            max_id = max_id.max(id);
            if let Ok(ev) = serde_json::from_str::<MintEvent>(&json) {
                events.push(ev);
            }
        }
        *self.last_id.write().unwrap() = max_id;
        Ok(events)
    }
}

#[derive(Debug, Clone)]
pub struct ReserveConfig {
    pub secret_key: SecretKey,
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
}

pub struct EpochFolder {
    mint_sk: SecretKey,
    mint_id: [u8; 32],
    genesis_state_hash: [u8; 32],
    current_state: MintState,
    nf_acc: NullifierAccumulator,
    reserves: Vec<ReserveConfig>,
    history: HashMap<u64, SolvencyBundle>,
    latest_epoch: u64,
    /// The first state this sidecar saw; background-folded proofs span from it.
    genesis_state: MintState,
    /// Folds steps on a worker thread when the backend supports it.
    incremental: IncrementalFold,
    /// Epochs whose steps are queued but whose proof is not ready yet, oldest first.
    pending: VecDeque<PendingEpoch>,
}

/// An epoch that has been sealed and queued for folding.
struct PendingEpoch {
    start_state: MintState,
    state: MintState,
    step_proofs: Vec<FoldedProof>,
    snapshot: Option<SnapshotHandle>,
}

impl EpochFolder {
    pub fn new(mint_sk: SecretKey, reserves: Vec<ReserveConfig>) -> Self {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &mint_sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        let mint_id = xonly.serialize();

        let nf_acc = NullifierAccumulator::new();
        let genesis = MintState::genesis(nf_acc.root(), [0u8; 32]);
        let genesis_state_hash = genesis.state_hash();

        Self {
            mint_sk,
            mint_id,
            genesis_state_hash,
            current_state: genesis.clone(),
            nf_acc,
            reserves,
            history: HashMap::new(),
            latest_epoch: 0,
            genesis_state: genesis,
            incremental: IncrementalFold::from_env()
                .expect("invalid ZASHU_PCD_BACKEND or backend not compiled in"),
            pending: VecDeque::new(),
        }
    }

    pub fn mint_id(&self) -> [u8; 32] {
        self.mint_id
    }

    /// Seals an epoch and returns its solvency bundle, waiting for the proof.
    pub fn seal_epoch(&mut self, events: &[MintEvent]) -> Result<SolvencyBundle> {
        let epoch = self.begin_epoch(events)?;
        self.complete_pending(true)?;
        self.history.get(&epoch).cloned().ok_or(SidecarError::NoBundle)
    }

    /// Publishes the bundle of every queued epoch whose proof is ready, in
    /// order. Returns how many were published. Never blocks on proving.
    pub fn poll_epochs(&mut self) -> Result<usize> {
        self.complete_pending(false)
    }

    /// Epochs sealed with [`begin_epoch`](Self::begin_epoch) that are still being folded.
    pub fn pending_epochs(&self) -> usize {
        self.pending.len()
    }

    fn complete_pending(&mut self, wait: bool) -> Result<usize> {
        let mut done = 0;
        while let Some(mut epoch) = self.pending.pop_front() {
            let snapshot = if wait {
                epoch.snapshot.take().expect("snapshot requested when the epoch was queued").wait()
            } else {
                match epoch.snapshot.as_mut().expect("snapshot requested when the epoch was queued").try_take() {
                    Some(result) => result,
                    None => {
                        self.pending.push_front(epoch);
                        break;
                    }
                }
            };
            let bundle = self.build_bundle(&epoch, snapshot?)?;
            self.latest_epoch = epoch.state.epoch;
            self.history.insert(self.latest_epoch, bundle);
            done += 1;
        }
        Ok(done)
    }

    /// Applies an epoch's events and queues its proof, returning the epoch
    /// number at once. With a background-folding backend the bundle appears
    /// (see [`poll_epochs`](Self::poll_epochs)) once the worker has caught up.
    pub fn begin_epoch(&mut self, events: &[MintEvent]) -> Result<u64> {
        let start_state = self.current_state.clone();
        let mut step_proofs: Vec<FoldedProof> = Vec::with_capacity(events.len() + 1);
        let mut state = start_state.clone();
        state.epoch += 1;
        // The epoch advance is its own zero-delta step, so the step chain starts
        // exactly at `start_state`. It also serves as the heartbeat for an
        // epoch with no events.
        step_proofs.push(prove_swap_step(&start_state, &state, 0, 0, &[])?);

        for ev in events {
            let prev = state.clone();
            match ev {
                MintEvent::Mint { amount, quote_hash } => {
                    state.total_liabilities = state
                        .total_liabilities
                        .checked_add(*amount)
                        .ok_or_else(|| SidecarError::Circuit(zashu_circuits::CircuitError::ValueBounds))?;
                    state.event_log_hash = hash_event_mint(&prev.event_log_hash, quote_hash, *amount);
                    step_proofs.push(prove_mint_step(&prev, &state, *amount)?.with_event(*quote_hash));
                }
                MintEvent::Swap {
                    input_nullifiers,
                    sum_in,
                    sum_out,
                } => {
                    let mut transitions = Vec::with_capacity(input_nullifiers.len());
                    for nf in input_nullifiers {
                        transitions.push(self.nf_acc.insert(canonical_fp_bytes(b"zashu-cdk-nf", nf))?);
                    }
                    state.nullifier_acc_root = self.nf_acc.root();
                    step_proofs.push(prove_swap_step(&prev, &state, *sum_in, *sum_out, &transitions)?);
                }
                MintEvent::Melt {
                    input_nullifiers,
                    amount,
                    payout_hash,
                } => {
                    let mut transitions = Vec::with_capacity(input_nullifiers.len());
                    for nf in input_nullifiers {
                        transitions.push(self.nf_acc.insert(canonical_fp_bytes(b"zashu-cdk-nf", nf))?);
                    }
                    state.nullifier_acc_root = self.nf_acc.root();
                    state.total_liabilities = state
                        .total_liabilities
                        .checked_sub(*amount)
                        .ok_or_else(|| SidecarError::Circuit(zashu_circuits::CircuitError::ValueBounds))?;
                    state.event_log_hash = hash_event_melt(&prev.event_log_hash, payout_hash, *amount);
                    step_proofs.push(
                        prove_melt_step(&prev, &state, *amount)?
                            .with_event(*payout_hash)
                            .with_root_updates(transitions, Vec::new()),
                    );
                }
            }
        }

        self.nf_acc.seal_epoch();
        self.nf_acc.prune_before_epoch(8);

        for step in &step_proofs {
            self.incremental.push(step);
        }
        let epoch = state.epoch;
        self.pending.push_back(PendingEpoch {
            start_state,
            state: state.clone(),
            step_proofs,
            snapshot: Some(self.incremental.request_snapshot()),
        });
        self.current_state = state;
        Ok(epoch)
    }

    fn build_bundle(&self, epoch: &PendingEpoch, snapshot: Option<FoldedProof>) -> Result<SolvencyBundle> {
        let state = &epoch.state;
        // A background-folded proof spans from this sidecar's first state; a
        // batch fold covers just this epoch.
        let (proof_start, folded) = match snapshot {
            Some(folded) => (self.genesis_state.clone(), folded),
            None => (
                epoch.start_state.clone(),
                fold_mode_a_batch(&epoch.start_state, state, &epoch.step_proofs)?,
            ),
        };
        let challenge = compute_reserves_challenge(&self.mint_id, state);
        let utxos = self
            .reserves
            .iter()
            .map(|r| sign_taproot_reserve_utxo(&r.secret_key, &r.txid, r.vout, r.value_sats, &challenge))
            .collect();

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &self.mint_sk);
        let msg = Message::from_digest(state.state_hash());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);

        let _ = self.genesis_state_hash;
        Ok(SolvencyBundle {
            version: "NUTZ-1".to_string(),
            mint_id: self.mint_id,
            genesis_state_hash: proof_start.state_hash(),
            state: state.clone(),
            pcd_proof: folded.to_base64()?,
            reserves: ReservesAttestation { challenge, utxos },
            mint_signature: hex::encode(sig.serialize()),
        })
    }

    pub fn latest_bundle(&self) -> Option<&SolvencyBundle> {
        self.history.get(&self.latest_epoch)
    }

    pub fn bundle_at_epoch(&self, epoch: u64) -> Option<&SolvencyBundle> {
        self.history.get(&epoch)
    }
}

pub type SharedSidecarState = Arc<RwLock<EpochFolder>>;

pub fn sidecar_router(state: SharedSidecarState) -> Router {
    Router::new()
        .route("/v1/solvency", get(get_latest_solvency))
        .route("/v1/solvency/epoch/{epoch}", get(get_epoch_solvency))
        .with_state(state)
}

async fn get_latest_solvency(
    State(state): State<SharedSidecarState>,
) -> std::result::Result<Json<SolvencyBundle>, StatusCode> {
    let guard = state.read().unwrap();
    guard
        .latest_bundle()
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_epoch_solvency(
    State(state): State<SharedSidecarState>,
    AxumPath(epoch): AxumPath<u64>,
) -> std::result::Result<Json<SolvencyBundle>, StatusCode> {
    let guard = state.read().unwrap();
    guard
        .bundle_at_epoch(epoch)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
