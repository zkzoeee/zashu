use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use ff::Field;
use group::Group;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use zashu_acc::NoteAccumulator;
use zashu_auditor::verify_solvency_bundle;
use zashu_circuits::mode_b::{
    balance_blinding, prove_zk_melt, prove_zk_mint, prove_zk_shield, prove_zk_swap,
    InputNoteWitness, OutputNoteWitness,
};
use zashu_circuits::predicates::PredicateWitness;
use zashu_core::field::{bytes_to_fq, fq_to_bytes, hash_bytes_to_fq, Fq, PallasPoint};
use zashu_core::reserves::MockUtxoProvider;
use zashu_core::stealth::{
    create_stealth_output, decrypt_stealth_memo, EncryptedStealthMemo, PointBytesExt,
    StealthKeypair, StealthMemoPayload,
};
use zashu_core::types::{MintState, Note};

use crate::{MintReserveKey, ZashuMint, ZkMeltRequest, ZkMintRequest, ZkShieldRequest, ZkSwapRequest};

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct DemoNoteView {
    pub value: u64,
    pub commitment: String,
    pub leaf_index: u64,
    pub spent: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct XRayLogEntry {
    pub endpoint: String,
    pub summary: String,
    pub opaque_payload: serde_json::Value,
    pub hidden_from_mint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoAuditView {
    pub solvent: bool,
    pub epoch: u64,
    pub total_liabilities: u64,
    pub total_reserves: u64,
    pub verify_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoStateResponse {
    pub session_id: String,
    pub alice_balance: u64,
    pub alice_notes: Vec<DemoNoteView>,
    pub bob_address: String,
    pub bob_balance: u64,
    pub bob_notes: Vec<DemoNoteView>,
    pub bob_pending_memos: usize,
    pub bob_synced_epoch: u64,
    pub mint_state: MintState,
    pub reserve_sats: u64,
    pub last_action_ms: u128,
    pub xray_logs: Vec<XRayLogEntry>,
    pub audit: DemoAuditView,
}

#[derive(Clone)]
struct DemoStoredNote {
    note: Note,
    sk: [u8; 32],
    blind: Fq,
    leaf_index: u64,
    spent: bool,
}

pub struct PlaygroundSession {
    mint: ZashuMint,
    provider: MockUtxoProvider,
    reserve_sats: u64,
    rng: StdRng,
    alice_sk: [u8; 32],
    alice_pk: [u8; 32],
    alice_acc: NoteAccumulator,
    alice_notes: Vec<DemoStoredNote>,
    bob_stealth: StealthKeypair,
    bob_acc: NoteAccumulator,
    bob_synced_epoch: u64,
    bob_notes: Vec<DemoStoredNote>,
    pending_memos: Vec<(EncryptedStealthMemo, Fq, u64)>,
    last_spent_swap_req: Option<ZkSwapRequest>,
    last_action_ms: u128,
    xray_logs: Vec<XRayLogEntry>,
    nonce_counter: u8,
}

impl Default for PlaygroundSession {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaygroundSession {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let mint_sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let res_sk = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &res_sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        let spk = ScriptBuf::new_p2tr(&secp, xonly, None);
        let txid = "aa".repeat(32);
        let reserve_sats = 10_000_000u64;

        let mut provider = MockUtxoProvider::new();
        provider.insert(&txid, 0, reserve_sats, hex::encode(spk.as_bytes()));

        let mint = ZashuMint::new(
            mint_sk,
            vec![MintReserveKey {
                secret_key: res_sk,
                txid,
                vout: 0,
                value_sats: reserve_sats,
            }],
            64,
        );

        let mut rng = StdRng::seed_from_u64(2026);
        let alice_sk_fq = hash_bytes_to_fq(b"demo-alice", b"seed");
        let alice_pk = (PallasPoint::generator() * alice_sk_fq).to_affine_bytes();
        let bob_stealth = StealthKeypair::random(&mut rng);

        Self {
            mint,
            provider,
            reserve_sats,
            rng,
            alice_sk: fq_to_bytes(&alice_sk_fq),
            alice_pk,
            alice_acc: NoteAccumulator::new(64),
            alice_notes: Vec::new(),
            bob_stealth,
            bob_acc: NoteAccumulator::new(64),
            bob_synced_epoch: 0,
            bob_notes: Vec::new(),
            pending_memos: Vec::new(),
            last_spent_swap_req: None,
            last_action_ms: 0,
            xray_logs: Vec::new(),
            nonce_counter: 1,
        }
    }

    fn next_rand32(&mut self) -> [u8; 32] {
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut out = [self.nonce_counter; 32];
        out[0] = self.nonce_counter.wrapping_mul(7);
        out
    }

    fn sync_alice(&mut self) {
        let last = self.alice_acc.len();
        let sync = self.mint.sync_from_epoch(0);
        for (idx, cm) in sync.new_commitments {
            if idx >= last {
                let _ = self.alice_acc.insert(cm.0);
            }
        }
    }

    pub fn mint_arbitrary(&mut self, amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("amount must be > 0".into());
        }
        let t0 = Instant::now();
        let rho = self.next_rand32();
        let r = self.next_rand32();
        let blind = Fq::random(&mut self.rng);
        let note = Note {
            value: amount,
            owner_pk: self.alice_pk,
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho,
            r,
        };
        let (cm, cv, proof) = prove_zk_mint(&note, blind, amount).map_err(|e| e.to_string())?;
        let req = ZkMintRequest {
            quote_id: format!("demo_mint_{}", self.nonce_counter),
            amount,
            cm,
            cv,
            proof: proof.to_base64().map_err(|e| e.to_string())?,
        };
        let res = self.mint.zk_mint(req.clone()).map_err(|e| e.to_string())?;
        self.last_action_ms = t0.elapsed().as_millis();
        self.sync_alice();
        self.alice_notes.push(DemoStoredNote {
            note,
            sk: self.alice_sk,
            blind,
            leaf_index: res.leaf_index,
            spent: false,
        });
        self.xray_logs.insert(
            0,
            XRayLogEntry {
                endpoint: "POST /v1/zk/mint".into(),
                summary: format!(
                    "Minted 1 arbitrary shielded note ({amount} sats) at leaf #{} in {}ms",
                    res.leaf_index, self.last_action_ms
                ),
                opaque_payload: serde_json::json!({
                    "cm": format!("0x{}...", hex::encode(&cm.0[..6])),
                    "cv": format!("0x{}...", hex::encode(&cv.bytes[..6])),
                    "proof_bytes": req.proof.len(),
                }),
                hidden_from_mint: "Owner public key & predicate policy".into(),
            },
        );
        Ok(())
    }

    pub fn shield_legacy(&mut self, amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("amount must be > 0".into());
        }
        let t0 = Instant::now();
        let mut parts = Vec::new();
        let mut rem = amount;
        let mut bit = 0u32;
        while rem > 0 {
            if rem & 1 == 1 {
                parts.push(1u64 << bit);
            }
            rem >>= 1;
            bit += 1;
        }
        let legacy = self.mint.mint_legacy_bdhke(&parts).map_err(|e| e.to_string())?;
        let rho = self.next_rand32();
        let r = self.next_rand32();
        let blind = Fq::random(&mut self.rng);
        let note = Note {
            value: amount,
            owner_pk: self.alice_pk,
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho,
            r,
        };
        let (cm, cv, proof) = prove_zk_shield(&note, blind, amount).map_err(|e| e.to_string())?;
        let res = self
            .mint
            .zk_shield(ZkShieldRequest {
                bdhke_proofs: legacy,
                cm,
                cv,
                proof: proof.to_base64().map_err(|e| e.to_string())?,
            })
            .map_err(|e| e.to_string())?;
        self.last_action_ms = t0.elapsed().as_millis();
        self.sync_alice();
        self.alice_notes.push(DemoStoredNote {
            note,
            sk: self.alice_sk,
            blind,
            leaf_index: res.leaf_index,
            spent: false,
        });
        self.xray_logs.insert(
            0,
            XRayLogEntry {
                endpoint: "POST /v1/zk/shield".into(),
                summary: format!(
                    "Merged {} legacy Cashu tokens ({:?}) -> 1 Zashu note ({amount} sats) in {}ms",
                    parts.len(),
                    parts,
                    self.last_action_ms
                ),
                opaque_payload: serde_json::json!({
                    "bdhke_denominations": parts,
                    "cm": format!("0x{}...", hex::encode(&cm.0[..6])),
                }),
                hidden_from_mint: "New shielded owner key & future swap amounts".into(),
            },
        );
        Ok(())
    }

    pub fn stealth_send(&mut self, amount: u64) -> Result<(), String> {
        self.sync_alice();
        let t0 = Instant::now();
        let idx = self
            .alice_notes
            .iter()
            .position(|n| !n.spent && n.note.value >= amount)
            .ok_or_else(|| format!("Alice needs a single unspent note >= {amount} sats"))?;
        let inp = self.alice_notes[idx].clone();
        let witness = self.alice_acc.witness(inp.leaf_index).map_err(|e| e.to_string())?;
        let anchor = self.alice_acc.root();

        let rho_bob = self.next_rand32();
        let r_bob = self.next_rand32();
        let (one_time_pk, memo) = create_stealth_output(
            &self.bob_stealth.address,
            &StealthMemoPayload {
                value: amount,
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho: rho_bob,
                r: r_bob,
                leaf_index: 0,
            },
            &mut self.rng,
        )
        .map_err(|e| e.to_string())?;

        let bob_note = Note {
            value: amount,
            owner_pk: one_time_pk,
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho: rho_bob,
            r: r_bob,
        };

        let change = inp.note.value - amount;
        let mut out_notes = vec![bob_note];
        let mut out_blinds = Vec::new();
        if change > 0 {
            let b_bob = Fq::random(&mut self.rng);
            let b_ch = balance_blinding(&[inp.blind], &[b_bob]);
            out_blinds.push(b_bob);
            out_blinds.push(b_ch);
            out_notes.push(Note {
                value: change,
                owner_pk: self.alice_pk,
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho: self.next_rand32(),
                r: self.next_rand32(),
            });
        } else {
            out_blinds.push(inp.blind);
        }

        let out_refs: Vec<OutputNoteWitness<'_>> = out_notes
            .iter()
            .zip(out_blinds.iter())
            .map(|(n, &b)| OutputNoteWitness { note: n, blind: b })
            .collect();

        let (nfs, cms, cvs, proof) = prove_zk_swap(
            &anchor,
            &[InputNoteWitness {
                note: &inp.note,
                blind: inp.blind,
                witness: &witness,
                predicate: &PredicateWitness::StandardSpend { sk: inp.sk },
            }],
            &out_refs,
        )
        .map_err(|e| e.to_string())?;

        let req = ZkSwapRequest {
            anchor_root: anchor,
            nullifiers: nfs.clone(),
            output_commitments: cms.clone(),
            output_value_commitments: cvs,
            proof: proof.to_base64().map_err(|e| e.to_string())?,
        };
        let res = self.mint.zk_swap(req.clone()).map_err(|e| e.to_string())?;
        self.last_action_ms = t0.elapsed().as_millis();
        self.last_spent_swap_req = Some(req.clone());
        self.alice_notes[idx].spent = true;
        self.sync_alice();

        if change > 0 {
            self.alice_notes.push(DemoStoredNote {
                note: out_notes[1].clone(),
                sk: self.alice_sk,
                blind: out_blinds[1],
                leaf_index: res.leaf_indices[1],
                spent: false,
            });
        }
        self.pending_memos.push((memo, out_blinds[0], res.leaf_indices[0]));

        self.xray_logs.insert(
            0,
            XRayLogEntry {
                endpoint: "POST /v1/zk/swap (Unified k=13 Proof)".into(),
                summary: format!(
                    "Single-proof stealth swap confirmed (Bob offline, leaf #{}) in {}ms",
                    res.leaf_indices[0], self.last_action_ms
                ),
                opaque_payload: serde_json::json!({
                    "anchor_root": format!("0x{}...", hex::encode(&anchor[..6])),
                    "nullifiers": nfs.iter().map(|n| format!("0x{}...", hex::encode(&n.0[..6]))).collect::<Vec<_>>(),
                    "output_commitments": cms.iter().map(|c| format!("0x{}...", hex::encode(&c.0[..6]))).collect::<Vec<_>>(),
                    "unified_proof_bytes": req.proof.len(),
                }),
                hidden_from_mint: "Amounts, sender->receiver link, input note index & predicate!".into(),
            },
        );
        Ok(())
    }

    pub fn try_double_spend(&mut self) -> Result<String, String> {
        let Some(req) = self.last_spent_swap_req.clone() else {
            return Err("Perform at least one Stealth Send first so Alice has a spent nullifier to replay".into());
        };
        let t0 = Instant::now();
        match self.mint.zk_swap(req.clone()) {
            Ok(_) => Err("unexpectedly accepted double-spend".into()),
            Err(e) => {
                self.last_action_ms = t0.elapsed().as_millis();
                let msg = e.to_string();
                self.xray_logs.insert(
                    0,
                    XRayLogEntry {
                        endpoint: "POST /v1/zk/swap (REPLAY ATTACK)".into(),
                        summary: format!("REJECTED: {msg}"),
                        opaque_payload: serde_json::json!({
                            "replayed_nullifier": format!("0x{}...", hex::encode(&req.nullifiers[0].0[..6])),
                            "http_status": 400,
                            "error": msg,
                        }),
                        hidden_from_mint: "NullifierAccumulator blocked replay without learning note value".into(),
                    },
                );
                Ok(msg)
            }
        }
    }

    pub fn bob_sync(&mut self) -> Result<usize, String> {
        let t0 = Instant::now();
        let sync = self.mint.sync_from_epoch(self.bob_synced_epoch);
        for (_, cm) in &sync.new_commitments {
            self.bob_acc.insert(cm.0).map_err(|e| e.to_string())?;
        }
        self.bob_synced_epoch = sync.to_epoch;

        let memos = std::mem::take(&mut self.pending_memos);
        let count = memos.len();
        for (memo, blind, leaf_idx) in memos {
            let (payload, one_time_sk) =
                decrypt_stealth_memo(&self.bob_stealth, &memo).map_err(|e| e.to_string())?;
            let sk_fq = bytes_to_fq(&one_time_sk).map_err(|e| e.to_string())?;
            let one_time_pk = (PallasPoint::generator() * sk_fq).to_affine_bytes();
            let note = Note {
                value: payload.value,
                owner_pk: one_time_pk,
                predicate_id: payload.predicate_id,
                predicate_params_hash: payload.predicate_params_hash,
                rho: payload.rho,
                r: payload.r,
            };
            self.bob_notes.push(DemoStoredNote {
                note,
                sk: one_time_sk,
                blind,
                leaf_index: leaf_idx,
                spent: false,
            });
        }
        self.last_action_ms = t0.elapsed().as_millis();

        self.xray_logs.insert(
            0,
            XRayLogEntry {
                endpoint: "GET /v1/zk/sync (Oblivious Sync)".into(),
                summary: format!(
                    "Bob synced {} commitments to epoch {} & decrypted {} stealth note(s) in {}ms",
                    sync.new_commitments.len(),
                    self.bob_synced_epoch,
                    count,
                    self.last_action_ms
                ),
                opaque_payload: serde_json::json!({
                    "from_epoch": sync.from_epoch,
                    "to_epoch": sync.to_epoch,
                    "commitments_downloaded": sync.new_commitments.len(),
                }),
                hidden_from_mint: "Mint never learns which leaf_index or note belongs to Bob!".into(),
            },
        );
        Ok(count)
    }

    pub fn bob_melt(&mut self) -> Result<u64, String> {
        let idx = self
            .bob_notes
            .iter()
            .position(|n| !n.spent)
            .ok_or_else(|| "Bob has no unspent notes to melt. Sync Bob's wallet first!".to_string())?;

        let t0 = Instant::now();
        // Ensure Bob's accumulator is up to date before proving
        let sync = self.mint.sync_from_epoch(self.bob_synced_epoch);
        for (_, cm) in &sync.new_commitments {
            self.bob_acc.insert(cm.0).map_err(|e| e.to_string())?;
        }
        self.bob_synced_epoch = sync.to_epoch;

        let inp = self.bob_notes[idx].clone();
        let witness = self.bob_acc.witness(inp.leaf_index).map_err(|e| e.to_string())?;
        let anchor = self.bob_acc.root();

        let (nfs, _, proof) = prove_zk_melt(
            &anchor,
            &[InputNoteWitness {
                note: &inp.note,
                blind: inp.blind,
                witness: &witness,
                predicate: &PredicateWitness::StandardSpend { sk: inp.sk },
            }],
            inp.note.value,
            None,
        )
        .map_err(|e| e.to_string())?;

        let proof_b64 = proof.to_base64().map_err(|e| e.to_string())?;
        self.mint
            .zk_melt(ZkMeltRequest {
                quote_id: format!("bob_ln_pay_{}", self.nonce_counter),
                amount: inp.note.value,
                anchor_root: anchor,
                nullifiers: nfs.clone(),
                change_cm: None,
                change_cv: None,
                proof: proof_b64.clone(),
            })
            .map_err(|e| e.to_string())?;

        self.bob_notes[idx].spent = true;
        self.last_action_ms = t0.elapsed().as_millis();
        self.xray_logs.insert(
            0,
            XRayLogEntry {
                endpoint: "POST /v1/zk/melt (Unified k=13 Proof)".into(),
                summary: format!(
                    "Bob melted {} sats to Lightning invoice in {}ms (liabilities decremented)",
                    inp.note.value, self.last_action_ms
                ),
                opaque_payload: serde_json::json!({
                    "anchor_root": format!("0x{}...", hex::encode(&anchor[..6])),
                    "nullifiers": nfs.iter().map(|n| format!("0x{}...", hex::encode(&n.0[..6]))).collect::<Vec<_>>(),
                    "public_ln_payout": inp.note.value,
                    "unified_proof_bytes": proof_b64.len(),
                }),
                hidden_from_mint: "Originating sender (Alice), input note index & prior history!".into(),
            },
        );
        Ok(inp.note.value)
    }

    pub fn audit(&self, tamper_fractional: bool) -> DemoAuditView {
        let mut bundle = match self.mint.solvency_bundle() {
            Ok(b) => b,
            Err(e) => {
                return DemoAuditView {
                    solvent: false,
                    epoch: 0,
                    total_liabilities: 0,
                    total_reserves: self.reserve_sats,
                    verify_ms: 0,
                    error: Some(e.to_string()),
                }
            }
        };
        if tamper_fractional {
            bundle.state.total_liabilities = self.reserve_sats + 50_000;
        }
        match verify_solvency_bundle(&bundle, &self.provider) {
            Ok(rep) => DemoAuditView {
                solvent: rep.solvent,
                epoch: rep.epoch,
                total_liabilities: rep.total_liabilities,
                total_reserves: rep.total_reserves,
                verify_ms: rep.verify_ms,
                error: None,
            },
            Err(e) => DemoAuditView {
                solvent: false,
                epoch: bundle.state.epoch,
                total_liabilities: bundle.state.total_liabilities,
                total_reserves: self.reserve_sats,
                verify_ms: 0,
                error: Some(e.to_string()),
            },
        }
    }

    pub fn state_view(&self, session_id: &str) -> DemoStateResponse {
        let info = self.mint.info();
        let to_views = |notes: &[DemoStoredNote]| -> Vec<DemoNoteView> {
            notes
                .iter()
                .map(|n| DemoNoteView {
                    value: n.note.value,
                    commitment: format!("0x{}...", hex::encode(&n.note.commitment().0[..8])),
                    leaf_index: n.leaf_index,
                    spent: n.spent,
                })
                .collect()
        };
        DemoStateResponse {
            session_id: session_id.to_string(),
            alice_balance: self.alice_notes.iter().filter(|n| !n.spent).map(|n| n.note.value).sum(),
            alice_notes: to_views(&self.alice_notes),
            bob_address: self.bob_stealth.address.encode(),
            bob_balance: self.bob_notes.iter().filter(|n| !n.spent).map(|n| n.note.value).sum(),
            bob_notes: to_views(&self.bob_notes),
            bob_pending_memos: self.pending_memos.len(),
            bob_synced_epoch: self.bob_synced_epoch,
            mint_state: info.state,
            reserve_sats: self.reserve_sats,
            last_action_ms: self.last_action_ms,
            xray_logs: self.xray_logs.iter().take(12).cloned().collect(),
            audit: self.audit(false),
        }
    }
}

/// Multi-session store for online web deployment (isolates each visitor's browser tab).
#[derive(Default)]
pub struct PlaygroundStore {
    sessions: HashMap<String, (PlaygroundSession, Instant)>,
}

impl PlaygroundStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.sessions
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) < SESSION_TTL);
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest_key) = self
                .sessions
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest_key);
            }
        }
    }

    pub fn with_session_mut<F, R>(&mut self, session_id: &str, f: F) -> R
    where
        F: FnOnce(&mut PlaygroundSession) -> R,
    {
        self.gc();
        let entry = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| (PlaygroundSession::new(), Instant::now()));
        entry.1 = Instant::now();
        f(&mut entry.0)
    }

    pub fn reset_session(&mut self, session_id: &str) -> DemoStateResponse {
        self.gc();
        let s = PlaygroundSession::new();
        let view = s.state_view(session_id);
        self.sessions
            .insert(session_id.to_string(), (s, Instant::now()));
        view
    }
}

pub type SharedPlayground = Arc<RwLock<PlaygroundStore>>;

pub fn playground_router(store: SharedPlayground) -> Router {
    Router::new()
        .route("/", get(serve_landing))
        .route("/playground", get(serve_html))
        .route("/assets/zashi-mascot.jpg", get(serve_mascot))
        .route("/assets/zashi-var-streetwear.jpg", get(serve_var_streetwear))
        .route("/assets/zashi-var-cyber.jpg", get(serve_var_cyber))
        .route("/assets/zashi-var-monk.jpg", get(serve_var_monk))
        .route("/v1/demo/state", get(demo_state))
        .route("/v1/demo/reset", post(demo_reset))
        .route("/v1/demo/mint", post(demo_mint))
        .route("/v1/demo/shield_legacy", post(demo_shield_legacy))
        .route("/v1/demo/stealth_send", post(demo_stealth_send))
        .route("/v1/demo/double_spend", post(demo_double_spend))
        .route("/v1/demo/bob_sync", post(demo_bob_sync))
        .route("/v1/demo/bob_melt", post(demo_bob_melt))
        .route("/v1/demo/audit", post(demo_audit))
        .with_state(store)
}

fn extract_session_id(headers: &HeaderMap) -> String {
    headers
        .get("x-zashu-session")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(64).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string())
}

async fn serve_landing() -> Html<&'static str> {
    Html(include_str!("landing.html"))
}

async fn serve_html() -> Html<&'static str> {
    Html(include_str!("playground.html"))
}

async fn serve_mascot() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
        include_bytes!("../../../assets/zashi-mascot.jpg").as_slice(),
    )
}

async fn serve_var_streetwear() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
        include_bytes!("../../../assets/zashi-var-streetwear.jpg").as_slice(),
    )
}

async fn serve_var_cyber() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
        include_bytes!("../../../assets/zashi-var-cyber.jpg").as_slice(),
    )
}

async fn serve_var_monk() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
        include_bytes!("../../../assets/zashi-var-monk.jpg").as_slice(),
    )
}

async fn demo_state(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
) -> Json<DemoStateResponse> {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    Json(g.with_session_mut(&sid, |sess| sess.state_view(&sid)))
}

async fn demo_reset(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
) -> Json<DemoStateResponse> {
    let sid = extract_session_id(&headers);
    Json(s.write().unwrap().reset_session(&sid))
}

#[derive(Deserialize)]
pub struct AmountReq {
    pub amount: u64,
}

#[derive(Deserialize)]
pub struct AuditReq {
    #[serde(default)]
    pub tamper_fractional: bool,
}

fn json_err(msg: String) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg })))
}

async fn demo_mint(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
    Json(req): Json<AmountReq>,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        sess.mint_arbitrary(req.amount)?;
        Ok::<_, String>(sess.state_view(&sid))
    });
    match res {
        Ok(view) => (StatusCode::OK, Json(serde_json::to_value(view).unwrap())),
        Err(e) => json_err(e),
    }
}

async fn demo_shield_legacy(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
    Json(req): Json<AmountReq>,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        sess.shield_legacy(req.amount)?;
        Ok::<_, String>(sess.state_view(&sid))
    });
    match res {
        Ok(view) => (StatusCode::OK, Json(serde_json::to_value(view).unwrap())),
        Err(e) => json_err(e),
    }
}

async fn demo_stealth_send(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
    Json(req): Json<AmountReq>,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        sess.stealth_send(req.amount)?;
        Ok::<_, String>(sess.state_view(&sid))
    });
    match res {
        Ok(view) => (StatusCode::OK, Json(serde_json::to_value(view).unwrap())),
        Err(e) => json_err(e),
    }
}

async fn demo_double_spend(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        let rejection = sess.try_double_spend()?;
        Ok::<_, String>((rejection, sess.state_view(&sid)))
    });
    match res {
        Ok((rejection, view)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "rejected": true,
                "reason": rejection,
                "state": view,
            })),
        ),
        Err(e) => json_err(e),
    }
}

async fn demo_bob_sync(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        sess.bob_sync()?;
        Ok::<_, String>(sess.state_view(&sid))
    });
    match res {
        Ok(view) => (StatusCode::OK, Json(serde_json::to_value(view).unwrap())),
        Err(e) => json_err(e),
    }
}

async fn demo_bob_melt(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    let res = g.with_session_mut(&sid, |sess| {
        sess.bob_melt()?;
        Ok::<_, String>(sess.state_view(&sid))
    });
    match res {
        Ok(view) => (StatusCode::OK, Json(serde_json::to_value(view).unwrap())),
        Err(e) => json_err(e),
    }
}

async fn demo_audit(
    State(s): State<SharedPlayground>,
    headers: HeaderMap,
    Json(req): Json<AuditReq>,
) -> Json<DemoAuditView> {
    let sid = extract_session_id(&headers);
    let mut g = s.write().unwrap();
    Json(g.with_session_mut(&sid, |sess| sess.audit(req.tamper_fractional)))
}
