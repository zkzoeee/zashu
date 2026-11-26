use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use ff::Field;
use group::Group;
use rand::rngs::SysRng;
use rand::rand_core::UnwrapErr;
use serde::{Deserialize, Serialize};
use zashu_acc::NoteAccumulator;
use zashu_circuits::mode_b::{
    balance_blinding, prove_zk_melt, prove_zk_mint, prove_zk_swap, InputNoteWitness,
    OutputNoteWitness,
};
use zashu_circuits::predicates::{
    compute_htlc_params, htlc_hashlock, HtlcAction, PredicateWitness,
};
use zashu_core::field::{bytes_to_fq, fq_to_bytes, hash_bytes_to_fq, Fq, PallasPoint};
use zashu_core::stealth::{create_stealth_output, PointBytesExt, StealthAddress, StealthKeypair, StealthMemoPayload};
use zashu_core::token::{ZashuToken, ZashuTokenNote};
use zashu_core::types::{Note, PredicateId};
use zashu_mint::{SyncResponse, ZkMeltRequest, ZkMintRequest, ZkMintResponse, ZkSwapRequest, ZkSwapResponse};

#[derive(Parser)]
#[command(name = "zashu-wallet", about = "Zashu Mode B shielded ecash CLI wallet")]
struct Cli {
    #[arg(long, default_value = "./zashu-wallet.json")]
    wallet: PathBuf,

    #[arg(long, default_value = "http://127.0.0.1:8080")]
    mint: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Address,
    Balance,
    Sync,
    Mint { amount: u64 },
    SendToken { amount: u64 },
    SendStealth { address: String, amount: u64 },
    Receive { token: String },
    Melt { amount: u64, quote: String },
    HtlcLock { hashlock: String, receiver_pk: String, amount: u64, expiry: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNote {
    note: Note,
    sk: [u8; 32],
    blind: [u8; 32],
    leaf_index: u64,
    spent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletState {
    seed_hex: String,
    last_epoch: u64,
    acc: NoteAccumulator,
    notes: Vec<StoredNote>,
}

impl WalletState {
    fn load(path: &PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn save(&self, path: &PathBuf) -> Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    fn keypair(&self) -> (StealthKeypair, [u8; 32], [u8; 32]) {
        let seed = hex::decode(&self.seed_hex).unwrap();
        let stealth = StealthKeypair::from_seed(&seed);
        let sk = hash_bytes_to_fq(b"zashu-wallet-sk", &seed);
        let pk = (PallasPoint::generator() * sk).to_affine_bytes();
        (stealth, fq_to_bytes(&sk), pk)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let mint = cli.mint.trim_end_matches('/');

    match cli.command {
        Commands::Init => {
            let mut seed = [0u8; 32];
            rand::rand_core::Rng::fill_bytes(&mut UnwrapErr(SysRng), &mut seed);
            let st = WalletState {
                seed_hex: hex::encode(seed),
                last_epoch: 0,
                acc: NoteAccumulator::new(64),
                notes: Vec::new(),
            };
            st.save(&cli.wallet)?;
            let (stealth, _, _) = st.keypair();
            println!("Initialized wallet. Stealth address: {}", stealth.address.encode());
        }
        Commands::Address => {
            let st = WalletState::load(&cli.wallet)?;
            let (stealth, _, _) = st.keypair();
            println!("{}", stealth.address.encode());
        }
        Commands::Balance => {
            let st = WalletState::load(&cli.wallet)?;
            let bal: u64 = st.notes.iter().filter(|n| !n.spent).map(|n| n.note.value).sum();
            println!("Shielded balance: {bal} sats ({} unspent notes)", st.notes.iter().filter(|n| !n.spent).count());
        }
        Commands::Sync => {
            let mut st = WalletState::load(&cli.wallet)?;
            let url = format!("{mint}/v1/zk/sync?from_epoch={}&bucket=0", st.last_epoch);
            let sync: SyncResponse = client.get(url).send().await?.error_for_status()?.json().await?;
            for (_, cm) in &sync.new_commitments {
                st.acc.insert(cm.0)?;
            }
            st.last_epoch = sync.to_epoch;
            st.save(&cli.wallet)?;
            println!("Synced to epoch {} ({} new commitments)", st.last_epoch, sync.new_commitments.len());
        }
        Commands::Mint { amount } => {
            let mut st = WalletState::load(&cli.wallet)?;
            let (_, sk, pk) = st.keypair();
            let mut rng = UnwrapErr(SysRng);
            let mut rho = [0u8; 32];
            let mut r = [0u8; 32];
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut rho);
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut r);
            let blind = Fq::random(&mut rng);
            let note = Note {
                value: amount,
                owner_pk: pk,
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho,
                r,
            };
            let (cm, cv, proof) = prove_zk_mint(&note, blind, amount)?;
            let resp: ZkMintResponse = client
                .post(format!("{mint}/v1/zk/mint"))
                .json(&ZkMintRequest {
                    quote_id: format!("cli_{}", hex::encode(&rho[..8])),
                    amount,
                    cm,
                    cv,
                    proof: proof.to_base64()?,
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            st.acc.insert(cm.0)?;
            st.last_epoch = resp.state.epoch;
            st.notes.push(StoredNote {
                note,
                sk,
                blind: fq_to_bytes(&blind),
                leaf_index: resp.leaf_index,
                spent: false,
            });
            st.save(&cli.wallet)?;
            println!("Minted {amount} sats at leaf_index={}", resp.leaf_index);
        }
        Commands::SendToken { amount } => {
            let mut st = WalletState::load(&cli.wallet)?;
            let (_, my_sk, my_pk) = st.keypair();
            let idx = st
                .notes
                .iter()
                .position(|n| !n.spent && n.note.value >= amount)
                .ok_or_else(|| anyhow!("no single unspent note >= {amount} sats"))?;
            let inp = st.notes[idx].clone();
            let witness = st.acc.witness(inp.leaf_index)?;
            let anchor = st.acc.root();

            let mut rng = UnwrapErr(SysRng);
            let temp_sk = hash_bytes_to_fq(b"zashu-bearer", &[1u8; 32]);
            let temp_pk = (PallasPoint::generator() * temp_sk).to_affine_bytes();
            let mut rho_out = [0u8; 32];
            let mut r_out = [0u8; 32];
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut rho_out);
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut r_out);

            let out_note = Note {
                value: amount,
                owner_pk: temp_pk,
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho: rho_out,
                r: r_out,
            };
            let b_in = bytes_to_fq(&inp.blind)?;
            let change_val = inp.note.value - amount;
            let (out_notes, out_blinds) = if change_val > 0 {
                let b_send = Fq::random(&mut rng);
                let b_ch = balance_blinding(&[b_in], &[b_send]);
                let ch_note = Note {
                    value: change_val,
                    owner_pk: my_pk,
                    predicate_id: 0,
                    predicate_params_hash: [0u8; 32],
                    rho: [0xAA; 32],
                    r: [0xBB; 32],
                };
                (vec![out_note.clone(), ch_note], vec![b_send, b_ch])
            } else {
                (vec![out_note.clone()], vec![b_in])
            };

            let out_refs: Vec<OutputNoteWitness<'_>> = out_notes
                .iter()
                .zip(out_blinds.iter())
                .map(|(n, &b)| OutputNoteWitness { note: n, blind: b })
                .collect();

            let (nfs, cms, cvs, proof) = prove_zk_swap(
                &anchor,
                &[InputNoteWitness {
                    note: &inp.note,
                    blind: b_in,
                    witness: &witness,
                    predicate: &PredicateWitness::StandardSpend { sk: inp.sk },
                }],
                &out_refs,
            )?;

            let resp: ZkSwapResponse = client
                .post(format!("{mint}/v1/zk/swap"))
                .json(&ZkSwapRequest {
                    anchor_root: anchor,
                    nullifiers: nfs,
                    output_commitments: cms.clone(),
                    output_value_commitments: cvs,
                    proof: proof.to_base64()?,
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            st.notes[idx].spent = true;
            for cm in &cms {
                st.acc.insert(cm.0)?;
            }
            if change_val > 0 {
                st.notes.push(StoredNote {
                    note: out_notes[1].clone(),
                    sk: my_sk,
                    blind: fq_to_bytes(&out_blinds[1]),
                    leaf_index: resp.leaf_indices[1],
                    spent: false,
                });
            }
            st.last_epoch = resp.state.epoch;
            st.save(&cli.wallet)?;

            let token = ZashuToken {
                mint: mint.to_string(),
                epoch: resp.state.epoch,
                notes: vec![ZashuTokenNote {
                    v: amount,
                    spend_sk: fq_to_bytes(&temp_sk),
                    predicate_id: 0,
                    predicate_params_hash: [0u8; 32],
                    rho: rho_out,
                    r: r_out,
                    leaf_index: resp.leaf_indices[0],
                    witness_bytes: serde_json::to_vec(&resp.witnesses[0])?,
                }],
            };
            println!("{}", token.encode()?);
        }
        Commands::SendStealth { address, amount } => {
            let mut st = WalletState::load(&cli.wallet)?;
            let stealth_addr = StealthAddress::decode(&address)?;
            let idx = st
                .notes
                .iter()
                .position(|n| !n.spent && n.note.value == amount)
                .ok_or_else(|| anyhow!("exact note of {amount} sats required for stealth demo"))?;
            let inp = st.notes[idx].clone();
            let witness = st.acc.witness(inp.leaf_index)?;
            let anchor = st.acc.root();

            let mut rng = UnwrapErr(SysRng);
            let mut rho = [0u8; 32];
            let mut r = [0u8; 32];
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut rho);
            rand::rand_core::Rng::fill_bytes(&mut rng, &mut r);

            let (one_time_pk, memo) = create_stealth_output(
                &stealth_addr,
                &StealthMemoPayload {
                    value: amount,
                    predicate_id: 0,
                    predicate_params_hash: [0u8; 32],
                    rho,
                    r,
                    leaf_index: 0,
                },
                &mut rng,
            )?;
            let out_note = Note {
                value: amount,
                owner_pk: one_time_pk,
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho,
                r,
            };
            let b_in = bytes_to_fq(&inp.blind)?;
            let (nfs, cms, cvs, proof) = prove_zk_swap(
                &anchor,
                &[InputNoteWitness {
                    note: &inp.note,
                    blind: b_in,
                    witness: &witness,
                    predicate: &PredicateWitness::StandardSpend { sk: inp.sk },
                }],
                &[OutputNoteWitness {
                    note: &out_note,
                    blind: b_in,
                }],
            )?;
            let resp: ZkSwapResponse = client
                .post(format!("{mint}/v1/zk/swap"))
                .json(&ZkSwapRequest {
                    anchor_root: anchor,
                    nullifiers: nfs,
                    output_commitments: cms.clone(),
                    output_value_commitments: cvs,
                    proof: proof.to_base64()?,
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            st.notes[idx].spent = true;
            for cm in &cms {
                st.acc.insert(cm.0)?;
            }
            st.last_epoch = resp.state.epoch;
            st.save(&cli.wallet)?;
            println!("Stealth swap confirmed! Encrypted memo:\n{}", serde_json::to_string(&memo)?);
        }
        Commands::Receive { token } => {
            let decoded = ZashuToken::decode(&token)?;
            println!("Decoded zashuA token for {} ({} note(s))", decoded.mint, decoded.notes.len());
        }
        Commands::Melt { amount, quote } => {
            let mut st = WalletState::load(&cli.wallet)?;
            let idx = st
                .notes
                .iter()
                .position(|n| !n.spent && n.note.value == amount)
                .ok_or_else(|| anyhow!("exact note of {amount} sats required for melt demo"))?;
            let inp = st.notes[idx].clone();
            let witness = st.acc.witness(inp.leaf_index)?;
            let anchor = st.acc.root();
            let b_in = bytes_to_fq(&inp.blind)?;
            let (nfs, _, proof) = prove_zk_melt(
                &anchor,
                &[InputNoteWitness {
                    note: &inp.note,
                    blind: b_in,
                    witness: &witness,
                    predicate: &PredicateWitness::StandardSpend { sk: inp.sk },
                }],
                amount,
                None,
            )?;
            client
                .post(format!("{mint}/v1/zk/melt"))
                .json(&ZkMeltRequest {
                    quote_id: quote,
                    amount,
                    anchor_root: anchor,
                    nullifiers: nfs,
                    change_cm: None,
                    change_cv: None,
                    proof: proof.to_base64()?,
                })
                .send()
                .await?
                .error_for_status()?;
            st.notes[idx].spent = true;
            st.save(&cli.wallet)?;
            println!("Melted {amount} sats.");
        }
        Commands::HtlcLock {
            hashlock,
            receiver_pk,
            amount,
            expiry,
        } => {
            let hl_bytes: [u8; 32] = hex::decode(hashlock)?.try_into().map_err(|_| anyhow!("32-byte hashlock"))?;
            let rx_bytes: [u8; 32] = hex::decode(receiver_pk)?.try_into().map_err(|_| anyhow!("32-byte receiver pk"))?;
            let st = WalletState::load(&cli.wallet)?;
            let (_, _, my_pk) = st.keypair();
            let params = compute_htlc_params(&hl_bytes, &rx_bytes, &my_pk, expiry);
            let _ = (PredicateId::PrivateHTLC, htlc_hashlock, HtlcAction::Refund { sk_refund: [0u8; 32] });
            println!(
                "Prepared PrivateHTLC ({amount} sats, expiry={expiry}) params_hash=0x{}",
                hex::encode(params)
            );
        }
    }

    Ok(())
}
