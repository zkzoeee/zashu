use std::collections::HashMap;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;

use crate::error::{Result, ZashuError};
use crate::types::{MintState, ReserveUtxo, ReservesAttestation};

pub trait UtxoProvider: Send + Sync {
    fn verify_utxo_unspent(&self, txid: &str, vout: u32, expected_value_sats: u64, expected_spk: &str) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct MockUtxoProvider {
    utxos: HashMap<(String, u32), (u64, String)>,
}

impl MockUtxoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, txid: impl Into<String>, vout: u32, value_sats: u64, spk: impl Into<String>) {
        self.utxos.insert((txid.into(), vout), (value_sats, spk.into()));
    }
}

impl UtxoProvider for MockUtxoProvider {
    fn verify_utxo_unspent(&self, txid: &str, vout: u32, expected_value_sats: u64, expected_spk: &str) -> Result<()> {
        let Some((val, spk)) = self.utxos.get(&(txid.to_string(), vout)) else {
            return Err(ZashuError::ReservesError(format!("UTXO {txid}:{vout} not found or spent")));
        };
        if *val != expected_value_sats {
            return Err(ZashuError::ReservesError(format!(
                "UTXO {txid}:{vout} value mismatch: expected {expected_value_sats}, found {val}"
            )));
        }
        if spk != expected_spk {
            return Err(ZashuError::ReservesError(format!(
                "UTXO {txid}:{vout} scriptPubKey mismatch"
            )));
        }
        Ok(())
    }
}

pub fn compute_reserves_challenge(mint_id: &[u8; 32], state: &MintState) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    use bitcoin::hashes::HashEngine;
    engine.input(b"zashu-reserves-v1");
    engine.input(mint_id);
    engine.input(&state.epoch.to_le_bytes());
    engine.input(&state.state_hash());
    sha256::Hash::from_engine(engine).to_byte_array()
}

pub fn sign_taproot_reserve_utxo(
    secret_key: &SecretKey,
    txid: impl Into<String>,
    vout: u32,
    value_sats: u64,
    challenge: &[u8; 32],
) -> ReserveUtxo {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret_key);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let spk = ScriptBuf::new_p2tr(&secp, xonly, None);
    let tweaked_keypair = keypair.tap_tweak(&secp, None).to_keypair();
    let msg = Message::from_digest(*challenge);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_keypair);

    ReserveUtxo {
        txid: txid.into(),
        vout,
        value_sats,
        script_pubkey: hex::encode(spk.as_bytes()),
        signature: hex::encode(sig.serialize()),
    }
}

pub fn verify_reserves_attestation(
    mint_id: &[u8; 32],
    state: &MintState,
    attestation: &ReservesAttestation,
    utxo_provider: &dyn UtxoProvider,
) -> Result<u64> {
    let expected_challenge = compute_reserves_challenge(mint_id, state);
    if attestation.challenge != expected_challenge {
        return Err(ZashuError::ReservesError("reserves challenge mismatch".into()));
    }

    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(expected_challenge);
    let mut total_reserves = 0u64;
    let mut seen = std::collections::HashSet::new();

    for utxo in &attestation.utxos {
        if !seen.insert((utxo.txid.clone(), utxo.vout)) {
            return Err(ZashuError::ReservesError("duplicate reserve UTXO".into()));
        }
        utxo_provider.verify_utxo_unspent(&utxo.txid, utxo.vout, utxo.value_sats, &utxo.script_pubkey)?;

        let spk_bytes = hex::decode(&utxo.script_pubkey)?;
        let spk = ScriptBuf::from_bytes(spk_bytes);
        if !spk.is_p2tr() || spk.len() != 34 {
            return Err(ZashuError::ReservesError("expected P2TR scriptPubKey for reserve UTXO".into()));
        }
        let xonly = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34])
            .map_err(|e| ZashuError::ReservesError(format!("invalid P2TR x-only key: {e}")))?;

        let sig_bytes = hex::decode(&utxo.signature)?;
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| ZashuError::ReservesError(format!("invalid schnorr sig: {e}")))?;

        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| ZashuError::ReservesError(format!("schnorr verification failed: {e}")))?;

        total_reserves = total_reserves
            .checked_add(utxo.value_sats)
            .ok_or_else(|| ZashuError::ReservesError("reserves u64 overflow".into()))?;
    }

    if total_reserves < state.total_liabilities {
        return Err(ZashuError::ReservesError(format!(
            "fractional reserve detected: reserves ({total_reserves}) < liabilities ({})",
            state.total_liabilities
        )));
    }

    Ok(total_reserves)
}
