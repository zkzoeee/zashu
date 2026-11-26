use serde::Deserialize;
use zashu_core::reserves::UtxoProvider;
use zashu_core::{Result, ZashuError};

/// Verifies L1 reserve UTXOs against an Esplora-compatible REST API
/// (e.g. `https://mempool.space/signet/api` or `https://mempool.space/api`).
pub struct EsploraUtxoProvider {
    base_url: String,
}

#[derive(Deserialize)]
struct OutspendResp {
    spent: bool,
}

#[derive(Deserialize)]
struct TxResp {
    vout: Vec<TxOutResp>,
}

#[derive(Deserialize)]
struct TxOutResp {
    scriptpubkey: String,
    value: u64,
}

impl EsploraUtxoProvider {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Queries Esplora asynchronously; designed to be called inside a blocking/Tokio-compatible check.
    pub async fn verify_utxo_async(
        &self,
        txid: &str,
        vout: u32,
        expected_value_sats: u64,
        expected_spk: &str,
    ) -> Result<()> {
        let client = reqwest::Client::new();

        let outspend_url = format!("{}/tx/{txid}/outspend/{vout}", self.base_url);
        let outspend: OutspendResp = client
            .get(&outspend_url)
            .send()
            .await
            .map_err(|e| ZashuError::ReservesError(format!("esplora outspend request: {e}")))?
            .error_for_status()
            .map_err(|e| ZashuError::ReservesError(format!("esplora outspend status: {e}")))?
            .json()
            .await
            .map_err(|e| ZashuError::ReservesError(format!("esplora outspend json: {e}")))?;

        if outspend.spent {
            return Err(ZashuError::ReservesError(format!(
                "UTXO {txid}:{vout} is already spent on-chain"
            )));
        }

        let tx_url = format!("{}/tx/{txid}", self.base_url);
        let tx: TxResp = client
            .get(&tx_url)
            .send()
            .await
            .map_err(|e| ZashuError::ReservesError(format!("esplora tx request: {e}")))?
            .error_for_status()
            .map_err(|e| ZashuError::ReservesError(format!("esplora tx status: {e}")))?
            .json()
            .await
            .map_err(|e| ZashuError::ReservesError(format!("esplora tx json: {e}")))?;

        let out = tx
            .vout
            .get(vout as usize)
            .ok_or_else(|| ZashuError::ReservesError(format!("vout {vout} missing in tx {txid}")))?;

        if out.value != expected_value_sats {
            return Err(ZashuError::ReservesError(format!(
                "on-chain value mismatch for {txid}:{vout}: expected {expected_value_sats}, found {}",
                out.value
            )));
        }
        if out.scriptpubkey != expected_spk {
            return Err(ZashuError::ReservesError(format!(
                "on-chain scriptPubKey mismatch for {txid}:{vout}"
            )));
        }
        Ok(())
    }
}

impl UtxoProvider for EsploraUtxoProvider {
    fn verify_utxo_unspent(
        &self,
        txid: &str,
        vout: u32,
        expected_value_sats: u64,
        expected_spk: &str,
    ) -> Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.verify_utxo_async(
                txid,
                vout,
                expected_value_sats,
                expected_spk,
            ))
        })
    }
}
