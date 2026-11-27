use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use zashu_auditor::esplora::EsploraUtxoProvider;
use zashu_auditor::verify_solvency_bundle;
use zashu_core::reserves::UtxoProvider;
use zashu_core::types::SolvencyBundle;

#[derive(Parser)]
#[command(name = "zashu-auditor", about = "Verify NUTZ-1 ZK Mint Solvency bundles")]
struct Cli {
    #[arg(
        long,
        help = "Esplora API URL (e.g. https://mempool.space/signet/api) to verify reserve UTXOs on-chain"
    )]
    esplora: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Allow auditing without on-chain UTXO verification (dev/mock mode only)"
    )]
    allow_unverified_utxos: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch GET /v1/solvency from a mint URL and verify it
    Verify { mint_url: String },
    /// Verify a saved NUTZ-1 JSON bundle file offline
    VerifyFile { path: std::path::PathBuf },
}

struct SelfReportedUtxoProvider;
impl UtxoProvider for SelfReportedUtxoProvider {
    fn verify_utxo_unspent(&self, _txid: &str, _vout: u32, _val: u64, _spk: &str) -> zashu_core::Result<()> {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bundle: SolvencyBundle = match cli.command {
        Commands::Verify { mint_url } => {
            let url = format!("{}/v1/solvency", mint_url.trim_end_matches('/'));
            reqwest::get(url).await?.error_for_status()?.json().await?
        }
        Commands::VerifyFile { path } => {
            let raw = std::fs::read_to_string(path)?;
            serde_json::from_str(&raw)?
        }
    };

    let report = if let Some(esplora_url) = cli.esplora {
        let provider = EsploraUtxoProvider::new(esplora_url);
        verify_solvency_bundle(&bundle, &provider)?
    } else if cli.allow_unverified_utxos {
        verify_solvency_bundle(&bundle, &SelfReportedUtxoProvider)?
    } else {
        bail!("must provide --esplora <URL> for on-chain UTXO verification, or pass --allow-unverified-utxos for local dev");
    };

    println!(
        "SOLVENT | epoch={} | liabilities={} sats | reserves={} sats | verified in {}ms | proof={} | steps proven={} | roots bound={} | unbound ops={}",
        report.epoch,
        report.total_liabilities,
        report.total_reserves,
        report.verify_ms,
        report.fold_proof,
        report.steps_proven,
        report.roots_bound,
        match (report.unbound_ops, report.ops) {
            (Some(u), Some(n)) => format!("{u}/{n}"),
            _ => "n/a".to_string(),
        }
    );
    Ok(())
}
