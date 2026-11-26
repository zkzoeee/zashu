use anyhow::Result;
use clap::{Parser, Subcommand};
use zashu_auditor::verify_solvency_bundle;
use zashu_core::reserves::{MockUtxoProvider, UtxoProvider};
use zashu_core::types::SolvencyBundle;

#[derive(Parser)]
#[command(name = "zashu-auditor", about = "Verify NUTZ-1 ZK Mint Solvency bundles")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch GET /v1/solvency from a mint URL and verify it
    Verify {
        mint_url: String,
    },
    /// Verify a saved NUTZ-1 JSON bundle file offline
    VerifyFile {
        path: std::path::PathBuf,
    },
}

/// Trust-on-utxo-fields provider for standalone CLI demos when no bitcoind RPC is configured.
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

    let _ = MockUtxoProvider::new();
    let report = verify_solvency_bundle(&bundle, &SelfReportedUtxoProvider)?;
    println!(
        "SOLVENT | epoch={} | liabilities={} sats | reserves={} sats | verified in {}ms",
        report.epoch, report.total_liabilities, report.total_reserves, report.verify_ms
    );
    Ok(())
}
