use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use zashu_mint::playground::{playground_router, PlaygroundStore};
use zashu_mint::{mint_router, MintReserveKey, SharedMintState, ZashuMint};

#[derive(Parser)]
#[command(name = "zashu-mint", about = "Unified Mode A + Mode B Zashu Mint HTTP server")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,

    #[arg(long, default_value_t = 64)]
    rolling_window: usize,

    #[arg(long, help = "32-byte hex mint secret key (defaults to deterministic dev key)")]
    mint_sk: Option<String>,

    #[arg(long, help = "32-byte hex reserve P2TR secret key (defaults to deterministic dev key)")]
    reserve_sk: Option<String>,

    #[arg(long, default_value = "0000000000000000000000000000000000000000000000000000000000000001")]
    reserve_txid: String,

    #[arg(long, default_value_t = 0)]
    reserve_vout: u32,

    #[arg(long, default_value_t = 10_000_000)]
    reserve_sats: u64,
}

fn parse_sk(hex_opt: Option<String>, fallback: u8) -> Result<SecretKey> {
    match hex_opt {
        Some(h) => {
            let bytes = hex::decode(h.trim_start_matches("0x"))?;
            Ok(SecretKey::from_slice(&bytes)?)
        }
        None => Ok(SecretKey::from_slice(&[fallback; 32])?),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    let mint_sk = parse_sk(cli.mint_sk, 0x11)?;
    let reserve_sk = parse_sk(cli.reserve_sk, 0x22)?;

    let secp = Secp256k1::new();
    let res_kp = Keypair::from_secret_key(&secp, &reserve_sk);
    let (res_xonly, _) = XOnlyPublicKey::from_keypair(&res_kp);
    let res_spk = ScriptBuf::new_p2tr(&secp, res_xonly, None);

    let mint = ZashuMint::new(
        mint_sk,
        vec![MintReserveKey {
            secret_key: reserve_sk,
            txid: cli.reserve_txid.clone(),
            vout: cli.reserve_vout,
            value_sats: cli.reserve_sats,
        }],
        cli.rolling_window,
    );

    let info = mint.info();
    tracing::info!(
        "Starting zashu-mint on http://{} | mint_id=0x{} | reserve_spk={} ({} sats)",
        cli.bind,
        hex::encode(info.mint_id),
        hex::encode(res_spk.as_bytes()),
        cli.reserve_sats
    );

    let shared: SharedMintState = Arc::new(RwLock::new(mint));
    let playground = Arc::new(RwLock::new(PlaygroundStore::new()));
    let app = mint_router(shared).merge(playground_router(playground));
    tracing::info!("Web Playground available at http://{}/", cli.bind);
    let listener = TcpListener::bind(cli.bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("zashu-mint stopped");
    Ok(())
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C, `docker stop`, Fly auto-stop), so
/// in-flight requests finish before exit. Needed when running as PID 1, where
/// the kernel ignores signals that have no handler installed.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutdown signal received, draining connections");
}
