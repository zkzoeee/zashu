use std::sync::Arc;

use axum::body::Body;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use http::{Request, StatusCode};
use tower::ServiceExt;
use zashu_auditor::verify_solvency_bundle;
use zashu_cdk_sidecar::{
    sidecar_router, EpochFolder, InMemoryEventSource, MintEvent, MintEventSource, ReserveConfig,
    SharedSidecarState,
};
use zashu_core::reserves::MockUtxoProvider;
use zashu_core::types::SolvencyBundle;

#[tokio::test]
async fn mode_a_e2e_http_and_tamper_rejection() {
    let secp = Secp256k1::new();
    let mint_sk = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
    let reserve_sk = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
    let reserve_kp = Keypair::from_secret_key(&secp, &reserve_sk);
    let (reserve_xonly, _) = XOnlyPublicKey::from_keypair(&reserve_kp);
    let reserve_spk = ScriptBuf::new_p2tr(&secp, reserve_xonly, None);
    let _ = reserve_kp.tap_tweak(&secp, None);

    let mut utxo_provider = MockUtxoProvider::new();
    utxo_provider.insert(
        "abcd".repeat(16),
        0,
        500_000,
        hex::encode(reserve_spk.as_bytes()),
    );

    let reserves = vec![ReserveConfig {
        secret_key: reserve_sk,
        txid: "abcd".repeat(16),
        vout: 0,
        value_sats: 500_000,
    }];

    let mut folder = EpochFolder::new(mint_sk, reserves);
    let source = InMemoryEventSource::new();

    for i in 1u64..=5 {
        source.push(MintEvent::Mint {
            amount: 10_000 * i,
            quote_hash: [i as u8; 32],
        });
    }
    source.push(MintEvent::Swap {
        input_nullifiers: vec![[0xA1u8; 32], [0xA2u8; 32]],
        sum_in: 5_000,
        sum_out: 5_000,
    });
    source.push(MintEvent::Melt {
        input_nullifiers: vec![[0xB1u8; 32]],
        amount: 20_000,
        payout_hash: [0xC1u8; 32],
    });

    let events = source.drain_pending_events().unwrap();
    let valid_bundle = folder.seal_epoch(&events).unwrap();
    assert_eq!(valid_bundle.state.total_liabilities, 130_000);

    // Double-spend secret rejection
    assert!(folder
        .seal_epoch(&[MintEvent::Swap {
            input_nullifiers: vec![[0xA1u8; 32]],
            sum_in: 1_000,
            sum_out: 1_000,
        }])
        .is_err());

    let shared: SharedSidecarState = Arc::new(std::sync::RwLock::new(folder));
    let app = sidecar_router(shared);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/solvency")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let fetched: SolvencyBundle = serde_json::from_slice(&body_bytes).unwrap();

    let report = verify_solvency_bundle(&fetched, &utxo_provider).unwrap();
    assert!(report.solvent);
    assert_eq!(report.total_liabilities, 130_000);
    assert_eq!(report.total_reserves, 500_000);

    // Tamper 1: Under-reported liability
    let mut t1 = fetched.clone();
    t1.state.total_liabilities = 10_000;
    assert!(verify_solvency_bundle(&t1, &utxo_provider).is_err());

    // Tamper 2: Tampered proof bytes
    let mut t2 = fetched.clone();
    t2.pcd_proof = "invalid_base64_proof".into();
    assert!(verify_solvency_bundle(&t2, &utxo_provider).is_err());

    // Tamper 3: Insufficient L1 reserves (fractional reserve)
    let mut low_provider = MockUtxoProvider::new();
    low_provider.insert(
        "abcd".repeat(16),
        0,
        10_000,
        hex::encode(reserve_spk.as_bytes()),
    );
    assert!(verify_solvency_bundle(&fetched, &low_provider).is_err());
}
