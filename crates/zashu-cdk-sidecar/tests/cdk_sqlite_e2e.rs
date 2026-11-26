use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use zashu_auditor::verify_solvency_bundle;
use zashu_cdk_sidecar::{
    CdkSqliteEventSource, EpochFolder, MintEvent, MintEventSource, ReserveConfig,
};
use zashu_core::reserves::MockUtxoProvider;

#[test]
fn cdk_sqlite_sidecar_persists_and_audits_across_epochs() {
    let db_path = std::env::temp_dir().join(format!(
        "zashu_cdk_test_{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&db_path);

    let secp = Secp256k1::new();
    let mint_sk = SecretKey::from_slice(&[0x44u8; 32]).unwrap();
    let res_sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
    let res_kp = Keypair::from_secret_key(&secp, &res_sk);
    let (res_xonly, _) = XOnlyPublicKey::from_keypair(&res_kp);
    let res_spk = ScriptBuf::new_p2tr(&secp, res_xonly, None);

    let mut provider = MockUtxoProvider::new();
    provider.insert("deadbeef".repeat(8), 0, 200_000, hex::encode(res_spk.as_bytes()));

    let source = CdkSqliteEventSource::new(&db_path).unwrap();
    source
        .append_event(&MintEvent::Mint {
            amount: 50_000,
            quote_hash: [1u8; 32],
        })
        .unwrap();
    source
        .append_event(&MintEvent::Swap {
            input_nullifiers: vec![[2u8; 32]],
            sum_in: 10_000,
            sum_out: 10_000,
        })
        .unwrap();

    let mut folder = EpochFolder::new(
        mint_sk,
        vec![ReserveConfig {
            secret_key: res_sk,
            txid: "deadbeef".repeat(8),
            vout: 0,
            value_sats: 200_000,
        }],
    );

    let ev1 = source.drain_pending_events().unwrap();
    assert_eq!(ev1.len(), 2);
    let b1 = folder.seal_epoch(&ev1).unwrap();
    assert!(verify_solvency_bundle(&b1, &provider).unwrap().solvent);

    // Second epoch appended to SQLite
    source
        .append_event(&MintEvent::Melt {
            input_nullifiers: vec![[3u8; 32]],
            amount: 15_000,
            payout_hash: [4u8; 32],
        })
        .unwrap();
    let ev2 = source.drain_pending_events().unwrap();
    assert_eq!(ev2.len(), 1);
    let b2 = folder.seal_epoch(&ev2).unwrap();
    assert_eq!(b2.state.total_liabilities, 35_000);
    assert!(verify_solvency_bundle(&b2, &provider).unwrap().solvent);

    let _ = std::fs::remove_file(&db_path);
}
