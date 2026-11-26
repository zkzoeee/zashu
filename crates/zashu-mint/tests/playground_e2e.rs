use std::sync::{Arc, RwLock};

use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt;
use zashu_mint::playground::{playground_router, PlaygroundSession};

#[tokio::test]
async fn playground_html_and_full_flow_e2e() {
    let session = Arc::new(RwLock::new(PlaygroundSession::new()));
    let app = playground_router(session);

    // 1. GET / serves playground HTML
    let html_resp = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(html_resp.status(), StatusCode::OK);
    let html_bytes = axum::body::to_bytes(html_resp.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(html_bytes.to_vec()).unwrap();
    assert!(html.contains("ZK-Cashu Glass-Box Playground"));

    // 2. Alice mints 137 sats (arbitrary note)
    let mint_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/mint")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"amount":137}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::OK);

    // 3. Alice stealth sends 37 sats to offline Bob (unified k=13 single proof)
    let send_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/stealth_send")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"amount":37}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(send_resp.status(), StatusCode::OK);
    let st: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(send_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(st["alice_balance"], 100);
    assert_eq!(st["bob_pending_memos"], 1);
    assert_eq!(st["audit"]["solvent"], true);

    // 4. Alice attempts double-spend -> blocked
    let ds_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/double_spend")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ds_resp.status(), StatusCode::OK);
    let ds_val: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(ds_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(ds_val["rejected"], true);

    // 5. Bob comes online & oblivious syncs
    let bob_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/bob_sync")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_resp.status(), StatusCode::OK);
    let bob_st: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(bob_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(bob_st["bob_balance"], 37);

    // 6. Evil Mint fractional reserve simulation fails audit
    let evil_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/audit")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"tamper_fractional":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evil_resp.status(), StatusCode::OK);
    let evil_val: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(evil_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(evil_val["solvent"], false);
}
