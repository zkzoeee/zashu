use std::sync::{Arc, RwLock};

use axum::body::Body;
use http::{Request, StatusCode};
use tower::ServiceExt;
use zashu_mint::playground::{playground_router, PlaygroundStore};

#[tokio::test]
async fn playground_html_and_multi_session_flow_e2e() {
    let store = Arc::new(RwLock::new(PlaygroundStore::new()));
    let app = playground_router(store);

    // 1. GET / serves landing page, GET /playground serves playground HTML, GET /assets/zashi-mascot.jpg serves mascot
    let landing_resp = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(landing_resp.status(), StatusCode::OK);
    let landing_html = String::from_utf8(
        axum::body::to_bytes(landing_resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(landing_html.contains("Cashu + Zashu: Better Together"));

    let html_resp = app
        .clone()
        .oneshot(Request::builder().uri("/playground").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(html_resp.status(), StatusCode::OK);
    let html_bytes = axum::body::to_bytes(html_resp.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(html_bytes.to_vec()).unwrap();
    assert!(html.contains("ZK-Cashu Glass-Box Playground"));
    assert!(html.contains("/assets/zashi-mascot.jpg"));
    assert!(html.contains("X-Zashu-Session"));

    let img_resp = app
        .clone()
        .oneshot(Request::builder().uri("/assets/zashi-mascot.jpg").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(img_resp.status(), StatusCode::OK);

    // 2. Alice in session "tab-a" mints 137 sats
    let mint_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/mint")
                .header("content-type", "application/json")
                .header("x-zashu-session", "tab-a")
                .body(Body::from(r#"{"amount":137}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mint_resp.status(), StatusCode::OK);

    // Verify session isolation: "tab-b" still has 0 balance
    let tab_b_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/demo/state")
                .header("x-zashu-session", "tab-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let tab_b_st: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(tab_b_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(tab_b_st["alice_balance"], 0);

    // 3. Alice in "tab-a" stealth sends 37 sats to offline Bob
    let send_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/stealth_send")
                .header("content-type", "application/json")
                .header("x-zashu-session", "tab-a")
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

    // 4. Double-spend blocked
    let ds_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/double_spend")
                .header("x-zashu-session", "tab-a")
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

    // 5. Bob syncs
    let bob_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/bob_sync")
                .header("x-zashu-session", "tab-a")
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

    // 6. Evil Mint fractional reserve fails
    let evil_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/audit")
                .header("content-type", "application/json")
                .header("x-zashu-session", "tab-a")
                .body(Body::from(r#"{"tamper_fractional":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let evil_val: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(evil_resp.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(evil_val["solvent"], false);
}
