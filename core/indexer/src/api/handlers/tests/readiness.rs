use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use serde_json::json;
use tokio::sync::watch;
use tower::ServiceExt;

use super::new_test_env;
use crate::api::handlers::{get_healthz_live, get_healthz_ready};
use crate::bitcoin_client::{Client, observation::ChainObservation};
use crate::info::InfoCore;
use crate::stopper::Shutdown;

async fn ready(app: &Router) -> Result<StatusCode> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz/ready")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok(response.status())
}

#[tokio::test]
async fn readiness_tracks_replay_without_adding_rpc_calls() -> Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let rpc = Router::new().route(
        "/",
        post({
            let calls = calls.clone();
            let fail = fail.clone();
            move || {
                let calls = calls.clone();
                let fail = fail.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    Json(if fail.load(Ordering::Relaxed) {
                        json!({"result":null,"error":{"code":-1,"message":"unavailable"},"id":"0"})
                    } else {
                        json!({"result":{"chain":"regtest","blocks":100,"headers":100,
                        "difficulty":1.0,"mediantime":0,"verificationprogress":1.0,
                        "initialblockdownload":false,"size_on_disk":0,"pruned":false},
                        "error":null,"id":"0"})
                    })
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let rpc_server = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });
    scopeguard::defer! { rpc_server.abort(); }

    let (mut env, _conn, _dir) = new_test_env().await?;
    let client = Client::new(format!("http://{address}"), "test".into(), "test".into())?;
    env.bitcoin = client.clone();
    let (info_tx, info_rx) = watch::channel(InfoCore::default());
    env.info_rx = info_rx;
    let shutdown = Shutdown::new();
    env.shutdown = shutdown.signal();
    let app = Router::new()
        .route("/healthz/ready", get(get_healthz_ready))
        .route("/healthz/live", get(get_healthz_live))
        .with_state(env.clone());

    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    info_tx.send(InfoCore {
        height: Some(1),
        ..InfoCore::default()
    })?;
    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "warm DB is not a backend observation"
    );

    // The follower and HTTP handler hold different clones of this same client.
    client.clone().get_blockchain_info().await?;
    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    info_tx.send(InfoCore {
        height: Some(99),
        ..InfoCore::default()
    })?;
    env.reactor_ready.store(false, Ordering::Relaxed);
    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    env.reactor_ready.store(true, Ordering::Relaxed);
    for _ in 0..20 {
        assert_eq!(ready(&app).await?, StatusCode::OK);
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "health checks must not send RPCs"
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz/ready")
                .body(Body::empty())?,
        )
        .await?;
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["height"], json!(99));
    assert_eq!(body["bitcoin_height"], json!(100));
    assert_eq!(body["bitcoin_synced"], json!(true));

    let last_success = client.chain_observation().unwrap();
    fail.store(true, Ordering::Relaxed);
    assert!(client.get_blockchain_info().await.is_err());
    assert_eq!(
        client.chain_observation().unwrap().observed_at,
        last_success.observed_at
    );
    assert_eq!(
        ready(&app).await?,
        StatusCode::OK,
        "brief backend errors have bounded tolerance"
    );
    client.set_chain_observation_for_test(ChainObservation {
        observed_at: Instant::now() - Duration::from_secs(31),
        ..last_success
    });
    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    fail.store(false, Ordering::Relaxed);
    client.get_blockchain_info().await?;
    assert_eq!(ready(&app).await?, StatusCode::OK);

    shutdown.cancel();
    assert_eq!(ready(&app).await?, StatusCode::SERVICE_UNAVAILABLE);
    let live = app
        .oneshot(
            Request::builder()
                .uri("/healthz/live")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        live.status(),
        StatusCode::OK,
        "readiness must not restart healthy replay"
    );
    Ok(())
}
