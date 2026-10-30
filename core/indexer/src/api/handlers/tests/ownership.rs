use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Result, anyhow};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use indexer_types::{ViewExpr, ViewResult};
use tempfile::TempDir;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;
use tower::ServiceExt;

use super::{insert_block_at, new_test_env};
use crate::api::Env;
use crate::api::handlers::get_healthz_ready;
use crate::api::handlers::post_contract;
use crate::info::InfoCore;
use crate::runtime::ownership::RootOutcome;
use crate::runtime::{BlockingGate, ComponentCache, Runtime, Storage, token};
use crate::test_utils::test_genesis;

async fn seeded_contract_env() -> Result<(Env, String, TempDir)> {
    let (env, conn, dir) = new_test_env().await?;
    insert_block_at(
        &conn,
        0,
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .await?;
    let storage = Storage::builder().height(0).conn(conn).build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.publish_native_contracts(&test_genesis(&[])).await?;
    let direct = runtime
        .execute(None, None, &token::address(), "total-supply()")
        .await?;
    Ok((env, direct, dir))
}

fn owned_route(env: Env, started: Arc<Notify>) -> Router {
    Router::new()
        .route(
            "/owned",
            get(move |State(env): State<Env>| {
                let started = started.clone();
                async move {
                    let object = env
                        .runtime_pool
                        .get()
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    let mut root = env
                        .owner_service
                        .start_pooled(object, move |_| {
                            Box::pin(async move {
                                started.notify_one();
                                pending::<()>().await;
                                Ok(RootOutcome {
                                    value: (),
                                    commit: false,
                                })
                            })
                        })
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    root.result()
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    Ok::<_, StatusCode>(StatusCode::OK)
                }
            }),
        )
        .with_state(env)
}

#[tokio::test]
async fn dropped_http_request_releases_its_root_after_supervision() -> Result<()> {
    let (env, _conn, _dir) = new_test_env().await?;
    let service = env.owner_service.clone();
    let pool = env.runtime_pool.clone();
    let started = Arc::new(Notify::new());
    let observed = started.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let app = owned_route(env, started.clone());
    let request = Request::builder().uri("/owned").body(Body::empty())?;
    let http = tokio::spawn(async move { app.oneshot(request).await });
    timeout(Duration::from_secs(2), observed).await?;
    http.abort();
    let _ = http.await;
    timeout(Duration::from_secs(2), async {
        while service.active_roots().await != 0 || pool.status().available != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(pool.status().available, 1);
    Ok(())
}

#[tokio::test]
async fn owner_shutdown_waits_for_cancelled_http_root() -> Result<()> {
    let (env, _conn, _dir) = new_test_env().await?;
    let service = env.owner_service.clone();
    let driver = service.take_driver().expect("test owner has a driver");
    let started = Arc::new(Notify::new());
    let observed = started.notified();
    tokio::pin!(observed);
    observed.as_mut().enable();
    let app = owned_route(env, started.clone());
    let request = Request::builder().uri("/owned").body(Body::empty())?;
    let http = tokio::spawn(async move { app.oneshot(request).await });
    timeout(Duration::from_secs(2), observed).await?;
    service.shutdown();
    http.abort();
    let _ = http.await;
    timeout(Duration::from_secs(2), driver).await???;
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}

#[tokio::test]
async fn post_contract_matches_direct_view_and_reuses_pool_object() -> Result<()> {
    let (env, direct, _dir) = seeded_contract_env().await?;
    for _ in 0..2 {
        let response = post_contract(
            Path(token::address().to_string()),
            State(env.clone()),
            Json(ViewExpr {
                expr: "total-supply()".to_string(),
            }),
        )
        .await
        .map_err(|_| anyhow!("post_contract rejected a published native view"))?;
        assert_eq!(
            response.0.0.result,
            ViewResult::Ok {
                value: direct.clone()
            }
        );
        assert_eq!(env.owner_service.active_roots().await, 0);
        assert_eq!(env.runtime_pool.status().available, 1);
    }
    Ok(())
}

#[tokio::test]
async fn post_contract_shutdown_waits_for_cold_decode_before_pool_release() -> Result<()> {
    let (env, _direct, _dir) = seeded_contract_env().await?;
    let gate = Arc::new(BlockingGate::default());
    let mut object = env.runtime_pool.get().await?;
    object.storage.decode_gate = Some(gate.clone());
    drop(object);
    let pool = env.runtime_pool.clone();
    let service = env.owner_service.clone();
    let mut driver = service.take_driver().expect("test owner has a driver");
    let app = Router::new()
        .route("/view/{address}", post(post_contract))
        .with_state(env);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/view/{}", token::address()))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"expr":"total-supply()"}"#))?;
    let http = tokio::spawn(async move { app.oneshot(request).await });
    let entered = timeout(Duration::from_secs(30), async {
        while !gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    service.shutdown();
    http.abort();
    let _ = http.await;
    let retained = timeout(Duration::from_millis(100), &mut driver)
        .await
        .is_err();
    gate.release();
    entered?;
    assert!(
        retained,
        "HTTP shutdown completed while decode worker was live"
    );
    timeout(Duration::from_secs(5), driver).await???;
    assert_eq!(service.active_roots().await, 0);
    assert_eq!(pool.status().available, 1);
    Ok(())
}

#[tokio::test]
async fn fatal_owner_withdraws_http_readiness() -> Result<()> {
    let (mut env, _conn, _dir) = new_test_env().await?;
    env.reactor_ready.store(true, Ordering::Relaxed);
    let (_info_tx, info_rx) = watch::channel(InfoCore {
        height: Some(1),
        ..InfoCore::default()
    });
    env.info_rx = info_rx;
    let app = Router::new()
        .route("/healthz/ready", get(get_healthz_ready))
        .with_state(env.clone());
    let request = Request::builder()
        .uri("/healthz/ready")
        .body(Body::empty())?;
    assert_eq!(app.clone().oneshot(request).await?.status(), StatusCode::OK);

    let driver = env
        .owner_service
        .take_driver()
        .expect("test owner has a driver");
    env.owner_service.fail_driver_for_test().await?;
    assert!(timeout(Duration::from_secs(2), driver).await??.is_err());
    assert!(env.owner_service.is_fatal());
    let request = Request::builder()
        .uri("/healthz/ready")
        .body(Body::empty())?;
    assert_eq!(
        app.oneshot(request).await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
