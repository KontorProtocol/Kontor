//! Tests for `GET /api/` — the long-poll info endpoint — and the
//! `run_info_publisher` task that keeps its snapshot fresh.

use std::time::{Duration, Instant};

use anyhow::Result;
use axum::http::StatusCode;
use axum::{Router, routing::get};
use axum_test::TestServer;
use indexer_types::{Event, Info};
use tempfile::TempDir;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

use super::get_index;
use super::tests::{ApiResult, insert_block_at, new_test_env};
use crate::info::{InfoCore, compute_info_core, run_info_publisher};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// A `GET /api/` test server whose `InfoCore` snapshot is driven by the
/// returned `watch::Sender` — the test plays the role of the publisher.
async fn info_test_server(
    initial: InfoCore,
) -> Result<(TestServer, watch::Sender<InfoCore>, TempDir)> {
    let (mut env, _conn, dir) = new_test_env().await?;
    let (info_tx, info_rx) = watch::channel(initial);
    env.info_rx = info_rx;
    let app = Router::new().route("/", get(get_index)).with_state(env);
    Ok((TestServer::new(app), info_tx, dir))
}

fn core_with_signature(signature: &str, height: i64) -> InfoCore {
    InfoCore {
        height,
        signature: signature.to_string(),
        ..Default::default()
    }
}

/// `compute_info_core`'s signature moves whenever the chain advances, and
/// is deterministic for a fixed state.
#[tokio::test]
async fn info_signature_tracks_chain_state() -> Result<()> {
    let (_env, conn, _dir) = new_test_env().await?;

    let empty = compute_info_core(&conn, -1).await?.signature;

    insert_block_at(&conn, 0, ZERO_HASH).await?;
    let one_block = compute_info_core(&conn, -1).await?.signature;
    assert_ne!(empty, one_block, "signature must change when a block lands");

    insert_block_at(&conn, 1, ONE_HASH).await?;
    let two_blocks = compute_info_core(&conn, -1).await?.signature;
    assert_ne!(one_block, two_blocks, "signature must change on a new block");

    let recomputed = compute_info_core(&conn, -1).await?.signature;
    assert_eq!(two_blocks, recomputed, "signature must be deterministic");
    Ok(())
}

/// A plain `GET /api/` (no query params) returns the current snapshot
/// immediately.
#[tokio::test]
async fn get_index_plain_returns_immediately() -> Result<()> {
    let (server, _tx, _dir) = info_test_server(core_with_signature("sig-a", 5)).await?;

    let start = Instant::now();
    let resp = server.get("/").await;

    assert_eq!(resp.status_code(), StatusCode::OK);
    assert!(start.elapsed() < Duration::from_secs(1));
    let body: ApiResult<Info> = serde_json::from_slice(resp.as_bytes())?;
    assert_eq!(body.result.signature, "sig-a");
    assert_eq!(body.result.height, 5);
    Ok(())
}

/// Long-poll with a `since` that no longer matches returns at once — the
/// caller has already missed an update.
#[tokio::test]
async fn get_index_longpoll_stale_since_returns_now() -> Result<()> {
    let (server, _tx, _dir) = info_test_server(core_with_signature("sig-current", 9)).await?;

    let start = Instant::now();
    let resp = server.get("/?wait=10000&since=sig-stale").await;

    assert_eq!(resp.status_code(), StatusCode::OK);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "stale since must not block"
    );
    let body: ApiResult<Info> = serde_json::from_slice(resp.as_bytes())?;
    assert_eq!(body.result.signature, "sig-current");
    Ok(())
}

/// Long-poll with a current `since` blocks, then wakes as soon as a new
/// snapshot is published — well before the timeout.
#[tokio::test]
async fn get_index_longpoll_wakes_on_publish() -> Result<()> {
    let (server, tx, _dir) = info_test_server(core_with_signature("sig-1", 1)).await?;

    let publisher = {
        let tx = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.send(core_with_signature("sig-2", 2)).unwrap();
        })
    };

    let start = Instant::now();
    let resp = server.get("/?wait=5000&since=sig-1").await;
    let elapsed = start.elapsed();
    publisher.await?;

    assert_eq!(resp.status_code(), StatusCode::OK);
    assert!(
        elapsed >= Duration::from_millis(90),
        "must actually block until the publish"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "must wake on publish, not wait the full timeout"
    );
    let body: ApiResult<Info> = serde_json::from_slice(resp.as_bytes())?;
    assert_eq!(body.result.signature, "sig-2");
    assert_eq!(body.result.height, 2);
    Ok(())
}

/// Long-poll with a current `since` and no publish returns after `wait`
/// ms with the unchanged snapshot.
#[tokio::test]
async fn get_index_longpoll_times_out() -> Result<()> {
    let (server, _tx, _dir) = info_test_server(core_with_signature("sig-stable", 4)).await?;

    let start = Instant::now();
    let resp = server.get("/?wait=300&since=sig-stable").await;
    let elapsed = start.elapsed();

    assert_eq!(resp.status_code(), StatusCode::OK);
    assert!(
        elapsed >= Duration::from_millis(280),
        "must block for ~wait ms"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "must return shortly after the timeout"
    );
    let body: ApiResult<Info> = serde_json::from_slice(resp.as_bytes())?;
    assert_eq!(body.result.signature, "sig-stable");
    Ok(())
}

/// `run_info_publisher` recomputes `InfoCore` from the database and
/// republishes it on the `watch` channel when an `Event` arrives.
#[tokio::test]
async fn info_publisher_republishes_on_event() -> Result<()> {
    let (env, conn, _dir) = new_test_env().await?;
    insert_block_at(&conn, 0, ZERO_HASH).await?;
    insert_block_at(&conn, 7, ONE_HASH).await?;

    let (info_tx, mut info_rx) = watch::channel(InfoCore::default());
    let (event_tx, event_rx) = broadcast::channel(16);
    let cancel = CancellationToken::new();
    let handle = run_info_publisher(cancel.clone(), event_rx, env.reader.clone(), 1, info_tx);

    event_tx.send(Event::BatchProcessed { txids: vec![] })?;
    info_rx.changed().await?;

    let core = info_rx.borrow_and_update().clone();
    assert_eq!(core.height, 7, "publisher must recompute from current DB state");
    assert_eq!(core.recent_blocks.len(), 2);

    cancel.cancel();
    handle.await?;
    Ok(())
}
