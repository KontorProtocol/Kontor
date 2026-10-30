use std::ffi::OsString;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use axum::extract::{Path as RequestPath, State};
use axum::routing::post;
use axum::{Json, Router, serve};
use deadpool::managed::Pool;
use futures_util::FutureExt;
use indexer_types::{ContractAddress, ViewExpr, ViewResult};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::super::clock::monotonic_ns;
use super::{CLIENTS, CounterProgress, MixedConfig, PAGE_SAMPLES, pagination};
use crate::api::Env;
use crate::api::handlers::post_contract;
use crate::api::result::Result as ApiResult;
use crate::database::Reader;
use crate::runtime::pool::Manager;

#[derive(Clone)]
struct ViewState {
    env: Env,
    pages: String,
    writing: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

struct ActivePage(Arc<AtomicUsize>);

impl Drop for ActivePage {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn view(
    RequestPath(address): RequestPath<String>,
    State(state): State<ViewState>,
    expression: Json<ViewExpr>,
) -> ApiResult<ViewResult> {
    let _active = (address == state.pages).then(|| {
        let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
        if state.writing.load(Ordering::SeqCst) {
            state.peak.fetch_max(active, Ordering::SeqCst);
        }
        ActivePage(state.active.clone())
    });
    post_contract(RequestPath(address), State(state.env), expression).await
}

async fn send(stream: &mut BufReader<UnixStream>, value: Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    timeout(Duration::from_secs(60), stream.get_mut().write_all(&bytes)).await??;
    Ok(())
}

async fn receive(stream: &mut BufReader<UnixStream>) -> Result<Value> {
    let mut bytes = Vec::new();
    timeout(
        Duration::from_secs(90),
        stream.take(1024 * 1024 + 1).read_until(b'\n', &mut bytes),
    )
    .await??;
    ensure!(
        bytes.last() == Some(&b'\n') && bytes.len() <= 1024 * 1024,
        "external views disconnected or exceeded their message limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run<T>(
    directory: &Path,
    filename: &str,
    config: MixedConfig,
    pool: Pool<Manager>,
    pages: ContractAddress,
    counter: ContractAddress,
    progress: CounterProgress,
    cache_before: (u64, u64),
    socket: OsString,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    let socket = socket
        .to_str()
        .context("external view socket path is not UTF-8")?;
    let cache = pool.get().await?.component_cache.clone();
    let mut env = Env::new_test(
        Reader::new(directory, filename).await?,
        directory,
        filename.into(),
    )
    .await?;
    env.runtime_pool = pool;
    let state = ViewState {
        env,
        pages: pages.to_string(),
        writing: Arc::default(),
        active: Arc::default(),
        peak: Arc::default(),
    };
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let router = Router::new()
        .route("/view/{address}", post(view))
        .with_state(state.clone());
    let shutdown = CancellationToken::new();
    let _shutdown_on_drop = shutdown.clone().drop_guard();
    let token = shutdown.clone();
    let server = tokio::spawn(async move {
        serve(listener, router)
            .with_graceful_shutdown(token.cancelled_owned())
            .await
    });
    let result = async {
        let mut stream = BufReader::new(UnixStream::connect(&socket).await?);
        let samples: Vec<_> = (0..PAGE_SAMPLES)
            .map(|round| {
                json!({
                    "expr": pagination::call(round, config.live_keys, PAGE_SAMPLES),
                    "expected": pagination::expected_wave(round, config.live_keys, PAGE_SAMPLES),
                })
            })
            .collect();
        send(
            &mut stream,
            json!({
                "schema_version": 1, "clients": CLIENTS, "port": port, "restore": filename,
                "pages": pages.to_string(), "counter": counter.to_string(),
                "maximum": progress.maximum, "samples": samples,
            }),
        )
        .await?;
        ensure!(
            receive(&mut stream).await? == json!({"ready": true}),
            "external view readiness differs"
        );
        send(&mut stream, json!({"start": true})).await?;
        ensure!(
            receive(&mut stream).await? == json!({"started": true}),
            "external view start differs"
        );
        state.writing.store(true, Ordering::SeqCst);
        let writer_started_ns = monotonic_ns()?;
        let started = Instant::now();
        let result = AssertUnwindSafe(work).catch_unwind().await;
        let writer_ns = started.elapsed().as_nanos();
        let writer_finished_ns = monotonic_ns()?;
        state.writing.store(false, Ordering::SeqCst);
        let succeeded = matches!(&result, Ok(Ok(_)));
        send(
            &mut stream,
            json!({"succeeded": succeeded, "completed": progress.completed.load(Ordering::SeqCst),
                "writer_started_ns": writer_started_ns, "writer_finished_ns": writer_finished_ns}),
        )
        .await?;
        let report = receive(&mut stream).await;
        let value = result.map_err(|_| anyhow!("workload writer panicked"))??;
        let report = report?;
        ensure!(report["status"] == "passed" && report["restore"] == filename);
        ensure!(
            state.active.load(Ordering::SeqCst) == 0 && state.peak.load(Ordering::SeqCst) > 1,
            "external page requests did not overlap or drain"
        );
        eprintln!(
            "workload_external_views={}",
            json!({"socket": socket, "report": report})
        );
        eprintln!(
            "workload_competing_views={}",
            json!({
                "clients": CLIENTS, "pool_max_size": CLIENTS,
                "driver": "external supervisor HTTP clients using production contract view handler",
                "peak_inflight_page_calls": state.peak.load(Ordering::SeqCst),
                "peak_scope": "inflight production handlers, including pool checkout",
                "writer_interval_ns": writer_ns, "workers": report["workers"],
                "cache_before": cache_before, "cache_after": cache.workload_metrics().await,
                "cache_metric": "entry count and encoded-byte weight; not compiled code bytes",
                "timing_claim": "diagnostic_only",
            })
        );
        Ok(value)
    }
    .await;
    shutdown.cancel();
    timeout(Duration::from_secs(60), server).await???;
    result
}
