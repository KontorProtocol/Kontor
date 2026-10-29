use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Error, Result, anyhow, ensure};
use bitcoin::Network;
use deadpool::managed::Pool;
use futures_util::FutureExt;
use futures_util::future::join_all;
use indexer_types::ContractAddress;
use serde_json::{Value, json};
use tokio::sync::Barrier;

use super::super::{ANCHOR_HEIGHT, database_projection};
use super::configuration::MixedConfig;
use super::pagination;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::runtime::pool::Manager;
use crate::runtime::{Runtime, from_wave_expr};

const CLIENTS: usize = 8;
const PAGE_SAMPLES: usize = 5;

async fn check_connection(runtime: &Runtime) -> Result<()> {
    let mut rows = runtime.storage.conn.query("PRAGMA query_only", ()).await?;
    ensure!(
        rows.next()
            .await?
            .context("missing query_only")?
            .get::<i64>(0)?
            == 1
    );
    ensure!(runtime.storage.conn.is_autocommit());
    Ok(())
}

async fn counter_value(runtime: &mut Runtime, address: &ContractAddress) -> Result<u64> {
    Ok(from_wave_expr::<u64>(
        &runtime.execute(None, None, address, "get()").await?,
    ))
}

pub(super) async fn run<T>(
    directory: &Path,
    filename: &str,
    config: Option<MixedConfig>,
    before: &Value,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    run_steps(directory, filename, config, before, 1, work).await
}

pub(super) async fn run_steps<T>(
    directory: &Path,
    filename: &str,
    config: Option<MixedConfig>,
    before: &Value,
    steps: usize,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    ensure!(matches!(steps, 1 | 2 | 6 | 7));
    let Some(config) = config.filter(|config| config.view_concurrency > 0) else {
        return work.await;
    };
    ensure!(config.view_concurrency == CLIENTS);
    let pool: Pool<Manager> = Pool::builder(Manager::new(
        directory.to_path_buf(),
        filename.into(),
        Network::Regtest,
        DEFAULT_VIEW_GAS_LIMIT,
    )?)
    .max_size(CLIENTS)
    .build()?;
    let pages = ContractAddress {
        name: "mixedpages".into(),
        height: if config.historical_rows > 0 {
            0
        } else {
            ANCHOR_HEIGHT
        },
        tx_index: 7,
    };
    let counter = ContractAddress {
        name: "mixedcounter".into(),
        height: ANCHOR_HEIGHT,
        tx_index: 7,
    };
    let expected_counter = u64::try_from(config.transactions / 10 * 4 * steps)?;
    let mut connections = Vec::with_capacity(CLIENTS);
    // All fallible setup precedes the barrier, so a failed checkout cannot strand workers.
    for _ in 0..CLIENTS {
        let runtime = pool.get().await?;
        check_connection(&runtime).await?;
        connections.push(runtime);
    }
    ensure!(database_projection(&connections[0].storage.conn).await? == *before);
    let value = connections[0]
        .execute(
            None,
            None,
            &pages,
            &pagination::call(0, config.live_keys, PAGE_SAMPLES),
        )
        .await?;
    pagination::check(0, config.live_keys, PAGE_SAMPLES, &value)?;
    ensure!(counter_value(&mut connections[0], &counter).await? == 0);
    ensure!(database_projection(&connections[0].storage.conn).await? == *before);

    let barrier = Arc::new(Barrier::new(CLIENTS + 1));
    let writer_started = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let writer_succeeded = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(CLIENTS);
    for (client, first) in connections.into_iter().enumerate() {
        let (pool, pages, counter) = (pool.clone(), pages.clone(), counter.clone());
        let (barrier, stopped, writer_succeeded, active, peak, writer_started) = (
            barrier.clone(),
            stopped.clone(),
            writer_succeeded.clone(),
            active.clone(),
            peak.clone(),
            writer_started.clone(),
        );
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut next = Some(first);
            let mut completed = 0usize;
            let mut during_writer = 0usize;
            let mut last_counter = 0;
            while !stopped.load(Ordering::SeqCst) {
                let mut runtime = match next.take() {
                    Some(runtime) => runtime,
                    None => pool.get().await?,
                };
                check_connection(&runtime).await?;
                let sample = (client + completed) % PAGE_SAMPLES;
                let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
                let began_during_writer = writer_started.load(Ordering::SeqCst) && !stopped.load(Ordering::SeqCst);
                if began_during_writer {
                    peak.fetch_max(concurrent, Ordering::SeqCst);
                }
                let value = runtime.execute(
                    None, None, &pages, &pagination::call(sample, config.live_keys, PAGE_SAMPLES),
                ).await;
                active.fetch_sub(1, Ordering::SeqCst);
                if began_during_writer && !stopped.load(Ordering::SeqCst) {
                    during_writer += 1;
                }
                pagination::check(sample, config.live_keys, PAGE_SAMPLES, &value?)?;
                drop(runtime);
                let mut runtime = pool.get().await?;
                check_connection(&runtime).await?;
                let value = counter_value(&mut runtime, &counter).await?;
                ensure!(value >= last_counter && value <= expected_counter, "view counter regressed or exceeded canonical work");
                last_counter = value;
                completed += 1;
                // Reacquisition exercises production recycle, including cursor and snapshot cleanup.
                drop(runtime);
            }
            drop(next);
            if writer_succeeded.load(Ordering::SeqCst) {
                let mut runtime = pool.get().await?;
                check_connection(&runtime).await?;
                ensure!(counter_value(&mut runtime, &counter).await? == expected_counter, "view retained stale committed counter");
            }
            Ok::<_, Error>(json!({"client":client,"completed":completed,"completed_during_writer":during_writer,"last_counter_during_work":last_counter}))
        }));
    }
    barrier.wait().await;
    let started = Instant::now();
    writer_started.store(true, Ordering::SeqCst);
    // Preserve draining on both ordinary errors and unwinding panics in the writer.
    let result = AssertUnwindSafe(work).catch_unwind().await;
    writer_succeeded.store(matches!(&result, Ok(Ok(_))), Ordering::SeqCst);
    stopped.store(true, Ordering::SeqCst);
    let writer_ns = started.elapsed().as_nanos();
    let observations = join_all(workers).await;
    let result = result.map_err(|_| anyhow!("workload writer panicked"))?;
    let result = result?;
    let observations = observations
        .into_iter()
        .map(|item| item.context("view worker panicked")?)
        .collect::<Result<Vec<_>>>()?;
    ensure!(active.load(Ordering::SeqCst) == 0);
    ensure!(
        peak.load(Ordering::SeqCst) > 1,
        "no concurrent view executions observed"
    );
    ensure!(
        observations
            .iter()
            .all(|item| item["completed_during_writer"]
                .as_u64()
                .is_some_and(|count| count > 0)),
        "not every view client overlapped writer work"
    );
    eprintln!(
        "workload_competing_views={}",
        json!({
            "clients": CLIENTS, "pool_max_size": CLIENTS, "pool_size_policy": "fixture override of available_parallelism",
            "tokio_worker_threads": 2, "cpu_quota_enforced": false,
            "view_gas_limit": DEFAULT_VIEW_GAS_LIMIT, "fuel_async_yield_interval": null,
            "cache_setup": "unsigned pagination and counter warmup outside writer interval; separate view pool cache",
            "peak_inflight_page_calls": peak.load(Ordering::SeqCst), "writer_interval_ns": writer_ns,
            "writer_interval_scope": "canonical work and caller-provided checks; excludes setup and final view drain",
            "timing_claim": "diagnostic_only", "workers": observations,
        })
    );
    Ok(result)
}
