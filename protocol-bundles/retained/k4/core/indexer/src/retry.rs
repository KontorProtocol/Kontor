use anyhow::{Error, Result};
use backon::{ExponentialBuilder, Retryable};
use std::time::Duration;
use tracing::warn;

pub fn new_backoff() -> ExponentialBuilder {
    ExponentialBuilder::new()
        .with_jitter()
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_secs(10))
}

pub fn new_backoff_unlimited() -> ExponentialBuilder {
    new_backoff().without_max_times()
}

pub fn new_backoff_limited() -> ExponentialBuilder {
    new_backoff().with_max_times(6)
}

/// Same shape as `new_backoff_limited` but with more attempts — ~65s
/// total budget vs ~25s. For polling readiness of subprocesses that
/// can be slow under heavy parallel CI load (e.g. cluster startup
/// where 5 indexer processes are racing for resources).
pub fn new_backoff_extended() -> ExponentialBuilder {
    new_backoff().with_max_times(10)
}

pub fn notify<E: std::fmt::Debug>(action: &str) -> impl FnMut(&E, Duration) {
    move |e, d| {
        warn!("Retrying {} due to {:?} after {:?}", action, e, d);
    }
}

/// Retry `operation` per `backoff`, giving up only when the backoff does.
///
/// Takes no shutdown signal, and does not need one: a dropped future stops, and
/// dropping propagates to everything it owns — the in-flight RPC, the backoff
/// sleep, this loop. Every caller is droppable: either it lives below a task
/// root that races `ShutdownSignal::cancelled()`, or it rides in an owned
/// future the reactor polls at its root select (`Executor::validate_txs`).
/// This is the crate's ONE retry idiom — the raced variant
/// (`retry_until_cancelled`) died with the last call site that could not be
/// dropped, when consensus I/O moved off the event loop.
pub async fn retry<T, E, F, Fut>(
    operation: F,
    action: &str,
    backoff: ExponentialBuilder,
) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    operation
        .retry(&backoff)
        .notify(notify(action))
        .await
        .map_err(Into::into) // Convert backon::RetryError<E> to anyhow::Error
}

pub async fn retry_simple<T, E, F, Fut>(operation: F) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    retry(operation, "test_operation", new_backoff_limited()).await
}

/// `retry_simple` with the extended backoff — use for slow subprocess
/// readiness polls under contended CI load.
pub async fn retry_extended<T, E, F, Fut>(operation: F) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    retry(operation, "test_operation", new_backoff_extended()).await
}
