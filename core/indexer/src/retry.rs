use anyhow::{Error, Result};
use backon::{ExponentialBuilder, Retryable};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
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

pub fn retryable<E>(cancel_token: CancellationToken) -> impl FnMut(&E) -> bool {
    move |_| !cancel_token.is_cancelled()
}

pub async fn retry<T, E, F, Fut>(
    operation: F,
    action: &str,
    backoff: ExponentialBuilder,
    cancel_token: CancellationToken,
) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    operation
        .retry(&backoff)
        .notify(notify(action))
        .when(retryable(cancel_token))
        .await
        .map_err(Into::into) // Convert backon::RetryError<E> to anyhow::Error
}

pub async fn retry_simple<T, E, F, Fut>(operation: F) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    let cancel_token = CancellationToken::new();
    let backoff = new_backoff_limited();
    retry(operation, "test_operation", backoff, cancel_token).await
}

/// `retry_simple` with the extended backoff — use for slow subprocess
/// readiness polls under contended CI load.
pub async fn retry_extended<T, E, F, Fut>(operation: F) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    let cancel_token = CancellationToken::new();
    let backoff = new_backoff_extended();
    retry(operation, "test_operation", backoff, cancel_token).await
}
