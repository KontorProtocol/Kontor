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
    new_backoff().with_max_times(5)
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
