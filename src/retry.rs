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
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug + Into<anyhow::Error>,
{
    operation
        .retry(&backoff)
        .notify(notify(action))
        .when(retryable(cancel_token))
        .await
        .map_err(Into::into) // Convert backon::RetryError<E> to anyhow::Error
}
