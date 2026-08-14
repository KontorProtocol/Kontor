use anyhow::{Error, Result, anyhow};
use backon::{ExponentialBuilder, Retryable};
use std::time::Duration;
use tracing::warn;

use crate::stopper::ShutdownSignal;

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
/// sleep, this loop. Callers that live inside a task whose root races
/// `ShutdownSignal::cancelled()` are cancelled for free the moment that task is
/// asked to stop.
///
/// Use [`retry_until_cancelled`] instead from anywhere that *cannot* be dropped.
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

/// [`retry`] for work that cannot be drop-cancelled, so something has to cut the
/// retrying short from outside.
///
/// The callers are `validate_transaction`'s two RPCs — mempool acceptance and
/// broadcast — reached from `make_value` and `validate_and_accept_proposal`,
/// i.e. while building or checking a batch proposal. They cannot be dropped
/// simply because they run in the *body* of a branch of the reactor's `select!`,
/// and a chosen branch's body runs to completion; nothing above them is in a
/// position to race them. Without a way in, a node retrying an unreachable
/// bitcoind keeps going until the backoff runs out, spending the shutdown budget
/// on a proposal that will never be used.
///
/// Races the signal against the whole retry rather than checking a flag between
/// attempts. backon consults its `when` predicate only when an error *arrives*,
/// so a flag would first sit out the remaining backoff — up to 10s — and then
/// make one more RPC attempt, complete with its connect timeout, before noticing.
/// Racing abandons the in-flight request the instant the decision is made, which
/// costs nothing here: proposal validation writes no state, and the caller
/// already treats an RPC failure as "this transaction does not go in the batch".
pub async fn retry_until_cancelled<T, E, F, Fut>(
    operation: F,
    action: &str,
    backoff: ExponentialBuilder,
    shutdown: ShutdownSignal,
) -> Result<T>
where
    E: std::fmt::Debug + Into<Error>,
    Fut: Future<Output = Result<T, E>>,
    F: FnMut() -> Fut,
{
    tokio::select! {
        _ = shutdown.cancelled() => {
            Err(anyhow!("{action} abandoned: node is shutting down"))
        }
        result = retry(operation, action, backoff) => result,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stopper::Shutdown;
    use std::time::Instant;

    /// A cancelled retry gives up at once rather than sitting out its backoff.
    ///
    /// The failure this guards against is quiet: backon consults `when` only
    /// when an error arrives, so a flag-checking version waits out the remaining
    /// delay — up to 10s on the limited backoff — and then makes one more
    /// attempt before noticing. That is shutdown budget spent on a block that is
    /// going to be rolled back anyway.
    #[tokio::test]
    async fn cancelled_retry_abandons_its_backoff() {
        let shutdown = Shutdown::new();
        let signal = shutdown.signal();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown.cancel();
        });

        let started = Instant::now();
        let result: Result<()> = retry_until_cancelled(
            || async { Err::<(), Error>(anyhow!("bitcoind unreachable")) },
            "unreachable rpc",
            new_backoff_limited(),
            signal,
        )
        .await;

        let waited = started.elapsed();
        assert!(result.is_err(), "a cancelled retry cannot report success");
        assert!(
            waited < Duration::from_secs(2),
            "gave up after {waited:?} — it sat out the backoff instead of racing it"
        );
    }

    /// Cancellation is not consulted while things are working: a retry that
    /// succeeds still returns its value.
    #[tokio::test]
    async fn uncancelled_retry_returns_its_value() {
        let shutdown = Shutdown::new();
        let result: Result<u8> = retry_until_cancelled(
            || async { Ok::<u8, Error>(7) },
            "fine rpc",
            new_backoff_limited(),
            shutdown.signal(),
        )
        .await;
        assert_eq!(result.unwrap(), 7);
    }
}
