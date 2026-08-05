use tokio::{select, signal::ctrl_c};
use tracing::warn;

#[cfg(not(windows))]
use tokio::signal::unix::{SignalKind, signal};

#[cfg(not(windows))]
async fn sigterm_listener() {
    let mut stream = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    stream.recv().await;
}

#[cfg(windows)]
async fn sigterm_listener() {
    // On non-unix platforms, this future never resolves.
    std::future::pending::<()>().await;
}

/// Resolves when the process is asked to stop from outside — Ctrl-C or SIGTERM.
///
/// Deliberately just a future, not a task that cancels: whoever awaits it learns
/// that the stop was *asked for*, and that is the whole basis for telling an
/// operator-initiated shutdown from a subsystem that died. A task that cancelled
/// on our behalf would erase the distinction the moment it fired, which is how a
/// crashed node comes to exit 0.
pub async fn signal_received() {
    select! {
        _ = ctrl_c() => warn!("Ctrl+C received"),
        _ = sigterm_listener() => warn!("SIGTERM received"),
    }
}
