use anyhow::Result;
use tokio::{
    select,
    signal::ctrl_c,
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

#[cfg(unix)]
async fn sigterm_listener() {
    let mut stream = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    stream.recv().await;
}

#[cfg(not(unix))]
async fn sigterm_listener() {
    // On non-unix platforms, this future never resolves.
    std::future::pending::<()>().await;
}

pub fn run(cancel_token: CancellationToken) -> Result<JoinHandle<()>> {
    Ok(task::spawn(async move {
        select! {
            _ = cancel_token.cancelled() => warn!("Cancelled"),
            _ = ctrl_c() => warn!("Ctrl+C received"),
            _ = sigterm_listener() => warn!("SIGTERM received"),
        };
        info!("Initiating shutdown");
        cancel_token.cancel();
        info!("Exited");
    }))
}
