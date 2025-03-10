use anyhow::Result;
use tokio::{
    select,
    signal::{
        ctrl_c,
        unix::{SignalKind, signal},
    },
    task::{self, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub fn run(cancel_token: CancellationToken) -> Result<JoinHandle<()>> {
    let mut sigterm = signal(SignalKind::terminate())?;
    Ok(task::spawn(async move {
        select! {
            _ = cancel_token.cancelled() => warn!("Cancelled"),
            _ = ctrl_c() => warn!("Ctrl+C received"),
            _ = sigterm.recv() => warn!("SIGTERM received"),
        };
        info!("Initiating shutdown");
        cancel_token.cancel();
        info!("Exited");
    }))
}
