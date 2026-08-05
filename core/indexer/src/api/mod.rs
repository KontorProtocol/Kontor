pub mod client;
pub mod compose;
pub mod env;
pub mod error;
pub mod handlers;
pub mod result;
pub mod router;

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use axum_server::Handle;
pub use env::Env;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Wall-clock budget the router's `TimeoutLayer` allows any `/api`
/// request. The long-poll `GET /api/` handler derives its `?wait=` cap
/// from this, so a held request always returns before the middleware
/// would kill it with a non-JSON 408. Single source of truth — the
/// router and the handler both read this constant.
pub const API_REQUEST_TIMEOUT_MS: u64 = 30_000;

pub async fn run(
    env: Env,
    prom_handle: PrometheusHandle,
    fatal: crate::fatal::FatalSlot,
) -> Result<JoinHandle<()>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], env.config.api_port));
    let handle = Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        let cancel_token = env.cancel_token.clone();
        async move {
            cancel_token.cancelled().await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });

    // Log the *resolved* bound address once the listener is up. With
    // `api_port = 0` (OS-assigned — used by the regtest harness to bind without
    // a probe/release port race) the configured `addr` reads `:0`, so the real
    // port is only knowable after bind; `Handle::listening()` surfaces it.
    tokio::spawn({
        let handle = handle.clone();
        async move {
            if let Some(bound) = handle.listening().await {
                info!("HTTP server running @ http://{}", bound);
            }
        }
    });

    let cancel_token = env.cancel_token.clone();
    let router = router::new(env, prom_handle);

    Ok(tokio::spawn(async move {
        // This resolves on a bind failure (port already taken) as well as on a
        // serve error, and until now both only logged — leaving the node running
        // headless, with no API and no probe endpoint answering, while `main`
        // waited on tasks that would never finish. The probes are the only way an
        // orchestrator sees inside this process, so losing them is fatal.
        if let Err(e) = axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            error!("HTTP server failed on {addr}: {e}");
            fatal.record_msg("http server", format!("failed on {addr}: {e}"));
            cancel_token.cancel();
        }
        info!("HTTP server exited");
    }))
}
