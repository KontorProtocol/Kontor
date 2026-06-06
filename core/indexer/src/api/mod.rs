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

pub async fn run(env: Env, prom_handle: PrometheusHandle) -> Result<JoinHandle<()>> {
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

    let router = router::new(env, prom_handle);

    Ok(tokio::spawn(async move {
        if axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .is_err()
        {
            error!("HTTP server panicked on join");
        }
        info!("HTTP server exited");
    }))
}
