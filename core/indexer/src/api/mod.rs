pub mod client;
pub mod compose;
pub mod env;
pub mod error;
pub mod handlers;
pub mod result;
pub mod router;
pub mod ws;
pub mod ws_client;

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use axum_server::Handle;
pub use env::Env;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub async fn run(env: Env) -> Result<JoinHandle<()>> {
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

    let router = router::new(env);

    info!("HTTP server running @ http://{}", addr);
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
