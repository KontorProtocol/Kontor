pub mod compose;
pub mod env;
pub mod error;
pub mod handlers;
pub mod result;
pub mod router;
pub mod ws;

use std::{net::SocketAddr, time::Duration};

use anyhow::Result;
use axum_server::{Handle, tls_rustls::RustlsConfig};
pub use env::Env;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub async fn run(env: Env) -> Result<JoinHandle<()>> {
    let config = RustlsConfig::from_pem_file(
        env.config.data_dir.join("cert.pem"),
        env.config.data_dir.join("key.pem"),
    )
    .await?;
    let addr = SocketAddr::from(([127, 0, 0, 1], env.config.api_port));
    let handle = Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        let cancel_token = env.cancel_token.clone();
        async move {
            cancel_token.cancelled().await;
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });
    info!("Server running @ https://{}", addr);
    Ok(tokio::spawn(async move {
        if axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(router::new(env).into_make_service_with_connect_info::<SocketAddr>())
            .await
            .is_err()
        {
            error!("Panicked on join");
        }

        info!("Exited");
    }))
}
