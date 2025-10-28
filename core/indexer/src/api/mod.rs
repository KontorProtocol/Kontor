pub mod client;
pub mod compose;
pub mod env;
pub mod error;
pub mod handlers;
pub mod result;
pub mod router;
pub mod ws;
pub mod ws_client;

use std::{net::SocketAddr, path::Path, time::Duration};

use anyhow::Result;
use axum_server::{Handle, tls_rustls::RustlsConfig};
pub use env::Env;
use tokio::task::JoinHandle;
use tracing::{error, info};

pub async fn run(env: Env) -> Result<JoinHandle<()>> {
    let cert_path = env.config.data_dir.join("cert.pem");
    let key_path = env.config.data_dir.join("key.pem");
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

    let use_https = Path::new(&cert_path).exists() && Path::new(&key_path).exists();

    if use_https {
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path).await?;
        info!("HTTPS server running @ https://{}", addr);
        Ok(tokio::spawn(async move {
            if axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(router.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .is_err()
            {
                error!("HTTPS server panicked on join");
            }
            info!("HTTPS server exited");
        }))
    } else {
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
}
