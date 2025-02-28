use anyhow::Result;
use kontor::{
    bitcoin_client,
    config::Config,
    logging,
    retry::{new_backoff_limited, retry},
    stopper,
};
use tokio::{select, task};
use tokio_util::sync::CancellationToken;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    logging::setup();
    info!("Hello, World!");
    let client = bitcoin_client::Client::new_from_config(Config::load()?)?;
    let cancel_token = CancellationToken::new();
    let stopper_handle = stopper::run(cancel_token.clone());
    let retry_handle = task::spawn({
        let cancel_token = cancel_token.clone();
        async move {
            info!("Retry task started");
            let result = retry(
                || client.get_block_hash(900000),
                "get block hash",
                new_backoff_limited(),
                cancel_token,
            )
            .await;
            info!("{:?}", result);
            info!("Retry task exited");
        }
    });
    let task_handle = task::spawn(async move {
        info!("Task started");
        select! {
            _ = cancel_token.cancelled() => {
                info!("Task cancelled");
            }
        }
        info!("Exiting task");
    });
    for handle in [retry_handle, task_handle, stopper_handle] {
        handle.await?
    }
    info!("Goodbye.");
    Ok(())
}
