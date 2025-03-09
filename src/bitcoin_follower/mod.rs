use anyhow::Result;
use bitcoin::Transaction;
use events::Event;
use indexmap::IndexSet;
use tokio::{sync::mpsc::Sender, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{bitcoin_client, block::Tx, config::Config, database::Reader};

pub mod events;
pub mod messages;
pub mod reconciler;
pub mod rpc;
pub mod zmq;

pub async fn run<T: Tx + 'static>(
    config: Config,
    cancel_token: CancellationToken,
    reader: Reader,
    bitcoin: bitcoin_client::Client,
    f: fn(Transaction) -> T,
    tx: Sender<Event<T>>,
) -> Result<JoinHandle<()>> {
    let handle = reconciler::run(
        config,
        cancel_token.clone(),
        reader,
        bitcoin,
        IndexSet::new(),
        f,
        tx,
    )
    .await?;
    Ok(tokio::spawn(async move {
        if handle.await.is_err() {
            error!("Panicked on join");
        }
        info!("Exited");
    }))
}
