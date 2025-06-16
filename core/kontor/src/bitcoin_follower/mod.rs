use anyhow::Result;
use bitcoin::Transaction;
use tokio::{sync::mpsc::Receiver, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{bitcoin_client::client::BitcoinRpc, block::Tx, database::Reader};

pub mod events;
pub mod messages;
pub mod queries;
pub mod reconciler;
pub mod rpc;
pub mod seek;
pub mod zmq;

pub async fn run<T: Tx + 'static, C: BitcoinRpc>(
    zmq_address: Option<String>,
    cancel_token: CancellationToken,
    reader: Reader,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    ctrl: Receiver<seek::SeekMessage<T>>,
) -> Result<JoinHandle<()>> {
    let handle =
        reconciler::run(zmq_address, cancel_token.clone(), reader, bitcoin, f, ctrl).await?;

    Ok(tokio::spawn(async move {
        if handle.await.is_err() {
            error!("Panicked on join");
        }
        info!("Exited");
    }))
}
