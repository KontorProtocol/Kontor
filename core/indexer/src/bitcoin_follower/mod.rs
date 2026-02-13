use bitcoin::BlockHash;
use tokio::{select, sync::mpsc, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::{bitcoin_client::client::BitcoinRpc, block::TransactionFilterMap};

use self::{event::BitcoinEvent, mempool::MempoolConfig, poller::PollerConfig};

pub mod event;
pub mod mempool;
pub mod messages;
pub mod poller;

pub async fn run<C: BitcoinRpc>(
    bitcoin: C,
    f: TransactionFilterMap,
    cancel_token: CancellationToken,
    starting_block_height: u64,
    known_hashes: Vec<(u64, BlockHash)>,
    zmq_address: String,
) -> (mpsc::Receiver<BitcoinEvent>, JoinHandle<()>) {
    let (event_tx, event_rx) = mpsc::channel(32);

    let start_height = known_hashes
        .iter()
        .map(|(h, _)| *h)
        .max()
        .map(|h| h + 1)
        .unwrap_or(starting_block_height);

    let handle = tokio::spawn(async move {
        let poller_handle = tokio::spawn(poller::run(
            bitcoin.clone(),
            f,
            event_tx.clone(),
            cancel_token.clone(),
            start_height,
            known_hashes,
            PollerConfig::default(),
        ));

        let mempool_handle = tokio::spawn(mempool::run(
            bitcoin,
            f,
            event_tx,
            cancel_token.clone(),
            MempoolConfig::new(zmq_address),
        ));

        select! {
            r = poller_handle => {
                if let Ok(Err(e)) = r {
                    error!("Poller error: {:#}", e);
                }
                cancel_token.cancel();
            }
            r = mempool_handle => {
                if let Ok(Err(e)) = r {
                    error!("Mempool error: {:#}", e);
                }
                cancel_token.cancel();
            }
        }
    });

    (event_rx, handle)
}
