use bitcoin::BlockHash;
use std::sync::Arc;
use tokio::{
    select,
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::{bitcoin_client::client::BitcoinRpc, block::TransactionFilterMap, fatal::FatalSlot};

use self::{
    event::{BlockEvent, MempoolEvent},
    listener::ListenerConfig,
    poller::PollerConfig,
};

pub mod event;
pub mod listener;
pub mod messages;
pub mod poller;

pub async fn run<C: BitcoinRpc>(
    bitcoin: C,
    f: TransactionFilterMap,
    cancel_token: CancellationToken,
    starting_block_height: u64,
    known_hashes: Vec<(u64, BlockHash)>,
    zmq_address: String,
    fatal: FatalSlot,
) -> (
    mpsc::Receiver<BlockEvent>,
    mpsc::Receiver<MempoolEvent>,
    mpsc::Sender<u64>,
    JoinHandle<()>,
) {
    let (block_tx, block_rx) = mpsc::channel(32);
    let (mempool_tx, mempool_rx) = mpsc::channel(32);
    let (replay_tx, replay_rx) = mpsc::channel(4);

    let start_height = known_hashes
        .iter()
        .map(|(h, _)| *h)
        .max()
        .map(|h| (h + 1).max(starting_block_height))
        .unwrap_or(starting_block_height);

    let handle = tokio::spawn(async move {
        let poll_notify = Arc::new(Notify::new());
        let poller_handle = tokio::spawn(poller::run(
            bitcoin.clone(),
            f,
            block_tx,
            cancel_token.clone(),
            start_height,
            known_hashes,
            poll_notify.clone(),
            PollerConfig::default(),
            replay_rx,
        ));

        let listener_handle = tokio::spawn(listener::run(
            bitcoin,
            f,
            mempool_tx,
            cancel_token.clone(),
            poll_notify,
            ListenerConfig::new(zmq_address),
        ));

        // Whichever task exits first takes the whole node down with it — neither
        // is optional. `Ok(Ok(()))` is only legitimate as a response to
        // cancellation; reached any other way it means a task quietly stopped
        // feeding the reactor, which used to be silent (the old catch-all arm
        // logged nothing at all) and is just as fatal as an error.
        macro_rules! subsystem_exit {
            ($name:literal, $result:expr) => {{
                match $result {
                    Ok(Err(e)) => {
                        error!("{} error: {:#}", $name, e);
                        fatal.record($name, &e);
                    }
                    Err(e) => {
                        error!("{} task panicked: {}", $name, e);
                        fatal.record_msg($name, format!("task panicked: {e}"));
                    }
                    Ok(Ok(())) => {
                        if !cancel_token.is_cancelled() {
                            error!("{} exited without being cancelled", $name);
                            fatal.record_msg($name, "exited without being cancelled");
                        }
                    }
                }
                cancel_token.cancel();
            }};
        }

        select! {
            r = poller_handle => subsystem_exit!("bitcoin poller", r),
            r = listener_handle => subsystem_exit!("bitcoin listener", r),
        }
    });

    (block_rx, mempool_rx, replay_tx, handle)
}
