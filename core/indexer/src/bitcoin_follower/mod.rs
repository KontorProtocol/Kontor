use anyhow::{Context, Result, anyhow};
use bitcoin::BlockHash;
use std::sync::Arc;
use tokio::{
    select,
    sync::{Notify, mpsc},
    task::{JoinError, JoinHandle},
};
use tokio_util::sync::CancellationToken;

use crate::{bitcoin_client::client::BitcoinRpc, block::TransactionFilterMap};

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
) -> (
    mpsc::Receiver<BlockEvent>,
    mpsc::Receiver<MempoolEvent>,
    mpsc::Sender<u64>,
    JoinHandle<Result<()>>,
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

        // Whichever task exits first takes the follower with it — neither is
        // optional, and a task that stops feeding the reactor is as fatal as one
        // that errors. `Ok(Ok(()))` is only legitimate as a response to
        // cancellation; reached any other way it used to be silent, because the
        // old catch-all arm logged nothing at all.
        //
        // No `cancel()` here either: returning the error *is* the report, and
        // the supervisor that owns the token decides what it means.
        select! {
            r = poller_handle => subsystem_exit("bitcoin poller", r, &cancel_token),
            r = listener_handle => subsystem_exit("bitcoin listener", r, &cancel_token),
        }
    });

    (block_rx, mempool_rx, replay_tx, handle)
}

/// Turn a finished poller/listener task into the follower's own result.
fn subsystem_exit(
    name: &str,
    result: std::result::Result<Result<()>, JoinError>,
    cancel_token: &CancellationToken,
) -> Result<()> {
    match result {
        Ok(Err(e)) => Err(e).with_context(|| format!("{name} failed")),
        Err(e) => Err(anyhow!("{name} task panicked: {e}")),
        // Cancelled is the one way out that isn't a failure.
        Ok(Ok(())) if cancel_token.is_cancelled() => Ok(()),
        Ok(Ok(())) => Err(anyhow!("{name} exited without being cancelled")),
    }
}
