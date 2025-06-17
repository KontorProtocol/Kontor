use anyhow::Result;
use bitcoin::Transaction;
use futures_util::future::OptionFuture;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc::Receiver,
    sync::mpsc::{self, UnboundedSender},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{bitcoin_client::client::BitcoinRpc, block::Tx};

pub mod events;
pub mod info;
pub mod messages;
pub mod reconciler;
pub mod rpc;
pub mod seek;
pub mod zmq;

async fn zmq_runner<T: Tx + 'static, C: BitcoinRpc>(
    addr: String,
    cancel_token: CancellationToken,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    tx: UnboundedSender<events::ZmqEvent<T>>,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            let handle =
                zmq::run(&addr, cancel_token.clone(), bitcoin.clone(), f, tx.clone()).await?;

            match handle.await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) => {
                    if tx.send(events::ZmqEvent::Disconnected(e)).is_err() {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if tx.send(events::ZmqEvent::Disconnected(e.into())).is_err() {
                        return Ok(());
                    }
                }
            }

            select! {
                _ = sleep(Duration::from_secs(10)) => {}
                _ = cancel_token.cancelled() => {
                    return Ok(());
                }
            }

            info!("Restarting ZMQ listener");
        }
    })
}

pub async fn run<T: Tx + 'static, C: BitcoinRpc>(
    zmq_address: Option<String>,
    cancel_token: CancellationToken,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    ctrl_rx: Receiver<seek::SeekMessage<T>>,
) -> Result<JoinHandle<()>> {
    let info = info::Info::new(cancel_token.clone(), bitcoin.clone());

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);

    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();
    let runner_cancel_token = CancellationToken::new();
    let runner_handle = OptionFuture::from(zmq_address.map(|a| {
        zmq_runner(
            a,
            runner_cancel_token.clone(),
            bitcoin.clone(),
            f,
            zmq_tx.clone(),
        )
    }))
    .await;

    if runner_handle.is_none() {
        warn!("No ZMQ connection");
    }

    let mut reconciler =
        reconciler::Reconciler::new(cancel_token.clone(), info, fetcher, rpc_rx, zmq_rx);

    Ok(tokio::spawn(async move {
        reconciler.run(ctrl_rx).await;

        let _zmq_ch_keepalive = zmq_tx; // need to keep the channel alive when there's no ZMQ
        runner_cancel_token.cancel();
        if let Some(handle) = runner_handle {
            match handle.await {
                Err(_) => error!("ZMQ runner panicked on join"),
                Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
                Ok(Ok(_)) => (),
            }
        }

        info!("Exited");
    }))
}
