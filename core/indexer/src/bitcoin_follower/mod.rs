use anyhow::Result;
use bitcoin::Transaction;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc::Receiver,
    sync::mpsc::{self, UnboundedSender},
    task::JoinHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{bitcoin_client::client::BitcoinRpc, block::Tx};

pub mod ctrl;
pub mod events;
pub mod info;
pub mod messages;
pub mod reconciler;
pub mod rpc;
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
            match zmq::run(&addr, cancel_token.clone(), bitcoin.clone(), f, tx.clone()).await {
                Ok(handle) => match handle.await {
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
                },
                Err(e) => {
                    error!("ZMQ listener failed to start: {}", e);
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
    zmq_address: String,
    cancel_token: CancellationToken,
    bitcoin: C,
    f: fn(Transaction) -> Option<T>,
    ctrl_rx: Receiver<ctrl::StartMessage<T>>,
) -> Result<JoinHandle<()>> {
    let info = info::Info::new(cancel_token.clone(), bitcoin.clone());

    let (rpc_tx, rpc_rx) = mpsc::channel(10);
    let fetcher = rpc::Fetcher::new(bitcoin.clone(), f, rpc_tx);
    let mempool = rpc::MempoolFetcherImpl::new(cancel_token.clone(), bitcoin.clone(), f);

    let (zmq_tx, zmq_rx) = mpsc::unbounded_channel();
    let runner_cancel_token = CancellationToken::new();
    let runner_handle = zmq_runner(
        zmq_address,
        runner_cancel_token.clone(),
        bitcoin.clone(),
        f,
        zmq_tx.clone(),
    )
    .await;

    let mut reconciler =
        reconciler::Reconciler::new(cancel_token.clone(), info, fetcher, mempool, rpc_rx, zmq_rx);

    Ok(tokio::spawn(async move {
        reconciler.run(ctrl_rx).await;

        runner_cancel_token.cancel();
        match runner_handle.await {
            Err(_) => error!("ZMQ runner panicked on join"),
            Ok(Err(e)) => error!("ZMQ runner failed to start with error: {}", e),
            Ok(Ok(_)) => (),
        }

        info!("Exited");
    }))
}
