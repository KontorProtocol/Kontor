//! Relays batch transactions to bitcoind, off the consensus hot loop.
//!
//! `send_raw_transaction` used to run inside `validate_transaction`, which
//! meant two things neither side wanted: a vote gated on relay success, and a
//! bitcoind hiccup holding the reactor's event loop through a full retry
//! backoff. Neither is needed for correctness — confirmation is only ever
//! judged at the finality deadline, and the deadline machinery is the safety
//! net for a transaction that never relayed — so relay is a subsystem of its
//! own: channel-fed, supervised like the poller, and drop-cancelled at its
//! task root (the in-flight RPC included).

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::bitcoin_client::client::BitcoinRpc;
use crate::retry::{new_backoff_limited, retry};
use crate::stopper::ShutdownSignal;

/// Ample headroom over the largest plausible burst (every tx of a proposal
/// accepted at once); the reactor `try_send`s and must never block on us.
pub const CHANNEL_CAPACITY: usize = 1024;

pub fn run<C: BitcoinRpc + Clone + Send + Sync + 'static>(
    bitcoin: C,
    mut rx: mpsc::Receiver<bitcoin::Transaction>,
    shutdown: ShutdownSignal,
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        loop {
            let tx = tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                tx = rx.recv() => match tx {
                    Some(tx) => tx,
                    // The sender lives in the reactor; the channel closing
                    // means the reactor is gone. Its own exit carries the real
                    // cause (and outranks this by supervisor vec order) — this
                    // is the honest report from THIS task's point of view.
                    None => return Err(anyhow!("broadcast channel closed")),
                },
            };
            let txid = tx.compute_txid();
            let raw_hex = bitcoin::consensus::encode::serialize_hex(&tx);
            // A failed relay is warn-and-drop, never fatal: the tx usually
            // reached bitcoind through the mempool already, other validators
            // relay it too, and a tx that truly never relays simply misses its
            // finality deadline — the outcome the deadline machinery exists to
            // absorb. Dropping mid-RPC at shutdown is equally fine for the
            // same reason. (`-27` = already known; `-25`/`-26` = rejected.)
            let result = retry(
                || async {
                    match bitcoin.send_raw_transaction(&raw_hex).await {
                        Ok(_) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -27, ..
                        }) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -25 | -26,
                            ..
                        }) => Ok(false),
                        Err(e) => Err(e),
                    }
                },
                "send_raw_transaction",
                new_backoff_limited(),
            )
            .await;
            match result {
                Ok(true) => debug!(%txid, "Relayed to bitcoind"),
                Ok(false) => warn!(%txid, "Transaction rejected by bitcoind; not relayed"),
                Err(e) => warn!(%txid, error = %e, "Relay failed after retries; dropping"),
            }
        }
    })
}
