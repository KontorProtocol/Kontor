use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use deadpool::managed::Pool;
use indexer_types::Fees;
use tokio::sync::{mpsc::Sender, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    bitcoin_client::Client, config::Config, database, event::EventSubscriber, info::InfoCore,
    reactor::Simulation, runtime,
};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub reader: database::Reader,
    pub event_subscriber: EventSubscriber,
    pub bitcoin: Client,
    pub runtime_pool: Pool<runtime::pool::Manager>,
    pub simulate_tx: Sender<Simulation>,
    /// Set true once the reactor signals ready (consensus up + initial
    /// mempool sync complete). Half of the `require_available` middleware
    /// check; the other half is `info_rx.borrow().height.is_some()`.
    /// Both signals are required so a warm-DB restart (where chain state
    /// exists from disk before the reactor has populated `fees_rx`) still
    /// 503s until the reactor catches up.
    pub reactor_ready: Arc<AtomicBool>,
    /// This node's resolved consensus listen address, written by the reactor on
    /// the first `Listening` (before consensus is available) and surfaced by the
    /// ungated `GET /api/status`. `None` until bound / for non-consensus nodes.
    pub consensus_listen_addr: Arc<RwLock<Option<String>>>,
    /// Latest fee tier snapshot published by the reactor. `borrow()` is
    /// non-blocking and returns the most recent value.
    pub fees_rx: watch::Receiver<Fees>,
    /// Latest chain/result snapshot published by the reactor on every
    /// block/batch/rollback. The `GET /api/` handler reads it (and
    /// long-polls on `changed()`) without touching the database; the
    /// `require_available` middleware also reads it as the chain-state
    /// half of the availability check.
    pub info_rx: watch::Receiver<InfoCore>,
}

impl Env {
    pub async fn new_test(
        reader: database::Reader,
        db_path: &Path,
        db_name: String,
    ) -> Result<Self> {
        let (simulate_tx, _) = tokio::sync::mpsc::channel(10);
        let (_, fees_rx) = watch::channel(Fees::floor(1));
        Ok(Self {
            bitcoin: Client::new("".to_string(), "".to_string(), "".to_string())?,
            config: Config::new_na(),
            cancel_token: CancellationToken::new(),
            // Unit-test env skips the reactor; flip ready so handlers that
            // get mounted directly into a test router aren't perma-503'd.
            reactor_ready: Arc::new(AtomicBool::new(true)),
            consensus_listen_addr: Arc::new(RwLock::new(None)),
            event_subscriber: EventSubscriber::new(),
            runtime_pool: runtime::pool::new(db_path.to_path_buf(), db_name).await?,
            reader,
            simulate_tx,
            fees_rx,
            // No reactor in unit tests — the sender is dropped, so the
            // snapshot stays at its default and long-polls return at once.
            info_rx: watch::channel(InfoCore::default()).1,
        })
    }
}
