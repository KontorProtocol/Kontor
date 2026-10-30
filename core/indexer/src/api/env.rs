use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use deadpool::managed::Pool;
use indexer_types::Fees;
use tokio::sync::{mpsc::Sender, watch};

use crate::{
    bitcoin_client::Client, config::Config, database, event::EventSubscriber, info::InfoCore,
    reactor::Simulation, runtime, stopper::ShutdownSignal,
};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub shutdown: ShutdownSignal,
    pub reader: database::Reader,
    pub event_subscriber: EventSubscriber,
    pub bitcoin: Client,
    pub(crate) runtime_pool: Pool<runtime::pool::Manager>,
    pub owner_service: runtime::ownership::OwnerService,
    pub simulate_tx: Sender<Simulation>,
    /// Set true once the reactor signals ready (consensus up + initial
    /// mempool sync complete). Half of the `require_available` middleware
    /// check; the other half is `info_rx.borrow().height.is_some()`.
    /// Both signals are required so a warm-DB restart (where chain state
    /// exists from disk before the reactor has populated `fees_rx`) still
    /// 503s until the reactor catches up.
    pub reactor_ready: Arc<AtomicBool>,
    /// Set by `main` when the node is stopping because a subsystem died, before
    /// it cancels. `cancel_token` says only *that* we are stopping — a rollout
    /// and a dead reactor look identical there — and the two call for opposite
    /// treatment of in-flight traffic: drain the first, refuse the second. This
    /// is the only thing that tells them apart inside a handler.
    pub failed: Arc<AtomicBool>,
    /// This node's resolved consensus listen address, sent by the reactor on
    /// the first `Listening` (before consensus is available) and surfaced by the
    /// ungated `GET /api/status`. A watch so in-process cluster tests can await
    /// the bind event-driven rather than poll. `None` until bound / for
    /// non-consensus nodes.
    pub consensus_listen_addr: watch::Receiver<Option<String>>,
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

pub struct DaemonEnv {
    pub config: Config,
    pub shutdown: ShutdownSignal,
    pub reader: database::Reader,
    pub event_subscriber: EventSubscriber,
    pub bitcoin: Client,
    pub owner_service: runtime::ownership::OwnerService,
    pub simulate_tx: Sender<Simulation>,
    pub reactor_ready: Arc<AtomicBool>,
    pub failed: Arc<AtomicBool>,
    pub consensus_listen_addr: watch::Receiver<Option<String>>,
    pub fees_rx: watch::Receiver<Fees>,
    pub info_rx: watch::Receiver<InfoCore>,
    pub database_name: String,
}

impl Env {
    pub async fn new_daemon(parts: DaemonEnv) -> Result<Self> {
        let runtime_pool = runtime::pool::new(
            parts.config.data_dir.clone(),
            parts.database_name,
            parts.config.network,
            parts.config.view_gas_limit,
        )
        .await?;
        Ok(Self {
            config: parts.config,
            shutdown: parts.shutdown,
            reader: parts.reader,
            event_subscriber: parts.event_subscriber,
            bitcoin: parts.bitcoin,
            runtime_pool,
            owner_service: parts.owner_service,
            simulate_tx: parts.simulate_tx,
            reactor_ready: parts.reactor_ready,
            failed: parts.failed,
            consensus_listen_addr: parts.consensus_listen_addr,
            fees_rx: parts.fees_rx,
            info_rx: parts.info_rx,
        })
    }

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
            shutdown: ShutdownSignal::never(),
            // Unit-test env skips the reactor; flip ready so handlers that
            // get mounted directly into a test router aren't perma-503'd.
            reactor_ready: Arc::new(AtomicBool::new(true)),
            failed: Arc::new(AtomicBool::new(false)),
            consensus_listen_addr: watch::channel(None).1,
            event_subscriber: EventSubscriber::new(),
            runtime_pool: runtime::pool::new(
                db_path.to_path_buf(),
                db_name,
                bitcoin::Network::Regtest,
                crate::config::DEFAULT_VIEW_GAS_LIMIT,
            )
            .await?,
            owner_service: runtime::ownership::OwnerService::new(),
            reader,
            simulate_tx,
            fees_rx,
            // No reactor in unit tests — the sender is dropped, so the
            // snapshot stays at its default and long-polls return at once.
            info_rx: watch::channel(InfoCore::default()).1,
        })
    }
}
