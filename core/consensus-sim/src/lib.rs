use std::time::Duration;

use eyre::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info};

use indexer::bitcoin_follower::event::BitcoinEvent;
use indexer::consensus::Value;
use malachitebft_app_channel::app::config::*;
use malachitebft_app_channel::app::types::Keypair;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_app_channel::{
    ConsensusContext, NetworkContext, NetworkIdentity, RequestContext, SyncContext, WalContext,
};

use indexer::consensus::codec::ProtobufCodec;
use indexer::consensus::signing::{Ed25519Provider, PrivateKey};
use indexer::consensus::{Address, Ctx, Genesis, Height, Validator, ValidatorSet};

pub mod mock_bitcoin;
pub mod reactor;
pub mod state_log;

pub use reactor::FinalityEvent;
pub use reactor::StateEvent;

/// A decided batch observed from a node.
#[derive(Debug, Clone)]
pub struct DecidedBatch {
    pub node_index: usize,
    pub consensus_height: Height,
    pub value: Value,
}

/// Minimal config implementing NodeConfig for start_engine.
#[derive(Clone, Debug, Default)]
pub struct SimConfig {
    pub moniker: String,
    pub consensus: ConsensusConfig,
    pub value_sync: ValueSyncConfig,
}

impl NodeConfig for SimConfig {
    fn moniker(&self) -> &str {
        &self.moniker
    }
    fn consensus(&self) -> &ConsensusConfig {
        &self.consensus
    }
    fn consensus_mut(&mut self) -> &mut ConsensusConfig {
        &mut self.consensus
    }
    fn value_sync(&self) -> &ValueSyncConfig {
        &self.value_sync
    }
    fn value_sync_mut(&mut self) -> &mut ValueSyncConfig {
        &mut self.value_sync
    }
}

pub fn make_config(index: usize, ports: &[u16]) -> SimConfig {
    let persistent_peers: Vec<_> = ports
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != index)
        .map(|(_, &port)| TransportProtocol::Tcp.multiaddr("127.0.0.1", port as usize))
        .collect();

    SimConfig {
        moniker: format!("sim-node-{index}"),
        consensus: ConsensusConfig {
            enabled: true,
            value_payload: ValuePayload::ProposalAndParts,
            p2p: P2pConfig {
                listen_addr: TransportProtocol::Tcp
                    .multiaddr("127.0.0.1", ports[index] as usize),
                persistent_peers,
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig::default(),
    }
}

/// Allocate `n` free TCP ports by binding to port 0 and reading the OS-assigned port.
pub fn allocate_ports(n: usize) -> std::io::Result<Vec<u16>> {
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        ports.push(listener.local_addr()?.port());
        listeners.push(listener);
    }
    // Drop listeners so the ports are available for Malachite to bind
    drop(listeners);
    Ok(ports)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_node(
    index: usize,
    private_key: PrivateKey,
    genesis: Genesis,
    config: SimConfig,
    mut bitcoin_rx: mpsc::Receiver<BitcoinEvent>,
    decided_tx: Option<mpsc::Sender<DecidedBatch>>,
    finality_tx: Option<mpsc::Sender<FinalityEvent>>,
    state_tx: Option<mpsc::Sender<StateEvent>>,
    ready_tx: Option<mpsc::Sender<usize>>,
    cancel: CancellationToken,
) -> Result<()> {
    let public_key = private_key.public_key();
    let address = Address::from_public_key(&public_key);
    let keypair = Keypair::ed25519_from_bytes(private_key.inner().to_bytes())?;

    info!(%address, "Starting validator");

    let ctx = Ctx::new();
    let wal_dir = tempfile::tempdir()?;
    let wal_path = wal_dir.path().join("consensus.wal");

    let identity =
        NetworkIdentity::new(config.moniker.clone(), keypair, Some(address.to_string()));

    let engine_provider = Ed25519Provider::new(private_key.clone());
    let app_provider = Ed25519Provider::new(private_key);

    let (mut channels, _engine_handle) = malachitebft_app_channel::start_engine(
        ctx,
        config,
        WalContext::new(wal_path, ProtobufCodec),
        NetworkContext::new(identity, ProtobufCodec),
        ConsensusContext::new(address, engine_provider),
        SyncContext::new(ProtobufCodec),
        RequestContext::new(100),
    )
    .await?;

    info!(node = index, "Engine started, entering app loop");

    // Signal that this node's engine is up and listening
    if let Some(tx) = ready_tx {
        let _ = tx.send(index).await;
    }

    let mut state =
        reactor::State::new(index, app_provider, genesis, address, decided_tx, finality_tx, state_tx);
    reactor::run(&mut state, &mut channels, &mut bitcoin_rx, cancel)
        .await
        .map_err(|e| eyre::eyre!("{e}"))?;

    drop(wal_dir);
    Ok(())
}

/// Handle to a running cluster of validators.
pub struct ClusterHandle {
    pub bitcoin_tx: broadcast::Sender<BitcoinEvent>,
    pub decided_rx: mpsc::Receiver<DecidedBatch>,
    pub finality_rx: mpsc::Receiver<FinalityEvent>,
    pub state_rx: mpsc::Receiver<StateEvent>,
    pub cancel: CancellationToken,
    join_set: JoinSet<()>,
    node_count: usize,
    ready_rx: mpsc::Receiver<usize>,
}

impl ClusterHandle {
    /// Wait for all nodes to signal readiness (engine started, port bound).
    pub async fn wait_for_ready(&mut self) {
        let timeout = Duration::from_secs(30);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        let mut ready_count = 0;
        while ready_count < self.node_count {
            tokio::select! {
                _ = &mut deadline => {
                    panic!(
                        "Cluster readiness timeout: only {}/{} nodes ready after {timeout:?}",
                        ready_count, self.node_count
                    );
                }
                Some(_node_index) = self.ready_rx.recv() => {
                    ready_count += 1;
                }
            }
        }
    }

    /// Send a bitcoin event to all nodes.
    pub fn send_bitcoin_event(&self, event: BitcoinEvent) {
        let _ = self.bitcoin_tx.send(event);
    }

    /// Collect decided batches until we have at least `count` per node, or timeout.
    /// Returns a map of node_index → decisions (in order).
    pub async fn wait_for_decisions(
        &mut self,
        count: usize,
        timeout: Duration,
    ) -> Vec<Vec<DecidedBatch>> {
        let mut results: Vec<Vec<DecidedBatch>> = (0..self.node_count).map(|_| Vec::new()).collect();

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if results.iter().all(|r| r.len() >= count) {
                break;
            }

            tokio::select! {
                _ = &mut deadline => break,
                Some(batch) = self.decided_rx.recv() => {
                    if (batch.node_index) < self.node_count {
                        results[batch.node_index].push(batch);
                    }
                }
            }
        }

        results
    }

    /// Collect finality events until we have at least `count`, or timeout.
    pub async fn wait_for_finality_events(
        &mut self,
        count: usize,
        timeout: Duration,
    ) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if events.len() >= count {
                break;
            }
            tokio::select! {
                _ = &mut deadline => break,
                Some(event) = self.finality_rx.recv() => {
                    events.push(event);
                }
            }
        }

        events
    }

    /// Collect state events until we have at least `count`, or timeout.
    pub async fn wait_for_state_events(
        &mut self,
        count: usize,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if events.len() >= count {
                break;
            }
            tokio::select! {
                _ = &mut deadline => break,
                Some(event) = self.state_rx.recv() => {
                    events.push(event);
                }
            }
        }

        events
    }

    /// Shut down the cluster.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        // Give nodes a moment to process the cancellation
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.join_set.shutdown().await;
    }
}

/// Spin up a cluster of `n` validators with Malachite consensus.
pub async fn run_cluster(n: usize) -> Result<ClusterHandle> {
    let mut rng = rand::thread_rng();
    let private_keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::generate(&mut rng)).collect();

    let validators: Vec<Validator> = private_keys
        .iter()
        .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
        .collect();

    let validator_set = ValidatorSet::new(validators);
    let genesis = Genesis { validator_set };

    let ports = allocate_ports(n)?;

    let (bitcoin_tx, _) = broadcast::channel::<BitcoinEvent>(256);
    let cancel = CancellationToken::new();

    // Single merged channels for observation
    let (decided_tx, decided_rx) = mpsc::channel(1024);
    let (finality_tx, finality_rx) = mpsc::channel(1024);
    let (state_tx, state_rx) = mpsc::channel(1024);
    let (ready_tx, ready_rx) = mpsc::channel(n);

    let mut join_set = JoinSet::new();

    for (i, private_key) in private_keys.into_iter().enumerate() {
        let genesis = genesis.clone();
        let config = make_config(i, &ports);
        let cancel = cancel.clone();

        // Per-node: bridge broadcast → mpsc for bitcoin events
        let bitcoin_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = bitcoin_tx.subscribe();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = brx.recv() => {
                            match result {
                                Ok(event) => {
                                    if tx.send(event).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });
            rx
        };

        let dtx = decided_tx.clone();
        let ftx = finality_tx.clone();
        let stx = state_tx.clone();
        let rtx = ready_tx.clone();

        join_set.spawn(
            async move {
                if let Err(e) =
                    run_node(i, private_key, genesis, config, bitcoin_rx, Some(dtx), Some(ftx), Some(stx), Some(rtx), cancel).await
                {
                    tracing::error!(node = i, error = %e, "Node exited with error");
                }
            }
            .instrument(tracing::info_span!("validator", id = i)),
        );
    }

    Ok(ClusterHandle {
        bitcoin_tx,
        decided_rx,
        finality_rx,
        state_rx,
        cancel,
        join_set,
        node_count: n,
        ready_rx,
    })
}
