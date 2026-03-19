use std::time::Duration;

use eyre::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info};

use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Genesis, Validator, ValidatorSet};
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::ConsensusState;
use indexer::reactor::engine::{EngineConfig, start as start_engine};
use malachitebft_app_channel::app::types::core::VotingPower;

pub mod mock_bitcoin;
pub mod reactor;
pub mod state_log;

pub use reactor::FinalityEvent;
pub use reactor::StateEvent;

pub use indexer::consensus::finality_types::DecidedBatch;

pub fn make_engine_config(index: usize, ports: &[u16], private_key: PrivateKey) -> EngineConfig {
    let listen_addr = format!("/ip4/127.0.0.1/tcp/{}", ports[index]);
    let persistent_peers: Vec<String> = ports
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != index)
        .map(|(_, &port)| format!("/ip4/127.0.0.1/tcp/{port}"))
        .collect();

    EngineConfig {
        private_key,
        listen_addr,
        persistent_peers,
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
    engine_config: EngineConfig,
    genesis: Genesis,
    mut block_rx: mpsc::Receiver<BlockEvent>,
    mut mempool_rx: mpsc::Receiver<MempoolEvent>,
    decided_tx: Option<mpsc::Sender<DecidedBatch>>,
    finality_tx: Option<mpsc::Sender<FinalityEvent>>,
    state_tx: Option<mpsc::Sender<StateEvent>>,
    ready_tx: Option<mpsc::Sender<usize>>,
    cancel: CancellationToken,
) -> Result<()> {
    let engine_output = start_engine(engine_config, &genesis)
        .await
        .map_err(|e| eyre::eyre!("{e}"))?;

    info!(address = %engine_output.address, node = index, "Engine started, entering app loop");

    // Signal that this node's engine is up and listening
    if let Some(tx) = ready_tx {
        let _ = tx.send(index).await;
    }

    let mut consensus_state = ConsensusState::new(
        engine_output.signing_provider,
        genesis,
        engine_output.address,
    );
    if let (Some(dtx), Some(ftx), Some(stx)) = (decided_tx, finality_tx, state_tx) {
        consensus_state.observation = Some(indexer::reactor::consensus::ObservationChannels {
            decided_tx: dtx,
            finality_tx: ftx,
            state_tx: stx,
        });
    }

    let mut executor = state_log::StateLog::new();
    let mut bitcoin_state = BitcoinState::new();
    let mut channels = engine_output.channels;

    reactor::run(
        &mut consensus_state,
        &mut executor,
        &mut bitcoin_state,
        index,
        &mut channels,
        &mut block_rx,
        &mut mempool_rx,
        cancel,
    )
    .await
    .map_err(|e| eyre::eyre!("{e}"))?;

    Ok(())
}

/// Handle to a running cluster of validators.
pub struct ClusterHandle {
    pub block_tx: broadcast::Sender<BlockEvent>,
    pub mempool_tx: broadcast::Sender<MempoolEvent>,
    pub decided_rx: mpsc::Receiver<DecidedBatch>,
    pub finality_rx: mpsc::Receiver<FinalityEvent>,
    pub state_rx: mpsc::Receiver<StateEvent>,
    pub cancel: CancellationToken,
    join_set: JoinSet<()>,
    node_count: usize,
    ready_rx: mpsc::Receiver<usize>,
    // Stored for add_node
    genesis: Genesis,
    ports: Vec<u16>,
    decided_tx: mpsc::Sender<DecidedBatch>,
    finality_tx: mpsc::Sender<FinalityEvent>,
    state_tx: mpsc::Sender<StateEvent>,
    ready_tx: mpsc::Sender<usize>,
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

    /// Wait for a single node to signal readiness.
    pub async fn wait_for_node_ready(&mut self) {
        let timeout = Duration::from_secs(30);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        tokio::select! {
            _ = &mut deadline => {
                panic!("Node readiness timeout after {timeout:?}");
            }
            Some(_node_index) = self.ready_rx.recv() => {}
        }
    }

    /// Add a new node to the running cluster. Allocates a port, bridges
    /// broadcast events, and spawns the node. Call `wait_for_node_ready`
    /// after to ensure the engine is up.
    pub fn add_node(&mut self, private_key: PrivateKey) -> Result<usize> {
        let index = self.node_count;

        // Allocate a port for the new node
        let new_ports = allocate_ports(1).map_err(|e| eyre::eyre!("{e}"))?;
        self.ports.push(new_ports[0]);

        let engine_config = make_engine_config(index, &self.ports, private_key);

        // Bridge broadcast → mpsc for block events
        let node_block_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = self.block_tx.subscribe();
            let cancel = self.cancel.clone();
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

        // Bridge broadcast → mpsc for mempool events
        let node_mempool_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = self.mempool_tx.subscribe();
            let cancel = self.cancel.clone();
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

        let genesis = self.genesis.clone();
        let dtx = self.decided_tx.clone();
        let ftx = self.finality_tx.clone();
        let stx = self.state_tx.clone();
        let rtx = self.ready_tx.clone();
        let cancel = self.cancel.clone();

        self.join_set.spawn(
            async move {
                if let Err(e) = run_node(
                    index,
                    engine_config,
                    genesis,
                    node_block_rx,
                    node_mempool_rx,
                    Some(dtx),
                    Some(ftx),
                    Some(stx),
                    Some(rtx),
                    cancel,
                )
                .await
                {
                    tracing::error!(node = index, error = %e, "Node exited with error");
                }
            }
            .instrument(tracing::info_span!("validator", id = index)),
        );

        self.node_count += 1;
        Ok(index)
    }

    /// Send a block event to all nodes.
    pub fn send_block_event(&self, event: BlockEvent) {
        let _ = self.block_tx.send(event);
    }

    /// Send a mempool event to all nodes.
    pub fn send_mempool_event(&self, event: MempoolEvent) {
        let _ = self.mempool_tx.send(event);
    }

    /// Collect decided batches until we have at least `count` per node, or timeout.
    /// Returns a map of node_index → decisions (in order).
    pub async fn wait_for_decisions(
        &mut self,
        count: usize,
        timeout: Duration,
    ) -> Vec<Vec<DecidedBatch>> {
        let mut results: Vec<Vec<DecidedBatch>> =
            (0..self.node_count).map(|_| Vec::new()).collect();

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
    run_cluster_from_keys(private_keys, n).await
}

/// Create a cluster with `total` validators in genesis but only start `start_count`.
/// Returns the cluster handle and the private keys of the unstarted nodes.
pub async fn run_cluster_delayed(
    total: usize,
    start_count: usize,
) -> Result<(ClusterHandle, Vec<PrivateKey>)> {
    assert!(start_count <= total);
    let mut rng = rand::thread_rng();
    let private_keys: Vec<PrivateKey> =
        (0..total).map(|_| PrivateKey::generate(&mut rng)).collect();
    let remaining_keys = private_keys[start_count..].to_vec();
    let handle = run_cluster_from_keys(private_keys, start_count).await?;
    Ok((handle, remaining_keys))
}

/// Internal: create genesis from all keys, start `start_count` nodes.
async fn run_cluster_from_keys(
    private_keys: Vec<PrivateKey>,
    start_count: usize,
) -> Result<ClusterHandle> {
    let validators: Vec<Validator> = private_keys
        .iter()
        .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
        .collect();

    let validator_set = ValidatorSet::new(validators);
    let genesis = Genesis { validator_set };

    let ports = allocate_ports(start_count)?;

    let (block_tx, _) = broadcast::channel::<BlockEvent>(256);
    let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
    let cancel = CancellationToken::new();

    // Single merged channels for observation
    let (decided_tx, decided_rx) = mpsc::channel(1024);
    let (finality_tx, finality_rx) = mpsc::channel(1024);
    let (state_tx, state_rx) = mpsc::channel(1024);
    let (ready_tx, ready_rx) = mpsc::channel(private_keys.len());

    let mut join_set = JoinSet::new();

    for (i, private_key) in private_keys.into_iter().take(start_count).enumerate() {
        let genesis = genesis.clone();
        let engine_config = make_engine_config(i, &ports, private_key);
        let cancel = cancel.clone();
        // Per-node: bridge broadcast → mpsc for block events
        let node_block_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = block_tx.subscribe();
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

        // Per-node: bridge broadcast → mpsc for mempool events
        let node_mempool_rx = {
            let (tx, rx) = mpsc::channel(256);
            let mut brx = mempool_tx.subscribe();
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
                if let Err(e) = run_node(
                    i,
                    engine_config,
                    genesis,
                    node_block_rx,
                    node_mempool_rx,
                    Some(dtx),
                    Some(ftx),
                    Some(stx),
                    Some(rtx),
                    cancel,
                )
                .await
                {
                    tracing::error!(node = i, error = %e, "Node exited with error");
                }
            }
            .instrument(tracing::info_span!("validator", id = i)),
        );
    }

    Ok(ClusterHandle {
        block_tx,
        mempool_tx,
        decided_rx,
        finality_rx,
        state_rx,
        cancel,
        join_set,
        node_count: start_count,
        ready_rx,
        genesis,
        ports,
        decided_tx,
        finality_tx,
        state_tx,
        ready_tx,
    })
}
