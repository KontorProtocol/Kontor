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

pub fn make_config(index: usize, total: usize, base_port: usize) -> SimConfig {
    let persistent_peers: Vec<_> = (0..total)
        .filter(|j| *j != index)
        .map(|j| TransportProtocol::Tcp.multiaddr("127.0.0.1", base_port + j))
        .collect();

    SimConfig {
        moniker: format!("sim-node-{index}"),
        consensus: ConsensusConfig {
            enabled: true,
            value_payload: ValuePayload::ProposalAndParts,
            p2p: P2pConfig {
                listen_addr: TransportProtocol::Tcp
                    .multiaddr("127.0.0.1", base_port + index),
                persistent_peers,
                ..Default::default()
            },
            ..Default::default()
        },
        value_sync: ValueSyncConfig::default(),
    }
}

pub async fn run_node(
    index: usize,
    private_key: PrivateKey,
    genesis: Genesis,
    config: SimConfig,
    mut bitcoin_rx: mpsc::Receiver<BitcoinEvent>,
    decided_tx: Option<mpsc::Sender<DecidedBatch>>,
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

    let mut state = reactor::State::new(index, app_provider, genesis, address, decided_tx);
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
    pub cancel: CancellationToken,
    join_set: JoinSet<()>,
    node_count: usize,
}

impl ClusterHandle {
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

    /// Shut down the cluster.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        // Give nodes a moment to process the cancellation
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.join_set.shutdown().await;
    }
}

/// Spin up a cluster of `n` validators with Malachite consensus.
pub async fn run_cluster(n: usize, base_port: usize) -> Result<ClusterHandle> {
    let mut rng = rand::thread_rng();
    let private_keys: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::generate(&mut rng)).collect();

    let validators: Vec<Validator> = private_keys
        .iter()
        .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
        .collect();

    let validator_set = ValidatorSet::new(validators);
    let genesis = Genesis { validator_set };

    let (bitcoin_tx, _) = broadcast::channel::<BitcoinEvent>(256);
    let cancel = CancellationToken::new();

    // Single merged channel for all decided batches
    let (decided_tx, decided_rx) = mpsc::channel(1024);

    let mut join_set = JoinSet::new();

    for (i, private_key) in private_keys.into_iter().enumerate() {
        let genesis = genesis.clone();
        let config = make_config(i, n, base_port);
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

        join_set.spawn(
            async move {
                if let Err(e) =
                    run_node(i, private_key, genesis, config, bitcoin_rx, Some(dtx), cancel).await
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
        cancel,
        join_set,
        node_count: n,
    })
}
