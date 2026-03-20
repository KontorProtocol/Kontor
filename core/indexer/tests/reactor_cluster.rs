use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::reactor::mock_bitcoin::MockBitcoin;
use indexer::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Genesis, Validator, ValidatorSet};
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::{ConsensusState, ObservationChannels};
use indexer::reactor::engine::{self, EngineConfig};
use indexer::reactor::mock_executor::MockExecutor;
use indexer::reactor::{ConsensusHandle, Reactor};
use malachitebft_app_channel::app::types::core::VotingPower;

fn allocate_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Handle to a running cluster of validators using the prod reactor + StateLog.
#[allow(dead_code)]
struct ReactorCluster {
    block_tx: broadcast::Sender<BlockEvent>,
    mempool_tx: broadcast::Sender<MempoolEvent>,
    decided_rx: mpsc::Receiver<DecidedBatch>,
    finality_rx: mpsc::Receiver<FinalityEvent>,
    state_rx: mpsc::Receiver<StateEvent>,
    cancel: CancellationToken,
    join_set: JoinSet<()>,
    node_count: usize,
    ready_rx: mpsc::Receiver<usize>,
}

#[allow(dead_code)]
impl ReactorCluster {
    async fn start(n: usize) -> Result<Self> {
        let private_keys: Vec<PrivateKey> = (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[31] = 42;
                PrivateKey::from(seed)
            })
            .collect();

        let validators: Vec<Validator> = private_keys
            .iter()
            .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
            .collect();

        let validator_set = ValidatorSet::new(validators);
        let genesis = Genesis { validator_set };

        let ports: Vec<u16> = (0..n)
            .map(|_| allocate_port().expect("Failed to allocate port"))
            .collect();

        let (block_tx, _) = broadcast::channel::<BlockEvent>(256);
        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = CancellationToken::new();

        let (decided_tx, decided_rx) = mpsc::channel(1024);
        let (finality_tx, finality_rx) = mpsc::channel(1024);
        let (state_tx, state_rx) = mpsc::channel(1024);
        let (ready_tx, ready_rx) = mpsc::channel(n);

        let mut join_set = JoinSet::new();

        for (i, private_key) in private_keys.into_iter().enumerate() {
            let genesis = genesis.clone();
            let engine_config = EngineConfig {
                private_key,
                listen_addr: format!("/ip4/127.0.0.1/tcp/{}", ports[i]),
                persistent_peers: ports
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, &port)| format!("/ip4/127.0.0.1/tcp/{port}"))
                    .collect(),
            };
            let cancel = cancel.clone();

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
                                    Ok(event) => { if tx.send(event).await.is_err() { break; } }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
                rx
            };

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
                                    Ok(event) => { if tx.send(event).await.is_err() { break; } }
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

            join_set.spawn(async move {
                let engine_output = match engine::start(engine_config, &genesis).await {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::error!(node = i, %e, "Failed to start engine");
                        return;
                    }
                };

                info!(node = i, address = %engine_output.address, "Engine started");

                let node_index = genesis
                    .validator_set
                    .validators
                    .iter()
                    .position(|v| v.address == engine_output.address)
                    .unwrap_or(i);

                let mut state = ConsensusState::new(
                    engine_output.signing_provider,
                    genesis,
                    engine_output.address,
                );
                state.observation = Some(ObservationChannels {
                    decided_tx: dtx,
                    finality_tx: ftx,
                    state_tx: stx,
                });

                let consensus_handle = ConsensusHandle {
                    state,
                    channels: engine_output.channels,
                    _engine_handle: engine_output._handle,
                    _wal_dir: engine_output._wal_dir,
                    node_index,
                };

                let executor = MockExecutor::new();
                let bitcoin_state = BitcoinState::new();

                let mut reactor = Reactor::new(
                    executor,
                    node_block_rx,
                    node_mempool_rx,
                    cancel.clone(),
                    None,
                    None,
                    None,
                    bitcoin_state,
                    Some(consensus_handle),
                    0,
                    None,
                );

                let _ = rtx.send(i).await;

                if let Err(e) = reactor.run().await {
                    tracing::error!(node = i, %e, "Reactor error");
                }
            });
        }

        Ok(Self {
            block_tx,
            mempool_tx,
            decided_rx,
            finality_rx,
            state_rx,
            cancel,
            join_set,
            node_count: n,
            ready_rx,
        })
    }

    async fn wait_for_ready(&mut self) {
        for _ in 0..self.node_count {
            let _ = self.ready_rx.recv().await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    fn send_block_event(&self, event: BlockEvent) {
        let _ = self.block_tx.send(event);
    }

    fn send_mempool_event(&self, event: MempoolEvent) {
        let _ = self.mempool_tx.send(event);
    }

    async fn wait_for_decisions(&mut self, count: usize, timeout: Duration) -> Vec<DecidedBatch> {
        let mut batches = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            if batches.len() >= count {
                break;
            }
            tokio::select! {
                _ = &mut deadline => break,
                Some(batch) = self.decided_rx.recv() => {
                    batches.push(batch);
                }
            }
        }
        batches
    }

    async fn wait_for_state_events(&mut self, count: usize, timeout: Duration) -> Vec<StateEvent> {
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

    async fn wait_for_finality_events(
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

    async fn shutdown(mut self) {
        self.cancel.cancel();
        while self.join_set.join_next().await.is_some() {}
    }
}

/// Basic test: 4 validators decide a batch with mempool txs.
/// Same as consensus-sim's `validators_agree_on_values` but through the prod reactor.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_validators_agree_on_values() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for consensus to decide
    let results = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!results.is_empty(), "Expected at least one decision");

    // All nodes should produce BatchApplied with same checkpoint
    let state_events = cluster
        .wait_for_state_events(8, Duration::from_secs(10))
        .await;

    let batch_applied: Vec<_> = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::BatchApplied { .. }))
        .collect();

    assert!(
        batch_applied.len() >= 4,
        "Expected at least 4 BatchApplied events (one per node), got {}",
        batch_applied.len()
    );

    cluster.shutdown().await;
    Ok(())
}
