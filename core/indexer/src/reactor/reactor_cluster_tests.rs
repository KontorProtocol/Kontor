use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Genesis, Validator, ValidatorSet};
use crate::reactor::consensus::{ConsensusState, ObservationChannels};
use crate::reactor::engine::{self, EngineConfig};
use crate::reactor::lite_executor::{LiteExecutor, shared_engine_and_cache};
use crate::reactor::mock_bitcoin::MockBitcoin;
use crate::reactor::{ConsensusHandle, Reactor};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::GenesisValidator;
use malachitebft_app_channel::app::types::core::VotingPower;
use malachitebft_core_types::LinearTimeouts;

fn allocate_port() -> u16 {
    static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(19000);
    NEXT_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

async fn wait_matching<T>(
    rx: &mut mpsc::Receiver<T>,
    pred: impl Fn(&T) -> bool,
    n: usize,
    timeout: Duration,
) -> Vec<T> {
    let mut events = Vec::new();
    let mut matched = 0;
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        if matched >= n {
            break;
        }
        tokio::select! {
            _ = &mut deadline => break,
            Some(event) = rx.recv() => {
                if pred(&event) { matched += 1; }
                events.push(event);
            }
        }
    }
    events
}

#[allow(dead_code)]
struct ReactorCluster {
    block_txs: Vec<mpsc::Sender<BlockEvent>>,
    mempool_tx: broadcast::Sender<MempoolEvent>,
    decided_rx: mpsc::Receiver<DecidedBatch>,
    finality_rx: mpsc::Receiver<FinalityEvent>,
    state_rx: mpsc::Receiver<StateEvent>,
    cancel: CancellationToken,
    join_set: JoinSet<()>,
    node_count: usize,
    ready_rx: mpsc::Receiver<usize>,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    genesis: Genesis,
    genesis_validators: Vec<GenesisValidator>,
    private_keys: Vec<PrivateKey>,
    ports: Vec<u16>,
    shared_pubkey: String,
    engine: wasmtime::Engine,
    component_cache: crate::runtime::ComponentCache,
    decided_tx: mpsc::Sender<DecidedBatch>,
    finality_tx: mpsc::Sender<FinalityEvent>,
    state_tx: mpsc::Sender<StateEvent>,
    ready_tx: mpsc::Sender<usize>,
    started_nodes: Vec<bool>,
}

#[allow(dead_code)]
impl ReactorCluster {
    async fn start_with(total: usize, initial: usize) -> Result<Self> {
        let private_keys: Vec<PrivateKey> = (0..total)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[31] = 42;
                PrivateKey::from(seed)
            })
            .collect();

        let validators: Vec<Validator> = private_keys
            .iter()
            .map(|pk| Validator::new(pk.public_key(), 100 as VotingPower))
            .collect();

        let genesis_validators: Vec<GenesisValidator> = private_keys
            .iter()
            .enumerate()
            .map(|(i, pk)| GenesisValidator {
                x_only_pubkey: format!("{:064x}", i + 1),
                stake: crate::runtime::Decimal::from(100u64),
                ed25519_pubkey: pk.public_key().as_bytes().to_vec(),
            })
            .collect();

        let validator_set = ValidatorSet::new(validators);
        let genesis = Genesis { validator_set };

        let ports: Vec<u16> = (0..total).map(|_| allocate_port()).collect();

        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = CancellationToken::new();
        let mut block_txs = Vec::new();
        let mock_bitcoin = Arc::new(Mutex::new(MockBitcoin::new(0)));
        let shared_pubkey = random_x_only_pubkey();
        let (engine, component_cache) = shared_engine_and_cache().await;

        let (decided_tx, decided_rx) = mpsc::channel(1024);
        let (finality_tx, finality_rx) = mpsc::channel(1024);
        let (state_tx, state_rx) = mpsc::channel(1024);
        let (ready_tx, ready_rx) = mpsc::channel(total);

        let mut join_set = JoinSet::new();
        let mut started_nodes = vec![false; total];

        for i in 0..initial {
            let (node_block_tx, node_block_rx) = mpsc::channel(256);
            block_txs.push(node_block_tx.clone());

            let node_mempool_rx = Self::bridge_mempool(&mempool_tx, &cancel);

            Self::spawn_node(
                i,
                private_keys[i].clone(),
                &genesis,
                &genesis_validators,
                &ports,
                node_block_tx,
                node_block_rx,
                node_mempool_rx,
                cancel.clone(),
                decided_tx.clone(),
                finality_tx.clone(),
                state_tx.clone(),
                ready_tx.clone(),
                mock_bitcoin.clone(),
                shared_pubkey.clone(),
                engine.clone(),
                component_cache.clone(),
                &mut join_set,
            );
            started_nodes[i] = true;
        }

        Ok(Self {
            block_txs,
            mempool_tx,
            decided_rx,
            finality_rx,
            state_rx,
            cancel,
            join_set,
            node_count: initial,
            ready_rx,
            mock_bitcoin,
            genesis,
            genesis_validators,
            private_keys,
            ports,
            shared_pubkey,
            engine,
            component_cache,
            decided_tx,
            finality_tx,
            state_tx,
            ready_tx,
            started_nodes,
        })
    }

    async fn start(n: usize) -> Result<Self> {
        Self::start_with(n, n).await
    }

    fn bridge_mempool(
        mempool_tx: &broadcast::Sender<MempoolEvent>,
        cancel: &CancellationToken,
    ) -> mpsc::Receiver<MempoolEvent> {
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
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_node(
        i: usize,
        private_key: PrivateKey,
        genesis: &Genesis,
        genesis_validators: &[GenesisValidator],
        ports: &[u16],
        node_block_tx: mpsc::Sender<BlockEvent>,
        node_block_rx: mpsc::Receiver<BlockEvent>,
        node_mempool_rx: mpsc::Receiver<MempoolEvent>,
        cancel: CancellationToken,
        dtx: mpsc::Sender<DecidedBatch>,
        ftx: mpsc::Sender<FinalityEvent>,
        stx: mpsc::Sender<StateEvent>,
        rtx: mpsc::Sender<usize>,
        mock_btc: Arc<Mutex<MockBitcoin>>,
        pubkey: String,
        engine: wasmtime::Engine,
        component_cache: crate::runtime::ComponentCache,
        join_set: &mut JoinSet<()>,
    ) {
        let genesis = genesis.clone();
        let genesis_vals = genesis_validators.to_vec();
        let ports = ports.to_vec();
        join_set.spawn(async move {
            let (executor, runtime) = LiteExecutor::new(
                mock_btc,
                pubkey,
                &genesis_vals,
                engine,
                component_cache,
                node_block_tx,
            )
            .await
            .expect("LiteExecutor setup failed");

            let engine_config = EngineConfig {
                private_key,
                listen_addr: format!("/ip4/127.0.0.1/tcp/{}", ports[i]),
                persistent_peers: ports
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, &port)| format!("/ip4/127.0.0.1/tcp/{port}"))
                    .collect(),
                data_dir: executor.data_dir(),
            };

            let conn = runtime.get_storage_conn();

            let engine_output = match engine::start(engine_config, &genesis).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!(node = i, %e, "Failed to start engine");
                    return;
                }
            };

            info!(node = i, address = %engine_output.address, "Engine started");

            let validator_index = genesis
                .validator_set
                .validators
                .iter()
                .position(|v| v.address == engine_output.address);

            let mut state = ConsensusState::new(
                conn.clone(),
                engine_output.signing_provider,
                genesis,
                engine_output.address,
            );
            state.timeouts = LinearTimeouts {
                propose: Duration::from_millis(500),
                ..Default::default()
            };
            state.observation = Some(ObservationChannels {
                decided_tx: dtx,
                finality_tx: ftx,
                state_tx: stx,
            });

            let consensus_handle = ConsensusHandle {
                state,
                channels: engine_output.channels,
                _engine_handle: engine_output._handle,
                validator_index,
            };

            let mut reactor = Reactor::new(
                executor,
                runtime,
                node_block_rx,
                node_mempool_rx,
                cancel.clone(),
                None,
                None,
                None,
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

    async fn add_node(&mut self) -> Result<usize> {
        let i = self
            .started_nodes
            .iter()
            .position(|&started| !started)
            .ok_or_else(|| anyhow::anyhow!("All nodes already started"))?;

        let (node_block_tx, node_block_rx) = mpsc::channel(256);
        self.block_txs.push(node_block_tx.clone());

        let node_mempool_rx = Self::bridge_mempool(&self.mempool_tx, &self.cancel);

        Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis,
            &self.genesis_validators,
            &self.ports,
            node_block_tx,
            node_block_rx,
            node_mempool_rx,
            self.cancel.clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            self.engine.clone(),
            self.component_cache.clone(),
            &mut self.join_set,
        );

        self.started_nodes[i] = true;
        self.node_count += 1;

        let _ = self.ready_rx.recv().await;

        Ok(i)
    }

    async fn wait_for_ready(&mut self) {
        for _ in 0..self.node_count {
            let _ = self.ready_rx.recv().await;
        }
    }

    fn send_block_event(&self, event: BlockEvent) {
        for tx in &self.block_txs {
            let _ = tx.try_send(event.clone());
        }
    }

    fn send_mempool_event(&self, event: MempoolEvent) {
        let _ = self.mempool_tx.send(event);
    }

    fn mock_bitcoin(&self) -> std::sync::MutexGuard<'_, MockBitcoin> {
        self.mock_bitcoin.lock().unwrap()
    }

    fn mine_and_send(&self, txids: &[bitcoin::Txid]) {
        let (blk_events, mem_events) = if txids.is_empty() {
            self.mock_bitcoin().mine_block_all()
        } else {
            self.mock_bitcoin().mine_block(txids)
        };
        for event in mem_events {
            self.send_mempool_event(event);
        }
        for event in blk_events {
            self.send_block_event(event);
        }
    }

    fn mine_empty_and_send(&self) {
        let (blk_events, mem_events) = self.mock_bitcoin().mine_block(&[]);
        for event in mem_events {
            self.send_mempool_event(event);
        }
        for event in blk_events {
            self.send_block_event(event);
        }
    }

    async fn wait_for_decision_matching(
        &mut self,
        pred: impl Fn(&DecidedBatch) -> bool,
        timeout: Duration,
    ) -> Vec<DecidedBatch> {
        wait_matching(&mut self.decided_rx, pred, 1, timeout).await
    }

    async fn wait_for_state_event_matching(
        &mut self,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, 1, timeout).await
    }

    async fn wait_for_finality_event_matching(
        &mut self,
        pred: impl Fn(&FinalityEvent) -> bool,
        timeout: Duration,
    ) -> Vec<FinalityEvent> {
        wait_matching(&mut self.finality_rx, pred, 1, timeout).await
    }

    async fn wait_for_n_state_events_matching(
        &mut self,
        n: usize,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, n, timeout).await
    }

    async fn shutdown(mut self) {
        self.cancel.cancel();
        while self.join_set.join_next().await.is_some() {}
    }
}

impl Drop for ReactorCluster {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[tokio::test]
async fn prod_reactor_validators_agree_on_values() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        decisions.iter().any(|d| !d.value.batch_txids().is_empty()),
        "Expected a batch decision with txids"
    );

    let state_events = cluster
        .wait_for_n_state_events_matching(
            cluster.node_count,
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(10),
        )
        .await;

    let batch_applied_count = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::BatchApplied { .. }))
        .count();
    assert!(
        batch_applied_count >= cluster.node_count,
        "Expected at least {} BatchApplied events (one per node), got {batch_applied_count}",
        cluster.node_count
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_block_updates_anchor() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 0
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;
    assert!(
        decisions.iter().any(|d| d.value.block_height() == 0),
        "Expected a batch at anchor 0"
    );

    cluster.mine_and_send(&[]);

    let block_decisions = cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;
    assert!(
        block_decisions
            .iter()
            .any(|d| d.value.is_block() && d.value.block_height() == 1),
        "Expected a Value::Block decision at height 1"
    );

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    let batch_at_1 = cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;
    assert!(
        batch_at_1
            .iter()
            .any(|d| !d.value.is_block() && d.value.block_height() == 1),
        "Expected a Value::Batch anchored at height 1"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_happy_path_finalization() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        decisions.iter().any(|d| d.value.block_height() == 0),
        "Expected a batch at anchor 0"
    );

    cluster.mine_and_send(&[]);

    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0),
            Duration::from_secs(60),
        )
        .await;

    assert!(
        finality_events.iter().any(
            |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0)
        ),
        "Expected BatchFinalized at anchor 0, got: {finality_events:?}"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_missing_tx_invalidation() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    cluster.mine_empty_and_send();
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    let mempool_events = cluster.mock_bitcoin().generate_mempool_txs(3);
    let all_txids: Vec<bitcoin::Txid> = mempool_events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::Insert(tx) => Some(tx.compute_txid()),
            _ => None,
        })
        .collect();
    for event in mempool_events {
        cluster.send_mempool_event(event);
    }

    cluster
        .wait_for_n_state_events_matching(
            cluster.node_count,
            |e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count > 0),
            Duration::from_secs(60),
        )
        .await;

    let confirm_txids: Vec<bitcoin::Txid> = all_txids[..2].to_vec();
    let missing_txid = all_txids[2];

    cluster.mine_and_send(&confirm_txids);

    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if missing_txids.contains(&missing_txid)),
            Duration::from_secs(60),
        )
        .await;

    assert!(
        finality_events.iter().any(
            |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if missing_txids.contains(&missing_txid))
        ),
        "Expected Rollback with missing txid {missing_txid}, got: {finality_events:?}"
    );

    let all_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count == 2),
            Duration::from_secs(60),
        )
        .await;

    let has_rollback = all_events
        .iter()
        .any(|e| matches!(e, StateEvent::RollbackExecuted { .. }));
    assert!(has_rollback, "Expected RollbackExecuted event");

    let replayed_batches: Vec<_> = all_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BatchApplied { txid_count, .. } => Some(*txid_count),
            _ => None,
        })
        .collect();

    assert!(
        replayed_batches.contains(&2),
        "Expected replayed batch with 2 txids (excluding missing), got counts: {replayed_batches:?}"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_cascade_invalidation() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_empty_and_send();

    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;

    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { .. }),
            Duration::from_secs(60),
        )
        .await;

    let rollback = finality_events
        .iter()
        .find(|e| matches!(e, FinalityEvent::Rollback { .. }));
    assert!(
        rollback.is_some(),
        "Expected Rollback event, got: {finality_events:?}"
    );

    if let Some(FinalityEvent::Rollback {
        invalidated_batches,
        ..
    }) = rollback
    {
        assert!(
            invalidated_batches.len() >= 2,
            "Expected cascade to invalidate >= 2 batches, got {}",
            invalidated_batches.len()
        );
    }

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_cross_block_cascade_invalidation() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;
    let batch0_txids = decisions
        .iter()
        .find(|d| !d.value.batch_txids().is_empty())
        .unwrap()
        .value
        .batch_txids()
        .to_vec();

    cluster.mine_and_send(&batch0_txids);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_empty_and_send();
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(60),
        )
        .await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 2
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_empty_and_send();

    for _ in 0..4 {
        cluster.mine_empty_and_send();
    }

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1),
            Duration::from_secs(60),
        )
        .await;

    let rollback = finality_events
        .iter()
        .find(|e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1));
    assert!(
        rollback.is_some(),
        "Expected Rollback from anchor 1, got: {finality_events:?}"
    );

    if let Some(FinalityEvent::Rollback {
        invalidated_batches,
        ..
    }) = rollback
    {
        assert!(
            invalidated_batches.len() >= 2,
            "Expected cascade to invalidate batches at anchor 1 and 2, got {}",
            invalidated_batches.len()
        );
    }

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_batch_before_unbatched_at_same_anchor() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    let mempool_events = cluster.mock_bitcoin().generate_mempool_txs(2);
    let batch_txids: Vec<bitcoin::Txid> = mempool_events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::Insert(tx) => Some(tx.compute_txid()),
            _ => None,
        })
        .collect();
    for event in mempool_events {
        cluster.send_mempool_event(event);
    }

    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;

    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_and_send(&batch_txids);

    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    let block_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height, .. } if *height == 1),
            Duration::from_secs(60),
        )
        .await;
    let block_processed = block_events
        .iter()
        .find(|e| matches!(e, StateEvent::BlockProcessed { height, .. } if *height == 1));
    assert!(
        matches!(
            block_processed,
            Some(StateEvent::BlockProcessed {
                unbatched_count: 0,
                ..
            })
        ),
        "All block txs should be deduped (unbatched_count=0), got: {block_processed:?}"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_rollback_preserves_pre_anchor_state() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;

    cluster
        .wait_for_state_event_matching(
            |e| {
                matches!(
                    e,
                    StateEvent::BatchApplied {
                        anchor_height: 0,
                        ..
                    }
                )
            },
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;

    for _ in 0..6 {
        cluster.mine_empty_and_send();
    }

    cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1),
            Duration::from_secs(60),
        )
        .await;

    let rollback_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::RollbackExecuted { .. }),
            Duration::from_secs(60),
        )
        .await;
    let rollback_event = rollback_events
        .iter()
        .find(|e| matches!(e, StateEvent::RollbackExecuted { .. }));
    assert!(
        matches!(
            rollback_event,
            Some(StateEvent::RollbackExecuted {
                to_anchor: 1,
                checkpoint: Some(_),
                ..
            })
        ),
        "Expected RollbackExecuted to anchor 1 with checkpoint, got: {rollback_event:?}"
    );

    let rollback_checkpoint = match rollback_event.unwrap() {
        StateEvent::RollbackExecuted { checkpoint, .. } => *checkpoint,
        _ => unreachable!(),
    };
    assert!(
        rollback_checkpoint.is_some(),
        "Expected valid checkpoint after rollback (pre-anchor state preserved)"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_all_nodes_reach_same_checkpoint() -> Result<()> {
    crate::logging::setup();

    let num_nodes = 3;
    let mut cluster = ReactorCluster::start(num_nodes).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    let events = cluster
        .wait_for_n_state_events_matching(
            num_nodes,
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(60),
        )
        .await;
    let checkpoints: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed {
                height: 1,
                checkpoint,
                ..
            } => Some(*checkpoint),
            _ => None,
        })
        .collect();
    assert_eq!(
        checkpoints.len(),
        num_nodes,
        "Expected {num_nodes} BlockProcessed events at height 1"
    );
    assert!(
        checkpoints.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same checkpoint at height 1: {checkpoints:?}"
    );

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(60),
        )
        .await;
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(60),
        )
        .await;

    let events = cluster
        .wait_for_n_state_events_matching(
            num_nodes,
            |e| matches!(e, StateEvent::BlockProcessed { height: 2, .. }),
            Duration::from_secs(60),
        )
        .await;
    let checkpoints: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed {
                height: 2,
                checkpoint,
                ..
            } => Some(*checkpoint),
            _ => None,
        })
        .collect();
    assert_eq!(
        checkpoints.len(),
        num_nodes,
        "Expected {num_nodes} BlockProcessed events at height 2"
    );
    assert!(
        checkpoints.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same checkpoint at height 2: {checkpoints:?}"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_multi_batch_same_anchor() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;

    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(60),
        )
        .await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && d.value.batch_txids().len() >= 3,
            Duration::from_secs(60),
        )
        .await;

    let batches_at_0: Vec<_> = decisions
        .iter()
        .filter(|d| !d.value.is_block() && d.value.block_height() == 0)
        .collect();
    assert!(
        batches_at_0.len() >= 2,
        "Expected at least 2 batches at anchor 0, got {}",
        batches_at_0.len()
    );

    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(60),
        )
        .await;

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_bitcoin_rollback_reverts_state() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for expected_height in 1..=3u64 {
        cluster.mine_empty_and_send();
        cluster
            .wait_for_decision_matching(
                |d| d.value.is_block() && d.value.block_height() == expected_height,
                Duration::from_secs(60),
            )
            .await;
        cluster
            .wait_for_state_event_matching(
                |e| {
                    matches!(e, StateEvent::BlockProcessed { height, .. } if *height == expected_height)
                },
                Duration::from_secs(60),
            )
            .await;
    }

    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster.mine_empty_and_send();

    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, .. }),
            Duration::from_secs(60),
        )
        .await;
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(60),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 2, .. }),
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_empty_and_send();
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 3,
            Duration::from_secs(60),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 3, .. }),
            Duration::from_secs(60),
        )
        .await;

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_late_joiner_syncs_to_same_checkpoint() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start_with(4, 3).await?;
    cluster.wait_for_ready().await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(60),
        )
        .await;

    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(60),
        )
        .await;

    let pre_join_events = cluster
        .wait_for_n_state_events_matching(
            3,
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(60),
        )
        .await;
    let pre_join_checkpoints: Vec<_> = pre_join_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed { checkpoint, .. } => *checkpoint,
            _ => None,
        })
        .collect();
    assert!(
        !pre_join_checkpoints.is_empty(),
        "Should have checkpoints from initial nodes"
    );

    info!("Starting late joiner node");
    let node_idx = cluster.add_node().await?;
    info!(node = node_idx, "Late joiner started");

    let block_events = cluster.mock_bitcoin().get_all_block_events();
    for event in block_events {
        let _ = cluster.block_txs[node_idx].try_send(event);
    }

    let late_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(60),
        )
        .await;
    let late_checkpoint = late_events.iter().find_map(|e| match e {
        StateEvent::BlockProcessed { checkpoint, .. } => *checkpoint,
        _ => None,
    });

    assert!(
        late_checkpoint.is_some(),
        "Late joiner should produce a checkpoint"
    );
    assert!(
        pre_join_checkpoints.contains(&late_checkpoint.unwrap()),
        "Late joiner checkpoint should match existing nodes"
    );

    cluster.shutdown().await;
    Ok(())
}
