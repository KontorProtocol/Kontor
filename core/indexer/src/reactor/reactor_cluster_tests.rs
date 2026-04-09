use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use indexer_types::Event;
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
    event_rx: mpsc::Receiver<Event>,
    event_tx: mpsc::Sender<Event>,
    started_nodes: Vec<bool>,
}

#[allow(dead_code)]
struct BatchResult {
    txids: Vec<String>,
    state_events: Vec<StateEvent>,
    events: Vec<Event>,
}

#[allow(dead_code)]
struct BlockResult {
    state_events: Vec<StateEvent>,
    events: Vec<Event>,
}

#[allow(dead_code)]
struct RollbackResult {
    state_events: Vec<StateEvent>,
    events: Vec<Event>,
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
        let (event_tx, event_rx) = mpsc::channel(1024);

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
                event_tx.clone(),
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
            event_rx,
            event_tx,
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
        etx: mpsc::Sender<Event>,
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

            let engine_output = match engine::start(engine_config).await {
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
                0,
            )
            .await;
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
                Some(etx),
                None,
                Some(consensus_handle),
                0,
                None,
            );

            let _ = rtx.send(i).await;

            if let Err(e) = reactor.run().await {
                tracing::error!(node = i, e = format!("{e:#}"), "Reactor error");
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
            self.event_tx.clone(),
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

    /// Wait until a batch is decided and applied by all nodes.
    /// Cross-checks: decided_rx (DecidedBatch), state_rx (BatchApplied × node_count),
    /// event_rx (Event::BatchProcessed × node_count).
    async fn wait_for_batch(&mut self, anchor_height: u64, timeout: Duration) -> BatchResult {
        let n = self.node_count;
        let mut decided = false;
        let mut state_count = 0;
        let mut event_count = 0;
        let mut txids = Vec::new();
        let mut state_events = Vec::new();
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if decided && state_count >= n && event_count >= n {
                break;
            }
            tokio::select! {
                _ = &mut deadline => {
                    panic!(
                        "wait_for_batch(anchor={anchor_height}) timed out: decided={decided} state={state_count}/{n} event={event_count}/{n}"
                    );
                }
                Some(d) = self.decided_rx.recv() => {
                    if !d.value.is_block() && d.value.block_height() == anchor_height && !d.value.batch_txids().is_empty() {
                        txids = d.value.batch_txids().iter().map(|t| t.to_string()).collect();
                        decided = true;
                    }
                }
                Some(se) = self.state_rx.recv() => {
                    if matches!(&se, StateEvent::BatchApplied { anchor_height: ah, .. } if *ah == anchor_height) {
                        state_count += 1;
                    }
                    state_events.push(se);
                }
                Some(ev) = self.event_rx.recv() => {
                    if matches!(&ev, Event::BatchProcessed { .. }) {
                        event_count += 1;
                    }
                    events.push(ev);
                }
            }
        }
        BatchResult { txids, state_events, events }
    }

    /// Wait until a block is decided, processed by all nodes, and events emitted.
    /// Cross-checks: decided_rx (Value::Block), state_rx (BlockProcessed × node_count),
    /// event_rx (Event::Processed × node_count).
    async fn wait_for_block(&mut self, height: u64, timeout: Duration) -> BlockResult {
        let n = self.node_count;
        let mut decided = false;
        let mut state_count = 0;
        let mut event_count = 0;
        let mut state_events = Vec::new();
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if decided && state_count >= n && event_count >= n {
                break;
            }
            tokio::select! {
                _ = &mut deadline => {
                    panic!(
                        "wait_for_block(height={height}) timed out: decided={decided} state={state_count}/{n} event={event_count}/{n}"
                    );
                }
                Some(d) = self.decided_rx.recv() => {
                    if d.value.is_block() && d.value.block_height() == height {
                        decided = true;
                    }
                }
                Some(se) = self.state_rx.recv() => {
                    if matches!(&se, StateEvent::BlockProcessed { height: h, .. } if *h == height) {
                        state_count += 1;
                    }
                    state_events.push(se);
                }
                Some(ev) = self.event_rx.recv() => {
                    if matches!(&ev, Event::Processed { block, .. } if block.height == height as i64) {
                        event_count += 1;
                    }
                    events.push(ev);
                }
            }
        }
        BlockResult { state_events, events }
    }

    /// Wait until a rollback is executed and events emitted.
    /// Cross-checks: state_rx (RollbackExecuted), event_rx (Event::Rolledback).
    async fn wait_for_rollback(&mut self, to_height: u64, timeout: Duration) -> RollbackResult {
        let mut state_seen = false;
        let mut event_seen = false;
        let mut state_events = Vec::new();
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        loop {
            if state_seen && event_seen {
                break;
            }
            tokio::select! {
                _ = &mut deadline => {
                    panic!(
                        "wait_for_rollback(to={to_height}) timed out: state={state_seen} event={event_seen}"
                    );
                }
                Some(se) = self.state_rx.recv() => {
                    if matches!(&se, StateEvent::RollbackExecuted { to_anchor, .. } if *to_anchor == to_height) {
                        state_seen = true;
                    }
                    state_events.push(se);
                }
                Some(ev) = self.event_rx.recv() => {
                    if matches!(&ev, Event::Rolledback { height } if *height == to_height) {
                        event_seen = true;
                    }
                    events.push(ev);
                }
            }
        }
        RollbackResult { state_events, events }
    }

    /// Wait until a finality event matching the predicate arrives.
    async fn wait_for_finality_event_matching(
        &mut self,
        pred: impl Fn(&FinalityEvent) -> bool,
        timeout: Duration,
    ) -> Vec<FinalityEvent> {
        wait_matching(&mut self.finality_rx, pred, 1, timeout).await
    }

    /// Low-level: wait for a specific decided value matching a predicate.
    /// Use wait_for_block or wait_for_batch instead when possible.
    async fn wait_for_decision_matching(
        &mut self,
        pred: impl Fn(&DecidedBatch) -> bool,
        timeout: Duration,
    ) -> Vec<DecidedBatch> {
        wait_matching(&mut self.decided_rx, pred, 1, timeout).await
    }

    /// Low-level: wait for a state event matching a predicate.
    /// Use wait_for_block, wait_for_batch, or wait_for_rollback instead when possible.
    async fn wait_for_state_event_matching(
        &mut self,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, 1, timeout).await
    }

    /// Low-level: wait for n state events matching a predicate.
    /// Use wait_for_block, wait_for_batch, or wait_for_rollback instead when possible.
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

    let result = cluster.wait_for_batch(0, Duration::from_secs(60)).await;
    assert!(!result.txids.is_empty(), "Expected batch with txids");

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

    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

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

    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

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
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

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

    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

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

    // After rollback, expect replayed batch with 2 txids (missing one excluded)
    let replayed = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count == 2),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        replayed
            .iter()
            .any(|e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count == 2)),
        "Expected replayed batch with 2 txids (excluding missing), got: {replayed:?}"
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
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

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
    let batch0_result = cluster.wait_for_batch(0, Duration::from_secs(60)).await;
    let batch0_txids: Vec<bitcoin::Txid> = batch0_result
        .txids
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

    cluster.mine_and_send(&batch0_txids);
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(2, Duration::from_secs(60)).await;

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

    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    // Mine the same txids into a block — they should be deduped (unbatched_count=0)
    cluster.mine_and_send(&batch_txids);
    let block_result = cluster.wait_for_block(1, Duration::from_secs(60)).await;
    assert!(
        block_result
            .state_events
            .iter()
            .any(|e| matches!(e, StateEvent::BlockProcessed { unbatched_count: 0, .. })),
        "All block txs should be deduped (unbatched_count=0), got: {:?}",
        block_result.state_events
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
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    for _ in 0..6 {
        cluster.mine_empty_and_send();
    }

    cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1),
            Duration::from_secs(60),
        )
        .await;

    // Verify rollback preserves checkpoint from pre-anchor state
    let rollback_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, checkpoint: Some(_), .. }),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        rollback_events
            .iter()
            .any(|e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, checkpoint: Some(_), .. })),
        "Expected RollbackExecuted to anchor 1 with checkpoint, got: {rollback_events:?}"
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
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block1 = cluster.wait_for_block(1, Duration::from_secs(60)).await;
    let checkpoints: Vec<_> = block1
        .state_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed { checkpoint, .. } => Some(*checkpoint),
            _ => None,
        })
        .collect();
    assert_eq!(checkpoints.len(), num_nodes);
    assert!(
        checkpoints.windows(2).all(|w| w[0] == w[1]),
        "All nodes should have the same checkpoint at height 1: {checkpoints:?}"
    );

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block2 = cluster.wait_for_block(2, Duration::from_secs(60)).await;
    let checkpoints: Vec<_> = block2
        .state_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed { checkpoint, .. } => Some(*checkpoint),
            _ => None,
        })
        .collect();
    assert_eq!(checkpoints.len(), num_nodes);
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

    // First batch at anchor 0
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    // Second batch also at anchor 0 (no block mined yet)
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    // Now mine a block and verify it processes
    cluster.mine_and_send(&[]);
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

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
            .wait_for_block(expected_height, Duration::from_secs(60))
            .await;
    }

    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster
        .wait_for_rollback(1, Duration::from_secs(60))
        .await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

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
    cluster.wait_for_batch(0, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block1 = cluster.wait_for_block(1, Duration::from_secs(60)).await;
    let pre_join_checkpoints: Vec<_> = block1
        .state_events
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

    // Wait for late joiner to process block 1 and produce a checkpoint
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
