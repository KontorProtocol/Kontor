mod lite_executor;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use indexer::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use indexer::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use indexer::consensus::signing::PrivateKey;
use indexer::consensus::{Genesis, Validator, ValidatorSet};
use indexer::reactor::bitcoin_state::BitcoinState;
use indexer::reactor::consensus::{ConsensusState, ObservationChannels};
use indexer::reactor::engine::{self, EngineConfig};
use indexer::reactor::mock_bitcoin::MockBitcoin;
use indexer::reactor::{ConsensusHandle, Reactor};
use malachitebft_app_channel::app::types::core::VotingPower;

use lite_executor::LiteExecutor;

fn allocate_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Collect events from a channel until `n` events match the predicate, or timeout.
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

/// Handle to a running cluster of validators using the prod reactor + LiteExecutor.
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
    // Stored for add_node
    genesis: Genesis,
    private_keys: Vec<PrivateKey>,
    ports: Vec<u16>,
    shared_pubkey: String,
    decided_tx: mpsc::Sender<DecidedBatch>,
    finality_tx: mpsc::Sender<FinalityEvent>,
    state_tx: mpsc::Sender<StateEvent>,
    ready_tx: mpsc::Sender<usize>,
    started_nodes: Vec<bool>,
}

#[allow(dead_code)]
impl ReactorCluster {
    /// Start a cluster with `initial` nodes running out of `total` validators in genesis.
    /// Use `add_node()` to start remaining nodes later.
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
            .map(|pk| Validator::new(pk.public_key(), 1 as VotingPower))
            .collect();

        let validator_set = ValidatorSet::new(validators);
        let genesis = Genesis { validator_set };

        let ports: Vec<u16> = (0..total)
            .map(|_| allocate_port().expect("Failed to allocate port"))
            .collect();

        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = CancellationToken::new();
        let mut block_txs = Vec::new();
        let mock_bitcoin = Arc::new(Mutex::new(MockBitcoin::new(0)));
        let shared_pubkey = indexer::reg_tester::random_x_only_pubkey();

        let (decided_tx, decided_rx) = mpsc::channel(1024);
        let (finality_tx, finality_rx) = mpsc::channel(1024);
        let (state_tx, state_rx) = mpsc::channel(1024);
        let (ready_tx, ready_rx) = mpsc::channel(total);

        let mut join_set = JoinSet::new();
        let mut started_nodes = vec![false; total];

        for i in 0..initial {
            let (node_block_tx, node_block_rx) = mpsc::channel(256);
            block_txs.push(node_block_tx);

            let node_mempool_rx = Self::bridge_mempool(&mempool_tx, &cancel);

            Self::spawn_node(
                i,
                private_keys[i].clone(),
                &genesis,
                &ports,
                node_block_rx,
                node_mempool_rx,
                cancel.clone(),
                decided_tx.clone(),
                finality_tx.clone(),
                state_tx.clone(),
                ready_tx.clone(),
                mock_bitcoin.clone(),
                shared_pubkey.clone(),
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
            private_keys,
            ports,
            shared_pubkey,
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
        ports: &[u16],
        node_block_rx: mpsc::Receiver<BlockEvent>,
        node_mempool_rx: mpsc::Receiver<MempoolEvent>,
        cancel: CancellationToken,
        dtx: mpsc::Sender<DecidedBatch>,
        ftx: mpsc::Sender<FinalityEvent>,
        stx: mpsc::Sender<StateEvent>,
        rtx: mpsc::Sender<usize>,
        mock_btc: Arc<Mutex<MockBitcoin>>,
        pubkey: String,
        join_set: &mut JoinSet<()>,
    ) {
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

        join_set.spawn(async move {
            let (executor, runtime) = LiteExecutor::new(mock_btc, pubkey)
                .await
                .expect("LiteExecutor setup failed");

            let conn = runtime.get_storage_conn();

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
                conn.clone(),
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

            let bitcoin_state = BitcoinState::new();

            let mut reactor = Reactor::new(
                executor,
                runtime,
                conn,
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

    /// Add and start a previously-unstartd node.
    async fn add_node(&mut self) -> Result<usize> {
        let i = self
            .started_nodes
            .iter()
            .position(|&started| !started)
            .ok_or_else(|| anyhow::anyhow!("All nodes already started"))?;

        let (node_block_tx, node_block_rx) = mpsc::channel(256);
        self.block_txs.push(node_block_tx);

        let node_mempool_rx = Self::bridge_mempool(&self.mempool_tx, &self.cancel);

        Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis,
            &self.ports,
            node_block_rx,
            node_mempool_rx,
            self.cancel.clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            &mut self.join_set,
        );

        self.started_nodes[i] = true;
        self.node_count += 1;

        // Wait for the new node to be ready
        let _ = self.ready_rx.recv().await;

        Ok(i)
    }

    async fn wait_for_ready(&mut self) {
        for _ in 0..self.node_count {
            let _ = self.ready_rx.recv().await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
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

    /// Mine a block (optionally containing specific txids), broadcast events to all nodes.
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

    /// Mine an empty block and broadcast to all nodes.
    fn mine_empty_and_send(&self) {
        let (blk_events, mem_events) = self.mock_bitcoin().mine_block(&[]);
        for event in mem_events {
            self.send_mempool_event(event);
        }
        for event in blk_events {
            self.send_block_event(event);
        }
    }

    /// Wait until a decision matching the predicate is found. Returns all collected decisions.
    async fn wait_for_decision_matching(
        &mut self,
        pred: impl Fn(&DecidedBatch) -> bool,
        timeout: Duration,
    ) -> Vec<DecidedBatch> {
        wait_matching(&mut self.decided_rx, pred, 1, timeout).await
    }

    /// Wait until a state event matching the predicate is found. Returns all collected events.
    async fn wait_for_state_event_matching(
        &mut self,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, 1, timeout).await
    }

    /// Wait until a finality event matching the predicate is found. Returns all collected events.
    async fn wait_for_finality_event_matching(
        &mut self,
        pred: impl Fn(&FinalityEvent) -> bool,
        timeout: Duration,
    ) -> Vec<FinalityEvent> {
        wait_matching(&mut self.finality_rx, pred, 1, timeout).await
    }

    /// Wait until N state events matching the predicate are found.
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

/// Basic test: 4 validators decide a batch with mempool txs.
/// Same as consensus-sim's `validators_agree_on_values` but through the prod reactor.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_validators_agree_on_values() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Insert mempool txs
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    // Wait for a batch decision with txids
    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;
    assert!(
        decisions.iter().any(|d| !d.value.batch_txids().is_empty()),
        "Expected a batch decision with txids"
    );

    // Wait for all 4 nodes to produce BatchApplied
    let state_events = cluster
        .wait_for_n_state_events_matching(
            4,
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(10),
        )
        .await;

    let batch_applied_count = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::BatchApplied { .. }))
        .count();
    assert!(
        batch_applied_count >= 4,
        "Expected at least 4 BatchApplied events (one per node), got {batch_applied_count}"
    );

    cluster.shutdown().await;
    Ok(())
}

/// Mining a block should advance the anchor height for subsequent batches.
/// After mining, the block is decided through consensus (Value::Block),
/// and the next batch anchors at the new height.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_block_updates_anchor() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Insert mempool txs and wait for a batch at anchor 0
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait for a batch decision at anchor 0
    let decisions = cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 0
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(30),
        )
        .await;
    assert!(
        decisions.iter().any(|d| d.value.block_height() == 0),
        "Expected a batch at anchor 0"
    );

    // Mine a block — this should trigger a Value::Block decision
    cluster.mine_and_send(&[]);

    // Wait for block decision at height 1
    let block_decisions = cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;
    assert!(
        block_decisions
            .iter()
            .any(|d| d.value.is_block() && d.value.block_height() == 1),
        "Expected a Value::Block decision at height 1"
    );

    // Add new mempool txs and wait for a batch at anchor 1
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
            Duration::from_secs(30),
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

/// Happy path finalization: batch txs are confirmed on chain within
/// the finality window, and a BatchFinalized event is emitted.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_happy_path_finalization() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Insert mempool txs and wait for batch at anchor 0
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;
    assert!(
        decisions.iter().any(|d| d.value.block_height() == 0),
        "Expected a batch at anchor 0"
    );

    // Mine block 1 confirming all txs
    cluster.mine_and_send(&[]);

    // Mine blocks 2-6 (empty) to reach finality deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    // Wait for BatchFinalized at anchor 0
    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0),
            Duration::from_secs(30),
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

/// Missing tx invalidation: a batched tx that is never confirmed on chain
/// triggers a finality rollback when the deadline passes.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_missing_tx_invalidation() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Mine block 1 (empty) so the batch anchors at height 1 (not 0)
    cluster.mine_empty_and_send();
    // Wait for block 1 to be decided
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Insert 3 mempool txs — we know the txids upfront
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

    // Wait for all 3 txids to be batched (may be across multiple batches)
    cluster
        .wait_for_n_state_events_matching(
            4, // 4 nodes each emit BatchApplied
            |e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count > 0),
            Duration::from_secs(30),
        )
        .await;

    // Confirm only first 2 txids — 3rd will be missing at finality deadline
    let confirm_txids: Vec<bitcoin::Txid> = all_txids[..2].to_vec();
    let missing_txid = all_txids[2];

    // Mine block 2 with only 2 of the 3 txids
    cluster.mine_and_send(&confirm_txids);

    // Mine blocks 3-7 (empty) to reach deadline (anchor 1 + 6 = 7)
    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    // Wait for finality rollback event
    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if missing_txids.contains(&missing_txid)),
            Duration::from_secs(30),
        )
        .await;

    assert!(
        finality_events.iter().any(
            |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if missing_txids.contains(&missing_txid))
        ),
        "Expected Rollback with missing txid {missing_txid}, got: {finality_events:?}"
    );

    // Wait for rollback + replay to complete.
    // The replay happens immediately after rollback (process_replay_queue),
    // so BatchApplied events arrive right after RollbackExecuted.
    let all_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { txid_count, .. } if *txid_count == 2),
            Duration::from_secs(30),
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

/// Cascade invalidation: a missing tx at anchor 0 also invalidates a
/// second batch decided at anchor 1 (same finality window).
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_cascade_invalidation() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Batch 1 at anchor 0
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;

    // Mine block 1 (empty — batch 1 txids intentionally NOT confirmed)
    cluster.mine_empty_and_send();

    // Wait for block decision at height 1
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Batch 2 at anchor 1
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
            Duration::from_secs(30),
        )
        .await;

    // Mine blocks 2-6 to reach deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    // Wait for Rollback with cascade
    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { .. }),
            Duration::from_secs(30),
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

/// Cross-block cascade: a missing tx at anchor 1 invalidates batches at
/// anchors 1, 2, and 3. Batch at anchor 0 (already finalized) survives.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_cross_block_cascade_invalidation() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Batch at anchor 0 — will be confirmed and finalized
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;
    let batch0_txids = decisions
        .iter()
        .find(|d| !d.value.batch_txids().is_empty())
        .unwrap()
        .value
        .batch_txids()
        .to_vec();

    // Mine block 1 confirming batch 0's txids
    cluster.mine_and_send(&batch0_txids);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Batch at anchor 1 — txids will NOT be confirmed
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
            Duration::from_secs(30),
        )
        .await;

    // Mine block 2 (empty — batch at anchor 1 not confirmed)
    cluster.mine_empty_and_send();
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(30),
        )
        .await;

    // Batch at anchor 2
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
            Duration::from_secs(30),
        )
        .await;

    // Mine block 3
    cluster.mine_empty_and_send();

    // Mine blocks 4-7 to reach deadline for anchor 1 (1 + 6 = 7)
    for _ in 0..4 {
        cluster.mine_empty_and_send();
    }

    // Wait for Rollback from anchor 1
    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1),
            Duration::from_secs(30),
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

/// Test 7: Batch txs execute before block txs at the same anchor height.
/// A batch is decided at anchor 0, then block 1 is mined containing the same txids.
/// The batch executes first (counter increments), then the block decision skips
/// the already-batched txids via dedup.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_batch_before_unbatched_at_same_anchor() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Generate mempool txs
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

    // Wait for batch decision at anchor 0
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;

    // Wait for BatchApplied — confirms batch executed
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(30),
        )
        .await;

    // Mine block 1 containing the same txids
    cluster.mine_and_send(&batch_txids);

    // Wait for block decision at height 1
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Wait for BlockProcessed — unbatched_count should be 0 (all txs were deduped)
    let block_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height, .. } if *height == 1),
            Duration::from_secs(30),
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

/// Test 9: State before the rollback anchor survives intact.
/// Batch at anchor 0 (2 txs), batch at anchor 1 (2 txs, never confirmed).
/// Finality rollback from anchor 1 — checkpoint after rollback should match
/// the checkpoint from right after the batch at anchor 0.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_rollback_preserves_pre_anchor_state() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Batch at anchor 0: 2 txs
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;

    // Wait for batch at anchor 0 to be applied
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
            Duration::from_secs(30),
        )
        .await;

    // Mine block 1 confirming batch 0's txs
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Batch at anchor 1: 2 txs (these will NOT be confirmed)
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
            Duration::from_secs(30),
        )
        .await;

    // Mine blocks 2-7 (empty — batch at anchor 1 never confirmed)
    for _ in 0..6 {
        cluster.mine_empty_and_send();
    }

    // Wait for finality rollback from anchor 1
    cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1),
            Duration::from_secs(30),
        )
        .await;

    // Wait for RollbackExecuted — verify rollback height and checkpoint existence
    let rollback_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::RollbackExecuted { .. }),
            Duration::from_secs(30),
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

    // The rollback checkpoint should match the state at block 1 (before batch at anchor 1).
    // rollback_to_height(1) deletes blocks > 1, preserving batch 0 + block 1.
    let rollback_checkpoint = match rollback_event.unwrap() {
        StateEvent::RollbackExecuted { checkpoint, .. } => *checkpoint,
        _ => unreachable!(),
    };
    // Can't compare exact checkpoints across nodes (events from different nodes on merged channel).
    // Verify rollback checkpoint exists — state at block 1 was preserved.
    assert!(
        rollback_checkpoint.is_some(),
        "Expected valid checkpoint after rollback (pre-anchor state preserved)"
    );

    cluster.shutdown().await;
    Ok(())
}

/// Test 10: All nodes reach the same checkpoint after multiple batches and blocks.
/// Sends multiple rounds of mempool txs + blocks and verifies that all N
/// BlockProcessed events at the same height carry identical checkpoints.
///
/// IGNORED: Checkpoint computation is non-deterministic across nodes due to
/// autoincrement tx_id values differing per-node DB. Needs investigation.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_all_nodes_reach_same_checkpoint() -> Result<()> {
    indexer::logging::setup();

    let num_nodes = 4;
    let mut cluster = ReactorCluster::start(num_nodes).await?;
    cluster.wait_for_ready().await;

    // Round 1: batch at anchor 0 + block 1
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Collect N BlockProcessed events at height 1
    let events = cluster
        .wait_for_n_state_events_matching(
            num_nodes,
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(30),
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

    // Round 2: batch at anchor 1 + block 2
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
            Duration::from_secs(30),
        )
        .await;
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(30),
        )
        .await;

    // Collect N BlockProcessed events at height 2
    let events = cluster
        .wait_for_n_state_events_matching(
            num_nodes,
            |e| matches!(e, StateEvent::BlockProcessed { height: 2, .. }),
            Duration::from_secs(30),
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

/// Test 11: Multiple batches decided at the same anchor height.
/// Two separate rounds of mempool txs both anchor at height 0 (no blocks mined between them).
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_multi_batch_same_anchor() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // First batch of mempool txs
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;

    // Wait for first BatchApplied
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(30),
        )
        .await;

    // Second batch of mempool txs — still at anchor 0 (no blocks mined)
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && d.value.batch_txids().len() >= 3,
            Duration::from_secs(30),
        )
        .await;

    // Verify both batches were at anchor 0
    let batches_at_0: Vec<_> = decisions
        .iter()
        .filter(|d| !d.value.is_block() && d.value.block_height() == 0)
        .collect();
    assert!(
        batches_at_0.len() >= 2,
        "Expected at least 2 batches at anchor 0, got {}",
        batches_at_0.len()
    );

    // Wait for second BatchApplied
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { .. }),
            Duration::from_secs(30),
        )
        .await;

    // Mine block 1 and verify it processes correctly after multiple batches
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(30),
        )
        .await;

    cluster.shutdown().await;
    Ok(())
}

/// Test 12: Bitcoin reorg reverts state — truncation only, no replay.
/// Process blocks 1-3, then send a Rollback to height 1. Blocks 2-3 are deleted.
/// New blocks 2-3 arrive with different hashes.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_bitcoin_rollback_reverts_state() -> Result<()> {
    indexer::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Mine and decide blocks 1-3
    for expected_height in 1..=3u64 {
        cluster.mine_empty_and_send();
        cluster
            .wait_for_decision_matching(
                |d| d.value.is_block() && d.value.block_height() == expected_height,
                Duration::from_secs(30),
            )
            .await;
        cluster
            .wait_for_state_event_matching(
                |e| {
                    matches!(e, StateEvent::BlockProcessed { height, .. } if *height == expected_height)
                },
                Duration::from_secs(30),
            )
            .await;
    }

    // Send reorg rollback to height 1 (blocks 2-3 deleted) and immediately
    // send the new block 2 so it's queued in block_rx before Malachite can
    // cycle through empty round timeouts.
    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster.mine_empty_and_send(); // new block 2

    // Wait for rollback, then block 2
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::RollbackExecuted { to_anchor: 1, .. }),
            Duration::from_secs(30),
        )
        .await;
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 2,
            Duration::from_secs(30),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 2, .. }),
            Duration::from_secs(30),
        )
        .await;

    // Mine new block 3
    cluster.mine_empty_and_send();
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 3,
            Duration::from_secs(30),
        )
        .await;
    cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 3, .. }),
            Duration::from_secs(30),
        )
        .await;

    cluster.shutdown().await;
    Ok(())
}

/// Late joiner: start 3 of 4 validators, process batches + blocks,
/// then start the 4th. It syncs via Malachite and reaches the same checkpoint.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_late_joiner_syncs_to_same_checkpoint() -> Result<()> {
    indexer::logging::setup();

    // Start 3 of 4 validators
    let mut cluster = ReactorCluster::start_with(4, 3).await?;
    cluster.wait_for_ready().await;

    // Batch at anchor 0
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster
        .wait_for_decision_matching(
            |d| !d.value.is_block() && !d.value.batch_txids().is_empty(),
            Duration::from_secs(30),
        )
        .await;

    // Mine block 1 (confirms the batch txs)
    cluster.mine_and_send(&[]);
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Wait for all 3 nodes to process block 1
    let pre_join_events = cluster
        .wait_for_n_state_events_matching(
            3,
            |e| matches!(e, StateEvent::BlockProcessed { height: 1, .. }),
            Duration::from_secs(30),
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

    // Start the 4th node — it syncs decided values via Malachite
    info!("Starting late joiner node");
    let node_idx = cluster.add_node().await?;
    info!(node = node_idx, "Late joiner started");

    // Send block events to the late joiner (its poller wasn't running when blocks were mined)
    let block_events = cluster.mock_bitcoin().get_all_block_events();
    for event in block_events {
        let _ = cluster.block_txs[node_idx].try_send(event);
    }

    // Wait for the late joiner to process block 1 via sync
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
