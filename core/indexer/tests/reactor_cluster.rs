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

/// Handle to a running cluster of validators using the prod reactor + StateLog.
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

        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = CancellationToken::new();
        let mut block_txs = Vec::new();
        let mock_bitcoin = Arc::new(Mutex::new(MockBitcoin::new(0)));

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

            let (node_block_tx, node_block_rx) = mpsc::channel(256);
            block_txs.push(node_block_tx);

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
            let mock_btc = mock_bitcoin.clone();

            join_set.spawn(async move {
                let executor = LiteExecutor::new(mock_btc)
                    .await
                    .expect("LiteExecutor setup failed");

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

                let conn = executor.connection();
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

        Ok(Self {
            block_txs,
            mempool_tx,
            decided_rx,
            finality_rx,
            state_rx,
            cancel,
            join_set,
            node_count: n,
            ready_rx,
            mock_bitcoin,
        })
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

    /// Wait until a decision matching the predicate is found. Returns all collected decisions.
    async fn wait_for_decision_matching(
        &mut self,
        pred: impl Fn(&DecidedBatch) -> bool,
        timeout: Duration,
    ) -> Vec<DecidedBatch> {
        let mut batches = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                Some(batch) = self.decided_rx.recv() => {
                    let matched = pred(&batch);
                    batches.push(batch);
                    if matched { break; }
                }
            }
        }
        batches
    }

    /// Wait until a state event matching the predicate is found. Returns all collected events.
    async fn wait_for_state_event_matching(
        &mut self,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                Some(event) = self.state_rx.recv() => {
                    let matched = pred(&event);
                    events.push(event);
                    if matched { break; }
                }
            }
        }
        events
    }

    /// Wait until a finality event matching the predicate is found. Returns all collected events.
    async fn wait_for_finality_event_matching(
        &mut self,
        pred: impl Fn(&FinalityEvent) -> bool,
        timeout: Duration,
    ) -> Vec<FinalityEvent> {
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                Some(event) = self.finality_rx.recv() => {
                    let matched = pred(&event);
                    events.push(event);
                    if matched { break; }
                }
            }
        }
        events
    }

    /// Wait until N state events matching the predicate are found.
    async fn wait_for_n_state_events_matching(
        &mut self,
        n: usize,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        let mut events = Vec::new();
        let mut count = 0;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            if count >= n {
                break;
            }
            tokio::select! {
                _ = &mut deadline => break,
                Some(event) = self.state_rx.recv() => {
                    if pred(&event) { count += 1; }
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
    {
        let (blk_events, mem_events) = cluster.mock_bitcoin().mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

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
    {
        let (blk_events, mem_events) = cluster.mock_bitcoin().mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-6 (empty) to reach finality deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
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
    {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }
    // Wait for block 1 to be decided
    cluster
        .wait_for_decision_matching(
            |d| d.value.is_block() && d.value.block_height() == 1,
            Duration::from_secs(30),
        )
        .await;

    // Insert 3 mempool txs and wait for batch at anchor 1
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster
        .wait_for_decision_matching(
            |d| {
                !d.value.is_block()
                    && d.value.block_height() == 1
                    && !d.value.batch_txids().is_empty()
            },
            Duration::from_secs(30),
        )
        .await;
    let batch = decisions
        .iter()
        .find(|d| !d.value.batch_txids().is_empty())
        .expect("Expected a batch decision with txids");
    let decided_txids = batch.value.batch_txids().to_vec();
    assert!(
        decided_txids.len() >= 3,
        "Expected at least 3 txids in decided batch"
    );

    // Confirm only first 2 txids — 3rd will be missing at finality deadline
    let confirm_txids: Vec<bitcoin::Txid> = decided_txids[..2].to_vec();
    let missing_txid = decided_txids[2];

    // Mine block 2 with only 2 of the 3 txids
    {
        let (blk_events, mem_events) = cluster.mock_bitcoin().mine_block(&confirm_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 3-7 (empty) to reach deadline (anchor 1 + 6 = 7)
    for _ in 0..5 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
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
    {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

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
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
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
    {
        let (blk_events, mem_events) = cluster.mock_bitcoin().mine_block(&batch0_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }
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
    {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }
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
    {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 4-7 to reach deadline for anchor 1 (1 + 6 = 7)
    for _ in 0..4 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
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
