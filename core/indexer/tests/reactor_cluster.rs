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

/// Mining a block should advance the anchor height for subsequent batches.
/// After mining, the block is decided through consensus (Value::Block),
/// and the next batch anchors at the new height.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_block_updates_anchor() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs and wait for a batch at anchor 0
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!decisions.is_empty(), "Expected at least one decision");
    assert_eq!(
        decisions[0].value.block_height(),
        0,
        "First batch should anchor at height 0"
    );

    // Mine a block — this should trigger a Value::Block decision
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Add new mempool txs so the next batch has content
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait for more decisions — should see Value::Block at height 1,
    // then Value::Batch anchored at height 1
    let more_decisions = cluster.wait_for_decisions(8, Duration::from_secs(30)).await;

    let has_block_at_1 = more_decisions
        .iter()
        .any(|d| d.value.is_block() && d.value.block_height() == 1);
    assert!(
        has_block_at_1,
        "Expected a Value::Block decision at height 1, got: {:?}",
        more_decisions.iter().map(|d| format!("{:?}@{}", d.value.is_block(), d.value.block_height())).collect::<Vec<_>>()
    );

    let has_batch_at_1 = more_decisions
        .iter()
        .any(|d| !d.value.is_block() && d.value.block_height() == 1);
    assert!(
        has_batch_at_1,
        "Expected a Value::Batch anchored at height 1, got: {:?}",
        more_decisions.iter().map(|d| format!("{:?}@{}", d.value.is_block(), d.value.block_height())).collect::<Vec<_>>()
    );

    cluster.shutdown().await;
    Ok(())
}

/// Happy path finalization: batch txs are confirmed on chain within
/// the finality window, and a BatchFinalized event is emitted.
#[tokio::test]
#[serial_test::serial]
async fn prod_reactor_happy_path_finalization() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert mempool txs and wait for batch at anchor 0
    for event in mock.generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!decisions.is_empty(), "Expected at least one decision");
    assert_eq!(decisions[0].value.block_height(), 0);

    // Mine block 1 confirming all txs
    {
        let (blk_events, mem_events) = mock.mine_block_all();
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-6 (empty) to reach finality deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for finality event — all txs confirmed, should get BatchFinalized
    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(30))
        .await;

    let has_finalized = finality_events.iter().any(
        |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 0),
    );
    assert!(
        has_finalized,
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Insert 3 mempool txs and wait for batch
    let mempool_events = mock.generate_mempool_txs(3);
    // Save raw txs for re-injection during replay
    let raw_txs: Vec<bitcoin::Transaction> = mempool_events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::Insert(tx) => Some(tx.clone()),
            _ => None,
        })
        .collect();
    for event in mempool_events {
        cluster.send_mempool_event(event);
    }

    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!decisions.is_empty(), "Expected a decision");
    let decided_txids = decisions[0].value.batch_txids().to_vec();
    assert!(
        decided_txids.len() >= 3,
        "Expected at least 3 txids in decided batch"
    );

    // Confirm only first 2 txids — 3rd will be missing at finality deadline
    let confirm_txids: Vec<bitcoin::Txid> = decided_txids[..2].to_vec();
    let missing_txid = decided_txids[2];

    // Save block events so we can re-send after rollback
    let mut saved_block_events = Vec::new();

    // Mine block 1 with only 2 of the 3 txids
    {
        let (blk_events, mem_events) = mock.mine_block(&confirm_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        saved_block_events.extend(blk_events.clone());
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 2-6 (empty) to reach deadline (anchor 0 + 6 = 6)
    for _ in 0..5 {
        let (blk_events, _) = mock.mine_empty_block();
        saved_block_events.extend(blk_events.clone());
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for finality rollback event (finality channel is separate from state channel)
    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(30))
        .await;

    let has_rollback = finality_events.iter().any(
        |e| matches!(e, FinalityEvent::Rollback { missing_txids, .. } if missing_txids.contains(&missing_txid)),
    );
    assert!(
        has_rollback,
        "Expected Rollback with missing txid {missing_txid}, got: {finality_events:?}"
    );

    // Drain all state events — look for RollbackExecuted among them
    let state_events = cluster
        .wait_for_state_events(30, Duration::from_secs(10))
        .await;
    let rollback_executed = state_events
        .iter()
        .filter(|e| matches!(e, StateEvent::RollbackExecuted { .. }))
        .count();
    assert!(
        rollback_executed >= 1,
        "Expected RollbackExecuted state events, got: {state_events:?}"
    );

    // Re-inject the confirmed txs back into the mempool so the replay
    // path can resolve them. In prod, replay_blocks_from re-delivers blocks
    // and the tx cache has them. Here we re-add to mempool.
    for tx in &raw_txs {
        let txid = tx.compute_txid();
        if confirm_txids.contains(&txid) {
            cluster.send_mempool_event(MempoolEvent::Insert(tx.clone()));
        }
    }

    // Brief delay for mempool events to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Re-send blocks to trigger replay (reactor called replay_blocks_from)
    for event in saved_block_events {
        cluster.send_block_event(event);
    }

    // Wait for replay to complete — should see BatchApplied with only 2 txids
    // (the missing txid is excluded from replay)
    let replay_events = cluster
        .wait_for_state_events(8, Duration::from_secs(30))
        .await;

    let replayed_batches: Vec<_> = replay_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BatchApplied { txid_count, .. } => Some(*txid_count),
            _ => None,
        })
        .collect();

    assert!(
        !replayed_batches.is_empty(),
        "Expected replayed BatchApplied events, got: {replay_events:?}"
    );

    // The replayed batch should have fewer txids (excluded the missing one)
    assert!(
        replayed_batches.iter().any(|&count| count == 2),
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Batch 1 at anchor 0
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!decisions.is_empty());
    assert_eq!(decisions[0].value.block_height(), 0);

    // Mine block 1 (empty — batch 1 txids intentionally NOT confirmed)
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Batch 2 at anchor 1 — need to wait for block decision + batch decision
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait until we see a batch anchored at height 1 from any node
    let more = cluster.wait_for_decisions(20, Duration::from_secs(30)).await;
    let has_batch_at_1 = more
        .iter()
        .any(|d| !d.value.is_block() && d.value.block_height() == 1);
    assert!(has_batch_at_1, "Expected a batch at anchor 1");

    // Mine blocks 2-6 to reach deadline for anchor 0 (0 + 6 = 6)
    for _ in 0..5 {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    let finality_events = cluster
        .wait_for_finality_events(1, Duration::from_secs(30))
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter("error")
        .try_init();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let mut mock = MockBitcoin::new(0);

    // Batch at anchor 0 — will be confirmed and finalized
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let decisions = cluster.wait_for_decisions(1, Duration::from_secs(30)).await;
    assert!(!decisions.is_empty());
    let batch0_txids = decisions[0].value.batch_txids().to_vec();

    // Mine block 1 confirming batch 0's txids
    {
        let (blk_events, mem_events) = mock.mine_block(&batch0_txids);
        for event in mem_events {
            cluster.send_mempool_event(event);
        }
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Batch at anchor 1 — txids will NOT be confirmed
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait until we see a batch anchored at height 1
    let more = cluster.wait_for_decisions(20, Duration::from_secs(30)).await;
    assert!(
        more.iter().any(|d| !d.value.is_block() && d.value.block_height() == 1),
        "Expected a batch at anchor 1"
    );

    // Mine block 2 (empty — batch at anchor 1 not confirmed)
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Batch at anchor 2
    for event in mock.generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    // Wait until we see a batch anchored at height 2
    let more = cluster.wait_for_decisions(20, Duration::from_secs(30)).await;
    assert!(
        more.iter().any(|d| !d.value.is_block() && d.value.block_height() == 2),
        "Expected a batch at anchor 2"
    );

    // Mine block 3
    {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Mine blocks 4-7 to reach deadline for anchor 1 (1 + 6 = 7)
    for _ in 0..4 {
        let (blk_events, _) = mock.mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
    }

    // Wait for block decisions to propagate — need all 7 blocks decided
    // Each block decision produces state events, wait for enough
    let _ = cluster
        .wait_for_state_events(20, Duration::from_secs(30))
        .await;

    // Collect finality events — BatchFinalized at anchor 0 from multiple nodes,
    // then Rollback from anchor 1. Need enough events to capture both types.
    let all_events = cluster
        .wait_for_finality_events(8, Duration::from_secs(30))
        .await;

    let rollback = all_events
        .iter()
        .find(|e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 1));
    assert!(
        rollback.is_some(),
        "Expected Rollback from anchor 1, got: {all_events:?}"
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
