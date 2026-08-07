use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Genesis, Validator, ValidatorSet};
use crate::keygen;
use crate::reactor::consensus_state::{ConsensusState, ObservationChannels};
use crate::reactor::engine::{self, EngineConfig};
use crate::reactor::lite_executor::{LiteExecutor, shared_engine_and_cache};
use crate::reactor::mock_bitcoin::MockBitcoin;
use crate::reactor::{Reactor, Simulation};
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::GenesisValidator;
use bitcoin::hashes::Hash;
use indexer_types::Event;
use indexer_types::OpWithResult;
use malachitebft_app_channel::app::types::core::VotingPower;

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
    /// Per-node storage connections, resolved lazily from `conn_rxs` on first use.
    /// A node that has not been started yet has neither.
    conns: Vec<Option<libsql::Connection>>,
    conn_rxs: Vec<Option<oneshot::Receiver<libsql::Connection>>>,
    /// Each node's data directory, owned HERE so it survives the node's task and a
    /// restart can reopen it.
    node_dirs: Vec<(tempfile::TempDir, String)>,
    /// Child of the cluster token, so cancelling the cluster still stops everyone
    /// while a single node can also be stopped on its own.
    node_cancels: Vec<CancellationToken>,
    block_txs: Vec<mpsc::Sender<BlockEvent>>,
    /// Fatal errors that killed a node's reactor task.
    ///
    /// `spawn_node` used to log these and move on, which made "the reactor
    /// died" unassertable: a test whose node crashed showed up as a timeout on
    /// whatever it was waiting for, indistinguishable from consensus simply
    /// being slow. Tests that expect every node to survive assert this is empty.
    reactor_errors: Arc<Mutex<Vec<(usize, String)>>>,
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
    /// Node 0's resolved consensus listen multiaddr — the bootstrap seed every
    /// other node (including late joiners via `add_node`) discovers the cluster
    /// through. No fixed ports: each node binds `/tcp/0` and publishes its
    /// resolved address on a per-node watch the reactor writes on bind.
    seed_addr: String,
    shared_pubkey: String,
    engine: wasmtime::Engine,
    component_cache: crate::runtime::ComponentCache,
    decided_tx: mpsc::Sender<DecidedBatch>,
    finality_tx: mpsc::Sender<FinalityEvent>,
    state_tx: mpsc::Sender<StateEvent>,
    ready_tx: mpsc::Sender<usize>,
    event_rx: mpsc::Receiver<Event>,
    event_tx: mpsc::Sender<Event>,
    simulate_txs: Vec<mpsc::Sender<Simulation>>,
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
        // Same derivation path operators run in production via `kontor keygen`
        // — fixed master seed gives reproducible test runs.
        const TEST_MASTER_SEED: [u8; 32] = [0x42u8; 32];
        let validator_keys: Vec<keygen::ValidatorKeys> = (0..total)
            .map(|i| keygen::derive_validator(&TEST_MASTER_SEED, i as u32))
            .collect();

        let private_keys: Vec<PrivateKey> = validator_keys
            .iter()
            .map(|k| PrivateKey::from(k.ed25519_private))
            .collect();

        let validators: Vec<Validator> = private_keys
            .iter()
            .map(|pk| Validator::new(pk.public_key(), 100 as VotingPower))
            .collect();

        let genesis_validators: Vec<GenesisValidator> = validator_keys
            .iter()
            .map(|k| GenesisValidator {
                x_only_pubkey: hex::encode(k.x_only_pubkey),
                stake: crate::runtime::Decimal::try_from(100u64).unwrap(),
                ed25519_pubkey: k.ed25519_pubkey.to_vec(),
            })
            .collect();

        let validator_set = ValidatorSet::new(validators);
        let genesis = Genesis { validator_set };

        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = CancellationToken::new();
        let mut block_txs = Vec::new();
        let mut conn_rxs: Vec<Option<oneshot::Receiver<libsql::Connection>>> =
            (0..total).map(|_| None).collect();
        let node_dirs: Vec<(tempfile::TempDir, String)> = (0..total)
            .map(|_| crate::test_utils::new_test_db_dir().expect("node data dir"))
            .collect();
        let node_cancels: Vec<CancellationToken> =
            (0..total).map(|_| cancel.child_token()).collect();
        let mock_bitcoin = Arc::new(Mutex::new(MockBitcoin::new(0)));
        let shared_pubkey = random_x_only_pubkey();
        let (engine, component_cache) = shared_engine_and_cache().await;

        let (decided_tx, decided_rx) = mpsc::channel(1024);
        let (finality_tx, finality_rx) = mpsc::channel(1024);
        let (state_tx, state_rx) = mpsc::channel(1024);
        let (ready_tx, ready_rx) = mpsc::channel(total);
        let (event_tx, event_rx) = mpsc::channel(1024);

        let mut join_set = JoinSet::new();
        let reactor_errors: Arc<Mutex<Vec<(usize, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let mut started_nodes = vec![false; total];
        let mut simulate_txs = Vec::new();

        // Seed-first bring-up, no fixed ports. Node 0 boots with no peers; we
        // wait only for it to report its resolved listen address, then point
        // the rest at it. libp2p discovery meshes the cluster from there.
        let mut seed_addr = String::new();
        for i in 0..initial {
            let (node_block_tx, node_block_rx) = mpsc::channel(256);
            block_txs.push(node_block_tx.clone());

            let node_mempool_rx = Self::bridge_mempool(&mempool_tx, &cancel);
            let (sim_tx, sim_rx) = mpsc::channel(1);
            simulate_txs.push(sim_tx);

            let peers = if i == 0 {
                vec![]
            } else {
                vec![seed_addr.clone()]
            };

            // Per-node watch: the reactor publishes the resolved `/tcp/0` address
            // here on bind. Only the seed's receiver is read back (to bootstrap
            // the followers); the rest are dropped after spawn.
            let (addr_tx, addr_rx) = watch::channel(None);
            let (node_conn_tx, node_conn_rx) = oneshot::channel();
            conn_rxs[i] = Some(node_conn_rx);

            Self::spawn_node(
                i,
                private_keys[i].clone(),
                &genesis,
                &genesis_validators,
                peers,
                addr_tx,
                node_block_tx,
                node_block_rx,
                node_mempool_rx,
                node_cancels[i].clone(),
                decided_tx.clone(),
                finality_tx.clone(),
                state_tx.clone(),
                ready_tx.clone(),
                event_tx.clone(),
                Some(sim_rx),
                mock_bitcoin.clone(),
                shared_pubkey.clone(),
                engine.clone(),
                component_cache.clone(),
                node_conn_tx,
                node_dirs[i].0.path().to_path_buf(),
                node_dirs[i].1.clone(),
                true,
                reactor_errors.clone(),
                &mut join_set,
            );
            started_nodes[i] = true;

            if i == 0 {
                seed_addr = Self::await_listen_addr(addr_rx).await?;
            }
        }

        Ok(Self {
            conns: (0..total).map(|_| None).collect(),
            conn_rxs,
            node_dirs,
            node_cancels,
            block_txs,
            reactor_errors,
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
            seed_addr,
            shared_pubkey,
            engine,
            component_cache,
            decided_tx,
            finality_tx,
            state_tx,
            ready_tx,
            event_rx,
            event_tx,
            simulate_txs,
            started_nodes,
        })
    }

    /// This node's storage connection, so a test can assert on what it actually
    /// wrote rather than only on the events it emitted.
    ///
    /// Resolved on first use — the connection only exists once the node's runtime
    /// has been built inside its task, so call this after `wait_for_ready`.
    async fn node_conn(&mut self, i: usize) -> &libsql::Connection {
        if self.conns[i].is_none() {
            let rx = self.conn_rxs[i]
                .take()
                .unwrap_or_else(|| panic!("node {i} was never started"));
            let conn = tokio::time::timeout(Duration::from_secs(30), rx)
                .await
                .unwrap_or_else(|_| panic!("node {i} never reported its connection"))
                .unwrap_or_else(|_| panic!("node {i} died before reporting its connection"));
            self.conns[i] = Some(conn);
        }
        self.conns[i].as_ref().unwrap()
    }

    /// Stop one node, leaving the rest of the cluster running. Its data directory
    /// is owned by the cluster, so the database survives for a restart.
    async fn stop_node(&mut self, i: usize) {
        self.node_cancels[i].cancel();
        // Its connection belongs to a runtime that is going away.
        self.conns[i] = None;
    }

    /// Stop a node and bring it back up on the state it left behind — the shape of
    /// issue #515, where a restart inside the finality window lost tracking that
    /// lived only in memory.
    async fn restart_node(&mut self, i: usize) {
        self.stop_node(i).await;
        // Give the task a moment to unwind and release the database.
        tokio::time::sleep(Duration::from_millis(500)).await;

        self.node_cancels[i] = self.cancel.child_token();
        let (node_block_tx, node_block_rx) = mpsc::channel(256);
        self.block_txs[i] = node_block_tx.clone();
        let node_mempool_rx = Self::bridge_mempool(&self.mempool_tx, &self.cancel);
        let (sim_tx, sim_rx) = mpsc::channel(1);
        self.simulate_txs[i] = sim_tx;
        let (addr_tx, _addr_rx) = watch::channel(None);
        let (node_conn_tx, node_conn_rx) = oneshot::channel();
        self.conn_rxs[i] = Some(node_conn_rx);

        Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis,
            &self.genesis_validators,
            vec![self.seed_addr.clone()],
            addr_tx,
            node_block_tx,
            node_block_rx,
            node_mempool_rx,
            self.node_cancels[i].clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.event_tx.clone(),
            Some(sim_rx),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            self.engine.clone(),
            self.component_cache.clone(),
            node_conn_tx,
            self.node_dirs[i].0.path().to_path_buf(),
            self.node_dirs[i].1.clone(),
            false,
            self.reactor_errors.clone(),
            &mut self.join_set,
        );

        // Only this node reports ready — `wait_for_ready` would block forever
        // waiting on the peers that never went down.
        let _ = self.ready_rx.recv().await;
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

    /// Await a node's resolved consensus listen address on its watch. The
    /// reactor publishes it from its `ConsensusReady` handler once the swarm
    /// binds — event-driven, no polling.
    async fn await_listen_addr(mut rx: watch::Receiver<Option<String>>) -> Result<String> {
        rx.wait_for(Option::is_some)
            .await
            .map_err(|_| anyhow::anyhow!("node reactor dropped before reporting a listen address"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("listen address watch resolved to None"))
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_node(
        i: usize,
        private_key: PrivateKey,
        genesis: &Genesis,
        genesis_validators: &[GenesisValidator],
        peers: Vec<String>,
        consensus_listen_addr: watch::Sender<Option<String>>,
        node_block_tx: mpsc::Sender<BlockEvent>,
        node_block_rx: mpsc::Receiver<BlockEvent>,
        node_mempool_rx: mpsc::Receiver<MempoolEvent>,
        cancel: CancellationToken,
        dtx: mpsc::Sender<DecidedBatch>,
        ftx: mpsc::Sender<FinalityEvent>,
        stx: mpsc::Sender<StateEvent>,
        rtx: mpsc::Sender<usize>,
        etx: mpsc::Sender<Event>,
        sim_rx: Option<mpsc::Receiver<Simulation>>,
        mock_btc: Arc<Mutex<MockBitcoin>>,
        pubkey: String,
        engine: wasmtime::Engine,
        component_cache: crate::runtime::ComponentCache,
        // Hands this node's storage connection back to the test. The runtime is
        // built inside the spawned task, so without this a test has no way to look
        // at what a particular node actually wrote — which is most of what there is
        // to assert about a consensus bug.
        conn_tx: oneshot::Sender<libsql::Connection>,
        data_dir: std::path::PathBuf,
        db_name: String,
        // A restart must come back up on the state it left behind, so genesis
        // seeding runs only on the first boot. That distinction is the whole point
        // of the restart path — a node that re-seeds has not really restarted.
        first_boot: bool,
        reactor_errors: Arc<Mutex<Vec<(usize, String)>>>,
        join_set: &mut JoinSet<()>,
    ) {
        let genesis = genesis.clone();
        let genesis_vals = genesis_validators.to_vec();
        join_set.spawn(async move {
            let (executor, runtime) = if first_boot {
                LiteExecutor::new(
                    &data_dir,
                    &db_name,
                    mock_btc,
                    pubkey,
                    &genesis_vals,
                    engine,
                    component_cache,
                    node_block_tx,
                )
                .await
                .expect("LiteExecutor setup failed")
            } else {
                LiteExecutor::reopen(
                    &data_dir,
                    &db_name,
                    mock_btc,
                    pubkey,
                    engine,
                    component_cache,
                    node_block_tx,
                )
                .await
                .expect("LiteExecutor reopen failed")
            };

            let engine_config = EngineConfig {
                private_key,
                // OS-assigned port (no probe/release race). The seed boots with
                // no peers; everyone else bootstraps from the seed's reported
                // address and discovers the rest of the cluster.
                listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
                persistent_peers: peers,
                data_dir: executor.data_dir(),
                consensus_enabled: true,
                discovery_enabled: true,
            };

            let conn = runtime.get_storage_conn();
            // Ignore the error: a test that never asks for the connection drops the
            // receiver, which is fine.
            let _ = conn_tx.send(conn.clone());

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

            // A restarted node must resume from what it persisted. Hard-coding 0
            // would make it believe the chain is fresh, and the restart test would
            // then pass for entirely the wrong reason.
            let (resume_height, resume_hash) = if first_boot {
                (0, None)
            } else {
                match crate::database::queries::select_block_latest(&conn).await {
                    Ok(Some(row)) => (row.height, Some(row.hash)),
                    _ => (0, None),
                }
            };

            let mut state = ConsensusState::new(
                conn.clone(),
                engine_output.signing_provider,
                genesis,
                engine_output.address,
                resume_height,
                engine_output.channels,
                engine_output._handle,
                validator_index,
                crate::reactor::mempool_fee_index::MempoolFeeIndex::new(None),
            )
            .await
            .expect("ConsensusState::new failed");
            state.observation = Some(ObservationChannels {
                decided_tx: dtx,
                finality_tx: ftx,
                state_tx: stx,
            });

            let mut reactor = Reactor::new(
                executor,
                runtime,
                node_block_rx,
                node_mempool_rx,
                cancel.clone(),
                None,
                Some(etx),
                sim_rx,
                state,
                super::PruneConfig {
                    enabled: false,
                    retain_blocks: 144,
                },
                resume_height,
                resume_hash,
                // Same path as production: the reactor's `ConsensusReady` handler
                // reads the resolved address and publishes it here. `start_with`
                // awaits the seed's receiver to bootstrap the followers.
                consensus_listen_addr,
            );

            let _ = rtx.send(i).await;

            if let Err(e) = reactor.run().await {
                let msg = format!("{e:#}");
                tracing::error!(node = i, e = %msg, "Reactor error");
                reactor_errors.lock().unwrap().push((i, msg));
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
        let (sim_tx, sim_rx) = mpsc::channel(1);
        self.simulate_txs.push(sim_tx);

        // Late joiner bootstraps from the seed; its own address isn't read back.
        let (addr_tx, _addr_rx) = watch::channel(None);
        let (node_conn_tx, node_conn_rx) = oneshot::channel();
        self.conn_rxs[i] = Some(node_conn_rx);

        Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis,
            &self.genesis_validators,
            vec![self.seed_addr.clone()],
            addr_tx,
            node_block_tx,
            node_block_rx,
            node_mempool_rx,
            self.node_cancels[i].clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.event_tx.clone(),
            Some(sim_rx),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            self.engine.clone(),
            self.component_cache.clone(),
            node_conn_tx,
            self.node_dirs[i].0.path().to_path_buf(),
            self.node_dirs[i].1.clone(),
            true,
            self.reactor_errors.clone(),
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

        // Reactor-init is not mesh-readiness. If a test drives the cluster the
        // instant reactors are up, the first proposal races an unformed gossip
        // mesh and gets dropped (NoPeersSubscribedToTopic) — the proposer's peers
        // never see it, so height 1 churns through round changes. Under parallel
        // test load that startup churn is what pushes later finality waits past
        // their timeouts. Block here until every node has decided consensus height
        // 1, which proves the mesh is formed and consensus works on all nodes.
        let target = self.node_count;
        let mut decided: HashSet<usize> = HashSet::new();
        let barrier = tokio::time::timeout(Duration::from_secs(30), async {
            while decided.len() < target {
                match self.decided_rx.recv().await {
                    Some(d) if d.consensus_height.as_u64() >= 1 => {
                        if let Some(idx) = d.validator_index {
                            decided.insert(idx);
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        })
        .await;
        assert!(
            barrier.is_ok(),
            "consensus readiness barrier timed out: only {}/{target} nodes decided height 1",
            decided.len()
        );
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
                        // Recount events that arrived before we knew the txids
                        event_count = events
                            .iter()
                            .filter(|ev| match ev {
                                Event::BatchProcessed { txids: et } => {
                                    et.iter().any(|t| txids.contains(t))
                                }
                                _ => false,
                            })
                            .count();
                    }
                }
                Some(se) = self.state_rx.recv() => {
                    if matches!(&se, StateEvent::BatchApplied { anchor_height: ah, .. } if *ah == anchor_height) {
                        state_count += 1;
                    }
                    state_events.push(se);
                }
                Some(ev) = self.event_rx.recv() => {
                    if let Event::BatchProcessed { txids: ref ev_txids } = ev
                        && !txids.is_empty()
                        && ev_txids.iter().any(|t| txids.contains(t))
                    {
                        event_count += 1;
                    }
                    events.push(ev);
                }
            }
        }
        BatchResult {
            txids,
            state_events,
            events,
        }
    }

    /// Assert no node's reactor died during the test.
    ///
    /// Worth calling explicitly wherever survival is the property under test: a
    /// dead reactor otherwise surfaces only as a timeout somewhere downstream,
    /// which reads as "consensus was slow" and hides the actual failure.
    fn assert_no_reactor_errors(&self) {
        let errors = self.reactor_errors.lock().unwrap();
        assert!(errors.is_empty(), "reactor(s) died: {errors:?}");
    }

    /// Wait until `height` is DECIDED by consensus, without requiring every node
    /// to have executed it.
    ///
    /// `wait_for_block` demands `BlockProcessed` from all `node_count` nodes,
    /// which is the right check when everyone is healthy but cannot express
    /// "the chain advanced even though one node could not follow" — the exact
    /// property at stake when a node is deliberately left behind.
    async fn wait_for_block_decided(&mut self, height: u64, timeout: Duration) {
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    panic!("wait_for_block_decided(height={height}) timed out");
                }
                Some(d) = self.decided_rx.recv() => {
                    if d.value.is_block() && d.value.block_height() == height {
                        return;
                    }
                }
            }
        }
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
                    if matches!(&ev, Event::Processed { block, .. } if block.height == height) {
                        event_count += 1;
                    }
                    events.push(ev);
                }
            }
        }
        BlockResult {
            state_events,
            events,
        }
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
        RollbackResult {
            state_events,
            events,
        }
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

    /// Send a transaction to a specific node for simulation and await the result.
    async fn simulate(
        &self,
        node: usize,
        tx: indexer_types::Transaction,
    ) -> Result<Vec<OpWithResult>> {
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        self.simulate_txs[node]
            .send((tx, ret_tx))
            .await
            .map_err(|_| anyhow::anyhow!("simulate channel closed"))?;
        ret_rx
            .await
            .map_err(|_| anyhow::anyhow!("simulate response channel closed"))?
    }

    /// Assert all nodes produced the same checkpoint for a block at a given height.
    fn assert_checkpoints_match(result: &BlockResult, height: u64, expected_count: usize) {
        let checkpoints: Vec<_> = result
            .state_events
            .iter()
            .filter_map(|e| match e {
                StateEvent::BlockProcessed {
                    height: h,
                    checkpoint,
                    ..
                } if *h == height => Some(*checkpoint),
                _ => None,
            })
            .collect();
        assert_eq!(
            checkpoints.len(),
            expected_count,
            "Expected {expected_count} checkpoints, got {}",
            checkpoints.len()
        );
        assert!(
            checkpoints.windows(2).all(|w| w[0] == w[1]),
            "Checkpoints diverged across nodes: {checkpoints:?}"
        );
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
            MempoolEvent::KontorTxAdded { txid, .. } => Some(*txid),
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
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    // Mine blocks up to (but not including) the finality deadline block,
    // waiting for each to be processed. The last block triggers finality
    // checks which may cause a rollback, so we don't wait_for_block on it.
    for i in 0..4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(3 + i, Duration::from_secs(60)).await;
    }
    cluster.mine_empty_and_send();

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

    for i in 0..4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(2 + i, Duration::from_secs(60)).await;
    }
    cluster.mine_empty_and_send();

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
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

    for i in 0..3 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(4 + i, Duration::from_secs(60)).await;
    }
    cluster.mine_empty_and_send();

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
            MempoolEvent::KontorTxAdded { txid, .. } => Some(*txid),
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
        block_result.state_events.iter().any(|e| matches!(
            e,
            StateEvent::BlockProcessed {
                unbatched_count: 0,
                ..
            }
        )),
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
            |e| {
                matches!(
                    e,
                    StateEvent::RollbackExecuted {
                        to_anchor: 1,
                        checkpoint: Some(_),
                        ..
                    }
                )
            },
            Duration::from_secs(60),
        )
        .await;
    assert!(
        rollback_events.iter().any(|e| matches!(
            e,
            StateEvent::RollbackExecuted {
                to_anchor: 1,
                checkpoint: Some(_),
                ..
            }
        )),
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
    ReactorCluster::assert_checkpoints_match(&block1, 1, num_nodes);

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block2 = cluster.wait_for_block(2, Duration::from_secs(60)).await;
    ReactorCluster::assert_checkpoints_match(&block2, 2, num_nodes);

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
    cluster.wait_for_rollback(1, Duration::from_secs(60)).await;

    // Post-rollback, the decisions above the fork are forgotten and the
    // re-delivered blocks are proposed and decided FRESH; the duplicate
    // decided rows this leaves for identical blocks are drained safely on
    // sync by the drain's already-executed/stale checks.
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

    cluster.shutdown().await;
    Ok(())
}

/// A Bitcoin rollback across a NON-empty decided batch: the batch's effects
/// roll back with the blocks, the forgotten decision is not ghost-replayed
/// (the audit regression: a decided-value reload placed after the truncation
/// replayed batches with zero txids), the drain does not wedge on stale
/// decisions, and the txs re-execute via a fresh mempool→batch decision on
/// the re-delivered chain.
#[tokio::test]
async fn prod_reactor_bitcoin_rollback_across_decided_batch() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    let mempool_events = cluster.mock_bitcoin().generate_mempool_txs(2);
    for event in mempool_events.clone() {
        cluster.send_mempool_event(event);
    }
    let first = cluster.wait_for_batch(2, Duration::from_secs(60)).await;
    assert_eq!(first.txids.len(), 2, "setup batch must carry both txs");

    // Reorg below the batch anchor — its effects are wiped with the blocks
    // and its decision is forgotten (rows stay as consensus history).
    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster.wait_for_rollback(1, Duration::from_secs(60)).await;

    // The re-delivered chain decides block 2 fresh; the rolled-back txs
    // return via the mempool and re-execute in a NEW batch at the same
    // anchor. This times out if a ghost replay consumed the txids
    // (empty-batch record with txid_count=0) or if a stale reloaded
    // decision wedged the drain.
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;
    for event in mempool_events {
        cluster.send_mempool_event(event);
    }
    let replayed = cluster.wait_for_batch(2, Duration::from_secs(60)).await;
    assert_eq!(
        replayed.txids.len(),
        2,
        "rolled-back batch txs must re-execute in a fresh batch"
    );

    cluster.shutdown().await;
    Ok(())
}

/// THE #515 REGRESSION.
///
/// A validator executes a batch, restarts while that batch is still inside its
/// finality window, and its transactions never confirm. Finality tracking used to
/// live only in memory, so the restarted node came back owing a verdict it no
/// longer knew about: its peers rolled the batch back, it did not, and it kept
/// transaction rows they had deleted. Days later the network re-batched those same
/// transactions, the node hit `transactions.txid UNIQUE`, and crash-looped.
///
/// Four validators so the remaining three still hold a supermajority while one is
/// down. The assertion is on the restarted node's own database: after the deadline
/// passes, the batch's rows must be gone — meaning it rendered the verdict and
/// performed the rollback, which is only possible if tracking survived the restart.
#[tokio::test]
async fn prod_reactor_restart_inside_finality_window_still_rolls_back() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    // A batch anchored at 1 whose transactions are never mined — deadline 1 + 6 = 7.
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let batch = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    assert_eq!(batch.txids.len(), 2, "setup batch must carry both txs");

    // The node under test executed it, so the rows are there before the restart.
    {
        let conn = cluster.node_conn(3).await;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM transactions WHERE batch_height IS NOT NULL",
                (),
            )
            .await?;
        let before: u64 = rows.next().await?.expect("row").get(0)?;
        assert!(
            before > 0,
            "node 3 must have executed the batch before restart"
        );
    }

    // Restart INSIDE the finality window — the #515 trigger.
    cluster.restart_node(3).await;

    // Climb past the deadline. The transactions never confirmed, so every node owes
    // a rollback — including the one that restarted.
    for _ in 0..8 {
        cluster.mine_empty_and_send();
    }
    // Poll the restarted node's OWN database. Waiting on the shared finality
    // channel would prove nothing — any of the three peers that never went down
    // satisfies it. The restarted node has to sync the decisions it missed before
    // it can render the verdict, so the wait belongs here.
    let conn = cluster.node_conn(3).await.clone();
    let mut after = u64::MAX;
    for _ in 0..240 {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM transactions WHERE batch_height IS NOT NULL",
                (),
            )
            .await?;
        after = rows.next().await?.expect("row").get(0)?;
        if after == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        after, 0,
        "restarted node still holds batch rows its peers rolled back — finality \
         tracking did not survive the restart (#515)"
    );

    cluster.shutdown().await;
    Ok(())
}

/// Every consensus height must leave a row in `batches` — that table is the decided
/// sequence and the ONLY copy of it, since Malachite asks us for decided values
/// rather than keeping them. A height with no row is a hole that cannot be refilled:
/// the startup cleanup trims an unexecuted SUFFIX, never a gap in the middle.
///
/// SCOPE, so this is not mistaken for more than it is: measured green both with and
/// without `record_declined_block`, so it does NOT cover that fix. Every decision in
/// this scenario is executed before the reorg lands, so nothing is ever declined —
/// reaching those paths needs a reorg to arrive between decide and execute, which
/// the harness cannot schedule. What this does cover is the invariant itself, on a
/// real reorg: it would catch a future change that starts dropping decisions.
#[tokio::test]
async fn prod_reactor_reorg_leaves_no_gap_in_the_decided_sequence() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for h in 1..=3 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }

    // Reorg away the top two blocks, then let the new chain be decided.
    cluster.mock_bitcoin().reset_to(1);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 1 });
    cluster.wait_for_rollback(1, Duration::from_secs(60)).await;
    for h in 2..=4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }

    let conn = cluster.node_conn(0).await;
    let mut rows = conn
        .query(
            "SELECT MIN(consensus_height), MAX(consensus_height), COUNT(*) FROM batches",
            (),
        )
        .await?;
    let row = rows.next().await?.expect("batches must not be empty");
    let (min, max, count): (u64, u64, u64) = (row.get(0)?, row.get(1)?, row.get(2)?);
    assert_eq!(
        count,
        max - min + 1,
        "decided sequence has a gap: heights {min}..={max} but only {count} rows"
    );

    cluster.shutdown().await;
    Ok(())
}

/// A Bitcoin reorg that stops AT a tracked batch's anchor. The rollback deletes
/// blocks strictly above the target, so a batch anchored at or below it keeps its
/// `transactions` rows and is still owed a finality verdict. No other test
/// constructs this shape — the two existing reorg tests either track nothing or
/// reorg BELOW the anchor so the rows cascade away.
///
/// Asserts on WHICH batch was invalidated, not merely that some rollback happened:
/// the excluded transactions return via the mempool, so a rollback naming a
/// different consensus height fires even when tracking was wiped.
#[tokio::test]
async fn prod_reactor_reorg_at_batch_anchor_keeps_batch_tracked() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    // A batch anchored at 2, whose txs will never confirm — deadline 2 + 6 = 8.
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let batch = cluster.wait_for_batch(2, Duration::from_secs(60)).await;
    assert_eq!(batch.txids.len(), 2, "setup batch must carry both txs");
    let tracked_height = batch
        .state_events
        .iter()
        .find_map(|e| match e {
            StateEvent::BatchApplied {
                consensus_height, ..
            } => Some(*consensus_height),
            _ => None,
        })
        .expect("setup batch must report a consensus height");

    cluster.mine_empty_and_send();
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

    // Reorg back to the batch's own anchor. Block 2 survives with the same hash, so
    // the batch is untouched — only the blocks above it go.
    cluster.mock_bitcoin().reset_to(2);
    cluster.send_block_event(BlockEvent::Rollback { to_height: 2 });
    cluster.wait_for_rollback(2, Duration::from_secs(60)).await;

    // Climb past the deadline. The surviving batch's txs are still unconfirmed, so
    // finality must still invalidate it.
    for _ in 0..7 {
        cluster.mine_empty_and_send();
    }
    // Assert on WHICH batch was invalidated, not merely that some rollback happened:
    // the excluded txs return via the mempool, so a rollback naming a DIFFERENT
    // consensus height fires even with tracking wiped.
    let events = cluster
        .wait_for_finality_event_matching(
            move |e| {
                matches!(e, FinalityEvent::Rollback { invalidated_batches, .. }
                    if invalidated_batches.contains(&tracked_height))
            },
            Duration::from_secs(60),
        )
        .await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            FinalityEvent::Rollback { invalidated_batches, .. }
                if invalidated_batches.contains(&tracked_height)
        )),
        "expected a Rollback invalidating the tracked batch {tracked_height}, got: {events:?}"
    );

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

#[tokio::test]
async fn prod_reactor_simulate_transaction() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    // Mine a block so the node has processed at least one block
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    // Create a stub transaction for simulation
    let tx = indexer_types::Transaction {
        txid: bitcoin::Txid::from_slice(&[0xAA; 32]).unwrap(),
        index: 0,
        inputs: vec![],
        op_return_raw: None,
    };

    // Simulate on node 0 — exercises savepoint → execute → inspect → rollback
    let result = cluster.simulate(0, tx).await?;
    assert!(
        result.is_empty(),
        "Expected empty results for stub transaction, got: {result:?}"
    );

    // Mine another block and verify all nodes agree on checkpoint.
    // If simulation leaked state on node 0, its checkpoint would diverge.
    cluster.mine_empty_and_send();
    let block2 = cluster.wait_for_block(2, Duration::from_secs(60)).await;
    ReactorCluster::assert_checkpoints_match(&block2, 2, cluster.node_count);

    cluster.shutdown().await;
    Ok(())
}

/// A node that can't finalize (here: consensus lacks quorum) must bound
/// `pending_blocks` and backpressure the block producer rather than buffer every
/// block up to the chain tip in memory — the unbounded-growth OOM that took down
/// the signet validator set. See `MAX_PENDING_BLOCKS`.
#[tokio::test]
async fn prod_reactor_pending_blocks_bounded_under_stalled_consensus() -> Result<()> {
    // 4-validator genesis, boot only 2 → 200/400 voting power, below the >2/3
    // BFT threshold, so no `Value::Block` is ever decided and `pending_blocks`
    // never drains. Without the high-water gate the reactor would drain its block
    // channel into the map without limit.
    let cluster = ReactorCluster::start_with(4, 2).await?;

    // Flood one node with far more blocks than the buffer + channel can hold. Each
    // send has a generous timeout; the first send that blocks past it is the
    // backpressure point — the reactor has stopped draining at the high-water mark.
    let producer = cluster.block_txs[0].clone();
    let flood = 1200u64;
    let mut accepted = 0u64;
    for height in 1..=flood {
        let event = BlockEvent::BlockInsert {
            target_height: height,
            block: indexer_types::Block {
                height,
                hash: crate::test_utils::new_mock_block_hash(height as u32),
                prev_hash: crate::test_utils::new_mock_block_hash(height.saturating_sub(1) as u32),
                transactions: Vec::new(),
            },
        };
        match tokio::time::timeout(Duration::from_secs(5), producer.send(event)).await {
            Ok(Ok(())) => accepted += 1,
            _ => break,
        }
    }

    // With the gate, accepted saturates near MAX_PENDING_BLOCKS (held in the map)
    // plus the 256-slot test channel — far below the flood. Without it, all 1200
    // would be accepted into the unbounded map.
    let ceiling = super::MAX_PENDING_BLOCKS as u64 + 256 + 16;
    assert!(
        accepted >= super::MAX_PENDING_BLOCKS as u64,
        "reactor did not drain up to the high-water mark: accepted {accepted}"
    );
    assert!(
        accepted <= ceiling,
        "pending_blocks is unbounded: accepted {accepted}/{flood} exceeds {ceiling} — high-water gate not applied"
    );

    cluster.shutdown().await;
    Ok(())
}

/// A node whose execution has fallen behind heights the network already decided
/// must PARK the out-of-order decision, not die on it.
///
/// This is the signet halt of 2026-08. One validator's executor was 128 blocks
/// behind while its buffer held the whole window, so a decision for the network's
/// tip found that block cached and went straight to the executor — whose height
/// guard is a `bail!`, taken *after* the `batches` row was already committed.
/// The reactor exited, the pod restarted, and because that validator held the
/// third of three usable votes in a 3/4 quorum, each restart bought exactly one
/// decided height before dying again: 121 restarts, 20 h, chain stopped.
///
/// The property is asymmetric on purpose. The lagging node stays stuck — the
/// heights it missed will not be re-decided, and value-sync will not backfill a
/// node whose *consensus* height is current — but it stays UP, keeps voting, and
/// the chain keeps moving. A stuck node is an operator problem; a crash-looping
/// one takes the network down with it.
#[tokio::test]
async fn prod_reactor_out_of_order_block_decision_parks_instead_of_dying() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    // Blocks 1 and 2 reach only nodes 0-2. Node 3 has no block at all, so it
    // rejects both proposals and votes nil; 3 of 4 still clears the 2/3
    // threshold, so consensus decides and executes them without it. Node 3's
    // consensus height advances with every decision — which is precisely why it
    // will never be re-sent these heights.
    let lagging = 3;
    for height in 1..=2u64 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            for (i, tx) in cluster.block_txs.iter().enumerate() {
                if i != lagging {
                    let _ = tx.try_send(event.clone());
                }
            }
        }
        cluster
            .wait_for_block_decided(height, Duration::from_secs(60))
            .await;
    }

    // Block 3 goes to everyone. Node 3 now holds a block for height 3 with a tip
    // of 0 — buffered, but 2 heights out of reach. It accepts the proposal (the
    // block IS the canonical one at that height, which is all a `Value::Block`
    // asserts) and votes for it, so the decision lands on a node that cannot
    // execute it. Before the ordering gate, this is the line that killed the
    // reactor: "Unexpected block height 3, expected 1".
    let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
    for event in blk_events {
        cluster.send_block_event(event);
    }
    cluster
        .wait_for_block_decided(3, Duration::from_secs(60))
        .await;

    // The chain keeps advancing afterwards — the lagging node still votes, so
    // quorum survives. Two more heights prove it is not a one-off.
    for height in 4..=5u64 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            cluster.send_block_event(event);
        }
        cluster
            .wait_for_block_decided(height, Duration::from_secs(60))
            .await;
    }

    cluster.assert_no_reactor_errors();
    cluster.shutdown().await;
    Ok(())
}

/// A block re-delivered AFTER the node already executed it must not stop the
/// chain.
///
/// This is not a synthetic poke: `replay_blocks_after` re-sends every stored
/// block event above a height, and the finality path deliberately keeps
/// `pending_blocks` across a rollback. A replayed `BlockInsert` can therefore
/// land after the deferred decisions have already drained and carried the tip
/// past that height — the poller redelivering a block the node has since
/// applied.
///
/// `process_block_event` buffers it with no tip check, and `make_value`
/// proposes `pending_blocks.first_key_value()` with no tip check either, so the
/// proposer offers an already-applied height. Nothing consumes it: the finalize
/// gate only removes from `pending_blocks` when the decision is in order, and
/// the drain's tip gate drops the decision without touching the buffer. If that
/// is a closed loop, the stale entry stays the minimum forever, newer blocks
/// are never proposed, and the chain stops.
#[tokio::test]
async fn prod_reactor_replayed_block_below_tip_does_not_stall_the_chain() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for height in 1..=3u64 {
        cluster.mine_empty_and_send();
        cluster
            .wait_for_block(height, Duration::from_secs(60))
            .await;
    }

    // Re-deliver block 2, now two heights below the tip — exactly what a late
    // replay looks like.
    let replayed = cluster
        .mock_bitcoin()
        .get_all_block_events()
        .into_iter()
        .find(|e| matches!(e, BlockEvent::BlockInsert { block, .. } if block.height == 2))
        .expect("block 2 must have been mined");
    cluster.send_block_event(replayed);

    // The chain must still make progress. If the stale entry pins `make_value`,
    // height 4 is never proposed and this times out.
    cluster.mine_empty_and_send();
    cluster.wait_for_block(4, Duration::from_secs(60)).await;

    cluster.assert_no_reactor_errors();
    cluster.shutdown().await;
    Ok(())
}
