#[path = "ordering_reward_tests.rs"]
mod ordering_reward_tests;
#[path = "startup_recovery_tests.rs"]
mod startup_recovery_tests;

use startup_recovery_tests::StartupFaults;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::stopper::{Shutdown, ShutdownSignal};
use anyhow::{Result, anyhow};
use bitcoin::Transaction as BitcoinTransaction;
use bitcoin::consensus::serialize;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{Instrument, info, info_span};

use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::consensus::finality_types::{DecidedBatch, FinalityEvent, StateEvent};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Genesis, Height};
use crate::database::certified_history;
use crate::database::receipt_stream::{recovery_boundary, stream_state};
use crate::keygen;
use crate::logging;
use crate::protocol::coordinator::application_closure::WorkItem;
use crate::protocol::coordinator::linked;
use crate::reactor::certified_fixture;
use crate::reactor::consensus_state::{ConsensusState, ObservationChannels, certified_startup};
use crate::reactor::engine::{self, EngineConfig};
use crate::reactor::execution::ExecutionContext;
use crate::reactor::lite_executor::{LiteExecutor, shared_session_factory};
use crate::reactor::mock_bitcoin::MockBitcoin;
use crate::reactor::{Reactor, Simulation};
use crate::runtime::GenesisValidator;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::ownership::{AsyncGate, OwnerService};
use bitcoin::Network;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use indexer_types::Event;
use indexer_types::OpWithResult;
use indexer_types::{ContractAddress, Inst, InstKind, Insts};
use malachitebft_app_channel::app::config::{BootstrapProtocol, DiscoveryConfig, Selector};

fn counter_key() -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[31; 32]).unwrap(),
    )
}

fn counter_address() -> ContractAddress {
    ContractAddress {
        name: "counter".into(),
        height: 1,
        tx_index: 1,
    }
}

fn counter_transaction(nonce: u32) -> BitcoinTransaction {
    certified_fixture::transaction(
        &counter_key(),
        Insts::direct(vec![Inst {
            gas_limit: 100_000,
            kind: InstKind::Call {
                contract: counter_address(),
                expr: "increment()".into(),
            },
        }]),
        nonce,
    )
    .unwrap()
}

fn counter_setup_transaction() -> Result<BitcoinTransaction> {
    certified_fixture::transaction(
        &counter_key(),
        Insts::direct(vec![
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Publish {
                    name: "counter".into(),
                    bytes: include_bytes!("../../../../test-contracts/binaries/counter.wasm.br")
                        .to_vec(),
                    provenance: testlib::sample_provenance(),
                },
            },
        ]),
        0,
    )
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
    /// Per-node storage connections, resolved lazily from `conn_rxs` on first use.
    /// A node that has not been started yet has neither.
    conns: Vec<Option<libsql::Connection>>,
    conn_rxs: Vec<Option<oneshot::Receiver<libsql::Connection>>>,
    /// Each node's data directory, owned HERE so it survives the node's task and a
    /// restart can reopen it.
    node_dirs: Vec<(tempfile::TempDir, String)>,
    /// Child of the cluster token, so cancelling the cluster still stops everyone
    /// while a single node can also be stopped on its own.
    node_cancels: Vec<Shutdown>,
    node_completions: Vec<Option<oneshot::Receiver<()>>>,
    owner_services: Arc<Mutex<Vec<Option<OwnerService>>>>,
    /// Per-node `validate_txs` latency, passed to every spawned/restarted node.
    validation_delay: Option<Duration>,
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
    cancel: Shutdown,
    join_set: JoinSet<()>,
    node_count: usize,
    ready_rx: mpsc::Receiver<usize>,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    genesis_validators: Vec<GenesisValidator>,
    private_keys: Vec<PrivateKey>,
    /// Node 0's resolved consensus listen multiaddr — the bootstrap seed every
    /// other node (including late joiners via `add_node`) discovers the cluster
    /// through. No fixed ports: each node binds `/tcp/0` and publishes its
    /// resolved address on a per-node watch the reactor writes on bind.
    seed_addr: String,
    shared_pubkey: String,
    session_factory: SessionFactory,
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
    consensus_height: Height,
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
impl ReactorCluster {
    async fn start_with(total: usize, initial: usize) -> Result<Self> {
        Self::start_with_options(total, initial, None).await
    }

    /// [`Self::start_with`], with every node's `LiteExecutor` holding each
    /// `validate_txs` open for `validation_delay` — for asserting the event
    /// loop stays live while consensus I/O is in flight.
    async fn start_with_options(
        total: usize,
        initial: usize,
        validation_delay: Option<Duration>,
    ) -> Result<Self> {
        Self::start_with_faults(total, initial, validation_delay, None).await
    }

    async fn start_with_faults(
        total: usize,
        initial: usize,
        validation_delay: Option<Duration>,
        startup_faults: Option<StartupFaults>,
    ) -> Result<Self> {
        logging::setup();
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

        let genesis_validators: Vec<GenesisValidator> = validator_keys
            .iter()
            .map(|k| GenesisValidator {
                x_only_pubkey: hex::encode(k.x_only_pubkey),
                stake: crate::runtime::Decimal::try_from(100u64).unwrap(),
                ed25519_pubkey: k.ed25519_pubkey.to_vec(),
            })
            .collect();

        let (mempool_tx, _) = broadcast::channel::<MempoolEvent>(256);
        let cancel = Shutdown::new();
        let mut block_txs = Vec::new();
        let mut conn_rxs: Vec<Option<oneshot::Receiver<libsql::Connection>>> =
            (0..total).map(|_| None).collect();
        let node_dirs: Vec<(tempfile::TempDir, String)> = (0..total)
            .map(|_| crate::test_utils::new_test_db_dir().expect("node data dir"))
            .collect();
        let node_cancels: Vec<Shutdown> = (0..total).map(|_| cancel.child()).collect();
        let mut node_completions: Vec<Option<oneshot::Receiver<()>>> =
            (0..total).map(|_| None).collect();
        let owner_services = Arc::new(Mutex::new((0..total).map(|_| None).collect()));
        let mock_bitcoin = Arc::new(Mutex::new(
            MockBitcoin::new(0)
                .with_transactions(counter_setup_transaction()?, counter_transaction),
        ));
        let shared_pubkey = counter_key().x_only_public_key().0.to_string();
        let session_factory = shared_session_factory().await;

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

            let node_mempool_rx = Self::bridge_mempool(&mempool_tx, &cancel.signal());
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

            node_completions[i] = Some(Self::spawn_node(
                i,
                private_keys[i].clone(),
                &genesis_validators,
                peers,
                addr_tx,
                node_block_rx,
                node_mempool_rx,
                node_cancels[i].signal(),
                owner_services.clone(),
                decided_tx.clone(),
                finality_tx.clone(),
                state_tx.clone(),
                ready_tx.clone(),
                event_tx.clone(),
                Some(sim_rx),
                mock_bitcoin.clone(),
                shared_pubkey.clone(),
                session_factory.clone(),
                node_conn_tx,
                node_dirs[i].0.path().to_path_buf(),
                node_dirs[i].1.clone(),
                true,
                validation_delay,
                startup_faults.clone(),
                reactor_errors.clone(),
                &mut join_set,
            ));
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
            node_completions,
            owner_services,
            validation_delay,
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
            genesis_validators,
            private_keys,
            seed_addr,
            shared_pubkey,
            session_factory,
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
        if let Some(completed) = self.node_completions[i].take() {
            timeout(Duration::from_secs(30), completed)
                .await
                .expect("node task did not finish after cancellation")
                .expect("node task panicked before completing");
        }
        self.conns[i] = None;
    }

    /// Stop a node and bring it back up on the state it left behind — the shape of
    /// issue #515, where a restart inside the finality window lost tracking that
    /// lived only in memory.
    async fn restart_node(&mut self, i: usize) {
        self.stop_node(i).await;

        self.node_cancels[i] = self.cancel.child();
        let (node_block_tx, node_block_rx) = mpsc::channel(256);
        self.block_txs[i] = node_block_tx.clone();
        let node_mempool_rx = Self::bridge_mempool(&self.mempool_tx, &self.cancel.signal());
        let (sim_tx, sim_rx) = mpsc::channel(1);
        self.simulate_txs[i] = sim_tx;
        let (addr_tx, _addr_rx) = watch::channel(None);
        let (node_conn_tx, node_conn_rx) = oneshot::channel();
        self.conn_rxs[i] = Some(node_conn_rx);

        self.node_completions[i] = Some(Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis_validators,
            vec![self.seed_addr.clone()],
            addr_tx,
            node_block_rx,
            node_mempool_rx,
            self.node_cancels[i].signal(),
            self.owner_services.clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.event_tx.clone(),
            Some(sim_rx),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            self.session_factory.clone(),
            node_conn_tx,
            self.node_dirs[i].0.path().to_path_buf(),
            self.node_dirs[i].1.clone(),
            false,
            self.validation_delay,
            None,
            self.reactor_errors.clone(),
            &mut self.join_set,
        ));

        // Only this node reports ready — `wait_for_ready` would block forever
        // waiting on the peers that never went down.
        let _ = self.ready_rx.recv().await;
    }

    async fn start(n: usize) -> Result<Self> {
        Self::start_with(n, n).await
    }

    fn bridge_mempool(
        mempool_tx: &broadcast::Sender<MempoolEvent>,
        cancel: &ShutdownSignal,
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
        genesis_validators: &[GenesisValidator],
        peers: Vec<String>,
        consensus_listen_addr: watch::Sender<Option<String>>,
        node_block_rx: mpsc::Receiver<BlockEvent>,
        node_mempool_rx: mpsc::Receiver<MempoolEvent>,
        cancel: ShutdownSignal,
        owner_services: Arc<Mutex<Vec<Option<OwnerService>>>>,
        dtx: mpsc::Sender<DecidedBatch>,
        ftx: mpsc::Sender<FinalityEvent>,
        stx: mpsc::Sender<StateEvent>,
        rtx: mpsc::Sender<usize>,
        etx: mpsc::Sender<Event>,
        sim_rx: Option<mpsc::Receiver<Simulation>>,
        mock_btc: Arc<Mutex<MockBitcoin>>,
        pubkey: String,
        session_factory: SessionFactory,
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
        // Artificial `validate_txs` latency — see `validation_delay` on the
        // cluster.
        validation_delay: Option<Duration>,
        startup_faults: Option<StartupFaults>,
        reactor_errors: Arc<Mutex<Vec<(usize, String)>>>,
        join_set: &mut JoinSet<()>,
    ) -> oneshot::Receiver<()> {
        let genesis_vals = genesis_validators.to_vec();
        let owner_service = OwnerService::new();
        owner_services.lock().unwrap()[i] = Some(owner_service.clone());
        let span = info_span!("cluster", id = %pubkey, node = i);
        let node = async move {
            assert_eq!(data_dir.join(&db_name).exists(), !first_boot);
            let (mut executor, session, resume_height, resume_hash) = LiteExecutor::open(
                &data_dir,
                &db_name,
                mock_btc,
                &genesis_vals,
                session_factory,
                &owner_service,
            )
            .await
            .expect("certified cluster session");
            if let Some(delay) = validation_delay {
                executor.set_validation_delay(delay);
            }

            let engine_config = EngineConfig {
                private_key,
                // OS-assigned port (no probe/release race). The seed boots with
                // no peers; everyone else bootstraps from the seed's reported
                // address and discovers the rest of the cluster.
                listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
                persistent_peers: peers,
                data_dir: executor.data_dir(),
                consensus_enabled: true,
                discovery: DiscoveryConfig {
                    enabled: true,
                    bootstrap_protocol: BootstrapProtocol::Full,
                    selector: Selector::Random,
                    // All local peers share one IP, so a transient disconnect must not
                    // throttle the whole cluster for the production 30-second window.
                    ip_throttle_duration: Duration::ZERO,
                    ..Default::default()
                },
            };

            let conn = session.conn.clone();
            // Ignore the error: a test that never asks for the connection drops the
            // receiver, which is fine.
            let _ = conn_tx.send(conn.clone());

            let context = certified_history::frontier(&conn)
                .await
                .unwrap()
                .context
                .unwrap();
            let mut execution = ExecutionContext::new(
                executor,
                session,
                Network::Regtest,
                owner_service,
                context,
                super::PruneConfig {
                    enabled: false,
                    retain_blocks: 144,
                },
                resume_height,
                resume_hash,
            );
            if !execution.recover(&cancel).await.expect("cluster recovery") {
                return;
            }
            let resume_height = execution.last_height;
            let (_, _, validator_set) = certified_startup(&conn)
                .await
                .expect("recovered cluster committee");
            let genesis = Genesis { validator_set };

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
                resume_height,
                engine_output.channels,
                engine_output._handle,
                validator_index,
                crate::reactor::mempool_fee_index::MempoolFeeIndex::new(None),
            )
            .await
            .expect("ConsensusState::new failed");
            let _fault_tasks = startup_faults.map(|faults| {
                state.timeouts.propose = Duration::from_secs(10);
                faults.install(&mut state.channels)
            });
            state.observation = Some(ObservationChannels {
                decided_tx: dtx,
                finality_tx: ftx,
                state_tx: stx,
            });

            let mut reactor = Reactor::from_execution(
                execution,
                node_block_rx,
                node_mempool_rx,
                cancel.clone(),
                None,
                Some(etx),
                sim_rx,
                state,
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
        };
        let (completed, completion) = oneshot::channel();
        join_set.spawn(async move {
            node.instrument(span).await;
            // The node future and its owned database/engine handles are dropped
            // before a restart is allowed to open that database again.
            let _ = completed.send(());
        });
        completion
    }

    async fn counter_value(&self, node: usize) -> Result<String> {
        let (dir, name) = &self.node_dirs[node];
        let pool = linked::new_read_pool(
            dir.path().to_path_buf(),
            name.clone(),
            Network::Regtest,
            DEFAULT_VIEW_GAS_LIMIT,
        )?;
        let address = counter_address();
        linked::execute_view(
            &OwnerService::new(),
            pool.get().await?,
            Network::Regtest,
            (address.name, address.height, address.tx_index),
            "get()".into(),
        )
        .await?
        .map_err(|(_, message)| anyhow!(message))
    }

    async fn add_node(&mut self) -> Result<usize> {
        let i = self
            .started_nodes
            .iter()
            .position(|&started| !started)
            .ok_or_else(|| anyhow::anyhow!("All nodes already started"))?;

        let (node_block_tx, node_block_rx) = mpsc::channel(256);
        self.block_txs.push(node_block_tx.clone());

        let node_mempool_rx = Self::bridge_mempool(&self.mempool_tx, &self.cancel.signal());
        let (sim_tx, sim_rx) = mpsc::channel(1);
        self.simulate_txs.push(sim_tx);

        // Late joiner bootstraps from the seed; its own address isn't read back.
        let (addr_tx, _addr_rx) = watch::channel(None);
        let (node_conn_tx, node_conn_rx) = oneshot::channel();
        self.conn_rxs[i] = Some(node_conn_rx);

        self.node_completions[i] = Some(Self::spawn_node(
            i,
            self.private_keys[i].clone(),
            &self.genesis_validators,
            vec![self.seed_addr.clone()],
            addr_tx,
            node_block_rx,
            node_mempool_rx,
            self.node_cancels[i].signal(),
            self.owner_services.clone(),
            self.decided_tx.clone(),
            self.finality_tx.clone(),
            self.state_tx.clone(),
            self.ready_tx.clone(),
            self.event_tx.clone(),
            Some(sim_rx),
            self.mock_bitcoin.clone(),
            self.shared_pubkey.clone(),
            self.session_factory.clone(),
            node_conn_tx,
            self.node_dirs[i].0.path().to_path_buf(),
            self.node_dirs[i].1.clone(),
            true,
            self.validation_delay,
            None,
            self.reactor_errors.clone(),
            &mut self.join_set,
        ));

        self.started_nodes[i] = true;
        self.node_count += 1;

        let _ = self.ready_rx.recv().await;

        Ok(i)
    }

    async fn wait_for_ready(&mut self) {
        for _ in 0..self.node_count {
            let _ = self.ready_rx.recv().await;
        }

        // Mesh formation is established by each test's first certified block.
        // There is deliberately no empty Batch(0) startup barrier.
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
        let mut consensus_height = None;
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
                    if !d.value.is_block()
                        && d.value.block_height() == anchor_height
                        && !d.value.batch_txids().is_empty()
                        && consensus_height.is_none_or(|height| d.consensus_height > height)
                    {
                        consensus_height = Some(d.consensus_height);
                        txids = d.value.batch_txids().iter().map(|t| t.to_string()).collect();
                        decided = true;
                        // An anchor can have several batches, including empty ones.
                        // Only observations of this decision establish its application.
                        state_count = state_events
                            .iter()
                            .filter(|se| matches!(se, StateEvent::BatchApplied { consensus_height: h, .. } if Some(*h) == consensus_height))
                            .count();
                        event_count = events
                            .iter()
                            .filter(|ev| match ev {
                                Event::BatchProcessed { txids: et } => {
                                    et == &txids
                                }
                                _ => false,
                            })
                            .count();
                    }
                }
                Some(se) = self.state_rx.recv() => {
                    if matches!(&se, StateEvent::BatchApplied { consensus_height: h, .. } if Some(*h) == consensus_height) {
                        state_count += 1;
                    }
                    state_events.push(se);
                }
                Some(ev) = self.event_rx.recv() => {
                    if let Event::BatchProcessed { txids: ref ev_txids } = ev
                        && !txids.is_empty()
                        && ev_txids == &txids
                    {
                        event_count += 1;
                    }
                    events.push(ev);
                }
            }
        }
        BatchResult {
            consensus_height: consensus_height.expect("batch decision observed"),
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

    async fn replace_after(&mut self, surviving_height: u64) -> BlockResult {
        self.mock_bitcoin().reset_to(surviving_height);
        self.send_block_event(BlockEvent::Rollback {
            to_height: surviving_height,
        });
        self.mine_empty_and_send();
        let result = self
            .wait_for_block(surviving_height + 1, Duration::from_secs(60))
            .await;
        assert_eq!(result.state_events.iter().filter(|event| matches!(event,
            StateEvent::RollbackExecuted { to_anchor, .. } if *to_anchor == surviving_height + 1
        )).count(), self.node_count);
        assert_eq!(
            result
                .events
                .iter()
                .filter(|event| matches!(event,
                    Event::Rolledback { height } if *height == surviving_height
                ))
                .count(),
            self.node_count
        );
        result
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
    /// Use wait_for_block or wait_for_batch instead when possible.
    async fn wait_for_state_event_matching(
        &mut self,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, 1, timeout).await
    }

    /// Low-level: wait for n state events matching a predicate.
    /// Use wait_for_block or wait_for_batch instead when possible.
    async fn wait_for_n_state_events_matching(
        &mut self,
        n: usize,
        pred: impl Fn(&StateEvent) -> bool,
        timeout: Duration,
    ) -> Vec<StateEvent> {
        wait_matching(&mut self.state_rx, pred, n, timeout).await
    }

    /// Send a transaction to a specific node for simulation and await the result.
    async fn simulate(&self, node: usize, tx: BitcoinTransaction) -> Result<Vec<OpWithResult>> {
        let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
        self.simulate_txs[node]
            .send((serialize(&tx), ret_tx))
            .await
            .map_err(|_| anyhow::anyhow!("simulate channel closed"))?;
        ret_rx
            .await
            .map_err(|_| anyhow::anyhow!("simulate response channel closed"))??
            .map_err(anyhow::Error::msg)
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

    async fn shutdown_with_owners(mut self) -> Result<()> {
        self.cancel.cancel();
        for owner in self.owner_services.lock().unwrap().iter().flatten() {
            owner.shutdown();
        }
        while let Some(joined) = self.join_set.join_next().await {
            joined
                .map_err(|error| anyhow!("reactor task failed during owner shutdown: {error}"))?;
        }
        Ok(())
    }
}

impl Drop for ReactorCluster {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[tokio::test]
async fn prod_reactor_validators_agree_on_values() -> Result<()> {
    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;
    let mut batch_heights = Vec::new();
    for _ in 0..2 {
        for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
            cluster.send_mempool_event(event);
        }
        let result = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
        assert_eq!(result.txids.len(), 3);
        batch_heights.push(result.consensus_height.as_u64());
    }
    for node in 0..3 {
        assert_eq!(cluster.counter_value(node).await?, "6");
        let conn = cluster.node_conn(node).await.clone();
        assert!(
            certified_history::load(&conn, 1)
                .await?
                .decision()
                .descriptor
                .command
                .position()
                .2
        );
        for height in &batch_heights {
            let decision = certified_history::load(&conn, *height).await?;
            let (anchor, _, is_block) = decision.decision().descriptor.command.position();
            assert_eq!(anchor, 1);
            assert!(!is_block);
        }
    }
    cluster.mine_and_send(&[]);
    cluster.wait_for_block(2, Duration::from_secs(60)).await;
    for node in 0..3 {
        assert_eq!(
            cluster.counter_value(node).await?,
            "6",
            "confirmation must not execute twice"
        );
    }
    cluster.restart_node(1).await;
    assert_eq!(cluster.counter_value(1).await?, "6");
    assert!(cluster.reactor_errors.lock().unwrap().is_empty());
    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_block_updates_anchor() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }

    cluster.wait_for_batch(2, Duration::from_secs(60)).await;

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_happy_path_finalization() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }

    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);

    for _ in 0..5 {
        cluster.mine_empty_and_send();
    }

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 1),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        finality_events.iter().any(
            |e| matches!(e, FinalityEvent::BatchFinalized { anchor_height, .. } if *anchor_height == 1)
        ),
        "Expected BatchFinalized at anchor 1, got: {finality_events:?}"
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_missing_tx_invalidation() -> Result<()> {
    assert_missing_tx_invalidation(3).await
}

#[tokio::test]
async fn prod_reactor_missing_tx_invalidation_with_partial_submission() -> Result<()> {
    assert_missing_tx_invalidation(1).await
}

async fn assert_missing_tx_invalidation(submitted: usize) -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    let mempool_events = cluster.mock_bitcoin().generate_mempool_txs(3);
    let all_txids: Vec<bitcoin::Txid> = mempool_events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::TransactionAdded { txid, .. } => Some(*txid),
            _ => None,
        })
        .collect();
    for event in mempool_events.into_iter().take(submitted) {
        cluster.send_mempool_event(event);
    }

    let batch = cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    // Submission can straddle proposals; withhold a tx that was actually ordered.
    let missing_txid = batch.txids.last().unwrap().parse::<bitcoin::Txid>()?;
    let confirm_txids: Vec<bitcoin::Txid> = all_txids
        .into_iter()
        .filter(|txid| *txid != missing_txid)
        .collect();

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
            |e| matches!(e, FinalityEvent::Rollback { missing, .. } if missing.iter().any(|m| m.txids.contains(&missing_txid))),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        finality_events.iter().any(
            |e| matches!(e, FinalityEvent::Rollback { missing, .. } if missing.iter().any(|m| m.txids.contains(&missing_txid)))
        ),
        "Expected Rollback with missing txid {missing_txid}, got: {finality_events:?}"
    );

    let replayed_txid_count = batch.txids.len() - 1;
    let replayed = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BatchApplied { consensus_height, txid_count, .. } if *consensus_height == batch.consensus_height && *txid_count == replayed_txid_count),
            Duration::from_secs(60),
        )
        .await;
    assert!(
        replayed
            .iter()
            .any(|e| matches!(e, StateEvent::BatchApplied { consensus_height, txid_count, .. } if *consensus_height == batch.consensus_height && *txid_count == replayed_txid_count)),
        "Expected replayed batch {} with {replayed_txid_count} txids (excluding missing), got: {replayed:?}",
        batch.consensus_height
    );

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_cascade_invalidation() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
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

    for i in 0..4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(3 + i, Duration::from_secs(60)).await;
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
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let batch0_result = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    let batch0_txids: Vec<bitcoin::Txid> = batch0_result
        .txids
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

    cluster.mine_and_send(&batch0_txids);
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(2, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(3, Duration::from_secs(60)).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(4, Duration::from_secs(60)).await;

    for i in 0..3 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(5 + i, Duration::from_secs(60)).await;
    }
    cluster.mine_empty_and_send();

    let finality_events = cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 2),
            Duration::from_secs(60),
        )
        .await;

    let rollback = finality_events
        .iter()
        .find(|e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 2));
    assert!(
        rollback.is_some(),
        "Expected Rollback from anchor 2, got: {finality_events:?}"
    );

    if let Some(FinalityEvent::Rollback {
        invalidated_batches,
        ..
    }) = rollback
    {
        assert!(
            invalidated_batches.len() >= 2,
            "Expected cascade to invalidate batches at anchor 2 and 3, got {}",
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
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    let mempool_events = cluster.mock_bitcoin().generate_mempool_txs(2);
    let batch_txids: Vec<bitcoin::Txid> = mempool_events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::TransactionAdded { txid, .. } => Some(*txid),
            _ => None,
        })
        .collect();
    for event in mempool_events {
        cluster.send_mempool_event(event);
    }

    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    // Mine the same txids into a block — they should be deduped (unbatched_count=0)
    cluster.mine_and_send(&batch_txids);
    let block_result = cluster.wait_for_block(2, Duration::from_secs(60)).await;
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
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    let preserved = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    let checkpoint = preserved
        .state_events
        .iter()
        .find_map(|event| match event {
            StateEvent::BatchApplied {
                consensus_height,
                checkpoint,
                ..
            } if *consensus_height == preserved.consensus_height => *checkpoint,
            _ => None,
        })
        .expect("preserved batch checkpoint");
    let txids = preserved
        .txids
        .iter()
        .map(|txid| txid.parse().unwrap())
        .collect::<Vec<_>>();
    cluster.mine_and_send(&txids);
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(2, Duration::from_secs(60)).await;

    for _ in 0..6 {
        cluster.mine_empty_and_send();
    }

    cluster
        .wait_for_finality_event_matching(
            |e| matches!(e, FinalityEvent::Rollback { from_anchor, .. } if *from_anchor == 2),
            Duration::from_secs(60),
        )
        .await;

    // The confirmed batch must survive rollback of the later missing batch.
    let rollback_events = cluster
        .wait_for_state_event_matching(
            |e| {
                matches!(
                    e,
                    StateEvent::RollbackExecuted {
                        to_anchor: 2,
                        checkpoint: Some(restored),
                        ..
                    } if *restored == checkpoint
                )
            },
            Duration::from_secs(60),
        )
        .await;
    assert!(
        rollback_events.iter().any(|e| matches!(
            e,
            StateEvent::RollbackExecuted {
                to_anchor: 2,
                checkpoint: Some(restored),
                ..
            } if *restored == checkpoint
        )),
        "Expected RollbackExecuted to anchor 2 with checkpoint, got: {rollback_events:?}"
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
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block1 = cluster.wait_for_block(2, Duration::from_secs(60)).await;
    ReactorCluster::assert_checkpoints_match(&block1, 2, num_nodes);

    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(2, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block2 = cluster.wait_for_block(3, Duration::from_secs(60)).await;
    ReactorCluster::assert_checkpoints_match(&block2, 3, num_nodes);

    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_multi_batch_same_anchor() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    // First batch at anchor 1
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    // Second batch also at anchor 1 (no intervening block)
    for event in cluster.mock_bitcoin().generate_mempool_txs(3) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    // Now mine a block and verify it processes
    cluster.mine_and_send(&[]);
    cluster.wait_for_block(2, Duration::from_secs(60)).await;

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

    let conn = cluster.node_conn(0).await.clone();
    let before_stream = stream_state(&conn).await?;
    cluster.replace_after(1).await;

    cluster.mine_empty_and_send();
    cluster.wait_for_block(3, Duration::from_secs(60)).await;

    cluster.shutdown().await;
    let after_stream = stream_state(&conn).await?;
    assert_eq!(after_stream.epoch, before_stream.epoch);
    assert!(after_stream.generation > before_stream.generation);
    let recovery = recovery_boundary(
        &conn,
        &after_stream,
        before_stream.generation,
        before_stream.max_result_id,
    )
    .await?
    .expect("Bitcoin rollback must be recoverable by a disconnected client");
    assert_eq!(recovery.surviving_height, 1);
    Ok(())
}

/// Replacing a block below a batch's anchor removes its effects but preserves
/// its certificate. Re-submission on the new branch executes through a new decision.
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

    for node in 0..3 {
        assert_eq!(cluster.counter_value(node).await?, "2");
    }
    let conn = cluster.node_conn(0).await.clone();
    let original = certified_history::load(&conn, first.consensus_height.as_u64()).await?;
    let original_id = original.decision().id()?;
    cluster.replace_after(1).await;
    for node in 0..3 {
        assert_eq!(cluster.counter_value(node).await?, "0");
    }
    assert_eq!(
        certified_history::load(&conn, first.consensus_height.as_u64())
            .await?
            .decision()
            .id()?,
        original_id
    );

    for event in mempool_events {
        cluster.send_mempool_event(event);
    }
    let replayed = cluster.wait_for_batch(2, Duration::from_secs(60)).await;
    assert_eq!(
        replayed.txids.len(),
        2,
        "rolled-back batch txs must re-execute in a fresh batch"
    );

    assert!(replayed.consensus_height > first.consensus_height);
    for node in 0..3 {
        assert_eq!(cluster.counter_value(node).await?, "2");
    }

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

    // A batch anchored at 1 whose transaction is never mined. Deadline 1 + 6 = 7.
    for event in cluster.mock_bitcoin().generate_mempool_txs(1) {
        cluster.send_mempool_event(event);
    }
    let batch = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    assert_eq!(batch.txids.len(), 1, "setup batch must carry the tx");
    let before_stream = stream_state(cluster.node_conn(3).await).await?;

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
    let after_stream = stream_state(&conn).await?;
    assert_eq!(after_stream.epoch, before_stream.epoch);
    assert!(after_stream.generation > before_stream.generation);
    let recovery = recovery_boundary(
        &conn,
        &after_stream,
        before_stream.generation,
        before_stream.max_result_id,
    )
    .await?
    .expect("same-chain finality replay must retain a durable recovery boundary");
    assert_eq!(recovery.surviving_height, 0);
    assert!(recovery.cursor <= before_stream.max_result_id);
    Ok(())
}

#[tokio::test]
async fn shutdown_during_finality_replay_waits_for_active_replay() -> Result<()> {
    crate::logging::setup();
    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;
    for event in cluster.mock_bitcoin().generate_mempool_txs(1) {
        cluster.send_mempool_event(event);
    }
    let batch = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    assert_eq!(batch.txids.len(), 1);
    let mut conns = Vec::new();
    for index in 0..3 {
        conns.push(cluster.node_conn(index).await.clone());
    }
    timeout(Duration::from_secs(10), async {
        loop {
            let mut rows = conns[0]
                .query(
                    "SELECT COUNT(*) FROM transactions WHERE batch_height IS NOT NULL",
                    (),
                )
                .await?;
            if rows.next().await?.expect("batch count").get::<i64>(0)? > 0 {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let gate = Arc::new(AsyncGate::default());
    cluster.mock_bitcoin().rollback_stage_gate = Some(gate.clone());
    for _ in 0..8 {
        cluster.mine_empty_and_send();
    }
    let all_replaying = timeout(Duration::from_secs(90), async {
        while gate.entries.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    if all_replaying.is_err() {
        gate.release();
        cluster.shutdown_with_owners().await?;
        return Err(anyhow!("not all reactors reached finality replay"));
    }
    let owners: Vec<OwnerService> = cluster
        .owner_services
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .cloned()
        .collect();
    assert_eq!(gate.entries.load(Ordering::SeqCst), 3);
    for (conn, owner) in conns.iter().zip(&owners) {
        assert_eq!(owner.active_roots().await, 1);
        assert!(!conn.is_autocommit());
        let frontier = certified_history::frontier(conn).await?;
        assert!(frontier.authenticated_height > frontier.closed_height);
        let progress =
            certified_history::closure::progress(conn, frontier.authenticated_height).await?;
        assert_eq!(
            progress.next.map(|(action, _)| action),
            Some(WorkItem::Rollback { height: 0 })
        );
    }
    let reactor_errors = cluster.reactor_errors.clone();
    let mut shutdown = tokio::spawn(async move { cluster.shutdown_with_owners().await });
    let retained = timeout(Duration::from_millis(150), &mut shutdown)
        .await
        .is_err();
    gate.release();
    assert!(
        retained,
        "shutdown released reactors while replay was active"
    );
    timeout(Duration::from_secs(30), shutdown).await???;
    let errors = reactor_errors.lock().unwrap().clone();
    assert!(
        errors.iter().all(|(_, error)| {
            error.contains("operation-owner node admission closed")
                || error.contains("operation-owner root capacity closed")
        }),
        "unexpected reactor errors during shutdown: {errors:?}"
    );
    for owner in owners {
        assert_eq!(owner.active_roots().await, 0);
        assert_eq!(owner.quarantined_roots().await, 0);
        assert!(!owner.is_fatal());
        let mut driver = owner.take_driver().expect("node owner has a driver");
        timeout(Duration::from_secs(2), &mut driver).await???;
    }
    for conn in conns {
        assert!(conn.is_autocommit());
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM transactions WHERE batch_height IS NOT NULL",
                (),
            )
            .await?;
        assert_eq!(rows.next().await?.expect("batch count").get::<i64>(0)?, 0);
    }
    Ok(())
}

/// Every certified decision remains verifiable after execution moves to a new
/// Bitcoin branch, including the abandoned branch's original bodies and proofs.
#[tokio::test]
async fn prod_reactor_reorg_leaves_no_gap_in_the_decided_sequence() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(3).await?;
    cluster.wait_for_ready().await;

    for h in 1..=3 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }

    let conn = cluster.node_conn(0).await.clone();
    let before = certified_history::frontier(&conn).await?.closed_height;
    let mut original_ids = Vec::new();
    for height in 1..=before {
        original_ids.push(
            certified_history::load(&conn, height)
                .await?
                .decision()
                .id()?,
        );
    }
    cluster.replace_after(1).await;
    for h in 3..=4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }
    cluster.shutdown().await;
    let frontier = certified_history::frontier(&conn).await?;
    assert_eq!(frontier.authenticated_height, frontier.closed_height);
    assert!(frontier.closed_height > before);
    for height in 1..=frontier.closed_height {
        let decision = certified_history::load(&conn, height).await?;
        certified_history::completion::completed(&conn, height).await?;
        if height <= before {
            assert_eq!(
                decision.decision().id()?,
                original_ids[(height - 1) as usize]
            );
        }
    }
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

    // A batch anchored at 2, whose transaction will never confirm. Deadline 2 + 6 = 8.
    for event in cluster.mock_bitcoin().generate_mempool_txs(1) {
        cluster.send_mempool_event(event);
    }
    let batch = cluster.wait_for_batch(2, Duration::from_secs(60)).await;
    assert_eq!(batch.txids.len(), 1, "setup batch must carry the tx");
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
    cluster.replace_after(2).await;
    for node in 0..3 {
        assert_eq!(cluster.counter_value(node).await?, "1");
    }

    // Climb past the deadline. The surviving batch's txs are still unconfirmed, so
    // finality must still invalidate it.
    for _ in 0..6 {
        cluster.mine_empty_and_send();
    }
    // Assert on WHICH batch was invalidated, not merely that some rollback happened:
    // the excluded tx returns via the mempool, so a rollback naming a DIFFERENT
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

/// A new node must replay the abandoned and replacement branches from certified
/// inputs even though its Bitcoin poller now provides only the surviving branch.
#[tokio::test]
async fn prod_reactor_late_joiner_syncs_across_a_deep_reorg() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start_with(4, 3).await?;
    cluster.wait_for_ready().await;

    for h in 1..=3 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }

    cluster.replace_after(1).await;
    for h in 3..=4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }
    let source = cluster.node_conn(0).await.clone();
    let source_height = certified_history::frontier(&source).await?.closed_height;

    // The joiner's poller serves only the surviving chain.
    let node_idx = cluster.add_node().await?;
    for event in cluster.mock_bitcoin().get_all_block_events() {
        let _ = cluster.block_txs[node_idx].try_send(event);
    }

    // Poll the joiner's OWN database: it must execute the post-reorg chain to
    // height 4. The shared event channel would be satisfied by the live nodes.
    let conn = cluster.node_conn(node_idx).await.clone();
    let mut tip = 0u64;
    for _ in 0..240 {
        let mut rows = conn
            .query("SELECT COALESCE(MAX(height), 0) FROM blocks", ())
            .await?;
        tip = rows.next().await?.expect("row").get(0)?;
        if tip >= 4 && certified_history::frontier(&conn).await?.closed_height >= source_height {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        tip >= 4,
        "late joiner stuck at tip {tip} while replaying certified branches"
    );

    assert!(certified_history::frontier(&conn).await?.closed_height >= source_height);
    for height in 1..=source_height {
        let retained = certified_history::load(&source, height).await?;
        let replayed = certified_history::load(&conn, height).await?;
        assert_eq!(replayed.decision().id()?, retained.decision().id()?);
        assert_eq!(replayed.input(), retained.input());
        certified_history::completion::completed(&conn, height).await?;
    }

    cluster.shutdown().await;
    Ok(())
}

/// The pool moves DURING validation: tx0 is removed mid-flight (an RBF
/// replacement or eviction through the mempool arm, which now runs freely
/// while the I/O is off-loop). Without re-checking membership at apply/use
/// time, the superseded tx is proposed anyway — measured: the decided batch
/// carried tx0 with the `retain`s disabled. Validation latency (4s) exceeds
/// the proposal deadline here, so the verdict-banking path is exercised too;
/// banking itself is robustness rather than a pinnable liveness property —
/// without it a completed validation can still land inside the NEXT proposal
/// window and fulfill it, so the un-banked behavior is timing-dependent, not
/// deterministically broken.
#[tokio::test]
async fn banked_verdicts_survive_the_deadline_and_track_the_pool() -> Result<()> {
    crate::logging::setup();

    let mut cluster =
        ReactorCluster::start_with_options(1, 1, Some(Duration::from_secs(4))).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    let events = cluster.mock_bitcoin().generate_mempool_txs(2);
    let txids: Vec<String> = events
        .iter()
        .filter_map(|e| match e {
            MempoolEvent::TransactionAdded { txid, .. } => Some(txid.to_string()),
            _ => None,
        })
        .collect();
    let [removed, surviving] = txids.as_slice() else {
        panic!("expected two txids, got {txids:?}");
    };
    let removed_txid = removed.parse().expect("txid");
    for event in events {
        cluster.send_mempool_event(event);
    }

    // Let the validation get in flight, then yank tx0 out from under it.
    tokio::time::sleep(Duration::from_secs(1)).await;
    cluster.send_mempool_event(MempoolEvent::Remove(removed_txid));

    // The first non-empty decided batch must hold exactly the survivor.
    let batch = cluster.wait_for_batch(1, Duration::from_secs(60)).await;
    assert_eq!(
        batch.txids,
        vec![surviving.clone()],
        "the batch must carry the surviving tx and only it (removed: {removed})"
    );

    cluster.assert_no_reactor_errors();
    cluster.shutdown().await;
    Ok(())
}

/// THE liveness property PR B exists for: the reactor keeps deciding and
/// executing BLOCKS while batch validation is stuck on a slow bitcoind.
///
/// Before the io-job split, `validate_txs` ran inline in the select body
/// holding `&mut` on the whole reactor — an unreachable bitcoind froze the
/// event loop (blocks, mempool, finality) for backoff × candidate txs, on
/// every node at once. Here every node's validation hangs for minutes, far
/// past the test budget; blocks must flow anyway, which also pins the rule
/// that a pending block outranks an in-flight batch job in the proposer.
#[tokio::test]
async fn prod_reactor_blocks_flow_while_validation_is_stuck() -> Result<()> {
    crate::logging::setup();

    // ONE node: the only proposer holds the stuck job, so nothing can route a
    // block proposal around it — a 3-node cluster hides the bug behind
    // proposer rotation.
    let mut cluster =
        ReactorCluster::start_with_options(1, 1, Some(Duration::from_secs(600))).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    // Park a candidate batch in the proposer: the mempool txs trigger a build
    // job whose validation outlives the test. The sleep guarantees the job is
    // in flight before the next block arrives: the mempool debounce (500ms) or at
    // latest the next held GetValue (~3s propose timeout) snapshots the
    // candidates and starts the 600s validation, which cannot finish. The
    // proof this ordering catches the regression: gating block proposals on
    // the in-flight job makes this test time out on `wait_for_block(2)`.
    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    for h in 2..=4 {
        cluster.mine_empty_and_send();
        cluster.wait_for_block(h, Duration::from_secs(60)).await;
    }

    cluster.assert_no_reactor_errors();
    cluster.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn prod_reactor_late_joiner_syncs_to_same_checkpoint() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start_with(4, 3).await?;
    cluster.wait_for_ready().await;
    cluster.mine_empty_and_send();
    cluster.wait_for_block(1, Duration::from_secs(60)).await;

    for event in cluster.mock_bitcoin().generate_mempool_txs(2) {
        cluster.send_mempool_event(event);
    }
    cluster.wait_for_batch(1, Duration::from_secs(60)).await;

    cluster.mine_and_send(&[]);
    let block1 = cluster.wait_for_block(2, Duration::from_secs(60)).await;
    let pre_join_checkpoints: Vec<_> = block1
        .state_events
        .iter()
        .filter_map(|e| match e {
            StateEvent::BlockProcessed {
                height: 2,
                checkpoint,
                ..
            } => *checkpoint,
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

    // Wait for late joiner to process block 2 and produce a checkpoint
    let late_events = cluster
        .wait_for_state_event_matching(
            |e| matches!(e, StateEvent::BlockProcessed { height: 2, .. }),
            Duration::from_secs(60),
        )
        .await;
    let late_checkpoint = late_events.iter().find_map(|e| match e {
        StateEvent::BlockProcessed {
            height: 2,
            checkpoint,
            ..
        } => *checkpoint,
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

    assert_eq!(cluster.counter_value(node_idx).await?, "2");

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

    assert_eq!(cluster.counter_value(0).await?, "0");
    let result = cluster.simulate(0, counter_transaction(99)).await?;
    assert_eq!(result.len(), 1);
    assert!(result[0].op().is_some());
    assert!(result[0].result().is_some());
    assert_eq!(result[0].error_message(), None);
    assert_eq!(
        cluster.counter_value(0).await?,
        "0",
        "simulation leaked its increment"
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
    let mut bitcoin = MockBitcoin::new(0);
    for _ in 1..=flood {
        let (mut events, _) = bitcoin.mine_empty_block();
        let event = events.pop().expect("mined block event");
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

/// Missing local Bitcoin events must not strand execution behind consensus.
/// The certified input carries the bytes needed to close each decision.
#[tokio::test]
async fn prod_reactor_missing_local_blocks_recover_from_certified_inputs() -> Result<()> {
    crate::logging::setup();

    let mut cluster = ReactorCluster::start(4).await?;
    cluster.wait_for_ready().await;

    let lagging = 3;
    for height in 1..=2u64 {
        let (blk_events, _) = cluster.mock_bitcoin().mine_empty_block();
        for event in blk_events {
            for (i, tx) in cluster.block_txs.iter().enumerate() {
                if i != lagging {
                    tx.try_send(event.clone())?;
                }
            }
        }
        let result = cluster
            .wait_for_block(height, Duration::from_secs(60))
            .await;
        ReactorCluster::assert_checkpoints_match(&result, height, 4);
    }

    let source = cluster.node_conn(0).await.clone();
    let recovered = cluster.node_conn(lagging).await.clone();
    let source_height = certified_history::frontier(&source)
        .await?
        .authenticated_height;
    assert!(source_height >= 2);
    timeout(Duration::from_secs(10), async {
        while certified_history::frontier(&recovered).await?.closed_height < source_height {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    for height in 1..=source_height {
        let retained = certified_history::load(&source, height).await?;
        let replayed = certified_history::load(&recovered, height).await?;
        assert_eq!(replayed.decision().id()?, retained.decision().id()?);
        assert_eq!(replayed.input(), retained.input());
        certified_history::completion::completed(&recovered, height).await?;
    }

    for height in 3..=5u64 {
        cluster.mine_empty_and_send();
        let result = cluster
            .wait_for_block(height, Duration::from_secs(60))
            .await;
        ReactorCluster::assert_checkpoints_match(&result, height, 4);
    }

    cluster.assert_no_reactor_errors();
    cluster.shutdown().await;
    Ok(())
}

/// A poller may redeliver an already applied block. Its stale candidate must
/// not pin the proposal queue ahead of newer blocks.
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
