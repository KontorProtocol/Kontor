use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Error, Result, anyhow, ensure};
use bitcoin::{Block, BlockHash, blockdata::constants::genesis_block, hashes::Hash};
use indexer_types::{
    Block as IndexedBlock, ContractProvenanceResponse, Event, Fees, ResultResponse, ViewResult,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::fixture::native_fixture_address;
use super::{DATABASE, NETWORK};
use crate::api::handlers::NodeStatus;
use crate::api::{DaemonEnv, Env, router};
use crate::bitcoin_client::mock::MockBitcoinRpc;
use crate::bitcoin_client::observation::ChainObservation;
use crate::bitcoin_client::{BitcoinRpc, Client};
use crate::bitcoin_follower;
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::config::Config;
use crate::database::Reader;
use crate::event::EventSubscriber;
use crate::info::{compute_info_core, run_info_publisher};
use crate::reactor::Simulation;
use crate::reactor::status::{EngineAuthority, RuntimeStatus};
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;
use crate::upgrade_control::UpgradeSubmission;

#[derive(Deserialize)]
struct DiagnosticResponse {
    result: Value,
}

pub(super) struct Connections {
    pub(super) blocks: mpsc::Receiver<BlockEvent>,
    pub(super) mempool: mpsc::Receiver<MempoolEvent>,
    pub(super) ready: oneshot::Sender<bool>,
    pub(super) events: mpsc::Sender<Event>,
    pub(super) simulate: mpsc::Receiver<Simulation>,
    pub(super) upgrade: mpsc::Receiver<UpgradeSubmission>,
    pub(super) fees: watch::Sender<Fees>,
    pub(super) runtime_status: watch::Sender<Option<RuntimeStatus>>,
}

pub(super) struct Services {
    reader: Reader,
    bitcoin: MockBitcoinRpc,
    client: Client,
    http: HttpClient,
    address: SocketAddr,
    tasks: Vec<(&'static str, JoinHandle<Result<()>>)>,
    ready: oneshot::Receiver<bool>,
    reactor_ready: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    observed_requests: u64,
    _publisher: Mutex<zmq::Socket>,
}

fn bitcoin_fixture() -> MockBitcoinRpc {
    let first = genesis_block(NETWORK);
    let mut blocks = Vec::new();
    for offset in [0, 10] {
        let mut block = first.clone();
        block.header.nonce = block.header.nonce.wrapping_add(offset);
        blocks.push((1, block.clone()));
        for height in 2..=3 {
            block.header.prev_blockhash = block.block_hash();
            block.header.nonce = block.header.nonce.wrapping_add(1);
            blocks.push((height, block.clone()));
        }
    }
    // Retain exact raw blocks for both branches while exposing only the current
    // fixture tip. The production follower discovers each advance and reorg.
    let bitcoin = MockBitcoinRpc::from_bitcoin_blocks(blocks);
    bitcoin.replace_blocks(vec![IndexedBlock {
        height: 0,
        hash: BlockHash::all_zeros(),
        prev_hash: BlockHash::all_zeros(),
        transactions: vec![],
    }]);
    bitcoin
}

impl Services {
    pub(super) async fn start(
        config: Config,
        reader: Reader,
        service: OwnerService,
        client: Client,
        addresses: watch::Receiver<Option<String>>,
        shutdown: &Shutdown,
    ) -> Result<(Self, Connections)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let publisher = zmq::Context::new().socket(zmq::PUB)?;
        publisher.set_linger(0)?;
        publisher.bind("tcp://127.0.0.1:*")?;
        let zmq_address = publisher
            .get_last_endpoint()?
            .map_err(|_| anyhow!("non-UTF8 fixture ZMQ address"))?;
        let http = HttpClient::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        let bitcoin = bitcoin_fixture();
        let reactor_ready = Arc::new(AtomicBool::new(false));
        let events = EventSubscriber::new();
        let initial = {
            let conn = reader.connection().await?;
            compute_info_core(&conn).await?
        };
        let (info_tx, info_rx) = watch::channel(initial);
        let (event_tx, event_rx) = mpsc::channel(10);
        let (ready_tx, ready) = oneshot::channel();
        let (simulate_tx, simulate) = mpsc::channel(1);
        let (upgrade_tx, upgrade) = mpsc::channel(1);
        let (fees, fees_rx) = watch::channel(Fees::floor(1));
        let (runtime_status, runtime_status_rx) = watch::channel(None);
        let env = Env::new_daemon(DaemonEnv {
            config,
            shutdown: shutdown.signal(),
            reader: reader.clone(),
            event_subscriber: events.clone(),
            bitcoin: client.clone(),
            owner_service: service,
            simulate_tx,
            upgrade_tx,
            reactor_ready: reactor_ready.clone(),
            failed: Arc::new(AtomicBool::new(false)),
            consensus_listen_addr: addresses,
            runtime_status: runtime_status_rx,
            fees_rx,
            info_rx,
            database_name: DATABASE.into(),
        })
        .await?;
        let app = router::new(env, PrometheusBuilder::new().build_recorder().handle());
        let signal = shutdown.signal();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move { signal.cancelled().await })
            .await
            .context("qualification HTTP server")
        });
        let publisher_task = run_info_publisher(
            shutdown.signal(),
            events.subscribe(),
            reader.clone(),
            info_tx,
        );
        let events_task = events.run(shutdown.signal(), event_rx);
        let (blocks, mempool, follower) = bitcoin_follower::run(
            bitcoin.clone(),
            shutdown.signal(),
            1,
            vec![(0, BlockHash::all_zeros())],
            zmq_address,
        )
        .await;
        let requests = Arc::new(AtomicU64::new(0));
        let count = requests.clone();
        let probe = http.clone();
        let signal = shutdown.signal();
        let traffic = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = signal.cancelled() => return Ok(()),
                    result = probe.get(format!("http://{address}/healthz/live")).send() => {
                        result?.error_for_status()?;
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                tokio::select! {
                    biased;
                    _ = signal.cancelled() => return Ok(()),
                    _ = sleep(Duration::from_millis(100)) => {}
                }
            }
        });
        Ok((
            Self {
                bitcoin,
                client,
                http,
                reader,
                address,
                ready,
                reactor_ready,
                requests,
                observed_requests: 0,
                tasks: vec![
                    ("HTTP server", server),
                    ("info publisher", publisher_task),
                    ("event subscriber", events_task),
                    ("Bitcoin follower", follower),
                    ("HTTP traffic", traffic),
                ],
                _publisher: Mutex::new(publisher),
            },
            Connections {
                blocks,
                mempool,
                ready: ready_tx,
                events: event_tx,
                simulate,
                upgrade,
                fees,
                runtime_status,
            },
        ))
    }

    pub(super) async fn ready(&mut self) -> Result<()> {
        ensure!(timeout(Duration::from_secs(30), &mut self.ready).await??);
        self.reactor_ready.store(true, Ordering::Relaxed);
        // The fixture follower uses MockBitcoinRpc directly, while readiness reads
        // the API Client's last observation. Mirror the current mock tip here.
        let tip = self.bitcoin.get_blockchain_info().await?;
        self.client
            .set_chain_observation_for_test(ChainObservation {
                chain: tip.chain,
                blocks: tip.blocks,
                headers: tip.headers,
                initial_block_download: tip.initial_block_download,
                observed_at: Instant::now(),
            });
        let response = self
            .http
            .get(format!("http://{}/healthz/ready", self.address))
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await?;
        ensure!(
            status == StatusCode::OK,
            "qualification readiness failed ({status}): {body}"
        );
        Ok(())
    }

    pub(super) fn healthy(&self) -> Result<()> {
        for (name, task) in &self.tasks {
            ensure!(!task.is_finished(), "{name} stopped during engine handoff");
        }
        Ok(())
    }

    pub(super) fn advance(&self, height: u64, block: &Block) {
        let mut blocks = self.bitcoin.blocks();
        blocks.retain(|block| block.height < height);
        blocks.push(IndexedBlock {
            height,
            hash: block.block_hash(),
            prev_hash: block.header.prev_blockhash,
            transactions: vec![],
        });
        self.bitcoin.replace_blocks(blocks);
    }

    pub(super) async fn view(&self) -> Result<ViewResult> {
        let (name, height, index) =
            native_fixture_address(&*self.reader.connection().await?).await?;
        Ok(self
            .http
            .post(format!(
                "http://{}/api/contracts/{name}_{height}_{index}",
                self.address
            ))
            .json(&json!({"expr": "version()"}))
            .send()
            .await?
            .error_for_status()?
            .json::<ResultResponse<ViewResult>>()
            .await?
            .result)
    }

    pub(super) async fn protocol(&self) -> Result<Value> {
        Ok(self
            .http
            .get(format!("http://{}/api/protocol", self.address))
            .send()
            .await?
            .error_for_status()?
            .json::<DiagnosticResponse>()
            .await?
            .result)
    }

    pub(super) async fn simulate(&self, raw: &[u8]) -> Result<Value> {
        Ok(self
            .http
            .post(format!(
                "http://{}/api/transactions/simulate/context",
                self.address
            ))
            .json(&json!({"hex": hex::encode(raw)}))
            .send()
            .await?
            .error_for_status()?
            .json::<DiagnosticResponse>()
            .await?
            .result)
    }

    pub(super) async fn runtime(&self, authority: EngineAuthority) -> Result<RuntimeStatus> {
        timeout(Duration::from_secs(10), async {
            loop {
                self.healthy()?;
                let status = self
                    .http
                    .get(format!("http://{}/api/status", self.address))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<NodeStatus>()
                    .await?;
                ensure!(!status.failed && !status.shutting_down);
                if let Some(runtime) = status.runtime
                    && runtime.authority == authority
                {
                    return Ok(runtime);
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .context("runtime authority observation timed out")?
    }

    pub(super) async fn provenance(&self, name: &str) -> Result<ContractProvenanceResponse> {
        Ok(self
            .http
            .get(format!(
                "http://{}/api/contracts/{name}_0_0/provenance",
                self.address
            ))
            .send()
            .await?
            .error_for_status()?
            .json::<ResultResponse<ContractProvenanceResponse>>()
            .await?
            .result)
    }

    pub(super) async fn progress(&mut self) -> Result<()> {
        self.healthy()?;
        timeout(Duration::from_secs(5), async {
            while self.requests.load(Ordering::Relaxed) <= self.observed_requests {
                self.healthy()?;
                sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, Error>(())
        })
        .await??;
        self.observed_requests = self.requests.load(Ordering::Relaxed);
        self.http
            .get(format!("http://{}/api/status", self.address))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub(super) async fn join(&mut self) -> Result<()> {
        let mut failure = None;
        for (name, mut task) in self.tasks.drain(..) {
            let result = match timeout(Duration::from_secs(15), &mut task).await {
                Ok(result) => result
                    .with_context(|| format!("{name} panicked"))
                    .and_then(|r| r),
                Err(error) => Err(error).with_context(|| format!("{name} did not stop")),
            };
            if let Err(error) = result {
                failure = Some(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
