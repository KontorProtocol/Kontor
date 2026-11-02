use std::time::Duration;

pub(crate) mod authorization;
pub(crate) mod cluster;
mod committee;
mod confirmation;
pub(crate) mod crash;
mod fixture;
pub(crate) mod recovery;
mod replay;
mod services;
mod token_count;
mod unsupported;

use anyhow::{Context, Error, Result, anyhow, ensure};
use bitcoin::{BlockHash, Network, blockdata::constants::genesis_block, hashes::Hash};
use indexer_types::BlockRow;
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

use super::engine::{EngineConfig, NodeCoordinator};
use super::execution::ExecutionContext;
use super::executor::RuntimeExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::bitcoin_follower::event::{BlockEvent, MempoolEvent};
use crate::consensus::signing::PrivateKey;
use crate::database::canonical_history;
use crate::database::certified_history::{self, closure, control, eras};
use crate::database::connection::new_read_only_connection;
use crate::database::queries::insert_block;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::control::{ControlState, PendingPlan};
use crate::protocol::coordinator::genesis::envelope;
use crate::protocol::coordinator::linked::{
    canonical_session, execute_view, initialize, read_only_factory,
};
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::coordinator::{bootstrap, successor};
use crate::protocol::identity::{ExecutionIdentity, PlanId, ProtocolId};
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::new_linked;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;

const NETWORK: Network = Network::Regtest;
const DATABASE: &str = "transition.db";

// Seed the accepted-schedule precondition before genesis authority is published.
// This isolates live activation/handoff from the separately tested approval and
// notice rules. It must never be reported as an end-to-end authorization test.
async fn accepted_schedule(conn: &Connection, baseline: &Baseline) -> Result<ProtocolId> {
    accepted_schedule_at(conn, baseline, 1).await
}

async fn accepted_schedule_at(
    conn: &Connection,
    baseline: &Baseline,
    activation: u64,
) -> Result<ProtocolId> {
    let manifest = successor::manifest(baseline.context.chain)?;
    accepted_manifest_schedule(conn, baseline, activation, manifest).await
}

async fn accepted_manifest_schedule(
    conn: &Connection,
    baseline: &Baseline,
    activation: u64,
    manifest: ProtocolManifest,
) -> Result<ProtocolId> {
    let target = manifest.id()?;
    let state = ControlState {
        context: baseline.context,
        current_manifest: baseline.manifest.clone(),
        head: [10; 32],
        nonce: 1,
        pending: Some(PendingPlan {
            id: PlanId([3; 32]),
            manifest,
            activation,
            consumed: false,
        }),
    };
    let transaction = conn.transaction().await?;
    let position = closure::canonical_position(&transaction, baseline.context.chain).await?;
    let application = CanonicalApplication {
        chain: baseline.context.chain,
        ordinal: position.ordinal + 1,
        parent_lineage: position.lineage,
        execution: ExecutionIdentity::Baseline(baseline.manifest.executor),
        storage_height: 0,
        source: ApplicationSource::UpgradeControl {
            decision: 1,
            action: [9; 32],
            control: state.head,
        },
        input: None,
    };
    canonical_history::append(&transaction, &application).await?;
    control::record(
        &transaction,
        &application,
        &state,
        control::Position {
            decision: 1,
            stage: 1,
        },
    )
    .await?;
    transaction.commit().await?;
    Ok(target)
}

async fn wait_closed(conn: &Connection, protocol: ProtocolId, height: u64) -> Result<()> {
    loop {
        let frontier = certified_history::frontier(conn).await?;
        if frontier
            .context
            .is_some_and(|context| context.protocol == protocol)
            && frontier.closed_height >= height
        {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn restart(
    config: EngineConfig,
    genesis: GenesisParameters,
    protocol: ProtocolId,
    expected_view: &str,
) -> Result<Value> {
    let (coordinator, _reader, writer) =
        NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis).await?;
    let observer = new_read_only_connection(&config.data_dir, DATABASE).await?;
    let frontier = certified_history::frontier(&observer).await?;
    ensure!(frontier.closed_height == 2);
    let expected_context = frontier.context.context("restart context")?;
    ensure!(expected_context.protocol == protocol);
    let service = OwnerService::new();
    let result = async {
        let pool = new_linked(
            config.data_dir.clone(),
            DATABASE.into(),
            read_only_factory(NETWORK, 1_000_000)?,
            1,
        )?;
        let (block_tx, blocks) = mpsc::channel(1);
        let (mempool_tx, mempool) = mpsc::channel(1);
        let (address_tx, mut addresses) = watch::channel(None);
        let shutdown = Shutdown::new();
        let mut running = super::run(
            1,
            shutdown.signal(),
            service.clone(),
            writer,
            blocks,
            mempool,
            None,
            None,
            None,
            None,
            config.clone(),
            coordinator,
            Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?,
            genesis,
            None,
            500,
            None,
            address_tx,
            NETWORK,
            PruneConfig {
                enabled: false,
                retain_blocks: 144,
            },
        );
        let observed = async {
            mempool_tx
                .send(MempoolEvent::Sync {
                    transactions: vec![],
                    fees: Default::default(),
                    mempool_min_fee_sat_per_vb: 1,
                })
                .await?;
            while addresses.borrow().is_none() {
                addresses.changed().await?;
            }
            ensure!(addresses.borrow().as_ref() == Some(&config.listen_addr));
            ensure!(
                certified_history::frontier(&observer).await? == frontier,
                "restart changed certified history before new input"
            );
            let view = execute_view(
                &service,
                pool.get().await?,
                NETWORK,
                ("token".into(), 0, 0),
                "positive-balance-count()".into(),
            )
            .await?;
            ensure!(
                view.as_ref().is_ok_and(|value| value == expected_view),
                "restart did not select the persisted P2 state: {view:?}"
            );
            let mut block = genesis_block(NETWORK);
            for _ in 0..2 {
                block.header.prev_blockhash = block.block_hash();
                block.header.nonce = block.header.nonce.wrapping_add(1);
            }
            block_tx
                .send(BlockEvent::BlockInsert {
                    target_height: 3,
                    block: BlockInput::from_bitcoin(3, block.block_hash(), block),
                })
                .await?;
            wait_closed(&observer, protocol, 3).await?;
            let decision = certified_history::load(&observer, 3).await?;
            ensure!(
                decision.input().descriptor().context == expected_context,
                "restart changed the era or selected an obsolete protocol"
            );
            Ok::<_, Error>(json!({"same_listener": true, "same_era": true,
                "persisted_view": view, "closed_decisions": 3,
                "production_startup": true}))
        };
        let observed = tokio::select! {
            result = timeout(Duration::from_secs(120), observed) =>
                result.context("restarted node did not resume").and_then(|result| result),
            result = &mut running => {
                result.context("restarted reactor task failed")??;
                return Err(anyhow!("restarted reactor stopped before observations completed"));
            }
        };
        shutdown.cancel();
        running.await.context("restarted reactor task failed")??;
        observed
    }
    .await;
    service.shutdown();
    result
}

pub(crate) async fn run() -> Result<Value> {
    let directory = TempDir::new()?;
    let config = EngineConfig {
        private_key: PrivateKey::from([7; 32]),
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        persistent_peers: vec![],
        data_dir: directory.path().to_path_buf(),
        consensus_enabled: true,
        discovery: Default::default(),
    };
    let genesis = GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: vec![GenesisValidator {
            x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            ed25519_pubkey: config.private_key.public_key().as_bytes().to_vec(),
            stake: Decimal::from("100"),
        }],
    };
    let (coordinator, _reader, writer) =
        NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis).await?;
    let conn = writer.connection();
    let service = OwnerService::new();
    let result = async {
        let genesis_envelope = envelope(&genesis);
        let (baseline, fresh) = bootstrap::prepare(&conn, NETWORK, 1, &genesis_envelope).await?;
        ensure!(fresh);
        insert_block(
            &conn,
            BlockRow::builder().height(0).hash(BlockHash::all_zeros()).build(),
        )
        .await?;
        let session = canonical_session(conn.clone(), NETWORK).await?;
        initialize(&service, &session, NETWORK, 1, genesis_envelope).await?;
        let target = accepted_schedule(&conn, &baseline).await?;
        bootstrap::complete(&service, &session, NETWORK, &baseline).await?;

        let pool = new_linked(
            directory.path().to_path_buf(), DATABASE.into(),
            read_only_factory(NETWORK, 1_000_000)?, 1,
        )?;
        let token = ("token".into(), 0, 0);
        let before = execute_view(&service, pool.get().await?, NETWORK,
            token.clone(), "positive-balance-count()".into()).await?;
        ensure!(before.is_err(), "P1 unexpectedly exposes the P2 token interface");
        let consensus = start_linked_consensus(config.clone(), Some(&coordinator),
            &session, &service, NETWORK, None, None, 0, MempoolFeeIndex::new(None)).await?;
        let execution = ExecutionContext::new(
            RuntimeExecutor::new(Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?),
            session, NETWORK, service.clone(), baseline.context,
            PruneConfig { enabled: false, retain_blocks: 144 }, 0, None,
        );
        let (block_tx, blocks) = mpsc::channel(2);
        let (_mempool_tx, mempool) = mpsc::channel(1);
        let (address_tx, mut addresses) = watch::channel(None);
        let shutdown = Shutdown::new();
        let mut reactor = Reactor::from_execution(execution, blocks, mempool,
            shutdown.signal(), None, None, None, consensus, address_tx);
        reactor.coordinator = Some(coordinator.clone());
        reactor.engine_config = Some(config.clone());
        let observer = new_read_only_connection(directory.path(), DATABASE).await?;
        let observe = async {
            let result = timeout(Duration::from_secs(120), async {
                while addresses.borrow().is_none() {
                    addresses.changed().await?;
                }
                let original_address = addresses.borrow().clone().context("listener")?;
                let block = genesis_block(NETWORK);
                let first_hash = block.block_hash();
                block_tx.send(BlockEvent::BlockInsert { target_height: 1,
                    block: BlockInput::from_bitcoin(1, first_hash, block.clone()) }).await?;
                wait_closed(&observer, target, 1).await?;
                let after = execute_view(&service, pool.get().await?, NETWORK,
                    token, "positive-balance-count()".into()).await?;
                ensure!(after.as_ref().is_ok_and(|value| value.parse::<u64>().is_ok_and(|count| count > 0)),
                    "P2 did not expose the migrated balance count: {after:?}");
                let mut second = block;
                second.header.prev_blockhash = first_hash;
                second.header.nonce = second.header.nonce.wrapping_add(1);
                block_tx.send(BlockEvent::BlockInsert { target_height: 2,
                    block: BlockInput::from_bitcoin(2, second.block_hash(), second) }).await?;
                wait_closed(&observer, target, 2).await?;
                let first = certified_history::load(&observer, 1).await?;
                let second = certified_history::load(&observer, 2).await?;
                ensure!(first.input().descriptor().context.protocol == baseline.context.protocol);
                ensure!(second.input().descriptor().context.protocol == target);
                let transition = eras::at(&observer, 1).await?.context("era transition")?;
                ensure!(transition.start_height()? == 2);
                ensure!(addresses.borrow().as_ref() == Some(&original_address));
                Ok::<_, Error>((after, original_address))
            }).await.context("live activation qualification timed out")?;
            result
        };
        let stopped = shutdown.signal();
        let observe = async {
            let result = tokio::select! {
                result = observe => result,
                _ = stopped.cancelled() => Err(anyhow!("reactor stopped before observations completed")),
            };
            shutdown.cancel();
            result
        };
        let running = async {
            let result = reactor.run().await;
            if result.is_err() {
                shutdown.cancel();
            }
            result
        };
        let (running, observed) = tokio::join!(running, observe);
        running?;
        let (after, listener) = observed?;
        ensure!(reactor.consensus.protocol_context.protocol == target);
        ensure!(reactor.consensus.engine.stop(Duration::ZERO).await?);
        ensure!(reactor.consensus.engine.next().await?.is_none());
        ensure!(reactor.consensus.engine.sign_proposal_fin(3, 0, vec![], [0; 32]).await.is_err());
        ensure!(reactor.execution.session.executor.execution_definition?
            == successor::manifest(baseline.context.chain)?.executor);
        ensure!(service.active_roots().await == 0);
        let expected_view = after.as_ref().map_err(|error| anyhow!("{error:?}"))?.clone();
        drop(reactor);
        drop(pool);
        drop(observer);
        drop(conn);
        drop(writer);
        drop(coordinator);
        let mut restarted_config = config;
        restarted_config.listen_addr = listener.clone();
        let restarted = restart(restarted_config, genesis, target, &expected_view).await?;
        Ok(json!({"scope": "one live validator, accepted schedule fixture, real P1/P2 engines and executors",
            "authorization_test": false, "first_protocol": hex::encode(baseline.context.protocol.0),
            "second_protocol": hex::encode(target.0), "handoff_height": 2,
            "first_view": before, "second_view": after, "listener": listener,
            "closed_decisions": 2, "reused_reader_pool": true, "restart": restarted}))
    }.await;
    service.shutdown();
    result
}
