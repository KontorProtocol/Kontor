//! Exercise canonical history through the live block and batch callers.

use std::slice;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{BlockHash, Network, Transaction, hashes::Hash};
use indexer_types::BlockRow;
use libsql::Connection;
use malachitebft_engine::node::NodeRef;
use serde_json::{Value as Json, json};
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use super::engine::EngineConfig;
use super::executor::RuntimeExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value};
use crate::database::canonical_history::{self, HistoryState};
use crate::database::connection::new_connection;
use crate::database::queries::{insert_block, select_block_at_height};
use crate::protocol::canonical_application::{
    ApplicationSource, CanonicalApplication, DecisionExclusions,
};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::decision::DeferredDecision;
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked::initialize;
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol::operations::GenesisEnvelope;
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use crate::stopper::Shutdown;

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

async fn records(conn: &Connection) -> Result<Vec<CanonicalApplication>> {
    let HistoryState::Ready(cursor) = canonical_history::state(conn).await? else {
        anyhow::bail!("fresh reactor lost its canonical history");
    };
    let mut rows = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut records = Vec::new();
    let mut parent = cursor.chain.0;
    while let Some(row) = rows.next().await? {
        let record = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        ensure!(record.chain == cursor.chain && record.ordinal == records.len() as u64 + 1);
        ensure!(record.parent_lineage == parent);
        parent = record.lineage()?;
        records.push(record);
    }
    ensure!(cursor.authentic && cursor.ordinal == records.len() as u64 && cursor.lineage == parent);
    Ok(records)
}

pub(crate) async fn run(
    factory: SessionFactory,
    service: &OwnerService,
    genesis: GenesisEnvelope,
    excluded: Transaction,
) -> Result<Json> {
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "reactor-history.db").await?;
    let network = Network::Regtest;
    bind_identity(&conn, network, 1, &genesis).await?;
    let anchor = BlockHash::from_byte_array([1; 32]);
    for height in 0..=1 {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(BlockHash::from_byte_array([height as u8; 32]))
                .build(),
        )
        .await?;
    }
    let session = LinkedSession::new(conn.clone(), factory(conn.clone()).await?);
    initialize(service, &session, network, 1, genesis).await?;
    let initial = records(&conn).await?;
    ensure!(
        !initial.is_empty()
            && initial
                .iter()
                .all(|record| matches!(record.source, ApplicationSource::Genesis { .. }))
    );
    let execution = ExecutionIdentity::Baseline(session.executor.execution_definition?);
    let consensus = start_linked_consensus(
        EngineConfig {
            private_key: PrivateKey::from([17; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &session,
        service,
        network,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
    let mut reactor = Reactor::from_session(
        RuntimeExecutor::new(client),
        session,
        network,
        service.clone(),
        block_rx,
        mempool_rx,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(anchor),
        addr_tx,
    );
    let cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
    let result = async {
        reactor.process_decided_batch(1, anchor, Height::new(1), &[], &[], None).await?;
        let empty = records(&conn).await?;
        ensure!(empty.len() == initial.len() + 1);
        ensure!(empty.last().context("empty batch journal")?.input == Some(CanonicalInput::bitcoin(&[])?));
        ensure!(empty.last().context("empty batch journal")?.source == ApplicationSource::Batch {
            anchor_height: 1, anchor_hash: anchor.to_byte_array(),
            exclusions: DecisionExclusions { consensus_height: 1, direct: Vec::new(), effective: Vec::new() } });
        let txid = excluded.compute_txid();
        // The same txid is excluded at another height too. Only this decision's
        // exclusions belong in its application identity.
        conn.execute("INSERT INTO excluded_batch_txids (batch_height, txid, deadline) VALUES (2, ?1, 10), (99, ?1, 10)", [txid.to_string()]).await?;
        reactor.process_decided_batch(1, anchor, Height::new(2), &[], &[], Some(slice::from_ref(&excluded))).await?;
        let prefix = records(&conn).await?;
        ensure!(prefix.len() == initial.len() + 2);
        let last = prefix.last().context("excluded batch journal")?;
        ensure!(last.execution == execution && last.storage_height == 1);
        ensure!(last.input == Some(CanonicalInput::bitcoin(slice::from_ref(&excluded))?));
        ensure!(last.source == ApplicationSource::Batch { anchor_height: 1, anchor_hash: anchor.to_byte_array(),
            exclusions: DecisionExclusions { consensus_height: 2, direct: vec![txid.to_byte_array()], effective: vec![txid.to_byte_array()] } });

        let mut raw = genesis_block(network);
        raw.header.prev_blockhash = anchor;
        let hash = raw.block_hash();
        let input = CanonicalInput::bitcoin(&raw.txdata)?;
        let block = BlockInput::from_bitcoin(2, hash, raw);
        let decision = DeferredDecision { consensus_height: Height::new(3), value: Value::Block { height: 2, hash },
            certificate: Vec::new(), certified_txs: None };
        // Fail the second journal append, after transactions and lifecycle ran.
        // Both journal entries and the block must share the effects transaction.
        conn.execute_batch(&format!("CREATE TRIGGER reject_lifecycle BEFORE INSERT ON canonical_applications WHEN NEW.ordinal = {} BEGIN SELECT RAISE(ABORT, 'qualification lifecycle failure'); END", prefix.len() + 2)).await?;
        let before_failure = full_state(&conn).await?;
        ensure!(reactor.handle_block(block.clone(), &decision).await.is_err());
        ensure!(full_state(&conn).await? == before_failure, "failed block leaked persistent effects");
        ensure!(records(&conn).await? == prefix && select_block_at_height(&conn, 2).await?.is_none());
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        conn.execute_batch("DROP TRIGGER reject_lifecycle").await?;
        reactor.handle_block(block.clone(), &decision).await?;
        let applied = records(&conn).await?;
        ensure!(applied.len() == prefix.len() + 2);
        let transactions = &applied[prefix.len()];
        let lifecycle = &applied[prefix.len() + 1];
        ensure!(transactions.source == ApplicationSource::BlockTransactions { height: 2, hash: hash.to_byte_array(), parent_hash: anchor.to_byte_array() });
        ensure!(transactions.input == Some(input) && transactions.execution == execution && transactions.storage_height == 2);
        ensure!(lifecycle.source == ApplicationSource::BlockLifecycle { height: 2, hash: hash.to_byte_array() });
        ensure!(lifecycle.input.is_none() && lifecycle.execution == execution && lifecycle.storage_height == 2);
        reactor.process_decided_batch(2, hash, Height::new(4), &[], &[], None).await?;
        let with_batch = records(&conn).await?;
        ensure!(with_batch.len() == applied.len() + 1);
        reactor.rollback(1).await?;
        ensure!(records(&conn).await? == prefix, "rollback did not preserve exactly the anchor-height prefix");
        reactor.handle_block(block, &decision).await?;
        reactor.process_decided_batch(2, hash, Height::new(4), &[], &[], None).await?;
        ensure!(records(&conn).await? == with_batch, "same input replay changed canonical lineage");
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        Ok(json!({"genesis_entries": initial.len(), "anchor_batch_entries": 2,
            "block_entries": 2, "later_batch_entries": 1, "atomic_failure": true,
            "rollback_prefix": true, "exact_replay": true}))
    }.await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await??;
    result
}
