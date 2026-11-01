//! Exercise retained execution and journal adapters without inventing consensus authority.

use std::slice;

use anyhow::{Context, Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::{BlockHash, Network, Transaction, hashes::Hash};
use indexer_types::BlockRow;
use libsql::Connection;
use serde_json::{Value as Json, json};
use tempfile::TempDir;

use super::PruneConfig;
use super::execution::ExecutionContext;
use super::executor::Executor;
use super::executor::RuntimeExecutor;
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::database::canonical_history::{self, HistoryState};
use crate::database::connection::new_connection;
use crate::database::queries::{insert_block, select_block_at_height};
use crate::protocol::canonical_application::{
    ApplicationSource, CanonicalApplication, DecisionExclusions,
};
use crate::protocol::canonical_input::CanonicalInput;
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::genesis::bind_identity;
use crate::protocol::coordinator::linked::{PreparedBlock, initialize};
use crate::protocol::coordinator::selection::ApplicationPosition;
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol::operations::GenesisEnvelope;
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;

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

// These synthetic empty/excluded units check the linked root and journal adapters.
// Certified caller construction and exclusion selection are checked separately.
async fn batch(
    execution: &mut ExecutionContext<RuntimeExecutor>,
    height: u64,
    hash: BlockHash,
    decision: u64,
    original: &[Transaction],
) -> Result<()> {
    let selection = execution
        .select_executor(ApplicationPosition::Batch {
            anchor_height: height,
            anchor_hash: hash,
            consensus_height: decision,
        })
        .await?;
    let lease = execution.begin_unit(&selection, false).await?;
    let result = async {
        let mut excluded: Vec<_> = original
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array())
            .collect();
        excluded.sort_unstable();
        execution
            .record_application(
                height,
                ApplicationSource::Batch {
                    anchor_height: height,
                    anchor_hash: hash.to_byte_array(),
                    exclusions: DecisionExclusions {
                        consensus_height: decision,
                        direct: excluded.clone(),
                        effective: excluded,
                    },
                },
                Some(CanonicalInput::bitcoin(original)?),
            )
            .await
    }
    .await;
    execution.finish_unit(lease, result, true).await
}

async fn apply_block(
    execution: &mut ExecutionContext<RuntimeExecutor>,
    block: BlockInput,
) -> Result<()> {
    let selection = execution
        .select_executor(ApplicationPosition::Block {
            height: block.height,
            hash: block.hash,
            consensus_height: 3,
        })
        .await?;
    let block: PreparedBlock = execution
        .executor
        .prepare_block(&execution.recognizer, &selection, block)
        .await?;
    let lease = execution.begin_unit(&selection, false).await?;
    let result = execution.block_txn(&selection, &block, 3, &[]).await;
    execution.finish_unit(lease, result, true).await?;
    execution.last_height = block.height;
    execution.last_hash = Some(block.hash);
    Ok(())
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
    let chain = bind_identity(&conn, network, 1, &genesis).await?;
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
    let client = Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?;
    let mut reactor = ExecutionContext::new(
        RuntimeExecutor::new(client),
        session,
        network,
        service.clone(),
        Baseline::current(chain)?.context,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(anchor),
    );
    async {
        batch(&mut reactor, 1, anchor, 1, &[]).await?;
        let empty = records(&conn).await?;
        ensure!(empty.len() == initial.len() + 1);
        ensure!(empty.last().context("empty batch journal")?.input == Some(CanonicalInput::bitcoin(&[])?));
        ensure!(empty.last().context("empty batch journal")?.source == ApplicationSource::Batch {
            anchor_height: 1, anchor_hash: anchor.to_byte_array(),
            exclusions: DecisionExclusions { consensus_height: 1, direct: Vec::new(), effective: Vec::new() } });
        let txid = excluded.compute_txid();
        batch(&mut reactor, 1, anchor, 2, slice::from_ref(&excluded)).await?;
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
        // Fail the second journal append, after transactions and lifecycle ran.
        // Both journal entries and the block must share the effects transaction.
        conn.execute_batch(&format!("CREATE TRIGGER reject_lifecycle BEFORE INSERT ON canonical_applications WHEN NEW.ordinal = {} BEGIN SELECT RAISE(ABORT, 'qualification lifecycle failure'); END", prefix.len() + 2)).await?;
        let before_failure = full_state(&conn).await?;
        ensure!(apply_block(&mut reactor, block.clone()).await.is_err());
        ensure!(full_state(&conn).await? == before_failure, "failed block leaked persistent effects");
        ensure!(records(&conn).await? == prefix && select_block_at_height(&conn, 2).await?.is_none());
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        conn.execute_batch("DROP TRIGGER reject_lifecycle").await?;
        apply_block(&mut reactor, block.clone()).await?;
        let applied = records(&conn).await?;
        ensure!(applied.len() == prefix.len() + 2);
        let transactions = &applied[prefix.len()];
        let lifecycle = &applied[prefix.len() + 1];
        ensure!(transactions.source == ApplicationSource::BlockTransactions { height: 2, hash: hash.to_byte_array(), parent_hash: anchor.to_byte_array() });
        ensure!(transactions.input == Some(input) && transactions.execution == execution && transactions.storage_height == 2);
        ensure!(lifecycle.source == ApplicationSource::BlockLifecycle { height: 2, hash: hash.to_byte_array() });
        ensure!(lifecycle.input.is_none() && lifecycle.execution == execution && lifecycle.storage_height == 2);
        batch(&mut reactor, 2, hash, 4, &[]).await?;
        let with_batch = records(&conn).await?;
        ensure!(with_batch.len() == applied.len() + 1);
        reactor.maintain_executor(Some(1)).await?;
        reactor.last_height = 1;
        reactor.last_hash = Some(anchor);
        ensure!(records(&conn).await? == prefix, "rollback did not preserve exactly the anchor-height prefix");
        apply_block(&mut reactor, block).await?;
        batch(&mut reactor, 2, hash, 4, &[]).await?;
        ensure!(records(&conn).await? == with_batch, "same input replay changed canonical lineage");
        ensure!(conn.is_autocommit() && service.active_roots().await == 0);
        Ok(json!({"genesis_entries": initial.len(), "anchor_batch_entries": 2,
            "block_entries": 2, "later_batch_entries": 1, "atomic_failure": true,
            "rollback_prefix": true, "exact_replay": true}))
    }.await
}
