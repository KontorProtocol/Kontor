use anyhow::Result;
use bitcoin::{BlockHash, Txid};
use indexer_types::OpWithResult;
use prost::Message;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::bitcoin_client::Client;
use crate::consensus::codec::decode_commit_certificate;
use crate::consensus::{CommitCertificate, Ctx, Height, Value};
use crate::consensus::finality_types::FINALITY_WINDOW;
use crate::database::queries::{
    get_transaction_by_txid, rollback_to_height, select_batch, select_batches_from_anchor,
    select_block_at_height, select_block_latest, select_min_batch_height,
    select_unconfirmed_batch_txs,
};
use crate::database::{self};
use crate::runtime::Runtime;

use super::block_handler::{batch_handler, block_handler, simulate_handler};

/// Check if a parsed transaction contains only batchable ops.
/// Non-batchable ops (Publish, Issuance, RegisterBlsKey) must only execute
/// via Value::Block decisions, not consensus batches.
pub fn is_batchable(ops: &[indexer_types::Op]) -> bool {
    !ops.iter().any(|op| {
        matches!(
            op,
            indexer_types::Op::Publish { .. }
                | indexer_types::Op::Issuance { .. }
                | indexer_types::Op::RegisterBlsKey { .. }
        )
    })
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
/// This allows different backends: `StateLog` (mock, used by consensus-sim)
/// and `RuntimeExecutor` (production, WASM execution + DB).
#[allow(async_fn_in_trait)]
pub trait Executor {
    /// Validate a transaction and parse its Kontor ops.
    /// Returns the parsed transaction if valid, None otherwise.
    /// Implementations may also propagate the tx to the local bitcoind mempool.
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction>;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    /// Sources: local mempool/block cache, Bitcoin RPC, LRU cache.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Filter a list of txids, returning only those NOT already in the system
    /// (not yet batched or confirmed in a block). Used for:
    /// - Proposal building: filter mempool txids to avoid re-batching
    /// - Block execution: identify which txids need execution vs confirmation-only
    async fn filter_unbatched_txids(&self, txids: &[Txid]) -> Vec<Txid>;

    /// Execute a consensus-decided batch of mempool transactions at the given anchor height.
    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
        raw_txs: &[bitcoin::Transaction],
    );

    /// Execute a confirmed Bitcoin block. Implementations handle deduplication of
    /// transactions already executed via a prior batch.
    async fn execute_block(&mut self, block: &indexer_types::Block);

    async fn rollback_state(&mut self, to_anchor: u64) -> usize;
    async fn checkpoint(&self) -> Option<[u8; 32]>;

    /// Was this txid confirmed in a Bitcoin block? Used by finality checks.
    /// In prod, this is a DB query. In sim, checks a HashSet.
    async fn is_confirmed_on_chain(&self, txid: &bitcoin::Txid) -> bool;

    // --- Decided value storage (used by Malachite sync protocol) ---

    /// Retrieve a decided value at the given height.
    async fn get_decided(&self, height: Height) -> Option<(Value, CommitCertificate<Ctx>)>;

    /// Return the minimum decided height, or None if no values stored.
    async fn min_decided_height(&self) -> Option<Height>;

    /// Return all decided values whose anchor_height >= `from_anchor`,
    /// ordered by consensus height. Used to populate the replay queue after rollback.
    async fn get_decided_from_anchor(&self, from_anchor: u64) -> Vec<(Height, Value)>;

    /// Signal the block source to re-deliver blocks starting from `height`.
    /// In prod: resets the poller via a control channel.
    /// In sim: records the call for test assertions; the test sends blocks manually.
    async fn replay_blocks_from(&mut self, height: u64);

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    /// Used during replay/sync when parsed_tx_cache misses.
    /// RuntimeExecutor uses filter_map; StateLog returns a dummy with the correct txid.
    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction>;

    /// Simulate executing a transaction without committing state changes.
    /// Returns the op results. Only meaningful for RuntimeExecutor.
    async fn simulate(&mut self, _btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
        anyhow::bail!("Simulation not supported on this executor")
    }

    /// Get the block hash at the given height. Used for anchor hash validation
    /// and rollback tracking.
    async fn block_hash_at_height(&self, _height: u64) -> Option<BlockHash> {
        None
    }
}

/// Placeholder executor that does nothing. Used by the production reactor until
/// `RuntimeExecutor` is implemented in Phase 7.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    async fn validate_transaction(
        &self,
        _tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        None
    }
    async fn resolve_transaction(&self, _txid: &Txid) -> Option<bitcoin::Transaction> {
        None
    }
    async fn filter_unbatched_txids(&self, txids: &[Txid]) -> Vec<Txid> {
        txids.to_vec()
    }
    async fn execute_batch(
        &mut self,
        _anchor_height: u64,
        _anchor_hash: bitcoin::BlockHash,
        _consensus_height: Height,
        _certificate: &[u8],
        _txs: &[indexer_types::Transaction],
        _raw_txs: &[bitcoin::Transaction],
    ) {
    }
    async fn execute_block(&mut self, _block: &indexer_types::Block) {}
    async fn rollback_state(&mut self, _to_anchor: u64) -> usize {
        0
    }
    async fn checkpoint(&self) -> Option<[u8; 32]> {
        None
    }
    async fn is_confirmed_on_chain(&self, _txid: &bitcoin::Txid) -> bool {
        false
    }
    async fn get_decided(&self, _height: Height) -> Option<(Value, CommitCertificate<Ctx>)> {
        None
    }
    async fn min_decided_height(&self) -> Option<Height> {
        None
    }
    async fn get_decided_from_anchor(&self, _from_anchor: u64) -> Vec<(Height, Value)> {
        Vec::new()
    }
    async fn replay_blocks_from(&mut self, _height: u64) {}
    fn parse_transaction(&self, _tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: real WASM execution via Runtime + DB persistence.
pub struct RuntimeExecutor {
    pub runtime: Runtime,
    pub writer: database::Writer,
    pub bitcoin_client: Option<Client>,
    pub replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    pub cancel_token: CancellationToken,
}

impl RuntimeExecutor {
    pub fn new(
        runtime: Runtime,
        writer: database::Writer,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            runtime,
            writer,
            bitcoin_client: None,
            replay_tx: None,
            cancel_token,
        }
    }

    pub fn with_bitcoin_client(mut self, client: Client) -> Self {
        self.bitcoin_client = Some(client);
        self
    }

    pub fn with_replay_tx(mut self, tx: tokio::sync::mpsc::Sender<u64>) -> Self {
        self.replay_tx = Some(tx);
        self
    }

    fn connection(&self) -> libsql::Connection {
        self.writer.connection()
    }
}

impl Executor for RuntimeExecutor {
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        use crate::block::filter_map;
        use crate::retry::{new_backoff_unlimited, retry};

        // Parse Kontor ops — reject if no valid ops
        let parsed = filter_map((0, tx.clone()))?;

        if !is_batchable(&parsed.ops) {
            return None;
        }

        // Push to local bitcoind mempool (idempotent, succeeds if already present)
        if let Some(client) = &self.bitcoin_client {
            let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
            let result = retry(
                || client.send_raw_transaction(&raw_hex),
                "send_raw_transaction",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await;
            if let Err(e) = result {
                warn!(txid = %tx.compute_txid(), %e, "Transaction rejected by bitcoind");
                return None;
            }
        }

        Some(parsed)
    }
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Check unconfirmed batch txs table first (for replay/sync recovery)
        if let Ok(Some(raw_bytes)) =
            crate::database::queries::select_unconfirmed_batch_tx(
                &self.connection(),
                &txid.to_string(),
            )
            .await
        {
            if let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes) {
                return Some(tx);
            }
        }

        // Fall back to Bitcoin RPC (via tx cache)
        let client = self.bitcoin_client.as_ref()?;
        match client.get_raw_transaction(txid).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                warn!(%txid, %e, "Failed to resolve transaction via RPC");
                None
            }
        }
    }
    async fn filter_unbatched_txids(&self, txids: &[Txid]) -> Vec<Txid> {
        use crate::database::queries::select_existing_txids;
        let txid_strs: Vec<String> = txids.iter().map(|t| t.to_string()).collect();
        let existing = select_existing_txids(&self.connection(), &txid_strs)
            .await
            .unwrap_or_default();
        txids
            .iter()
            .filter(|t| !existing.contains(&t.to_string()))
            .copied()
            .collect()
    }
    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
        raw_txs: &[bitcoin::Transaction],
    ) {
        if let Err(e) = batch_handler(
            &mut self.runtime,
            anchor_height,
            anchor_hash,
            consensus_height,
            certificate,
            txs,
            raw_txs,
        )
        .await
        {
            tracing::error!("batch_handler error: {e}");
        }
    }
    async fn execute_block(&mut self, block: &indexer_types::Block) {
        info!("# Block Kontor Transactions: {}", block.transactions.len());
        if let Err(e) = block_handler(&mut self.runtime, block).await {
            tracing::error!("block_handler error: {e}");
        }
    }
    async fn rollback_state(&mut self, to_anchor: u64) -> usize {
        match rollback_to_height(&self.writer.connection(), to_anchor).await {
            Ok(n) => {
                if let Err(e) = self
                    .runtime
                    .file_ledger
                    .force_resync_from_db(&self.runtime.storage.conn)
                    .await
                {
                    tracing::error!("file_ledger resync failed: {e}");
                }
                n as usize
            }
            Err(e) => {
                tracing::error!("rollback_to_height failed: {e}");
                0
            }
        }
    }
    async fn checkpoint(&self) -> Option<[u8; 32]> {
        use crate::database::queries::get_checkpoint_latest;
        match get_checkpoint_latest(&self.connection()).await {
            Ok(Some(row)) => {
                let mut bytes = [0u8; 32];
                if let Ok(decoded) = hex::decode(&row.hash)
                    && decoded.len() == 32
                {
                    bytes.copy_from_slice(&decoded);
                    return Some(bytes);
                }
                None
            }
            _ => None,
        }
    }
    async fn is_confirmed_on_chain(&self, txid: &bitcoin::Txid) -> bool {
        let conn = self.connection();
        match get_transaction_by_txid(&conn, &txid.to_string()).await {
            Ok(Some(row)) => row.confirmed_height.is_some(),
            _ => false,
        }
    }
    async fn get_decided(&self, height: Height) -> Option<(Value, CommitCertificate<Ctx>)> {
        let conn = self.connection();
        let (anchor_height, anchor_hash_str, cert_bytes, txid_strs) =
            select_batch(&conn, height.as_u64() as i64)
                .await
                .ok()
                .flatten()?;

        let anchor_hash = anchor_hash_str.parse::<BlockHash>().ok()?;
        let txids: Vec<Txid> = txid_strs.iter().filter_map(|s| s.parse().ok()).collect();

        // Include raw txs for unfinalized batches (within finality window of current tip)
        let raw_txs = if let Ok(Some(tip)) = select_block_latest(&conn).await {
            if (anchor_height as u64) + FINALITY_WINDOW > tip.height as u64 {
                // Within finality window — include raw txs from unconfirmed_batch_txs
                if let Ok(raw_bytes_list) =
                    select_unconfirmed_batch_txs(&conn, height.as_u64() as i64).await
                {
                    let txs: Vec<bitcoin::Transaction> = raw_bytes_list
                        .iter()
                        .filter_map(|raw| {
                            bitcoin::consensus::deserialize::<bitcoin::Transaction>(raw).ok()
                        })
                        .collect();
                    if txs.is_empty() { None } else { Some(txs) }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut value = Value::new_batch(anchor_height as u64, anchor_hash, txids);
        if let Value::Batch { raw_txs: ref mut rt, .. } = value {
            *rt = raw_txs;
        }

        let proto =
            crate::consensus::proto::CommitCertificate::decode(cert_bytes.as_slice()).ok()?;
        let certificate = decode_commit_certificate(proto).ok()?;

        Some((value, certificate))
    }
    async fn min_decided_height(&self) -> Option<Height> {
        select_min_batch_height(&self.connection())
            .await
            .ok()
            .flatten()
            .map(|h| Height::new(h as u64))
    }
    async fn get_decided_from_anchor(&self, from_anchor: u64) -> Vec<(Height, Value)> {
        let rows = match select_batches_from_anchor(&self.connection(), from_anchor as i64).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(%e, "Failed to query batches from anchor");
                return Vec::new();
            }
        };

        rows.into_iter()
            .filter_map(
                |(consensus_height, anchor_height, anchor_hash_str, txid_strs)| {
                    let anchor_hash = anchor_hash_str.parse::<BlockHash>().ok()?;
                    let txids: Vec<Txid> =
                        txid_strs.iter().filter_map(|s| s.parse().ok()).collect();
                    Some((
                        Height::new(consensus_height as u64),
                        Value::new_batch(anchor_height as u64, anchor_hash, txids),
                    ))
                },
            )
            .collect()
    }
    async fn replay_blocks_from(&mut self, height: u64) {
        if let Some(tx) = &self.replay_tx
            && let Err(e) = tx.send(height).await
        {
            tracing::error!(%e, height, "Failed to send replay request to poller");
        }
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        use crate::block::filter_map;
        filter_map((0, tx.clone()))
    }

    async fn simulate(&mut self, btx: bitcoin::Transaction) -> Result<Vec<OpWithResult>> {
        simulate_handler(&mut self.runtime, btx).await
    }

    async fn block_hash_at_height(&self, height: u64) -> Option<BlockHash> {
        let conn = self.writer.connection();
        let block: Option<indexer_types::BlockRow> = select_block_at_height(&conn, height as i64)
            .await
            .ok()
            .flatten();
        block.map(|b| b.hash)
    }
}
