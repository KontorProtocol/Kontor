use anyhow::{Context, Result, anyhow};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bon::Builder;
use futures_util::Stream;
use libsql::Connection;
use regex::bytes::RegexBuilder;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use wit_component::{ComponentEncoder, WitPrinter};

use crate::{
    database::{
        queries::{
            FOOTPRINT_BUILT_KEY, LiveRow, create_contract_signer, depositors_affected_by_reorg,
            exists_contract_state, find_live_subtree, find_matching_paths, footprint_cache_add,
            footprint_cache_get, footprint_cache_set, footprint_rebuild_all,
            get_contract_address_from_id, get_contract_bytes_by_id, get_contract_id_from_address,
            get_contract_provenance_publisher, get_latest_contract_state_value, get_meta_u64,
            hard_delete_matching_paths, insert_contract, insert_contract_provenance,
            insert_contract_result, insert_contract_state, latest_live_deposit,
            live_deposit_gas_sum, matching_path, path_prefix_filter_contract_state,
            prune_contract_state, rollback_to_height, select_block_at_height, set_meta_u64,
            tombstone_rows,
        },
        types::{ContractProvenanceRow, ContractResultRow, ContractRow, ContractStateRow},
    },
    runtime::{ContractAddress, counter::Counter, stack::Stack},
    test_utils::new_mock_transaction,
};

/// `block_entropy` recent-window size: a committed height older than this has
/// expired (so a stale draw falls out of the window and the contract can refund).
/// Bounds the lookup and forces prompt resolution. ~1 day on Bitcoin (144 blocks).
pub const BLOCK_ENTROPY_WINDOW: u64 = 144;

/// Decode the WIT embedded in already-encoded component bytes, unmodified
/// (`init`/core-context preserved) — for on-chain publish validation, where the
/// validator must see the real surface. `component_wit` strips `init`/core-context
/// afterward for client display. Pure, so callers that already hold the bytes
/// avoid re-fetching them.
pub(crate) fn print_component_wit(component_bytes: &[u8]) -> Result<String> {
    let decoded = wit_component::decode(component_bytes).context("Failed to decode component")?;
    let mut printer = WitPrinter::default();
    printer
        .print(decoded.resolve(), decoded.package(), &[])
        .context("Failed to print component")?;
    Ok(format!("{}", printer.output))
}

#[derive(Debug, Clone, PartialEq, Eq, Builder)]
pub struct TransactionContext {
    /// Autoincrement id from the transactions table (for contract_state/contract_results FK).
    /// None when no transaction row exists (e.g. publish_native_contracts).
    pub tx_id: Option<u64>,
    /// Position in the confirming Bitcoin block (for contracts table)
    #[builder(default = 0)]
    pub tx_index: u32,
    #[builder(default = 0)]
    pub input_index: u32,
    #[builder(default = 0)]
    pub op_index: u32,
    #[builder(default = new_mock_transaction(0).txid)]
    pub txid: Txid,
}

#[derive(Builder, Clone)]
pub struct Storage {
    pub conn: Connection,
    #[builder(default = Counter::builder().build())]
    pub savepoint_counter: Counter,
    #[builder(default = Stack::builder().build())]
    pub savepoint_stack: Stack<u64>,
    #[builder(default = 1)]
    pub height: u64,
    pub tx_context: Option<TransactionContext>,
}

/// The eager per-depositor storage-deposit FLOOR cache (`depositor_footprint`),
/// borrowing a DB connection. Off-checkpoint + reconstructible; maintained
/// incrementally on the write path (`on_set`/`on_free`) inside the op savepoint, so
/// it rolls back with the op. Read O(1) (`total_gas`) by the token's per-debit floor
/// check; built once (`reconstruct`) on first boot/upgrade; recomputed per affected
/// depositor on reorg (via [`Storage::rollback_with_footprint`]). INVARIANT:
/// `total_gas` == Σ live `deposited_gas` per depositor on every node — it gates token
/// debits, so it must stay an exact replica.
pub struct FootprintCache<'a> {
    conn: &'a Connection,
}

impl FootprintCache<'_> {
    /// The cached floor for `depositor`, in integer GAS — an O(1) read of the eager
    /// `depositor_footprint` sum (NEAR's `storage_usage`, keyed by depositor). Absent
    /// ⇒ 0. The host prices it to token (× gas→token) at the `storage_floor` read.
    pub async fn total_gas(&self, depositor: u64) -> Result<u64> {
        Ok(footprint_cache_get(self.conn, depositor)
            .await?
            .unwrap_or(0))
    }

    /// Maintain the cache for a `set`: subtract the live row being overwritten (read
    /// BEFORE the new row is written) from its setter, then add the new row to its
    /// depositor. A fresh create has no prior live row; an exempt/Core write
    /// (`depositor = None`) contributes nothing. The displaced-row read is a lean
    /// latest-by-height point lookup, not a window.
    pub async fn on_set(
        &self,
        contract_id: u64,
        path: &[u8],
        new_depositor: Option<u64>,
        new_gas: Option<u64>,
    ) -> Result<()> {
        if let Some(prev) = latest_live_deposit(self.conn, contract_id, path).await? {
            footprint_cache_add(self.conn, prev.depositor, -(prev.deposited_gas as i64)).await?;
        }
        if let (Some(d), Some(g)) = (new_depositor, new_gas) {
            footprint_cache_add(self.conn, d, g as i64).await?;
        }
        Ok(())
    }

    /// Maintain the cache for freed rows (delete/variant-cleanup): subtract each row's
    /// deposit from its setter. The rows were already read for metering, so this adds
    /// no read; deltas are summed PER DEPOSITOR (a K-row delete is almost always one
    /// depositor) so it issues ~1 statement, not 2·K.
    pub async fn on_free(&self, rows: &[LiveRow]) -> Result<()> {
        let mut deltas: HashMap<u64, i64> = HashMap::new();
        for row in rows {
            if let (Some(d), Some(g)) = (row.depositor, row.deposited_gas) {
                *deltas.entry(d).or_default() -= g as i64;
            }
        }
        for (depositor, delta) in deltas {
            footprint_cache_add(self.conn, depositor, delta).await?;
        }
        Ok(())
    }

    /// Re-add deposits REVIVED by a HARD delete. Hard-deleting a path's current-height
    /// row (intra-block variant cleanup) can expose an OLDER same-path version that
    /// becomes live again — its deposit must re-enter the cache, or the floor under-
    /// counts and the token allows spends it should reject. (A tombstone delete can't
    /// revive: its tombstone stays the latest row.) Mirrors the reorg resurrection
    /// handling. Call AFTER the hard delete — the revived row is whatever now remains
    /// latest-live for the path. `freed` is the just-deleted set; dedup by path since a
    /// subtree delete frees several rows under one path's siblings.
    pub async fn on_revive(&self, contract_id: u64, freed: &[LiveRow]) -> Result<()> {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for row in freed {
            if !seen.insert(row.path.as_slice()) {
                continue;
            }
            if let Some(revived) = latest_live_deposit(self.conn, contract_id, &row.path).await? {
                footprint_cache_add(self.conn, revived.depositor, revived.deposited_gas as i64)
                    .await?;
            }
        }
        Ok(())
    }

    /// Rebuild the cache from live state — ONCE, on first build (DB upgrade or first
    /// boot). Gated on a `node_meta` marker: block writes and reorgs both maintain the
    /// cache atomically, so once built it stays coherent and a clean restart skips the
    /// O(live-rows) rebuild. One grouped `SUM` pass, not a loop.
    pub async fn reconstruct(&self) -> Result<()> {
        if get_meta_u64(self.conn, FOOTPRINT_BUILT_KEY, 0).await? == 1 {
            return Ok(());
        }
        footprint_rebuild_all(self.conn).await?;
        set_meta_u64(self.conn, FOOTPRINT_BUILT_KEY, 1).await?;
        Ok(())
    }

    /// Recompute each given depositor's cached total from the (post-rollback) live
    /// rows — the cache-recovery half of a reorg. Each is overwritten with a fresh
    /// `SUM(deposited_gas)` (zero ⇒ row deleted). Bounded by the affected set.
    pub(crate) async fn recompute(&self, depositors: &[u64]) -> Result<()> {
        for &depositor in depositors {
            let total = live_deposit_gas_sum(self.conn, depositor).await?;
            let stored = (total != 0).then_some(total);
            footprint_cache_set(self.conn, depositor, stored).await?;
        }
        Ok(())
    }
}

impl Storage {
    pub async fn get(&self, fuel: u64, contract_id: u64, path: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(get_latest_contract_state_value(&self.conn, fuel, contract_id, path).await?)
    }

    /// Write a live value. `depositor` is the signer who collateralizes this row via
    /// the storage-deposit floor — `None` for Core/system writes; `deposited_gas`
    /// is its integer-gas deposit (paired with `depositor`), both computed by the
    /// caller (`_set_primitive`).
    pub async fn set(
        &self,
        contract_id: u64,
        path: &[u8],
        value: &[u8],
        depositor: Option<u64>,
        deposited_gas: Option<u64>,
    ) -> Result<()> {
        insert_contract_state(
            &self.conn,
            ContractStateRow::builder()
                .contract_id(contract_id)
                .maybe_tx_id(self.effective_tx_id())
                .height(self.height)
                .path(path.to_vec())
                .value(value.to_vec())
                .maybe_depositor(depositor)
                .maybe_deposited_gas(deposited_gas)
                .build(),
        )
        .await?;
        Ok(())
    }

    /// The read half of a delete: the live rows of `path`'s subtree (node + every
    /// live descendant) as `(path, size)` — NOT values. Split from the tombstone
    /// writes so the host can meter `Fuel::Delete` by the row count BEFORE the
    /// writes.
    pub async fn find_live_subtree(&self, contract_id: u64, path: &[u8]) -> Result<Vec<LiveRow>> {
        Ok(find_live_subtree(&self.conn, contract_id, path).await?)
    }

    /// The write half of a delete: value-less-tombstone the given (already-metered)
    /// rows. Returns `(removed, freed_bytes)` — the footprint accumulator subtracts
    /// the freed bytes.
    pub async fn tombstone_rows(&self, contract_id: u64, rows: &[LiveRow]) -> Result<(bool, u64)> {
        Ok(tombstone_rows(
            &self.conn,
            contract_id,
            self.height,
            self.effective_tx_id(),
            rows,
        )
        .await?)
    }

    /// The eager per-depositor storage-deposit FLOOR cache (see [`FootprintCache`]).
    pub fn footprint(&self) -> FootprintCache<'_> {
        FootprintCache { conn: &self.conn }
    }

    /// Reorg rollback that keeps the off-checkpoint footprint cache coherent
    /// ATOMICALLY: in ONE savepoint, capture the affected depositors (before the
    /// `blocks` cascade deletes their rows), run the cascade, then recompute just those
    /// from the post-rollback state. The capture→rollback→recompute ordering is
    /// enforced here, not by callers, and a crash can't leave a durably-stale cache.
    pub async fn rollback_with_footprint(&self, target_height: u64) -> Result<()> {
        self.savepoint().await?;
        match self.rollback_with_footprint_inner(target_height).await {
            Ok(()) => self.commit().await,
            Err(e) => {
                self.rollback().await?;
                Err(e)
            }
        }
    }

    async fn rollback_with_footprint_inner(&self, target_height: u64) -> Result<()> {
        // The band's upper bound (tip) is derived inside the query from the DB's own
        // MAX(height), NOT `self.height` — the in-memory height is 0 until the first block
        // executes, so a reorg right after startup would otherwise capture no depositors.
        let affected = depositors_affected_by_reorg(&self.conn, target_height).await?;
        rollback_to_height(&self.conn, target_height).await?;
        self.footprint().recompute(&affected).await?;
        Ok(())
    }

    pub async fn insert_contract_provenance(
        &self,
        contract_id: u64,
        author_signer_id: u64,
        provenance: &[u8],
    ) -> Result<()> {
        insert_contract_provenance(
            &self.conn,
            ContractProvenanceRow::builder()
                .contract_id(contract_id)
                .author_signer_id(author_signer_id)
                .height(self.height)
                .tx_index(
                    self.tx_context
                        .as_ref()
                        .expect("Transaction index is required when inserting provenance")
                        .tx_index,
                )
                .provenance(provenance.to_vec())
                .build(),
        )
        .await?;
        Ok(())
    }

    pub async fn contract_provenance_publisher(&self, contract_id: u64) -> Result<Option<u64>> {
        Ok(get_contract_provenance_publisher(&self.conn, contract_id).await?)
    }

    pub async fn exists(&self, contract_id: u64, path: &[u8]) -> Result<bool> {
        Ok(exists_contract_state(&self.conn, contract_id, path).await?)
    }

    /// Resolve which of `variants` is the current value under `base_path` (an
    /// enum/option discriminant), or `None` if unset. The host passes the variant
    /// names; the query checks them against the codec child element.
    pub async fn extend_path_with_match(
        &self,
        contract_id: u64,
        base_path: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Option<u32>> {
        Ok(matching_path(&self.conn, contract_id, base_path, candidates).await?)
    }

    /// Read half of the intra-block variant hard-delete: the `LiveRow`s it will
    /// remove, so the host can meter `Fuel::Delete` before the writes.
    pub async fn find_matching_paths(
        &self,
        contract_id: u64,
        base_path: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<LiveRow>> {
        Ok(
            find_matching_paths(&self.conn, contract_id, self.height, base_path, candidates)
                .await?,
        )
    }

    /// Write half: hard-delete the (already-metered) intra-block rows under any of
    /// `candidates`. Returns the rows removed.
    pub async fn hard_delete_matching_paths(
        &self,
        contract_id: u64,
        base_path: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<u64> {
        Ok(
            hard_delete_matching_paths(&self.conn, contract_id, self.height, base_path, candidates)
                .await?,
        )
    }

    pub async fn contract_id(&self, contract_address: &ContractAddress) -> Result<Option<u64>> {
        Ok(get_contract_id_from_address(&self.conn, contract_address).await?)
    }

    pub async fn contract_address(&self, contract_id: u64) -> Result<Option<ContractAddress>> {
        Ok(get_contract_address_from_id(&self.conn, contract_id).await?)
    }

    pub async fn contract_bytes(&self, contract_id: u64) -> Result<Option<Vec<u8>>> {
        Ok(get_contract_bytes_by_id(&self.conn, contract_id).await?)
    }

    pub async fn component_bytes(&self, contract_id: u64) -> Result<Vec<u8>> {
        let compressed_bytes = self
            .contract_bytes(contract_id)
            .await?
            .ok_or(anyhow!("Contract not found when trying to load component"))?;
        let module_bytes = tokio::task::spawn_blocking(move || {
            let mut decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
            let mut module_bytes = Vec::new();
            decompressor.read_to_end(&mut module_bytes)?;
            Ok::<_, std::io::Error>(module_bytes)
        })
        .await??;

        ComponentEncoder::default()
            .module(&module_bytes)?
            .validate(true)
            .encode()
    }

    pub async fn component_wit(&self, contract_id: u64) -> Result<String> {
        let wit = print_component_wit(&self.component_bytes(contract_id).await?)?;
        // regexr.com/8i6dk
        let re = RegexBuilder::new(r"(\n^.*(borrow<core-context>|export init:|\{\s*core-context\s*\}).*$|[,]{0,1}\s*core-context[,]{0,1}\s*)")
            .multi_line(true)
            .build()?;
        let wit =
            String::from_utf8_lossy(&re.replace_all(wit.as_bytes(), "".as_bytes())).into_owned();
        Ok(wit)
    }

    pub async fn insert_contract(&self, name: &str, bytes: &[u8]) -> Result<u64> {
        let signer_id = create_contract_signer(&self.conn, self.height).await?;
        Ok(insert_contract(
            &self.conn,
            ContractRow::builder()
                .height(self.height)
                .tx_index(
                    self.tx_context
                        .as_ref()
                        .expect("Transaction index is required when inserting contract")
                        .tx_index,
                )
                .name(name.to_string())
                .bytes(bytes.to_vec())
                .signer_id(signer_id)
                .build(),
        )
        .await?)
    }

    fn effective_tx_id(&self) -> Option<u64> {
        self.tx_context.as_ref().and_then(|c| c.tx_id)
    }

    pub fn build_contract_result_row(
        &self,
        result_index: u32,
        contract_id: u64,
        func: String,
        gas: u64,
        value: Option<String>,
        signer_id: u64,
        payer_signer_id: Option<u64>,
        status: indexer_types::OpStatus,
    ) -> ContractResultRow {
        ContractResultRow::builder()
            .contract_id(contract_id)
            .height(self.height)
            .maybe_tx_id(self.effective_tx_id())
            .maybe_input_index(self.tx_context.as_ref().map(|c| c.input_index))
            .maybe_op_index(self.tx_context.as_ref().map(|c| c.op_index))
            .result_index(result_index)
            .func(func)
            .gas(gas)
            .maybe_value(value)
            .signer_id(signer_id)
            .maybe_payer_signer_id(payer_signer_id)
            .status(status)
            .build()
    }

    pub async fn insert_contract_result(
        &self,
        result_index: u32,
        contract_id: u64,
        func: String,
        gas: u64,
        value: Option<String>,
        signer_id: u64,
        payer_signer_id: Option<u64>,
        status: indexer_types::OpStatus,
    ) -> Result<u64> {
        Ok(insert_contract_result(
            &self.conn,
            self.build_contract_result_row(
                result_index,
                contract_id,
                func,
                gas,
                value,
                signer_id,
                payer_signer_id,
                status,
            ),
        )
        .await?)
    }

    pub async fn keys(
        &self,
        contract_id: u64,
        path: Vec<u8>,
        after: Option<Vec<u8>>,
    ) -> Result<impl Stream<Item = Result<Vec<u8>, crate::database::queries::Error>> + Send + 'static>
    {
        Ok(path_prefix_filter_contract_state(&self.conn, contract_id, path, after).await?)
    }

    /// Canonical per-block entropy (the Bitcoin block hash) at `height`, within the
    /// recent window. `None` if `height` is beyond the block being executed (no
    /// entropy yet) or older than [`BLOCK_ENTROPY_WINDOW`] (expired). The canonical
    /// `blocks` table is the source, so it's reorg-correct without a cache.
    pub async fn block_entropy(&self, height: u64) -> Result<Option<Vec<u8>>> {
        if height > self.height || height + BLOCK_ENTROPY_WINDOW < self.height {
            return Ok(None);
        }
        Ok(select_block_at_height(&self.conn, height)
            .await?
            .map(|b| b.hash.to_byte_array().to_vec()))
    }

    /// Incrementally prune the finalized band `(w_prev, w]` (see
    /// [`prune_contract_state`]) inside a savepoint, so the two DELETEs and the
    /// watermark upsert commit (or roll back) atomically through the same
    /// transaction bookkeeping as every other write. Returns rows deleted.
    pub async fn prune(&self, w_prev: u64, w: u64) -> Result<u64> {
        self.savepoint().await?;
        match prune_contract_state(&self.conn, w_prev, w).await {
            Ok(deleted) => {
                self.commit().await?;
                Ok(deleted)
            }
            Err(e) => {
                self.rollback().await?;
                Err(e.into())
            }
        }
    }

    /// Free pages currently on the SQLite freelist (the prune-vacuum throttle reads
    /// this to decide whether returning pages to the OS is worth it).
    pub async fn freelist_count(&self) -> Result<i64> {
        let mut rows = self.conn.query("PRAGMA freelist_count;", ()).await?;
        Ok(match rows.next().await? {
            Some(row) => row.get(0)?,
            None => 0,
        })
    }

    /// Return up to `pages` freelist pages to the OS via `PRAGMA incremental_vacuum`.
    pub async fn incremental_vacuum(&self, pages: i64) -> Result<()> {
        self.conn
            .query(&format!("PRAGMA incremental_vacuum({pages});"), ())
            .await?;
        Ok(())
    }

    pub async fn savepoint(&self) -> Result<()> {
        if self.savepoint_stack.is_empty().await {
            self.conn.execute("BEGIN TRANSACTION", ()).await?;
            self.savepoint_stack.push(0).await?;
            self.savepoint_counter.reset().await;
        } else {
            let i = self.savepoint_counter.get().await;
            self.conn.execute(&format!("SAVEPOINT S{}", i), ()).await?;
            self.savepoint_stack.push(i).await?;
        }
        self.savepoint_counter.increment().await;
        Ok(())
    }

    pub async fn commit(&self) -> Result<()> {
        match self.savepoint_stack.pop().await {
            Some(0) => self.conn.execute("COMMIT", ()).await?,
            Some(i) => self.conn.execute(&format!("RELEASE S{}", i), ()).await?,
            None => 0,
        };
        Ok(())
    }

    pub async fn rollback_transaction(&self) -> Result<()> {
        self.savepoint_stack.clear().await;
        self.conn.execute("ROLLBACK", ()).await?;
        Ok(())
    }

    pub async fn rollback(&self) -> Result<()> {
        match self.savepoint_stack.pop().await {
            Some(0) => self.conn.execute("ROLLBACK", ()).await?,
            Some(i) => {
                self.conn
                    .execute(&format!("ROLLBACK TO S{}", i), ())
                    .await?
            }
            None => 0,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::new_connection;
    use crate::database::queries::insert_block;
    use crate::test_utils::{new_mock_block_hash, new_test_db};
    use indexer_types::BlockRow;

    // `block_entropy` returns a present block's hash only when the height is in the
    // recent window `[current - K, current]`: not future, not expired, and a row
    // exists. (K = BLOCK_ENTROPY_WINDOW = 144.)
    #[tokio::test]
    async fn block_entropy_windowing() -> Result<()> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        for h in [10u64, 100, 200] {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
        }
        // Execution height 200 → window is heights 56..=200.
        let storage = Storage::builder().height(200).conn(conn).build();
        let bytes = |h: u32| new_mock_block_hash(h).to_byte_array().to_vec();

        assert_eq!(storage.block_entropy(200).await?, Some(bytes(200))); // current block
        assert_eq!(storage.block_entropy(100).await?, Some(bytes(100))); // in window, present
        assert_eq!(storage.block_entropy(10).await?, None); // expired (10 < 56)
        assert_eq!(storage.block_entropy(201).await?, None); // future (> current)
        assert_eq!(storage.block_entropy(150).await?, None); // in window but no such block
        Ok(())
    }

    // `Storage::prune` collapses the band through a savepoint and persists the
    // watermark — exercising the transaction-wrapped path the reactor uses.
    #[tokio::test]
    async fn prune_collapses_band_and_persists_watermark() -> Result<()> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        // One path updated at heights 1, 2, 3.
        for h in [1u64, 2, 3] {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
            conn.execute(
                "INSERT INTO contract_state (contract_id, height, tx_id, size, path, value, deleted) \
                 VALUES (1, ?1, NULL, 1, ?2, ?3, 0)",
                libsql::params![h, vec![b'x'], vec![b'v']],
            )
            .await?;
        }
        let storage = Storage::builder().height(3).conn(conn.clone()).build();

        // Band (0, 3] collapses heights 1 and 2, keeping only the newest (3).
        assert_eq!(storage.prune(0, 3).await?, 2);

        let mut rows = conn
            .query(
                "SELECT height FROM contract_state WHERE contract_id = 1 ORDER BY height",
                (),
            )
            .await?;
        let mut heights = Vec::new();
        while let Some(r) = rows.next().await? {
            heights.push(r.get::<i64>(0)?);
        }
        assert_eq!(heights, vec![3], "only the newest version survives");

        // The watermark was persisted in the same (committed) transaction.
        let mut wm = conn
            .query(
                "SELECT value FROM node_meta WHERE key = 'prune_watermark'",
                (),
            )
            .await?;
        assert_eq!(wm.next().await?.unwrap().get::<i64>(0)?, 3);
        Ok(())
    }

    // THE cache invariant: `depositor_footprint.total_gas` must exactly equal
    // `live_deposit_gas_sum` for every depositor after EVERY mutation — the cache is
    // only correct because every write path calls on_set/on_free. This drives a
    // sequence of write / overwrite / cross-contract / delete / REORG through those
    // hooks and asserts the cached floor never drifts from the freshly-summed truth
    // (the regression guard against a future write path forgetting to maintain it).
    #[tokio::test]
    async fn footprint_cache_never_drifts_from_live_sum() -> Result<()> {
        use crate::database::queries::{create_contract_signer, live_deposit_gas_sum};

        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        for h in 1..=6u64 {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
        }
        let alice = create_contract_signer(&conn, 1).await?;
        let bob = create_contract_signer(&conn, 1).await?;
        let mut storage = Storage::builder().height(1).conn(conn.clone()).build();

        let path = |k: &str| k.as_bytes().to_vec();
        // cache == fresh sum for both depositors, asserted after every step.
        let check = async |storage: &Storage| -> Result<()> {
            for d in [alice, bob] {
                let cached = storage.footprint().total_gas(d).await?;
                let truth = live_deposit_gas_sum(&conn, d).await?;
                assert_eq!(
                    cached, truth,
                    "cache drifted from live sum for depositor {d}"
                );
            }
            Ok(())
        };
        // mirror _set_primitive: maintain the cache (on_set reads the displaced row)
        // BEFORE writing the new version.
        let write = async |storage: &Storage, cid: u64, k: &str, d: u64, gas: u64| -> Result<()> {
            storage
                .footprint()
                .on_set(cid, &path(k), Some(d), Some(gas))
                .await?;
            storage.set(cid, &path(k), b"v", Some(d), Some(gas)).await?;
            Ok(())
        };

        // h1: fresh create.
        write(&storage, 1, "a", alice, 10).await?;
        check(&storage).await?;
        // h2: alice grows in the same contract + a second contract.
        storage.height = 2;
        write(&storage, 1, "b", alice, 20).await?;
        write(&storage, 2, "a", bob, 5).await?; // cross-contract, different depositor
        check(&storage).await?;
        // h3: bob OVERWRITES alice's (1,"a") — obligation moves alice→bob.
        storage.height = 3;
        write(&storage, 1, "a", bob, 8).await?;
        check(&storage).await?;
        assert_eq!(storage.footprint().total_gas(alice).await?, 20); // 30 − 10
        assert_eq!(storage.footprint().total_gas(bob).await?, 13); // 5 + 8
        // h4: delete alice's (1,"b") — her floor relaxes.
        storage.height = 4;
        let rows = storage.find_live_subtree(1, &path("b")).await?;
        storage.footprint().on_free(&rows).await?;
        storage.tombstone_rows(1, &rows).await?;
        check(&storage).await?;
        assert_eq!(storage.footprint().total_gas(alice).await?, 0);

        // REORG to height 2: the h3 overwrite + h4 delete vanish via the cascade;
        // alice's (1,"a")@h1 and (1,"b")@h2 become live again. The reorg path must
        // recompute the affected depositors back to truth — with NO drift.
        storage.rollback_with_footprint(2).await?;
        check(&storage).await?;
        assert_eq!(storage.footprint().total_gas(alice).await?, 30); // a(10) + b(20) live again
        assert_eq!(storage.footprint().total_gas(bob).await?, 5); // only (2,"a")
        Ok(())
    }

    // Regression: a reorg right after startup, before any block has advanced the
    // in-memory tip. `Storage.height` is 0 (its builder default) until the first op
    // runs, so deriving the band's upper bound from it would capture NO depositors and
    // leave the cache stale. The tip must come from the DB's own MAX(height) instead.
    #[tokio::test]
    async fn rollback_recomputes_footprint_with_stale_in_memory_height() -> Result<()> {
        use crate::database::queries::{create_contract_signer, live_deposit_gas_sum};

        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        for h in 1..=2u64 {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
        }
        let alice = create_contract_signer(&conn, 1).await?;
        let path = |k: &str| k.as_bytes().to_vec();
        let mut storage = Storage::builder().height(1).conn(conn.clone()).build();
        storage
            .footprint()
            .on_set(1, &path("a"), Some(alice), Some(10))
            .await?;
        storage
            .set(1, &path("a"), b"v", Some(alice), Some(10))
            .await?;
        storage.height = 2;
        storage
            .footprint()
            .on_set(1, &path("b"), Some(alice), Some(20))
            .await?;
        storage
            .set(1, &path("b"), b"v", Some(alice), Some(20))
            .await?;
        assert_eq!(storage.footprint().total_gas(alice).await?, 30);

        // Simulate a fresh process: the cache is correct (reconstructed) but the
        // in-memory tip has not been advanced past its 0 default yet.
        storage.height = 0;
        storage.rollback_with_footprint(1).await?; // drops (1,"b")@h2

        assert_eq!(
            storage.footprint().total_gas(alice).await?,
            live_deposit_gas_sum(&conn, alice).await?,
            "reorg at stale in-memory height must still recompute the floor from live state"
        );
        assert_eq!(storage.footprint().total_gas(alice).await?, 10);
        Ok(())
    }

    // Regression: a HARD delete (intra-block variant cleanup) of a path's current-height
    // row exposes an OLDER same-path version that becomes live again. The cache must
    // re-add the revived deposit, else the floor under-counts and the token would allow
    // an over-spend. (Bugbot: "Hard delete drops revived deposits".)
    #[tokio::test]
    async fn hard_delete_revives_displaced_deposit() -> Result<()> {
        use crate::database::queries::{create_contract_signer, live_deposit_gas_sum};

        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        for h in 1..=2u64 {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
        }
        let alice = create_contract_signer(&conn, 1).await?;
        let bob = create_contract_signer(&conn, 1).await?;
        // The path is `base ++ candidate`, the shape the variant-cleanup delete matches.
        let base = b"e/".to_vec();
        let path = b"e/A".to_vec();
        let candidates = vec![b"A".to_vec()];

        let mut storage = Storage::builder().height(1).conn(conn.clone()).build();
        // h1: alice writes e/A (deposit 10).
        storage
            .footprint()
            .on_set(1, &path, Some(alice), Some(10))
            .await?;
        storage.set(1, &path, b"v", Some(alice), Some(10)).await?;
        // h2: bob overwrites e/A (deposit 20) — displaces alice in the cache.
        storage.height = 2;
        storage
            .footprint()
            .on_set(1, &path, Some(bob), Some(20))
            .await?;
        storage.set(1, &path, b"v", Some(bob), Some(20)).await?;
        assert_eq!(storage.footprint().total_gas(alice).await?, 0); // displaced
        assert_eq!(storage.footprint().total_gas(bob).await?, 20);

        // Intra-block hard-delete of e/A @ h2 — mirrors `_delete_matching_paths`.
        let rows = storage.find_matching_paths(1, &base, &candidates).await?;
        storage.footprint().on_free(&rows).await?;
        storage
            .hard_delete_matching_paths(1, &base, &candidates)
            .await?;
        storage.footprint().on_revive(1, &rows).await?;

        // alice's h1 row is live again → her deposit must be back in the cache.
        assert_eq!(storage.footprint().total_gas(bob).await?, 0);
        assert_eq!(
            storage.footprint().total_gas(alice).await?,
            live_deposit_gas_sum(&conn, alice).await?,
            "revived deposit must re-enter the cache (== live sum)"
        );
        assert_eq!(storage.footprint().total_gas(alice).await?, 10);
        Ok(())
    }

    // Answers the design doc's explicit open question ("footprint tally cost — the thing
    // we are choosing to measure"): is the eager `depositor_footprint` cache worth its
    // complexity vs. summing live rows fresh each debit? The floor is read on EVERY token
    // debit (every transfer/hold/burn, and the gas `hold` runs on every op), so this is
    // the consensus hot path. `live_deposit_gas_sum` is O(N) in a depositor's live-row
    // count (scan + per-row NOT-EXISTS liveness probe); the cache is an O(1) point read.
    //
    // Measured (release, in-process; absolute µs vary by host, the SHAPE is the point):
    //   N        fresh    cache   speedup
    //   1        7.0µs    2.1µs    3.4x
    //   10       8.7µs    2.0µs    4.3x
    //   100      29.6µs   2.0µs    14.5x
    //   1,000    291µs    2.0µs    142x
    //   10,000   3,188µs  2.1µs    1,521x
    //
    // N (rows a holder is the depositor of) is small for light users but reaches
    // thousands for heavy users of indexed storage — Kontor's TARGET workload. At those
    // counts the fresh sum is a per-debit multi-ms scan on every validator, unmetered
    // relative to N (a transfer's gas doesn't scale with the debited holder's footprint),
    // i.e. a gas-asymmetric DoS. The O(1) cache closes it. This is why the cache exists.
    #[tokio::test]
    #[ignore = "perf benchmark, not a correctness assertion; run explicitly with --nocapture"]
    async fn bench_floor_read_fresh_vs_cache() -> Result<()> {
        use std::time::Instant;

        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        for h in 1..=2u64 {
            insert_block(
                &conn,
                BlockRow::builder()
                    .height(h)
                    .hash(new_mock_block_hash(h as u32))
                    .build(),
            )
            .await?;
        }
        let alice = create_contract_signer(&conn, 1).await?;
        let storage = Storage::builder().height(1).conn(conn.clone()).build();

        let iters = 200u32;
        println!("\nN\tfresh_us\tcache_us\tspeedup");
        let mut inserted = 0usize;
        for n in [1usize, 10, 100, 1_000, 10_000] {
            while inserted < n {
                let path = format!("k{inserted}").into_bytes();
                storage
                    .footprint()
                    .on_set(1, &path, Some(alice), Some(7))
                    .await?;
                storage.set(1, &path, b"v", Some(alice), Some(7)).await?;
                inserted += 1;
            }
            // Cache must equal the fresh truth — keeps the benchmark honest.
            assert_eq!(
                live_deposit_gas_sum(&conn, alice).await?,
                footprint_cache_get(&conn, alice).await?.unwrap_or(0),
                "cache must equal fresh sum at N={n}"
            );

            for _ in 0..10 {
                live_deposit_gas_sum(&conn, alice).await?;
                footprint_cache_get(&conn, alice).await?;
            }
            let t = Instant::now();
            for _ in 0..iters {
                live_deposit_gas_sum(&conn, alice).await?;
            }
            let fresh_us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
            let t = Instant::now();
            for _ in 0..iters {
                footprint_cache_get(&conn, alice).await?;
            }
            let cache_us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
            println!(
                "{n}\t{fresh_us:.1}\t\t{cache_us:.1}\t\t{:.0}x",
                fresh_us / cache_us
            );
        }
        Ok(())
    }

    // Regression for the runtime-pool stale-snapshot bug behind the flaky floor-view
    // test: a pooled "view" connection that leaks an open read transaction stays pinned
    // to its old WAL snapshot and serves stale reads forever — unless reset on recycle.
    // This drives the exact scenario: a leaked BEGIN pins a snapshot, a concurrent
    // writer commits, the leaked connection reads stale, then `rollback_transaction`
    // (what the runtime pool's `recycle` now calls) restores a fresh snapshot.
    #[tokio::test]
    async fn pool_recycle_clears_stale_snapshot() -> Result<()> {
        let (_reader, writer, (temp, db_name)) = new_test_db().await?;
        let writer_conn = writer.connection();
        // A second physical connection to the SAME WAL db — stands in for a pooled
        // runtime/view connection handed out by the runtime pool.
        let view_conn = new_connection(temp.path(), &db_name).await?;
        let view = Storage::builder().conn(view_conn.clone()).build();

        let key = "stale_snapshot_probe";
        set_meta_u64(&writer_conn, key, 1).await?;

        // The view opens a transaction and reads — pinning its WAL snapshot at value 1.
        view.savepoint().await?;
        assert_eq!(get_meta_u64(&view_conn, key, 0).await?, 1);

        // The writer advances the value and commits (autocommit).
        set_meta_u64(&writer_conn, key, 2).await?;

        // Still inside its leaked transaction, the view is pinned to the old snapshot —
        // exactly the stale read a no-op recycle would serve indefinitely.
        assert_eq!(
            get_meta_u64(&view_conn, key, 0).await?,
            1,
            "an open transaction must still see its pinned (stale) snapshot"
        );

        // What the pool's `recycle` now does before handing the connection out again.
        view.rollback_transaction().await?;

        // A fresh read now sees the latest committed value — no stale snapshot.
        assert_eq!(
            get_meta_u64(&view_conn, key, 0).await?,
            2,
            "after the recycle reset, the connection must read the latest committed state"
        );
        Ok(())
    }

    // Floor-view flake probe at the libsql level. Cluster scenario: the reactor
    // (writer) commits, the reader pool confirms it (what `wait_for_txids` polls),
    // THEN the runtime pool serves the `/view` floor read. All three are separate
    // connections on one WAL db. If a fresh autocommit read on the view connection
    // can lag a commit the reader connection already saw, that IS the floor-view
    // flake's mechanism. A pass means libsql cross-connection visibility is sound
    // and the flake lives elsewhere (the cluster/consensus path), not here.
    #[tokio::test]
    async fn fresh_view_read_never_lags_reader_pool() -> Result<()> {
        let (_reader, writer, (temp, db_name)) = new_test_db().await?;
        let writer_conn = writer.connection();
        let reader_pool_conn = new_connection(temp.path(), &db_name).await?;
        let view_conn = new_connection(temp.path(), &db_name).await?;

        let key = "view_freshness_probe";
        for i in 1..=3000u64 {
            set_meta_u64(&writer_conn, key, i).await?; // reactor commits i
            let r = get_meta_u64(&reader_pool_conn, key, 0).await?; // reader pool confirms
            assert_eq!(r, i, "reader pool must see commit {i}, saw {r}");
            let v = get_meta_u64(&view_conn, key, 0).await?; // runtime pool /view read
            assert_eq!(
                v, i,
                "view read lagged a commit the reader pool already saw: committed {i}, view saw {v}"
            );
        }
        Ok(())
    }

    // Faithful version of the above: the writer commits via an EXPLICIT
    // transaction (like the reactor's batch savepoint), CONCURRENTLY, while the
    // view reads through the same `savepoint()`→read→`commit()` wrapper the
    // read-only `/view` runtime uses. Monotonicity invariant: a view read that
    // STARTS after the reader pool already observed value R must see >= R — it
    // can never go backwards. A violation reproduces the floor-view flake.
    #[tokio::test]
    async fn savepoint_wrapped_view_read_never_goes_backwards_under_concurrent_writes() -> Result<()>
    {
        let (_reader, writer, (temp, db_name)) = new_test_db().await?;
        let writer_conn = writer.connection();
        let reader_pool_conn = new_connection(temp.path(), &db_name).await?;
        let view = Storage::builder()
            .conn(new_connection(temp.path(), &db_name).await?)
            .build();
        let key = "view_monotonic_probe";
        set_meta_u64(&writer_conn, key, 0).await?;

        // Writer task: bump the value as fast as possible, concurrently.
        let w = writer_conn.clone();
        let writer_task = tokio::spawn(async move {
            for i in 1..=5000u64 {
                set_meta_u64(&w, key, i).await.unwrap();
            }
        });

        // Reader confirms a value, then the view (savepoint-wrapped) must not lag it.
        for _ in 0..20000u64 {
            let r = get_meta_u64(&reader_pool_conn, key, 0).await?;
            view.savepoint().await?;
            let v = get_meta_u64(&view.conn, key, 0).await?;
            view.commit().await?;
            assert!(
                v >= r,
                "savepoint-wrapped view read went BACKWARDS: reader pool already saw {r}, view saw {v}"
            );
            if writer_task.is_finished() {
                break;
            }
        }
        writer_task.await.unwrap();
        Ok(())
    }

    // THE root cause, proven directly (SQLDelight #2123 / SQLite WAL): a connection
    // that holds an UNDRAINED cursor cannot advance its read snapshot in WAL mode
    // ("a reader can't move its end mark while it has active statements"). A FRESH
    // read on that same connection then returns STALE data even though another
    // connection already committed — and `is_autocommit()` is still TRUE (it's an
    // implicit statement lock, not a BEGIN), so the recycle's autocommit check is
    // blind to it. Dropping the cursor releases the pin. This is the floor-view flake.
    #[tokio::test]
    async fn held_cursor_pins_wal_snapshot_until_dropped() -> Result<()> {
        let (_reader, writer, (temp, db_name)) = new_test_db().await?;
        let writer_conn = writer.connection();
        let view_conn = new_connection(temp.path(), &db_name).await?;

        let key = "wal_pin_probe";
        set_meta_u64(&writer_conn, key, 1).await?;
        writer_conn
            .execute("CREATE TABLE probe (x INTEGER)", ())
            .await?;
        for i in 0..200i64 {
            writer_conn
                .execute("INSERT INTO probe VALUES (?1)", [i])
                .await?;
        }

        // The view opens a cursor and reads ONE row, leaving the statement ACTIVE
        // (the leaked `Keys` stream in production). The connection is still autocommit.
        let mut held = view_conn.query("SELECT x FROM probe", ()).await?;
        let _ = held.next().await?;
        assert!(
            view_conn.is_autocommit(),
            "an open cursor does NOT flip autocommit — the recycle check can't see it"
        );
        assert_eq!(get_meta_u64(&view_conn, key, 0).await?, 1);

        // Another connection commits a newer value.
        set_meta_u64(&writer_conn, key, 2).await?;

        // A FRESH read on the view connection while the cursor is held: pinned to the
        // old snapshot → STALE. This is the bug.
        let pinned = get_meta_u64(&view_conn, key, 0).await?;

        // Dropping the cursor releases the pin; the next read sees the latest.
        drop(held);
        let after_drop = get_meta_u64(&view_conn, key, 0).await?;

        assert_eq!(
            pinned, 1,
            "REPRO: a held cursor pinned the WAL snapshot — fresh read saw stale {pinned}"
        );
        assert_eq!(
            after_drop, 2,
            "FIX: after dropping the cursor the connection advances to the latest commit"
        );
        Ok(())
    }
}
