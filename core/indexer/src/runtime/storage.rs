use anyhow::{Context, Result, anyhow};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bon::Builder;
use futures_util::Stream;
use libsql::Connection;
use regex::bytes::RegexBuilder;
use std::collections::HashMap;
use std::io::Read;
use wit_component::{ComponentEncoder, WitPrinter};

use crate::{
    database::{
        queries::{
            LiveRow, FOOTPRINT_BUILT_KEY, create_contract_signer, depositors_affected_by_reorg,
            exists_contract_state, find_live_subtree, find_matching_paths, footprint_cache_add,
            footprint_cache_get, footprint_cache_set, footprint_rebuild_all,
            get_contract_address_from_id, get_contract_bytes_by_id, get_contract_id_from_address,
            get_contract_provenance_publisher, get_latest_contract_state_value, get_meta_u64,
            hard_delete_matching_paths, insert_contract, insert_contract_provenance,
            insert_contract_result, insert_contract_state, latest_live_deposit, live_deposit_gas_sum,
            matching_path, path_prefix_filter_contract_state, prune_contract_state,
            rollback_to_height, select_block_at_height, set_meta_u64, tombstone_rows,
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
        Ok(footprint_cache_get(self.conn, depositor).await?.unwrap_or(0))
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
    pub async fn find_live_subtree(
        &self,
        contract_id: u64,
        path: &[u8],
    ) -> Result<Vec<LiveRow>> {
        Ok(find_live_subtree(&self.conn, contract_id, path).await?)
    }

    /// The write half of a delete: value-less-tombstone the given (already-metered)
    /// rows. Returns `(removed, freed_bytes)` — the footprint accumulator subtracts
    /// the freed bytes.
    pub async fn tombstone_rows(
        &self,
        contract_id: u64,
        rows: &[LiveRow],
    ) -> Result<(bool, u64)> {
        Ok(tombstone_rows(&self.conn, contract_id, self.height, self.effective_tx_id(), rows).await?)
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
        // `self.height` is the current tip (every write is stamped at it), so it bounds
        // the band's upper end and lets the discovery range-seek `idx_contract_state_height`.
        let affected =
            depositors_affected_by_reorg(&self.conn, target_height, self.height).await?;
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
                assert_eq!(cached, truth, "cache drifted from live sum for depositor {d}");
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
}
