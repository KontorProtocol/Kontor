use anyhow::{Context, Result, anyhow};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bon::Builder;
use futures_util::Stream;
use libsql::Connection;
use regex::bytes::RegexBuilder;
use std::io::Read;
use wit_component::{ComponentEncoder, WitPrinter};

use crate::{
    database::{
        queries::{
            DepositRow, create_contract_signer, depositors_affected_by_reorg, exists_contract_state,
            find_live_subtree, find_matching_paths, footprint_cache_add, footprint_cache_get,
            footprint_cache_set, get_contract_address_from_id, get_contract_bytes_by_id,
            get_contract_id_from_address, get_contract_provenance_publisher,
            get_latest_contract_state, get_latest_contract_state_value, hard_delete_matching_paths,
            insert_contract, insert_contract_provenance, insert_contract_result,
            insert_contract_state, live_deposit_gas_sum, live_depositors, matching_path,
            path_prefix_filter_contract_state, prune_contract_state, select_block_at_height,
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
    ) -> Result<Vec<DepositRow>> {
        Ok(find_live_subtree(&self.conn, contract_id, path).await?)
    }

    /// The write half of a delete: value-less-tombstone the given (already-metered)
    /// rows. Returns `(removed, freed_bytes)` — the footprint accumulator subtracts
    /// the freed bytes.
    pub async fn tombstone_rows(
        &self,
        contract_id: u64,
        rows: &[DepositRow],
    ) -> Result<(bool, u64)> {
        Ok(tombstone_rows(&self.conn, contract_id, self.height, self.effective_tx_id(), rows).await?)
    }

    /// The cached storage-deposit floor for `depositor`, in integer GAS — an O(1)
    /// read of the eager `depositor_footprint` sum (NEAR's `storage_usage`, keyed by
    /// depositor). Absent ⇒ 0. The host converts to the token floor (× gas→token) at
    /// the `storage_floor` read; the token consults that on every debit.
    pub async fn footprint_total_gas(&self, depositor: u64) -> Result<u64> {
        Ok(footprint_cache_get(&self.conn, depositor).await?.unwrap_or(0))
    }

    /// Add/subtract one row's `gas` from a depositor's cached floor — a single atomic
    /// `total_gas += delta` (no read-modify-write). Runs on `self.conn` inside the op
    /// savepoint, so it rolls back with the op like every other write.
    async fn footprint_adjust(&self, depositor: u64, gas: u64, add: bool) -> Result<()> {
        let delta = if add { gas as i64 } else { -(gas as i64) };
        Ok(footprint_cache_add(&self.conn, depositor, delta).await?)
    }

    /// Maintain the footprint cache for a `set`: subtract the live row being
    /// overwritten (read BEFORE the new row is written) from its setter, then add the
    /// new row to its depositor. A fresh create has no prior live row; an exempt/Core
    /// write (`depositor = None`) contributes nothing.
    pub async fn footprint_on_set(
        &self,
        contract_id: u64,
        path: &[u8],
        new_depositor: Option<u64>,
        new_gas: Option<u64>,
    ) -> Result<()> {
        if let Some(old) = get_latest_contract_state(&self.conn, contract_id, path).await? {
            if let (Some(d), Some(g)) = (old.depositor, old.deposited_gas) {
                self.footprint_adjust(d, g, false).await?;
            }
        }
        if let (Some(d), Some(g)) = (new_depositor, new_gas) {
            self.footprint_adjust(d, g, true).await?;
        }
        Ok(())
    }

    /// Maintain the footprint cache for freed rows (delete/variant-cleanup):
    /// subtract each row's deposit from its setter. The rows were already read for
    /// metering, so this adds no query.
    pub async fn footprint_on_free(&self, rows: &[DepositRow]) -> Result<()> {
        for row in rows {
            if let (Some(d), Some(g)) = (row.depositor, row.deposited_gas) {
                self.footprint_adjust(d, g, false).await?;
            }
        }
        Ok(())
    }

    /// Rebuild the entire footprint cache from `contract_state` (startup / migration).
    /// Reconstructible by design — the cache is a pure function of the live
    /// depositor/deposited_gas rows.
    pub async fn footprint_reconstruct(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM depositor_footprint", ())
            .await?;
        for depositor in live_depositors(&self.conn).await? {
            self.footprint_set_from_live(depositor).await?;
        }
        Ok(())
    }

    /// The depositors a rollback to `target_height` could affect — CAPTURE THIS
    /// BEFORE the rollback deletes the rows above the target (afterwards they're
    /// gone). Pair with [`Self::footprint_reverse_reorg`] run after the rollback.
    pub async fn footprint_affected_by_reorg(&self, target_height: u64) -> Result<Vec<u64>> {
        Ok(depositors_affected_by_reorg(&self.conn, target_height).await?)
    }

    /// After a rollback, recompute the floor of each `affected` depositor (captured
    /// pre-rollback by [`Self::footprint_affected_by_reorg`]) from the post-rollback
    /// live rows — bounded by the (shallow) reorg, NOT a full rebuild. The cache has
    /// no `blocks` FK, so the cascade that deletes the rolled-back rows leaves it
    /// stale until this runs.
    pub async fn footprint_reverse_reorg(&self, affected: &[u64]) -> Result<()> {
        for &depositor in affected {
            self.footprint_set_from_live(depositor).await?;
        }
        Ok(())
    }

    /// Overwrite one depositor's cached total with a fresh `SUM(deposited_gas)` of
    /// their live rows (one query — integer gas). Zero ⇒ delete the row.
    async fn footprint_set_from_live(&self, depositor: u64) -> Result<()> {
        let total = live_deposit_gas_sum(&self.conn, depositor).await?;
        let stored = (total != 0).then_some(total);
        footprint_cache_set(&self.conn, depositor, stored).await?;
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

    /// Read half of the intra-block variant hard-delete: the `DepositRow`s it will
    /// remove, so the host can meter `Fuel::Delete` before the writes.
    pub async fn find_matching_paths(
        &self,
        contract_id: u64,
        base_path: &[u8],
        candidates: &[Vec<u8>],
    ) -> Result<Vec<DepositRow>> {
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
}
