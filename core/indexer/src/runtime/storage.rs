use anyhow::{Context, Result, anyhow};
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bon::Builder;
use futures_util::Stream;
#[cfg(test)]
use futures_util::TryStreamExt;
use libsql::Connection;
use regex::bytes::RegexBuilder;
use std::io::Read;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::{Condvar, Mutex as StdMutex};
use wit_component::{ComponentEncoder, WitPrinter};

use super::bundle_ownership::{BundleOwner, HostFailure};
#[cfg(test)]
use super::resource_diagnostics;
use super::storage_host::StorageHost;
use crate::database::storage_callbacks_v1::storage_callbacks;
use crate::protocol::storage_identity::SignerRecord;
use crate::protocol::v1::native_bootstrap::{self, BootstrapProgress};
use crate::protocol::v1::storage_contracts;
use crate::protocol::v1::storage_error::{ReadError, host_failure};
use crate::protocol::v1::storage_footprint::FootprintCache;
use crate::protocol::v1::storage_identity::{self, IdentityError};
use crate::protocol::v1::storage_keys::keys;
use crate::protocol::v1::storage_point::read_value;
use crate::protocol::v1::storage_rows::StorageRowCursor;
use crate::protocol::v1::storage_session;
use crate::protocol::v1::storage_state::{
    LiveRow, exists, live_subtree, tombstone_rows, write_value,
};
use crate::runtime::{ContractAddress, counter::Counter, ownership::ChildContext, stack::Stack};

#[cfg(test)]
mod variant_tests;

/// `block_entropy` recent-window size: a committed height older than this has
/// expired (so a stale draw falls out of the window and the contract can refund).
/// Bounds the lookup and forces prompt resolution. ~1 day on Bitcoin (144 blocks).
pub const BLOCK_ENTROPY_WINDOW: u64 = 144;

/// Why decoding stored contract bytes failed.
///
/// The split is load-bearing, not cosmetic: `Content` is a pure function of the
/// bytes, so every node reaches it identically and a publish carrying such bytes must
/// be REJECTED deterministically. `Infrastructure` is this node failing to do the
/// work, so it must propagate — recording it as a rejection would make one node
/// refuse a publish its peers accept, which is the silent mirror of a chain halt.
pub enum ComponentDecodeError {
    Content(anyhow::Error),
    Infrastructure(anyhow::Error),
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct BlockingGate {
    pub(crate) entered: AtomicBool,
    released: StdMutex<bool>,
    wake: Condvar,
}

#[cfg(test)]
impl BlockingGate {
    pub(super) fn block(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let mut released = self.released.lock().expect("blocking gate poisoned");
        while !*released {
            released = self.wake.wait(released).expect("blocking gate poisoned");
        }
    }

    pub(crate) fn release(&self) {
        *self.released.lock().expect("blocking gate poisoned") = true;
        self.wake.notify_all();
    }
}

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
    #[builder(default = Txid::from_byte_array([0; 32]))]
    pub txid: Txid,
}

#[derive(Builder, Clone)]
pub struct Storage {
    pub conn: Connection,
    #[builder(default = StorageHost::from(storage_callbacks(&conn)), setters(vis = "pub(crate)"))]
    pub(crate) host: StorageHost,
    #[builder(skip)]
    pub(super) ownership: Option<ChildContext>,
    #[builder(skip)]
    pub(super) bundle_owner: Option<BundleOwner>,
    #[builder(default = Counter::builder().build())]
    pub savepoint_counter: Counter,
    #[builder(default = Stack::builder().build())]
    pub savepoint_stack: Stack<u64>,
    #[cfg(test)]
    #[builder(skip)]
    pub(super) fail_rollback_once: Arc<AtomicBool>,
    #[cfg(test)]
    #[builder(skip)]
    pub(super) fail_outer_commit_before_once: Arc<AtomicBool>,
    #[cfg(test)]
    #[builder(skip)]
    pub(super) fail_outer_commit_after_once: Arc<AtomicBool>,
    #[cfg(test)]
    #[builder(skip)]
    pub(crate) decode_gate: Option<Arc<BlockingGate>>,
    #[builder(default = 1)]
    pub height: u64,
    pub tx_context: Option<TransactionContext>,
}

impl Storage {
    pub(crate) async fn native_bootstrap_progress(&self) -> Result<BootstrapProgress> {
        native_bootstrap::read_progress(self.host.bootstrap.clone()).await
    }

    pub(crate) async fn lookup_identity(&self, pubkey: &str) -> Result<Option<u64>> {
        self.host.identity.clone().0(pubkey.to_owned())
            .await
            .map_err(|error| anyhow!(error))
    }

    pub(crate) async fn ensure_identity(&self, pubkey: &str) -> Result<u64, IdentityError> {
        storage_identity::ensure_identity(self.host.identity.clone(), pubkey, self.height).await
    }

    pub(crate) async fn create_core_signer(&self) -> Result<u64, IdentityError> {
        storage_identity::create_core_signer(self.host.core.clone()).await
    }

    pub(crate) async fn identity_pubkey(&self, signer_id: u64) -> Result<String, IdentityError> {
        storage_identity::x_only_pubkey(self.host.identity.clone(), signer_id).await
    }

    pub(crate) async fn identity_bls_key(&self, signer_id: u64) -> Result<Option<Vec<u8>>> {
        self.host.identity.clone().5(signer_id)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub(crate) async fn write_identity_bls_key(&self, signer_id: u64, pubkey: &[u8]) -> Result<()> {
        self.host.identity.clone().6(signer_id, pubkey.to_vec(), self.height)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub(crate) async fn contract_signer(&self, contract_id: u64) -> Result<Option<u64>> {
        self.host.identity.clone().7(contract_id)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub(crate) async fn signer_entry(&self, signer_id: u64) -> Result<Option<SignerRecord>> {
        self.host.identity.clone().8(signer_id)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub(crate) async fn advance_nonce(
        &self,
        signer_id: u64,
        nonce: u64,
        height: u64,
    ) -> Result<u64, IdentityError> {
        storage_identity::advance_nonce(self.host.nonce.clone(), signer_id, nonce, height).await
    }

    pub async fn get(
        &self,
        max_value_bytes: u64,
        contract_id: u64,
        path: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(read_value(self.host.point.clone(), max_value_bytes, contract_id, path).await?)
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
        write_value(
            self.host.state.clone().0,
            (contract_id, self.height, self.effective_tx_id()),
            path,
            value,
            (depositor, deposited_gas),
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
    ) -> Result<impl Stream<Item = Result<LiveRow, ReadError>> + Send + 'static> {
        Ok(live_subtree(self.host.state.clone(), contract_id, path))
    }

    /// The write half of a delete: value-less-tombstone the given (already-metered)
    /// rows. Returns `(removed, freed_bytes)` — the footprint accumulator subtracts
    /// the freed bytes.
    pub async fn tombstone_rows(&self, contract_id: u64, rows: &[LiveRow]) -> Result<(bool, u64)> {
        Ok(tombstone_rows(
            self.host.state.clone().0,
            (contract_id, self.height, self.effective_tx_id()),
            rows,
        )
        .await?)
    }

    /// The eager per-depositor storage-deposit FLOOR cache (see [`FootprintCache`]).
    pub fn footprint(&self) -> FootprintCache {
        FootprintCache::new(self.host.footprint.clone())
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
        let affected = (self.host.history.0)(target_height)
            .await
            .map_err(host_failure)?;
        (self.host.history.1)(target_height)
            .await
            .map_err(host_failure)?;
        self.footprint().recompute(&affected).await?;
        Ok(())
    }

    pub async fn insert_contract_provenance(
        &self,
        contract_id: u64,
        author_signer_id: u64,
        provenance: &[u8],
    ) -> Result<()> {
        Ok(storage_contracts::insert_provenance(
            self.host.contracts.clone(),
            contract_id,
            author_signer_id,
            self.height,
            self.tx_context.as_ref().map(|context| context.tx_index),
            provenance,
        )
        .await?)
    }

    pub async fn contract_provenance_publisher(&self, contract_id: u64) -> Result<Option<u64>> {
        self.host.contracts.clone().6(contract_id)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub async fn exists(&self, contract_id: u64, path: &[u8]) -> Result<bool> {
        Ok(exists(self.host.state.clone(), contract_id, path).await?)
    }

    pub async fn contract_id(&self, contract_address: &ContractAddress) -> Result<Option<u64>> {
        self.host.contracts.clone().2((
            contract_address.name.clone(),
            contract_address.height,
            contract_address.tx_index,
        ))
        .await
        .map_err(|error| anyhow!(error))
    }

    pub async fn contract_address(&self, contract_id: u64) -> Result<Option<ContractAddress>> {
        Ok(self.host.contracts.clone().3(contract_id)
            .await
            .map_err(|error| anyhow!(error))?
            .map(|(name, height, tx_index)| ContractAddress {
                name,
                height,
                tx_index,
            }))
    }

    pub async fn contract_bytes(&self, contract_id: u64) -> Result<Option<Vec<u8>>> {
        self.host.contracts.clone().4(contract_id)
            .await
            .map_err(|error| anyhow!(error))
    }

    /// Plain accessor for callers that do not need the failure CLASS — the
    /// classification lives in [`decode_component_bytes`], which this delegates to
    /// so the decompression-bomb cap has exactly one definition.
    pub async fn component_bytes(&self, contract_id: u64) -> Result<Vec<u8>> {
        self.decode_component_bytes(contract_id)
            .await
            .map_err(|e| match e {
                ComponentDecodeError::Content(e) | ComponentDecodeError::Infrastructure(e) => e,
            })
    }

    /// Decode stored contract bytes, keeping content failures distinguishable from
    /// this node's own failures. See [`ComponentDecodeError`].
    pub async fn decode_component_bytes(
        &self,
        contract_id: u64,
    ) -> std::result::Result<Vec<u8>, ComponentDecodeError> {
        let compressed_bytes = self.stored_component_bytes(contract_id).await?;
        self.decode_stored_component_bytes(compressed_bytes).await
    }

    pub(crate) async fn stored_component_bytes(
        &self,
        contract_id: u64,
    ) -> std::result::Result<Vec<u8>, ComponentDecodeError> {
        self.contract_bytes(contract_id)
            .await
            .map_err(ComponentDecodeError::Infrastructure)?
            .ok_or_else(|| {
                ComponentDecodeError::Infrastructure(anyhow!(
                    "Contract not found when trying to load component"
                ))
            })
    }

    pub(crate) async fn decode_stored_component_bytes(
        &self,
        compressed_bytes: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, ComponentDecodeError> {
        // Split the join from the work: a JoinError is this node's task machinery
        // failing, everything inside is a property of the bytes.
        #[cfg(test)]
        let gate = self.decode_gate.clone();
        let encode = move || -> Result<Vec<u8>> {
            #[cfg(test)]
            let _trace =
                resource_diagnostics::scope("blocking_decode_entry", "blocking_decode_exit");
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.block();
            }
            // Cap decompressed size: a tiny on-chain brotli blob can otherwise
            // inflate without bound in memory on every node that loads the
            // contract (decompression bomb). 64 MiB is far above any legitimate
            // WASM component.
            const MAX_DECOMPRESSED: u64 = 64 * 1024 * 1024;
            let decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
            let mut module_bytes = Vec::new();
            decompressor
                .take(MAX_DECOMPRESSED + 1)
                .read_to_end(&mut module_bytes)?;
            if module_bytes.len() as u64 > MAX_DECOMPRESSED {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "decompressed contract component exceeds maximum size",
                )
                .into());
            }
            // Component encoding has a deep native call chain. Keep it on the
            // blocking thread to avoid adding it to the async worker's existing
            // stack depth during an otherwise valid paid operation.
            ComponentEncoder::default()
                .module(&module_bytes)?
                .validate(true)
                .encode()
        };
        let encoded = match (&self.ownership, &self.bundle_owner) {
            (Some(_), Some(_)) => Err(anyhow!("storage has conflicting ownership contexts")),
            (None, Some(owner)) => owner
                .run_blocking(encode)
                .await
                .map_err(|error| anyhow!(HostFailure::from(error))),
            (Some(owner), None) => owner.run_blocking(encode).await,
            (None, None) => tokio::task::spawn_blocking(encode)
                .await
                .map_err(anyhow::Error::from),
        }
        .map_err(ComponentDecodeError::Infrastructure)?
        .map_err(ComponentDecodeError::Content)?;

        Ok(encoded)
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
        Ok(storage_contracts::insert_contract(
            self.host.contracts.clone(),
            self.height,
            self.tx_context.as_ref().map(|context| context.tx_index),
            name,
            bytes,
        )
        .await?)
    }

    fn effective_tx_id(&self) -> Option<u64> {
        self.tx_context.as_ref().and_then(|c| c.tx_id)
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
        let row = storage_contracts::result_write(
            (
                self.height,
                self.effective_tx_id(),
                self.tx_context.as_ref().map(|context| context.input_index),
                self.tx_context.as_ref().map(|context| context.op_index),
            ),
            result_index,
            contract_id,
            func,
            gas,
            value,
            signer_id,
            payer_signer_id,
            status.as_str(),
        );
        self.host.contracts.clone().7(row)
            .await
            .map_err(|error| anyhow!(error))
    }

    pub async fn keys(
        &self,
        contract_id: u64,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Result<impl Stream<Item = Result<Vec<u8>, ReadError>> + Send + 'static> {
        Ok(keys(
            self.host.keys.clone(),
            contract_id,
            path,
            lo,
            hi,
            descending,
        ))
    }

    pub fn storage_rows(
        &self,
        contract_id: u64,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> StorageRowCursor {
        StorageRowCursor::new(
            self.host.rows.clone(),
            contract_id,
            path,
            lo,
            hi,
            descending,
        )
    }

    /// Canonical per-block entropy (the Bitcoin block hash) at `height`, within the
    /// recent window. `None` if `height` is beyond the block being executed (no
    /// entropy yet) or older than [`BLOCK_ENTROPY_WINDOW`] (expired). The canonical
    /// `blocks` table is the source, so it's reorg-correct without a cache.
    pub async fn block_entropy(&self, height: u64) -> Result<Option<Vec<u8>>> {
        if height > self.height || height + BLOCK_ENTROPY_WINDOW < self.height {
            return Ok(None);
        }
        (self.host.history.2)(height).await.map_err(host_failure)
    }

    /// Incrementally prune the finalized band `(w_prev, w]` through the node's
    /// pruning callback inside a savepoint, so the two DELETEs and the
    /// watermark upsert commit (or roll back) atomically through the same
    /// transaction bookkeeping as every other write. Returns rows deleted.
    pub async fn prune(&self, w_prev: u64, w: u64) -> Result<u64> {
        self.savepoint().await?;
        match (self.host.maintenance.0)(w_prev, w).await {
            Ok(deleted) => {
                self.commit().await?;
                Ok(deleted)
            }
            Err(e) => {
                self.rollback().await?;
                Err(host_failure(e))
            }
        }
    }

    /// Free pages currently on the SQLite freelist (the prune-vacuum throttle reads
    /// this to decide whether returning pages to the OS is worth it).
    pub async fn freelist_count(&self) -> Result<i64> {
        (self.host.maintenance.1)().await.map_err(host_failure)
    }

    /// Return up to `pages` freelist pages to the OS via `PRAGMA incremental_vacuum`.
    pub async fn incremental_vacuum(&self, pages: i64) -> Result<()> {
        (self.host.maintenance.2)(pages).await.map_err(host_failure)
    }

    pub async fn savepoint(&self) -> Result<()> {
        storage_session::savepoint(
            self.host.session.clone(),
            &self.savepoint_stack,
            &self.savepoint_counter,
        )
        .await
    }

    pub async fn commit(&self) -> Result<()> {
        if let Some(owner) = &self.bundle_owner {
            anyhow::ensure!(
                self.ownership.is_none(),
                "storage has conflicting ownership contexts"
            );
            owner
                .ensure_commit_authorized()
                .map_err(|error| anyhow!(HostFailure::from(error)))?;
        }
        if let Some(owner) = &self.ownership {
            owner.ensure_commit_authorized()?;
        }
        #[cfg(test)]
        let outer = self.savepoint_stack.peek().await == Some(0);
        #[cfg(test)]
        if outer
            && self
                .fail_outer_commit_before_once
                .swap(false, Ordering::SeqCst)
        {
            return Err(anyhow!("injected failure before outer commit"));
        }
        storage_session::commit(self.host.session.clone(), &self.savepoint_stack).await?;
        #[cfg(test)]
        if outer
            && self
                .fail_outer_commit_after_once
                .swap(false, Ordering::SeqCst)
        {
            return Err(anyhow!("injected failure after durable outer commit"));
        }
        Ok(())
    }

    pub async fn rollback_transaction(&self) -> Result<()> {
        #[cfg(test)]
        if self.fail_rollback_once.swap(false, Ordering::SeqCst) {
            return Err(anyhow!("injected rollback transaction failure"));
        }
        storage_session::rollback_transaction(self.host.session.clone(), &self.savepoint_stack)
            .await
    }

    pub async fn rollback(&self) -> Result<()> {
        storage_session::rollback(self.host.session.clone(), &self.savepoint_stack).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::new_connection;
    use crate::database::queries::{
        create_contract_signer, footprint_cache_get, get_meta_u64, insert_block,
        live_deposit_gas_sum, max_block_height, prune_contract_state, select_block_at_height,
        set_meta_u64,
    };
    use crate::protocol::v1::storage_error::ReadError;
    use crate::runtime::ExecutionError;
    use crate::test_utils::{new_mock_block_hash, new_test_db};
    use indexer_types::BlockRow;
    use libsql::Builder as DatabaseBuilder;
    use stdlib::KeyElement;

    #[tokio::test]
    async fn callback_failures_preserve_causes_and_release_savepoints() -> Result<()> {
        let database = DatabaseBuilder::new_local(":memory:").build().await?;
        let conn = database.connect()?;
        let storage = Storage::builder().conn(conn.clone()).build();

        // An uninitialized database forces real query failures with driver causes.
        let direct = anyhow::Error::from(select_block_at_height(&conn, 1).await.unwrap_err());
        let callback = storage.block_entropy(1).await.unwrap_err();
        assert_eq!(direct.to_string(), callback.to_string());
        assert_eq!(format!("{direct:#}"), format!("{callback:#}"));
        assert!(matches!(
            ExecutionError::from(callback),
            ExecutionError::NonDeterministic(_)
        ));

        let direct = anyhow::Error::from(prune_contract_state(&conn, 0, 1).await.unwrap_err());
        let callback = storage.prune(0, 1).await.unwrap_err();
        assert_eq!(format!("{direct:#}"), format!("{callback:#}"));
        assert!(matches!(
            ExecutionError::from(callback),
            ExecutionError::NonDeterministic(_)
        ));
        assert!(conn.is_autocommit());
        assert!(storage.savepoint_stack.is_empty().await);

        let error = storage.rollback_with_footprint(0).await.unwrap_err();
        assert!(matches!(
            ExecutionError::from(error),
            ExecutionError::NonDeterministic(_)
        ));
        assert!(conn.is_autocommit());
        assert!(storage.savepoint_stack.is_empty().await);
        assert!(storage.freelist_count().await? >= 0);
        storage.incremental_vacuum(0).await?;
        Ok(())
    }

    #[tokio::test]
    async fn row_cursor_preserves_versions_and_releases_its_snapshot() -> Result<()> {
        for exhaust_budget in [false, true] {
            let (_reader, writer, (temp, db_name)) = new_test_db().await?;
            let conn = writer.connection();
            for height in [1, 2] {
                insert_block(
                    &conn,
                    BlockRow::builder()
                        .height(height)
                        .hash(new_mock_block_hash(height as u32))
                        .build(),
                )
                .await?;
            }
            let mut storage = Storage::builder().conn(conn).build();
            let view = Storage::builder()
                .conn(new_connection(temp.path(), &db_name).await?)
                .build();
            let root = "row-snapshot".to_string().encode();
            let path = |member: u64| [root.clone(), member.encode()].concat();
            for member in 0..3u64 {
                storage
                    .set(1, &path(member), &[member as u8], None, None)
                    .await?;
            }
            let mut cursor = view.storage_rows(1, root.clone(), None, None, false);
            assert_eq!(cursor.next(u64::MAX).await?, Some((0u64.encode(), vec![0])));

            storage.height = 2;
            storage.savepoint().await?;
            storage.set(1, &path(1), &[7], None, None).await?;
            // Same-height replacement changes the rowid as well as the stored size.
            storage.set(1, &path(1), &[9; 128], None, None).await?;
            storage.set(2, &path(1), &[42], None, None).await?;
            let deleted = storage
                .find_live_subtree(1, &path(2))
                .await?
                .try_collect::<Vec<_>>()
                .await?;
            storage.tombstone_rows(1, &deleted).await?;
            storage.commit().await?;

            if exhaust_budget {
                assert!(matches!(
                    cursor.next(0).await,
                    Err(ReadError::ValueTooLarge)
                ));
            } else {
                // Value lookups must share the metadata cursor's pre-update snapshot.
                for member in 1..3u64 {
                    assert_eq!(
                        cursor.next(u64::MAX).await?,
                        Some((member.encode(), vec![member as u8]))
                    );
                }
            }
            assert!(cursor.next(u64::MAX).await?.is_none());

            // Keep the exhausted object alive: completion/error must release its pin.
            let mut current = view.storage_rows(1, root.clone(), None, None, false);
            assert_eq!(
                current.next(u64::MAX).await?,
                Some((0u64.encode(), vec![0]))
            );
            assert_eq!(
                current.next(u64::MAX).await?,
                Some((1u64.encode(), vec![9; 128]))
            );
            assert!(current.next(u64::MAX).await?.is_none());

            storage.rollback_with_footprint(1).await?;
            let mut restored = view.storage_rows(1, root.clone(), None, None, false);
            for member in 0..3u64 {
                assert_eq!(
                    restored.next(u64::MAX).await?,
                    Some((member.encode(), vec![member as u8]))
                );
            }
            assert!(restored.next(u64::MAX).await?.is_none());
        }
        Ok(())
    }

    // The savepoint must cover plain `conn.execute` writes issued through a
    // CLONE of the connection, not just those made through `Storage`.
    //
    // The reactor relies on this: `db_conn()` hands out a clone, and
    // `handle_block` writes the decided-batch record through it inside the
    // block's savepoint so a failed execution cannot leave a consensus record
    // behind. That is a property of libsql's `BEGIN TRANSACTION` on a shared
    // connection, invisible at the call site — pinned here so it fails loudly
    // if the connection sharing ever changes.
    #[tokio::test]
    async fn savepoint_covers_writes_through_a_cloned_connection() -> Result<()> {
        use crate::database::queries::{insert_batch, select_batch};

        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();
        let storage = Storage::builder().conn(conn.clone()).build();

        storage.savepoint().await?;
        insert_batch(&conn.clone(), 7, 100, "deadbeef", b"cert", true).await?;
        assert!(
            select_batch(&conn, 7).await?.is_some(),
            "the write must be visible inside its own transaction"
        );
        storage.rollback().await?;

        assert!(
            select_batch(&conn, 7).await?.is_none(),
            "rolling back the block transaction must discard the decision record too — \
             otherwise a node keeps a consensus record for a height it never executed"
        );
        Ok(())
    }

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
        let rows: Vec<_> = storage
            .find_live_subtree(1, &path("b"))
            .await?
            .try_collect()
            .await?;
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

    // The `/view` staleness diagnostic's discriminator: `max_block_height` on a
    // pooled read connection must report the LOWER tip when that connection is pinned
    // to an older snapshot — that's the `visible < committed` the WARN fires on — and
    // must recover to the committed tip once the pin is released. Proves the detector
    // can actually see a stale `/view` connection (vs. a fresh one that matches).
    #[tokio::test]
    async fn max_block_height_reports_stale_view_connection() -> Result<()> {
        let (_reader, writer, (temp, db_name)) = new_test_db().await?;
        let writer_conn = writer.connection();
        // A second physical connection to the same WAL db — a pooled `/view` connection.
        let view_conn = new_connection(temp.path(), &db_name).await?;
        let view = Storage::builder().conn(view_conn.clone()).build();

        let block = |h: u64| {
            BlockRow::builder()
                .height(h)
                .hash(new_mock_block_hash(h as u32))
                .build()
        };
        // Empty table → `None`; the diagnostic treats a `None` view tip as stale when
        // the committed tip is `Some` (a view pinned before any block was visible).
        assert_eq!(max_block_height(&view_conn).await?, None);
        insert_block(&writer_conn, block(1)).await?;

        // The view opens a transaction and reads — pinning its WAL snapshot at tip 1.
        view.savepoint().await?;
        assert_eq!(max_block_height(&view_conn).await?, Some(1));

        // The reactor (writer) commits block 2 (autocommit).
        insert_block(&writer_conn, block(2)).await?;

        // Pinned to its snapshot, the view still sees tip 1 while the committed tip is
        // 2 — exactly the `visible(1) < committed(2)` the diagnostic WARNs on.
        assert_eq!(
            max_block_height(&view_conn).await?,
            Some(1),
            "a pinned view connection must report its stale (lower) tip"
        );
        assert_eq!(max_block_height(&writer_conn).await?, Some(2));

        // After the recycle reset, a fresh read sees the committed tip — no stale WARN.
        view.rollback_transaction().await?;
        assert_eq!(
            max_block_height(&view_conn).await?,
            Some(2),
            "after the reset, the view connection must catch up to the committed tip"
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
