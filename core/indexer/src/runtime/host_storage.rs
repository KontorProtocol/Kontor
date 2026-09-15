use anyhow::{Result, anyhow};
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use wasmtime::component::{Accessor, Resource};
use wasmtime::{AsContext, Trap};

use crate::database::native_contracts::is_deposit_exempt;
use crate::database::queries::{Error as StorageError, LiveRow};
use crate::database::types::CORE_SIGNER_ID;

use super::{
    ExecutionError, Runtime,
    fuel::Fuel,
    wit::{HasContractId, Keys, StorageRows},
};

/// The storage trust boundary: reject a non-well-formed guest path ONCE, here,
/// before it reaches any subtree/keys/matching parse or gets persisted. This is
/// the single validation choke-point the old string scheme had at
/// `DotPathBuf::push`, relocated to the host now that the guest sends raw codec
/// bytes (`list<u8>`). Walking the elements once guarantees every downstream op
/// can rely on well-formedness, and — crucially — a malformed path can never be
/// STORED (which would later crash a `keys()` scan into a non-deterministic
/// error). An empty path is the valid zero-element key (whole-keyspace), so it
/// passes. The rejection is a DETERMINISTIC contract error (depends only on the
/// input bytes, identical on every node), NOT a host/infrastructure error —
/// otherwise it would be misclassified as non-deterministic (see `handle_call`).
fn validate_path(path: &[u8]) -> Result<()> {
    let mut rest = path;
    while !rest.is_empty() {
        match stdlib::next_element(rest) {
            Ok((_, r)) => rest = r,
            Err(_) => {
                return Err(ExecutionError::Deterministic(anyhow!(
                    "malformed storage path: not well-formed codec bytes"
                ))
                .into());
            }
        }
    }
    Ok(())
}

fn meter_path<T>(accessor: &Accessor<T, Runtime>, path: &[u8]) -> Result<()> {
    Fuel::Path(path.len() as u64).consume(accessor)?;
    validate_path(path)
}

/// Keep only paid-for metadata; exhausting discovery cannot mutate state. The
/// stream is dropped before callers write, so no SQL cursor survives mutation.
async fn collect_delete_rows<T>(
    accessor: &Accessor<T, Runtime>,
    rows: impl Stream<Item = Result<LiveRow, StorageError>>,
) -> Result<Vec<LiveRow>> {
    let mut rows = Box::pin(rows);
    let mut paid = Vec::new();
    loop {
        Fuel::StorageScan.consume(accessor)?;
        let Some(row) = rows.next().await.transpose()? else {
            return Ok(paid);
        };
        Fuel::Delete(1, (row.path.len() as u64).saturating_add(row.size)).consume(accessor)?;
        paid.push(row);
    }
}

// The guest selects the slot type. Valid writes through another setter can fail
// this decode, so this is a contract failure, not evidence of database corruption.
pub(crate) fn decode_storage_value<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|error| {
        ExecutionError::Deterministic(anyhow!("invalid storage value: {error}"))
    })?;
    if !rest.is_empty() {
        return Err(ExecutionError::Deterministic(anyhow!("trailing storage bytes")).into());
    }
    Ok(value)
}

impl Runtime {
    pub(crate) async fn _get_primitive<S, T: HasContractId, R: for<'de> Deserialize<'de>>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: Vec<u8>,
    ) -> Result<Option<R>> {
        Fuel::StorageRead.consume(accessor)?;
        meter_path(accessor, &path)?;
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        // Apply the byte price after the base/path charges, before copying the
        // stored blob out of SQL. Budget exhaustion must retain its Wasm trap type.
        let max_value_bytes = fuel / Fuel::Get(1).cost();
        let raw = self
            .storage
            .get(max_value_bytes, contract_id, &path)
            .await
            .map_err(|error| {
                if matches!(
                    error.downcast_ref::<StorageError>(),
                    Some(StorageError::ValueTooLarge)
                ) {
                    Trap::OutOfFuel.into()
                } else {
                    error
                }
            })?;
        let Some(bytes) = raw else { return Ok(None) };
        Fuel::Get(bytes.len()).consume(accessor)?;
        Ok(Some(decode_storage_value(&bytes)?))
    }

    pub(crate) async fn _get_keys<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Result<Resource<Keys>> {
        Fuel::GetKeys.consume(accessor)?;
        let bound_bytes = lo
            .as_ref()
            .map_or(0, Vec::len)
            .saturating_add(hi.as_ref().map_or(0, Vec::len));
        Fuel::Path(bound_bytes as u64).consume(accessor)?;
        meter_path(accessor, &path)?;
        // `lo`/`hi` are NOT validated as paths: they are synthetic byte-comparison
        // bounds (`cs.path >= path ++ lo`, `cs.path < path ++ hi`), never decoded. An
        // EXCLUSIVE bound is `sort_upper_bound`, which deliberately is
        // NOT well-formed codec bytes, so `validate_path` would reject a legitimate
        // `range(..=hi)`. Only real stored rows (always well-formed) are decoded, so a
        // malformed bound is harmless (an empty bound is normalized to unbounded in
        // `scan_bounds`, keeping the child-only `> path` invariant).
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.get_contract_id();
        let stream = Box::pin(
            self.storage
                .keys(contract_id, path, lo, hi, descending)
                .await?,
        );
        Ok(table.push(Keys { stream })?)
    }

    /// Open the shared scalar/covering row cursor. `_next_storage_row` meters
    /// stored bytes before decoding through the same helper as point reads.
    pub(crate) async fn _get_storage_rows<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        lo: Option<Vec<u8>>,
        hi: Option<Vec<u8>>,
        descending: bool,
    ) -> Result<Resource<StorageRows>> {
        Fuel::GetKeys.consume(accessor)?;
        let bound_bytes = lo
            .as_ref()
            .map_or(0, Vec::len)
            .saturating_add(hi.as_ref().map_or(0, Vec::len));
        Fuel::Path(bound_bytes as u64).consume(accessor)?;
        meter_path(accessor, &path)?;
        // `lo`/`hi` are byte-comparison bounds, not paths — see `_get_keys` for why they
        // are not validated as paths: the exclusive sentinel is not a stored element.
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.get_contract_id();
        let stream = Box::pin(
            self.storage
                .storage_rows(contract_id, path, lo, hi, descending)
                .await?,
        );
        Ok(table.push(StorageRows { stream })?)
    }

    pub(crate) async fn _exists<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
    ) -> Result<bool> {
        Fuel::Exists.consume(accessor)?;
        meter_path(accessor, &path)?;
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage.exists(_self.get_contract_id(), &path).await
    }

    pub(crate) async fn _extend_path_with_match<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<Option<u32>> {
        Fuel::ExtendPathWithMatch(candidates.len() as u64).consume(accessor)?;
        let candidate_bytes = candidates.iter().fold(0_u64, |bytes, candidate| {
            bytes.saturating_add(candidate.len() as u64)
        });
        Fuel::Path(candidate_bytes).consume(accessor)?;
        meter_path(accessor, &path)?;
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        self.storage
            .extend_path_with_match(_self.get_contract_id(), &path, &candidates)
            .await
    }

    pub(crate) async fn _delete_matching_paths<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        base_path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<u64> {
        Fuel::StorageDelete.consume(accessor)?;
        Fuel::ExtendPathWithMatch(candidates.len() as u64).consume(accessor)?;
        let candidate_bytes = candidates.iter().fold(0_u64, |bytes, candidate| {
            bytes.saturating_add(candidate.len() as u64)
        });
        Fuel::Path(candidate_bytes).consume(accessor)?;
        meter_path(accessor, &base_path)?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        // Read → meter → write: charge in proportion to the rows actually removed,
        // not a flat per-candidate fee. Freeing a row also subtracts its deposit from
        // its setter's footprint cache (the rows were already read for metering).
        let rows = self
            .storage
            .find_matching_paths(contract_id, &base_path, &candidates)
            .await?;
        let rows = collect_delete_rows(accessor, rows).await?;
        self.storage.footprint().on_free(&rows).await?;
        let deleted = self.storage.hard_delete_rows(contract_id, &rows).await?;
        // A hard delete (unlike a tombstone) can revive an older same-path version —
        // re-add its deposit to the footprint cache, else the floor under-counts.
        self.storage
            .footprint()
            .on_revive(contract_id, &rows)
            .await?;
        Ok(deleted)
    }

    /// Delete a key by tombstoning its WHOLE subtree (the node + every live
    /// descendant — a struct/map value persists under child paths). Metered by the
    /// subtree size. Discovery consumes fuel incrementally; all rows must be
    /// paid for before mutation. Returns true if a live value was removed.
    pub(crate) async fn _delete<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: Vec<u8>,
    ) -> Result<bool> {
        Fuel::StorageDelete.consume(accessor)?;
        meter_path(accessor, &path)?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        // Read → meter → write. A flat `Set(0)` charged the same whether the
        // subtree held one row or thousands; meter by the rows/bytes tombstoned.
        let rows = self.storage.find_live_subtree(contract_id, &path).await?;
        let rows = collect_delete_rows(accessor, rows).await?;
        self.storage.footprint().on_free(&rows).await?;
        let (removed, _freed) = self.storage.tombstone_rows(contract_id, &rows).await?;
        Ok(removed)
    }

    pub(crate) async fn _set_primitive<S, T: HasContractId, V: Serialize>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        value: V,
    ) -> Result<()> {
        Fuel::StorageWrite.consume(accessor)?;
        meter_path(accessor, &path)?;
        let contract_id = self.table.lock().await.get(&resource)?.get_contract_id();
        let bs = &indexer_types::serialize(&value)?;
        Fuel::Set(bs.len() as u64).consume(accessor)?;
        // Stamp the op's payer (from the current call frame) as this row's
        // depositor — who collateralizes it via the storage-deposit FLOOR. The
        // frame's `depositor` is `None` for non-settling ops (core-signed / no-payer
        // — set at prepare_call's stamp gate, which matches the settle gate), and
        // the token (deposit-denominating ledger) is exempt by contract id
        // (recursion). The host derives each holder's footprint by summing the live
        // rows they're the depositor of, so the floor moves with the row: a later
        // overwrite (new depositor) or delete drops it from the old setter's sum.
        let exempt = is_deposit_exempt(contract_id);
        let frame_depositor = self.stack.peek().await.and_then(|f| f.depositor);
        let depositor = match frame_depositor {
            Some(id) if id != CORE_SIGNER_ID && !exempt => Some(id),
            _ => None,
        };
        // The deposit for this row is a slice of GAS — `(path + value) bytes ×
        // storage rate` — charged against the op's fuel budget here, so an
        // unaffordable growth trips the out-of-gas path and the op deterministically
        // reverts (the per-op cap = the gas limit). The reservation is RETURNED at
        // settle (only execution burns), so it bounds per-op growth without being a
        // cost — the collateral is the floor, not a moved token. The per-row
        // `deposited_gas` records the deposit (integer gas) for the footprint cache;
        // the token value is derived (× gas→token) only at the floor read.
        let deposited_gas = if depositor.is_some() {
            let deposit_gas = self
                .pricing
                .storage_deposit_gas((path.len() + bs.len()) as u64)
                .ok_or_else(|| {
                    ExecutionError::Deterministic(anyhow!("storage reservation overflow"))
                })?;
            let deposit_fuel = deposit_gas
                .checked_mul(self.gas_to_fuel_multiplier)
                .ok_or_else(|| {
                    ExecutionError::Deterministic(anyhow!("storage reservation overflow"))
                })?;
            Fuel::Deposit(deposit_fuel).consume(accessor).map_err(|_| {
                ExecutionError::Deterministic(anyhow!(
                    "storage deposit exceeds the op's gas budget"
                ))
            })?;
            self.deposit.record_charge(deposit_gas).await;
            if let Some(gauge) = &self.gauge {
                gauge.record_deposit(deposit_fuel)?;
            }
            Some(deposit_gas)
        } else {
            None
        };
        // Maintain the eager footprint cache BEFORE the write: subtract the row this
        // overwrites (read while it's still live) from its setter, add the new row to
        // its depositor. Same connection/savepoint as the write, so it rolls back with
        // the op. Skipped for deposit-exempt contracts (the token ledger) — they never
        // carry a depositor, so neither the new row nor any row they overwrite can
        // affect a floor, and this avoids a displaced-row read on the hottest write.
        if !exempt {
            self.storage
                .footprint()
                .on_set(contract_id, &path, depositor, deposited_gas)
                .await?;
        }
        self.storage
            .set(contract_id, &path, bs, depositor, deposited_gas)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stdlib::KeyElement;

    proptest! {
        // The storage trust boundary must never PANIC on arbitrary guest bytes —
        // it returns Ok (well-formed, including empty) or a deterministic Err
        // (malformed). This is the regression guard for the whole class of bugs
        // that came from the host trusting raw codec bytes.
        #[test]
        fn validate_path_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = validate_path(&bytes);
        }

        // Anything built from real codec elements is well-formed and passes.
        #[test]
        fn well_formed_path_always_validates(
            s in any::<String>(),
            n in any::<u64>(),
            b in any::<bool>(),
        ) {
            let mut p = Vec::new();
            s.encode_to(&mut p);
            n.encode_to(&mut p);
            b.encode_to(&mut p);
            prop_assert!(validate_path(&p).is_ok());
        }
    }

    #[test]
    fn empty_path_is_valid() {
        // The zero-element key (contract root / whole-keyspace) is well-formed.
        assert!(validate_path(&[]).is_ok());
    }

    #[test]
    fn malformed_paths_are_rejected() {
        // String tag (0x02) with no terminator.
        assert!(validate_path(&[0x02, b'a', b'b']).is_err());
        // Int tag claiming 8 bytes but truncated.
        assert!(validate_path(&[0x1C, 0x00]).is_err());
        // A valid element followed by a dangling tag.
        let mut p = "ok".to_string().encode();
        p.push(0x02);
        assert!(validate_path(&p).is_err());
    }
}
