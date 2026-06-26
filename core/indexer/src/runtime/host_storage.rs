
use anyhow::{Result, anyhow};
use futures_util::future::OptionFuture;
use indexer_types::deserialize;
use serde::{Deserialize, Serialize};
use wasmtime::AsContext;
use wasmtime::component::{Accessor, Resource};

use crate::database::native_contracts::is_deposit_exempt;
use crate::database::types::CORE_SIGNER_ID;

use super::{
    ExecutionError, Runtime,
    fuel::Fuel,
    wit::{HasContractId, Keys},
};

/// Default storage-deposit rate `D`, in GAS per stored byte (path + value). It
/// bounds per-op storage growth (metered as fuel against the gas limit) and sets
/// the FLOOR a holder must keep (`footprint_bytes × D`, priced to token via
/// `gas_to_token`). GAS, not token, is the unit because growth is metered as fuel;
/// the reservation is RETURNED at settle (only execution burns), so `D` is a
/// collateral rate, not a fee. Routed through [`Runtime::deposit_rate`] so it can
/// become per-contract / governance-tunable later. (A sub-gas-per-byte `D` isn't
/// expressible as an integer; tune finer via `gas_to_token`.)
const DEFAULT_DEPOSIT_GAS_PER_BYTE: u64 = 1;

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

impl Runtime {
    /// The storage-deposit rate (GAS per byte) charged to writes of `contract_id`.
    /// Uniform today; this is the single seam to make `D` per-contract or
    /// governance-set later — every charge site routes through it.
    pub(crate) fn deposit_rate(&self, _contract_id: u64) -> u64 {
        DEFAULT_DEPOSIT_GAS_PER_BYTE
    }

    pub(crate) async fn _get_primitive<S, T: HasContractId, R: for<'de> Deserialize<'de>>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: Vec<u8>,
    ) -> Result<Option<R>> {
        validate_path(&path)?;
        let fuel = accessor.with(|access| access.as_context().get_fuel())?;
        let table = self.table.lock().await;
        let contract_id = table.get(&self_)?.get_contract_id();
        let raw = self.storage.get(fuel, contract_id, &path).await?;
        if raw.is_none() {
            tracing::debug!(
                "storage read returned None: contract_id={contract_id} path={path:?} fuel={fuel} height={}",
                self.storage.height
            );
        }
        OptionFuture::from(raw.map(async |bs| {
            Fuel::Get(bs.len())
                .consume(accessor, self.gauge.as_ref())
                .await?;
            deserialize(&bs)
        }))
        .await
        .transpose()
    }

    pub(crate) async fn _get_keys<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        after: Option<Vec<u8>>,
    ) -> Result<Resource<Keys>> {
        validate_path(&path)?;
        if let Some(after) = &after {
            validate_path(after)?;
        }
        let mut table = self.table.lock().await;
        let contract_id = table.get(&resource)?.get_contract_id();
        Fuel::GetKeys.consume(accessor, self.gauge.as_ref()).await?;
        let stream = Box::pin(self.storage.keys(contract_id, path, after).await?);
        Ok(table.push(Keys { stream })?)
    }

    pub(crate) async fn _exists<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
    ) -> Result<bool> {
        validate_path(&path)?;
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        Fuel::Exists.consume(accessor, self.gauge.as_ref()).await?;
        self.storage.exists(_self.get_contract_id(), &path).await
    }

    pub(crate) async fn _extend_path_with_match<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        resource: Resource<T>,
        path: Vec<u8>,
        candidates: Vec<Vec<u8>>,
    ) -> Result<Option<u32>> {
        validate_path(&path)?;
        let table = self.table.lock().await;
        let _self = table.get(&resource)?;
        Fuel::ExtendPathWithMatch(candidates.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
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
        validate_path(&base_path)?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        // Read → meter → write: charge in proportion to the rows actually removed,
        // not a flat per-candidate fee. Freeing a row also subtracts its deposit from
        // its setter's footprint cache (the rows were already read for metering).
        let rows = self
            .storage
            .find_matching_paths(contract_id, &base_path, &candidates)
            .await?;
        let bytes: u64 = rows.iter().map(|r| r.path.len() as u64 + r.size).sum();
        Fuel::Delete(rows.len() as u64, bytes)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage.footprint_on_free(&rows).await?;
        self.storage
            .hard_delete_matching_paths(contract_id, &base_path, &candidates)
            .await
    }

    /// Delete a key by tombstoning its WHOLE subtree (the node + every live
    /// descendant — a struct/map value persists under child paths). Metered by the
    /// subtree size: find the live rows first (a read), charge `Fuel::Delete` for
    /// them, THEN write the tombstones — so an underfunded delete traps after only
    /// the cheap read, never forcing the O(rows) writes. Returns true if a live
    /// value was removed.
    pub(crate) async fn _delete<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: Vec<u8>,
    ) -> Result<bool> {
        validate_path(&path)?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        // Read → meter → write. A flat `Set(0)` charged the same whether the
        // subtree held one row or thousands; meter by the rows/bytes tombstoned.
        let rows = self.storage.find_live_subtree(contract_id, &path).await?;
        let bytes: u64 = rows.iter().map(|r| r.path.len() as u64 + r.size).sum();
        Fuel::Delete(rows.len() as u64, bytes)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        self.storage.footprint_on_free(&rows).await?;
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
        validate_path(&path)?;
        let contract_id = self.table.lock().await.get(&resource)?.get_contract_id();
        Fuel::Path(path.clone())
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let bs = &indexer_types::serialize(&value)?;
        Fuel::Set(bs.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        // Stamp the op's payer (from the current call frame) as this row's
        // depositor — who collateralizes it via the storage-deposit FLOOR. The
        // frame's `depositor` is `None` for non-settling ops (core-signed / no-payer
        // — set at prepare_call's stamp gate, which matches the settle gate), and
        // the token (deposit-denominating ledger) is exempt by contract id
        // (recursion). The host derives each holder's footprint by summing the live
        // rows they're the depositor of, so the floor moves with the row: a later
        // overwrite (new depositor) or delete drops it from the old setter's sum.
        let frame_depositor = self.stack.peek().await.and_then(|f| f.depositor);
        let depositor = match frame_depositor {
            Some(id) if id != CORE_SIGNER_ID && !is_deposit_exempt(contract_id) => Some(id),
            _ => None,
        };
        // The deposit for this row is a slice of GAS — `(path + value) bytes ×
        // deposit_rate(contract)` — charged against the op's fuel budget here, so an
        // unaffordable growth trips the out-of-gas path and the op deterministically
        // reverts (the per-op cap = the gas limit). The reservation is RETURNED at
        // settle (only execution burns), so it bounds per-op growth without being a
        // cost — the collateral is the floor, not a moved token. The per-row
        // `deposited_gas` records the deposit (integer gas) for the footprint cache;
        // the token value is derived (× gas→token) only at the floor read.
        let deposited_gas = if depositor.is_some() {
            let deposit_gas = (path.len() + bs.len()) as u64 * self.deposit_rate(contract_id);
            Fuel::Deposit(deposit_gas * self.gas_to_fuel_multiplier)
                .consume(accessor, self.gauge.as_ref())
                .await
                .map_err(|_| {
                    ExecutionError::Deterministic(anyhow!(
                        "storage deposit exceeds the op's gas budget"
                    ))
                })?;
            self.deposit.record_charge(deposit_gas).await;
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
        if !is_deposit_exempt(contract_id) {
            self.storage
                .footprint_on_set(contract_id, &path, depositor, deposited_gas)
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
