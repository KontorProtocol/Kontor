use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use futures_util::future::OptionFuture;
use indexer_types::deserialize;
use serde::{Deserialize, Serialize};
use stdlib::CheckedArithmetics;
use wasmtime::AsContext;
use wasmtime::component::{Accessor, Resource};

use crate::database::native_contracts::is_deposit_exempt;
use crate::database::queries::DepositRow;
use crate::database::types::CORE_SIGNER_ID;

use super::{
    Decimal, ExecutionError, Runtime,
    fuel::Fuel,
    wit::{HasContractId, Keys},
};

/// Storage-deposit rate, in GAS per stored byte (path + value). Placeholder
/// (`D`); a slice of the op's gas budget gets LOCKED rather than burned. Small
/// enough to leave ample headroom under typical op gas limits, priced into the
/// token via the runtime's `gas_to_token` rate at write time.
const DEPOSIT_GAS_PER_BYTE: u64 = 1;

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
        // Meter BEFORE the writes (like `_delete`): read the matching rows, charge
        // `Fuel::Delete`, THEN hard-delete. The intra-block cleanup vanishes rows
        // that were counted on write, so subtract the freed bytes from the footprint
        // too, or the net delta over-counts. (3b also refunds each row's setter from
        // the `depositor`/`deposited_amount` these rows carry.)
        let rows = self
            .storage
            .find_matching_paths(contract_id, &base_path, &candidates)
            .await?;
        let freed: u64 = rows.iter().map(|r| r.path.len() as u64 + r.size).sum();
        Fuel::Delete(rows.len() as u64, freed)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let deleted = self
            .storage
            .hard_delete_matching_paths(contract_id, &base_path, &candidates)
            .await?;
        self.record_row_refunds(&rows).await?;
        Ok(deleted)
    }

    /// Record refunds for a set of freed/displaced rows into the op's deposit
    /// accumulator — each row's recorded `deposited_amount` back to its
    /// `depositor`, batched per setter. Rows with no depositor (Core/system) are
    /// skipped.
    async fn record_row_refunds(&self, rows: &[DepositRow]) -> Result<()> {
        for r in rows {
            if let (Some(setter), Some(amount)) = (r.depositor, r.deposited_amount.as_deref()) {
                self.deposit
                    .record_refund(setter, Decimal::from(amount))
                    .await?;
            }
        }
        Ok(())
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
        let rows = self.storage.find_live_subtree(contract_id, &path).await?;
        let bytes: u64 = rows.iter().map(|r| r.path.len() as u64 + r.size).sum();
        Fuel::Delete(rows.len() as u64, bytes)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let (removed, _freed) = self.storage.tombstone_rows(contract_id, &rows).await?;
        self.record_row_refunds(&rows).await?;
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
        // Stamp the op's payer as this row's depositor (the refund target), iff a
        // deposit is actually settled for this op. Skipped when:
        //   - the contract is the deposit-denominating token (recursion exemption);
        //   - there's no payer (op_payer 0); or
        //   - the payer is CORE — core-signed ops bypass hold/release/settle
        //     (`!signer.is_core()`), so a deposit recorded here would never be
        //     vault-backed and would drain the vault when the row is later freed.
        let depositor = match self.op_payer.load(Ordering::Relaxed) {
            id if id == 0 || id == CORE_SIGNER_ID || is_deposit_exempt(contract_id) => None,
            id => Some(id),
        };
        // The deposit for this row is a slice of GAS — `(path + value) bytes ×
        // DEPOSIT_GAS_PER_BYTE` — charged against the op's fuel budget here, so an
        // unaffordable deposit trips the out-of-gas path and the op deterministically
        // reverts (the per-op cap = the gas limit). Only non-exempt rows with a
        // payer carry one. The value stored for refund is that gas slice priced via
        // `gas_to_token` (refunded verbatim to the setter when the row is freed).
        let deposited_amount = if depositor.is_some() {
            let deposit_gas = (path.len() + bs.len()) as u64 * DEPOSIT_GAS_PER_BYTE;
            Fuel::Deposit(deposit_gas * self.gas_to_fuel_multiplier)
                .consume(accessor, self.gauge.as_ref())
                .await
                .map_err(|_| {
                    ExecutionError::Deterministic(anyhow!(
                        "storage deposit exceeds the op's gas budget"
                    ))
                })?;
            self.deposit.record_charge(deposit_gas).await?;
            // On an OVERWRITE, refund the displaced setter their recorded (token)
            // amount (read the old live row — never the old value). Gated inside
            // the deposited-write branch: an exempt/core write has no depositor and
            // never overwrites a deposited row, so it skips this per-write DB read
            // entirely (that's the common case — the whole token ledger + all core
            // writes — so the read no longer fires on most writes).
            if let Some(old) = self.storage.latest_deposit_row(contract_id, &path).await?
                && let (Some(setter), Some(amount)) =
                    (old.depositor, old.deposited_amount.as_deref())
            {
                self.deposit
                    .record_refund(setter, Decimal::from(amount))
                    .await?;
            }
            Some(
                Decimal::try_from(deposit_gas)?
                    .mul(self.gas_to_token_multiplier)?
                    .to_string(),
            )
        } else {
            None
        };
        self.storage
            .set(contract_id, &path, bs, depositor, deposited_amount)
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
