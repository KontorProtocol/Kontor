use anyhow::{Result, anyhow};
use futures_util::future::OptionFuture;
use indexer_types::deserialize;
use serde::{Deserialize, Serialize};
use wasmtime::AsContext;
use wasmtime::component::{Accessor, Resource};

use super::{
    ExecutionError, Runtime,
    fuel::Fuel,
    wit::{HasContractId, Keys},
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
        Fuel::DeleteMatchingPaths(candidates.len() as u64)
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        self.storage
            .delete_matching_paths(contract_id, &base_path, &candidates)
            .await
    }

    /// Tombstone a single path. Metered like a write (it appends a deleted
    /// version row). Returns true if a live value was removed.
    pub(crate) async fn _delete<S, T: HasContractId>(
        &self,
        accessor: &Accessor<S, Self>,
        self_: Resource<T>,
        path: Vec<u8>,
    ) -> Result<bool> {
        validate_path(&path)?;
        Fuel::Set(0).consume(accessor, self.gauge.as_ref()).await?;
        let contract_id = self.table.lock().await.get(&self_)?.get_contract_id();
        let (removed, freed) = self.storage.delete(contract_id, &path).await?;
        self.footprint.record_delta(-(freed as i64)).await;
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
        // Net footprint delta for the op's accumulator. A new key adds its whole
        // row (path + value); an overwrite keeps the same path, so only the value
        // length changes (new − old). One size-only point-read of the live value
        // (see `latest_size`) distinguishes the two and supplies the old length.
        let delta = match self.storage.latest_size(contract_id, &path).await? {
            None => (path.len() + bs.len()) as i64,
            Some(old_value_len) => bs.len() as i64 - old_value_len as i64,
        };
        self.footprint.record_delta(delta).await;
        self.storage.set(contract_id, &path, bs).await
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
