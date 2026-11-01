use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Holder;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::kontor::built_in::error::Error as WitError;

impl built_in::context::HostHolder for Runtime {
    async fn drop(&mut self, rep: Resource<Holder>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostHolderWithStore<T> for Runtime {
    async fn key(mut accessor: Access<'_, T, Self>, self_: Resource<Holder>) -> Result<String> {
        let runtime = accessor.get().clone();
        Fuel::HolderKey.consume(&mut accessor)?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.to_string())
    }

    async fn from_ref(
        mut accessor: Access<'_, T, Self>,
        ref_: HolderRef,
    ) -> Result<Result<Resource<Holder>, WitError>> {
        let bytes = match &ref_ {
            HolderRef::XOnlyPubkey(pubkey) => pubkey.len(),
            HolderRef::Utxo(out_point) => out_point.txid.len(),
            HolderRef::SignerId(_)
            | HolderRef::Core
            | HolderRef::Burner
            | HolderRef::OrderingPool
            | HolderRef::StoragePool => 0,
        };
        // Invalid references also incur ABI conversion and validation work.
        Fuel::HolderFromRef(bytes as u64).consume(&mut accessor)?;
        let runtime = accessor.get().clone();
        let holder = match Holder::from_holder_ref(ref_, &runtime).await? {
            Ok(h) => h,
            Err(e) => {
                // Debug-level: a "signer not found" in view context is
                // a legitimate deterministic outcome (the contract sees
                // it as Err and decides what to do — usually return
                // None). The WIT result already carries the error to
                // the contract; logging is purely diagnostic.
                tracing::debug!("Holder::from_ref returning Err: {e:?}");
                return Ok(Err(e));
            }
        };
        let mut table = runtime.table.lock().await;
        Ok(Ok(table.push(holder)?))
    }

    async fn as_ref(
        mut accessor: Access<'_, T, Self>,
        self_: Resource<Holder>,
    ) -> Result<HolderRef> {
        let runtime = accessor.get().clone();
        Fuel::HolderAsRef.consume(&mut accessor)?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.clone())
    }
}
