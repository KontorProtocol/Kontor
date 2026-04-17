use anyhow::Result;
use bitcoin::hashes::Hash;
use futures_util::StreamExt;
use wasmtime::component::{Accessor, Resource};

use super::{
    ContractAddress, Runtime,
    fuel::Fuel,
    hash_bytes,
    wit::kontor::built_in::{
        self,
        context::{HolderRef, OpReturnData, OutPoint},
        error::Error as WitError,
    },
    wit::{
        CoreContext, FallContext, Holder, Keys, ProcContext, ProcStorage, Signer, Transaction,
        ViewContext, ViewStorage,
    },
};

impl Runtime {
    async fn _generate_id<T>(&self, accessor: &Accessor<T, Self>) -> Result<String> {
        Fuel::CryptoGenerateId
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let count = self.id_generation_counter.get().await;
        self.id_generation_counter.increment().await;
        Ok(hex::encode(
            &hash_bytes(
                &[
                    self.tx_context()
                        .expect("Transaction context must be set to generate ids")
                        .txid
                        .to_raw_hash()
                        .to_byte_array()
                        .to_vec(),
                    count.to_le_bytes().to_vec(),
                ]
                .concat(),
            )[0..8],
        ))
    }

    async fn _signer_to_string<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<String> {
        Fuel::SignerToString
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(self.table.lock().await.get(&self_)?.to_string())
    }

    async fn _proc_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::ProcSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let signer = table.get(&self_)?.signer.clone();
        Ok(table.push(signer)?)
    }

    async fn _proc_contract_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::ProcContractSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(Signer::new_contract_id(contract_id))?)
    }

    async fn _proc_transaction<T>(
        &self,
        accessor: &Accessor<T, Self>,
        _: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        Fuel::ProcTransaction
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        Ok(table.push(Transaction {})?)
    }

    async fn _proc_view_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        Fuel::ProcViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn _proc_view_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        Fuel::ProcViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewStorage { contract_id })?)
    }

    async fn _view_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        Fuel::ViewStorage
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewStorage { contract_id })?)
    }

    async fn _proc_storage<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        Fuel::ProcStorage
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ProcStorage { contract_id })?)
    }

    async fn _next<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        let k = self
            .table
            .lock()
            .await
            .get_mut(&self_)?
            .stream
            .next()
            .await
            .transpose()?;
        if let Some(k) = &k {
            tracing::trace!("keys.next() returned: {k:?}");
            Fuel::KeysNext(k.len() as u64)
                .consume(accessor, self.gauge.as_ref())
                .await?;
        }
        Ok(k)
    }

    async fn _fall_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        Fuel::FallSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        Ok(table
            .get(&self_)?
            .signer
            .clone()
            .map(|s| table.push(s))
            .transpose()?)
    }

    async fn _fall_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        Fuel::FallProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        Ok(res
            .signer
            .clone()
            .map(|signer| {
                table.push(ProcContext {
                    contract_id,
                    signer,
                })
            })
            .transpose()?)
    }

    async fn _fall_view_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        Fuel::FallViewContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let contract_id = table.get(&self_)?.contract_id;
        Ok(table.push(ViewContext { contract_id })?)
    }

    async fn _core_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        Fuel::CoreProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        let signer = res.signer.clone();
        Ok(table.push(ProcContext {
            contract_id,
            signer: Signer::Core(Box::new(signer)),
        })?)
    }

    async fn _core_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::CoreProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let signer = res.signer.clone();
        Ok(table.push(Signer::Core(Box::new(signer)))?)
    }

    async fn _core_signer_proc_context<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        Fuel::CoreProcContext
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let mut table = self.table.lock().await;
        let res = table.get(&self_)?;
        let contract_id = res.contract_id;
        let signer = res.signer.clone();
        Ok(table.push(ProcContext {
            contract_id,
            signer,
        })?)
    }

    fn _signer_to_holder_ref(signer: &Signer) -> HolderRef {
        signer.into()
    }

    async fn _signer_as_holder<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<Resource<Holder>> {
        Fuel::SignerAsHolder
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let signer = {
            let table = self.table.lock().await;
            table.get(&self_)?.clone()
        };
        let holder_ref = Self::_signer_to_holder_ref(&signer);
        tracing::debug!("_signer_as_holder: signer={signer:?} holder_ref={holder_ref:?}");
        let conn = self.get_storage_conn();
        let height = self.storage.height;
        let holder = Holder::from_holder_ref(holder_ref, &conn, height)
            .await
            .map_err(|e| {
                tracing::error!("holder resolution failed for signer {signer:?}: {e:?}");
                anyhow::anyhow!("holder resolution failed: {e:?}")
            })?;
        let mut table = self.table.lock().await;
        Ok(table.push(holder)?)
    }

    pub(crate) async fn _get_contract_address<T>(
        &self,
        accessor: &Accessor<T, Self>,
    ) -> Result<ContractAddress> {
        Fuel::ContractAddress
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let id = self.stack.peek().await.expect("Stack is empty");
        Ok(self
            .storage
            .contract_address(id)
            .await?
            .expect("Failed to get contract address"))
    }

    pub(crate) async fn _drop<T: 'static>(&self, rep: Resource<T>) -> Result<()> {
        self.table.lock().await.delete(rep)?;
        Ok(())
    }
}

impl built_in::context::Host for Runtime {}

impl built_in::context::HostViewStorage for Runtime {}

impl built_in::context::HostViewStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewStorage>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }
}

impl built_in::context::HostViewContext for Runtime {}

impl built_in::context::HostViewContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ViewContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ViewContext>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._view_storage(accessor, self_)
            .await
    }
}

impl built_in::context::HostHolder for Runtime {}

impl built_in::context::HostHolderWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Holder>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn key<T>(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<String> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderKey
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.to_string())
    }

    async fn from_ref<T>(
        accessor: &Accessor<T, Self>,
        ref_: HolderRef,
    ) -> Result<Result<Resource<Holder>, WitError>> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderFromRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let conn = runtime.get_storage_conn();
        let height = runtime.storage.height;
        let holder = match Holder::from_holder_ref(ref_.clone(), &conn, height).await {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Holder::from_ref failed for {ref_:?}: {e:?}");
                return Ok(Err(e));
            }
        };
        let mut table = runtime.table.lock().await;
        Ok(Ok(table.push(holder)?))
    }

    async fn as_ref<T>(accessor: &Accessor<T, Self>, self_: Resource<Holder>) -> Result<HolderRef> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderAsRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let holder = table.get(&self_)?;
        Ok(holder.holder_ref.clone())
    }
}

impl built_in::context::HostSigner for Runtime {}

impl built_in::context::HostSignerWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Signer>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn key<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._signer_to_string(accessor, self_)
            .await
    }

    async fn as_holder<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<Resource<Holder>> {
        accessor
            .with(|mut access| access.get().clone())
            ._signer_as_holder(accessor, self_)
            .await
    }

    async fn as_ref<T>(accessor: &Accessor<T, Self>, self_: Resource<Signer>) -> Result<HolderRef> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Fuel::HolderAsRef
            .consume(accessor, runtime.gauge.as_ref())
            .await?;
        let table = runtime.table.lock().await;
        let signer = table.get(&self_)?;
        Ok(Self::_signer_to_holder_ref(signer))
    }
}

impl built_in::context::HostProcStorage for Runtime {}

impl built_in::context::HostProcStorageWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcStorage>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn get_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<u64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<i64>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<bool>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Option<Vec<u8>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_primitive(accessor, self_, path)
            .await
    }

    async fn get_keys<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<Resource<Keys>> {
        accessor
            .with(|mut access| access.get().clone())
            ._get_keys(accessor, self_, path)
            .await
    }

    async fn exists<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<bool> {
        accessor
            .with(|mut access| access.get().clone())
            ._exists(accessor, self_, path)
            .await
    }

    async fn extend_path_with_match<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        variants: Vec<String>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._extend_path_with_match(accessor, self_, path, variants)
            .await
    }

    async fn set_str<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_u64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: u64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_s64<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: i64,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_bool<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: bool,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_list_u8<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
        value: Vec<u8>,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, value)
            .await
    }

    async fn set_void<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        path: String,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._set_primitive(accessor, self_, path, ())
            .await
    }

    async fn delete_matching_paths<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
        base_path: String,
        variants: Vec<String>,
    ) -> Result<u64> {
        accessor
            .with(|mut access| access.get().clone())
            ._delete_matching_paths(
                accessor,
                self_,
                format!(r"^{}.({})(\..*|$)", base_path, variants.join("|")),
            )
            .await
    }

    async fn view_storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcStorage>,
    ) -> Result<Resource<ViewStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_storage(accessor, self_)
            .await
    }
}

impl built_in::context::HostProcContext for Runtime {}

impl built_in::context::HostProcContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<ProcContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_signer(accessor, self_)
            .await
    }

    async fn contract_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_contract_signer(accessor, self_)
            .await
    }

    async fn transaction<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Transaction>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_transaction(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_view_context(accessor, self_)
            .await
    }

    async fn generate_id<T>(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<String> {
        accessor
            .with(|mut access| access.get().clone())
            ._generate_id(accessor)
            .await
    }

    async fn storage<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<ProcStorage>> {
        accessor
            .with(|mut access| access.get().clone())
            ._proc_storage(accessor, self_)
            .await
    }

    async fn block_height<T>(
        accessor: &Accessor<T, Self>,
        _self: Resource<ProcContext>,
    ) -> Result<u64> {
        let runtime = accessor.with(|mut access| access.get().clone());
        Ok(runtime.storage.height as u64)
    }
}

impl built_in::context::HostKeys for Runtime {}

impl built_in::context::HostKeysWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Keys>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn next<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<Keys>,
    ) -> Result<Option<String>> {
        accessor
            .with(|mut access| access.get().clone())
            ._next(accessor, self_)
            .await
    }
}

impl built_in::context::HostFallContext for Runtime {}

impl built_in::context::HostFallContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<FallContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<Signer>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_signer(accessor, self_)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Option<Resource<ProcContext>>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_proc_context(accessor, self_)
            .await
    }

    async fn view_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<FallContext>,
    ) -> Result<Resource<ViewContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._fall_view_context(accessor, self_)
            .await
    }
}

impl built_in::context::HostCoreContext for Runtime {}

impl built_in::context::HostCoreContextWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<CoreContext>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_proc_context(accessor, self_)
            .await
    }

    async fn signer_proc_context<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<ProcContext>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_signer_proc_context(accessor, self_)
            .await
    }

    async fn core_signer<T>(
        accessor: &Accessor<T, Self>,
        self_: Resource<CoreContext>,
    ) -> Result<Resource<Signer>> {
        accessor
            .with(|mut access| access.get().clone())
            ._core_signer(accessor, self_)
            .await
    }
}

impl built_in::context::HostTransaction for Runtime {}

impl built_in::context::HostTransactionWithStore for Runtime {
    async fn drop<T>(accessor: &Accessor<T, Self>, rep: Resource<Transaction>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn id<T>(accessor: &Accessor<T, Self>, _: Resource<Transaction>) -> Result<String> {
        Ok(accessor
            .with(|mut access| access.get().tx_context().map(|c| c.txid))
            .expect("transaction id called without txid present")
            .to_string())
    }

    async fn out_point<T>(
        accessor: &Accessor<T, Self>,
        _: Resource<Transaction>,
    ) -> Result<OutPoint> {
        Ok(accessor
            .with(|mut access| access.get().previous_output)
            .expect("utxo_id called without previous_output present")
            .into())
    }

    async fn op_return_data<T>(
        accessor: &Accessor<T, Self>,
        _: Resource<Transaction>,
    ) -> Result<Option<OpReturnData>> {
        Ok(accessor.with(|mut access| access.get().op_return_data.clone()))
    }
}
