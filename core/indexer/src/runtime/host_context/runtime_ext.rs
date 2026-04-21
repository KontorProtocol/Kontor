use anyhow::Result;
use bitcoin::hashes::Hash;
use futures_util::StreamExt;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::wit::{
    CoreContext, FallContext, Holder, Keys, ProcContext, ProcStorage, Signer, Transaction,
    ViewContext, ViewStorage,
};
use crate::runtime::{ContractAddress, Runtime, fuel::Fuel, hash_bytes};

impl Runtime {
    pub(super) async fn _generate_id<T>(&self, accessor: &Accessor<T, Self>) -> Result<String> {
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

    pub(super) async fn _signer_to_string<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<Signer>,
    ) -> Result<String> {
        Fuel::SignerToString
            .consume(accessor, self.gauge.as_ref())
            .await?;
        Ok(self.table.lock().await.get(&self_)?.to_string())
    }

    pub(super) async fn _proc_signer<T>(
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

    pub(super) async fn _proc_contract_signer<T>(
        &self,
        accessor: &Accessor<T, Self>,
        self_: Resource<ProcContext>,
    ) -> Result<Resource<Signer>> {
        Fuel::ProcContractSigner
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let contract_id = {
            let table = self.table.lock().await;
            table.get(&self_)?.contract_id
        };
        let signer_id =
            crate::database::queries::get_contract_signer_id(&self.get_storage_conn(), contract_id)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!("no signer_id found for contract_id {contract_id}")
                })?;
        let mut table = self.table.lock().await;
        Ok(table.push(Signer::new_contract(contract_id, signer_id))?)
    }

    pub(super) async fn _proc_transaction<T>(
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

    pub(super) async fn _proc_view_context<T>(
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

    pub(super) async fn _proc_view_storage<T>(
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

    pub(super) async fn _view_storage<T>(
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

    pub(super) async fn _proc_storage<T>(
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

    pub(super) async fn _next<T>(
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

    pub(super) async fn _fall_signer<T>(
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

    pub(super) async fn _fall_proc_context<T>(
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

    pub(super) async fn _fall_view_context<T>(
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

    pub(super) async fn _core_proc_context<T>(
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

    pub(super) async fn _core_signer<T>(
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

    pub(super) async fn _core_signer_proc_context<T>(
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

    pub(super) fn _signer_to_holder_ref(signer: &Signer) -> HolderRef {
        signer.into()
    }

    pub(super) async fn _signer_as_holder<T>(
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
