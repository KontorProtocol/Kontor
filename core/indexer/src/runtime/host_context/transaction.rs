use anyhow::Result;
use wasmtime::component::{Accessor, Resource};

use crate::runtime::Runtime;
use crate::runtime::wit::Transaction;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::OutPoint;

impl built_in::context::HostTransaction for Runtime {}

impl<T> built_in::context::HostTransactionWithStore<T> for Runtime {
    async fn drop(accessor: &Accessor<T, Self>, rep: Resource<Transaction>) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._drop(rep)
            .await
    }

    async fn id(accessor: &Accessor<T, Self>, _: Resource<Transaction>) -> Result<String> {
        Ok(accessor
            .with(|mut access| access.get().tx_context().map(|c| c.txid))
            .expect("transaction id called without txid present")
            .to_string())
    }

    async fn out_point(accessor: &Accessor<T, Self>, _: Resource<Transaction>) -> Result<OutPoint> {
        Ok(accessor
            .with(|mut access| access.get().previous_output)
            .expect("utxo_id called without previous_output present")
            .into())
    }

    async fn op_return_data(
        accessor: &Accessor<T, Self>,
        _: Resource<Transaction>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(accessor.with(|mut access| access.get().op_return_data.clone()))
    }
}
