use anyhow::Result;
use wasmtime::component::{Access, Resource};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::types::outpoint_from_bitcoin;
use crate::runtime::wit::Transaction;
use crate::runtime::wit::kontor::built_in;
use crate::runtime::wit::kontor::built_in::context::OutPoint;

impl built_in::context::HostTransaction for Runtime {
    async fn drop(&mut self, rep: Resource<Transaction>) -> Result<()> {
        self._drop(rep).await
    }
}

impl<T: Send> built_in::context::HostTransactionWithStore<T> for Runtime {
    async fn id(mut accessor: Access<'_, T, Self>, _: Resource<Transaction>) -> Result<String> {
        Fuel::TransactionId.consume(&mut accessor)?;
        Ok(accessor
            .get()
            .tx_context()
            .map(|c| c.txid)
            .expect("transaction id called without txid present")
            .to_string())
    }

    async fn out_point(
        mut accessor: Access<'_, T, Self>,
        _: Resource<Transaction>,
    ) -> Result<OutPoint> {
        Fuel::TransactionOutPoint.consume(&mut accessor)?;
        Ok(outpoint_from_bitcoin(
            accessor
                .get()
                .previous_output
                .expect("utxo_id called without previous_output present"),
        ))
    }

    async fn op_return_data(
        mut accessor: Access<'_, T, Self>,
        _: Resource<Transaction>,
    ) -> Result<Option<Vec<u8>>> {
        let bytes = accessor
            .get()
            .op_return_data
            .as_deref()
            .map_or(0, <[u8]>::len);
        Fuel::TransactionData(bytes as u64).consume(&mut accessor)?;
        Ok(accessor.get().op_return_data.as_deref().map(<[u8]>::to_vec))
    }
}
