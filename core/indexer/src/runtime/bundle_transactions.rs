use std::sync::Arc;

use bitcoin::hashes::Hash;
use indexer_types::Transaction;

use super::Runtime;
use super::bundle_session::{BundleSession, infrastructure};
use crate::protocol::operations::{RecognitionCall, RecognizedEnvelope, TransactionCall};
use crate::protocol::v1::{execution, transactions};

#[cfg(test)]
mod tests;

struct RecognizedTransaction {
    version: u32,
    network: [u8; 4],
    transaction: Transaction,
}

impl RecognizedTransaction {
    fn envelope(self) -> RecognizedEnvelope {
        let txid = self.transaction.txid.to_byte_array();
        let batchable = transactions::is_batchable(&self.transaction.inputs);
        let inputs = self
            .transaction
            .inputs
            .iter()
            .map(|input| (input.input_index, input.insts.ops.len() as u64))
            .collect();
        (Arc::new(self), txid, batchable, inputs)
    }
}

impl Runtime {
    #[cfg(test)]
    pub(crate) fn recognition_fixture(
        version: u32,
        network: [u8; 4],
        transaction: Transaction,
    ) -> RecognizedEnvelope {
        RecognizedTransaction {
            version,
            network,
            transaction,
        }
        .envelope()
    }

    pub(crate) fn recognizer(&self) -> RecognitionCall {
        let version = self.executor_version().tag();
        let network = self.network.magic().to_bytes();
        Arc::new(move |selection, raw| {
            if selection.0 != version || selection.1 != network {
                return Err((2, "recognizer selection does not match executor".into()));
            }
            if !matches!(
                selection.3,
                (2, _, _, 0) | (3 | 4, _, Some(_), _) | (5, _, None, 0)
            ) {
                return Err((
                    2,
                    "recognition requires preparation or execution selection".into(),
                ));
            }
            let raw = match transactions::decode_simulation(&raw) {
                Ok(raw) => raw,
                Err(error) => return Ok(Err(error)),
            };
            Ok(Ok(transactions::filter_map((0, raw)).map(
                |transaction| -> RecognizedEnvelope {
                    RecognizedTransaction {
                        version,
                        network,
                        transaction,
                    }
                    .envelope()
                },
            )))
        })
    }
}

impl BundleSession {
    pub(crate) fn transaction(self: &Arc<Self>) -> TransactionCall {
        let expected = self.clone();
        Arc::new(move |opaque, selection, parsed, tx_index, tx_id| {
            let session = expected.clone();
            Box::pin(async move {
                session.verify_operation_owner(opaque)?;
                let parsed = parsed
                    .downcast::<RecognizedTransaction>()
                    .map_err(|_| (2, "transaction belongs to another executor".into()))?;
                if parsed.version != selection.0 || parsed.network != selection.1 {
                    return Err((
                        2,
                        "transaction recognition does not match execution selection".into(),
                    ));
                }
                let mut runtime = session.runtime.lock().await;
                runtime
                    .verify_bundle_operation(&selection, selection.3.0)
                    .map_err(infrastructure)?;
                if !matches!(selection.3.0, 3 | 4 | 5) {
                    return Err((
                        2,
                        "transaction requires a block, batch or simulation selection".into(),
                    ));
                }
                let mut runtime = runtime.bind_selection(&selection).map_err(infrastructure)?;
                if runtime.storage.savepoint_stack.is_empty().await {
                    return Err((2, "transaction requires an open canonical unit".into()));
                }
                let mut transaction = parsed.transaction.clone();
                // Position is assigned when ordered, not when a mempool input
                // is recognized. The immutable parsed operations stay unchanged.
                transaction.index = tx_index;
                let previous = runtime.start_usage();
                let result = execution::execute_transaction(
                    &mut runtime,
                    selection.3.1,
                    tx_id,
                    &transaction,
                )
                .await;
                let usage = runtime.finish_usage(previous);
                let failures = result.map_err(infrastructure)?;
                let usage = usage.map_err(infrastructure)?;
                Ok((
                    (usage.user_fuel, usage.system_fuel, usage.deposit_fuel),
                    failures
                        .into_iter()
                        .map(|input| {
                            input
                                .into_iter()
                                .map(|error| error.map(|error| format!("{error:#}")))
                                .collect()
                        })
                        .collect(),
                ))
            })
        })
    }
}
