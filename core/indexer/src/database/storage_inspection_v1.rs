use std::sync::Arc;

use libsql::Connection;

use super::queries::{get_op_result, get_signer_entry_by_x_only_pubkey};
use super::storage_aux_v1::failure;
use super::types::OpResultId;
use crate::protocol::storage_inspection::InspectionCallbacks;

pub(crate) fn inspection_callbacks(conn: &Connection) -> InspectionCallbacks {
    (
        {
            let conn = conn.clone();
            Arc::new(move |key| {
                let conn = conn.clone();
                Box::pin(async move {
                    get_signer_entry_by_x_only_pubkey(&conn, &key)
                        .await
                        .map(|entry| entry.map(|entry| entry.signer_id))
                        .map_err(failure)
                })
            })
        },
        {
            let conn = conn.clone();
            Arc::new(move |txid, input_index, op_index| {
                let conn = conn.clone();
                Box::pin(async move {
                    let id = OpResultId::builder()
                        .txid(txid)
                        .input_index(input_index)
                        .op_index(op_index)
                        .build();
                    get_op_result(&conn, &id).await.map_err(failure).map(|row| {
                        row.map(|row| {
                            (
                                (
                                    row.id,
                                    row.height,
                                    row.tx_index,
                                    row.input_index,
                                    row.op_index,
                                    row.result_index,
                                ),
                                (row.func, row.gas, row.status.as_str().to_owned(), row.value),
                                (
                                    (
                                        row.contract_name,
                                        row.contract_height,
                                        row.contract_tx_index,
                                    ),
                                    row.txid,
                                    row.signer_id,
                                    row.payer_signer_id,
                                ),
                            )
                        })
                    })
                })
            })
        },
    )
}
