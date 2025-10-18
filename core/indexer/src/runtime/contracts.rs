use anyhow::Result;

use crate::{
    database::{
        queries::{
            contract_has_state, get_transaction_by_txid, insert_block, insert_contract,
            insert_transaction, select_block_at_height,
        },
        types::{BlockRow, ContractRow, TransactionRow},
    },
    runtime::{ContractAddress, Runtime, wit::Signer},
    test_utils::{new_mock_block_hash, new_mock_transaction},
};

pub async fn load_contracts(
    runtime: &Runtime,
    signer: &Signer,
    contracts: &[(&str, &[u8])],
) -> Result<()> {
    let height = 0;
    let tx_index = 0;
    let conn = runtime.get_storage_conn();
    if select_block_at_height(&conn, 0).await?.is_none() {
        insert_block(
            &conn,
            BlockRow {
                height,
                hash: new_mock_block_hash(0),
            },
        )
        .await?;
    }

    let tx = new_mock_transaction(1);
    if get_transaction_by_txid(&conn, &tx.txid.to_string())
        .await?
        .is_none()
    {
        insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(height)
                .tx_index(0)
                .txid(tx.txid.to_string())
                .build(),
        )
        .await?;
    };

    for (name, bytes) in contracts {
        let contract_id = insert_contract(
            &conn,
            ContractRow::builder()
                .height(height)
                .tx_index(tx_index)
                .name(name.to_string())
                .bytes(bytes.to_vec())
                .build(),
        )
        .await?;
        if !contract_has_state(&conn, contract_id).await? {
            runtime
                .execute(
                    Some(signer),
                    &ContractAddress {
                        name: name.to_string(),
                        height,
                        tx_index,
                    },
                    "init()",
                )
                .await?;
        }
    }
    Ok(())
}
