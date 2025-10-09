use anyhow::Result;

use crate::{
    database::{
        queries::{contract_has_state, insert_block, insert_contract},
        types::{BlockRow, ContractRow},
    },
    runtime::{ContractAddress, Runtime, wit::Signer},
    test_utils::new_mock_block_hash,
};

pub async fn load_contracts(runtime: &Runtime, contracts: &[(&str, &[u8])]) -> Result<()> {
    let height = 0;
    let tx_index = 0;
    let conn = runtime.get_storage_conn();
    insert_block(
        &conn,
        BlockRow {
            height,
            hash: new_mock_block_hash(0),
        },
    )
    .await?;
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
                    Some(Signer::XOnlyPubKey("kontor".to_string())),
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
