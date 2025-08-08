use anyhow::Result;

use crate::{
    database::{
        queries::{contract_has_state, insert_block, insert_contract},
        types::{BlockRow, ContractRow},
    },
    runtime::{ContractAddress, Runtime},
    test_utils::new_mock_block_hash,
};

const FIB: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/fib.wasm.br");

const ARITH: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/arith.wasm.br");

const PROXY: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/proxy.wasm.br");

pub async fn load_native_contracts(runtime: &Runtime) -> Result<()> {
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
    for (name, bytes) in [("arith", ARITH), ("fib", FIB), ("proxy", PROXY)] {
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
                    Some("kontor"),
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
