use anyhow::Result;
use libsql::Connection;

use crate::{
    database::{
        queries::{insert_block, insert_contract},
        types::{BlockRow, ContractRow},
    },
    test_utils::new_mock_block_hash,
};

const FIB: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/fib.wasm.br");

const SUM: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/sum.wasm.br");

pub async fn load_native_contracts(conn: &Connection) -> Result<()> {
    let height = 0;
    let tx_index = 0;
    insert_block(
        conn,
        BlockRow {
            height: height as u64,
            hash: new_mock_block_hash(0),
        },
    )
    .await?;
    insert_contract(
        conn,
        ContractRow::builder()
            .height(height)
            .tx_index(tx_index)
            .name("fib".to_string())
            .bytes(FIB.to_vec())
            .build(),
    )
    .await?;
    insert_contract(
        conn,
        ContractRow::builder()
            .height(height)
            .tx_index(tx_index)
            .name("sum".to_string())
            .bytes(SUM.to_vec())
            .build(),
    )
    .await?;

    Ok(())
}
