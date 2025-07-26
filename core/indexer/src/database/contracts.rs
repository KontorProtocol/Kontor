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

const ARITH: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/arith.wasm.br");

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
    for (name, bytes) in [("arith", ARITH), ("fib", FIB)] {
        insert_contract(
            conn,
            ContractRow::builder()
                .height(height)
                .tx_index(tx_index)
                .name(name.to_string())
                .bytes(bytes.to_vec())
                .build(),
        )
        .await?;
    }

    Ok(())
}
