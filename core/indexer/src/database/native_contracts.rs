use anyhow::Result;
use libsql::Connection;

use crate::{
    database::{
        queries::{insert_block, insert_contract},
        types::{BlockRow, ContractRow},
    },
    test_utils::new_mock_block_hash,
};

pub const TOKEN: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/token.wasm.br");

pub async fn store_native_contracts(conn: &Connection) -> Result<()> {
    insert_block(
        conn,
        BlockRow::builder()
            .height(0)
            .hash(new_mock_block_hash(0))
            .build(),
    )
    .await?;
    for (name, bytes) in [("token", TOKEN)] {
        insert_contract(
            conn,
            ContractRow::builder()
                .name(name.to_string())
                .height(0)
                .tx_index(0)
                .bytes(bytes.to_vec())
                .build(),
        )
        .await?;
    }
    Ok(())
}
