use anyhow::Result;

use crate::{
    database::{
        queries::{contract_has_state, insert_block, insert_contract},
        types::{BlockRow, ContractRow},
    },
    runtime::{ContractAddress, Runtime},
    test_utils::new_mock_block_hash,
};

const ARITH: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/arith.wasm.br");

const CRYPTO: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/crypto.wasm.br");

const FIB: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/fib.wasm.br");

const PROXY: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/proxy.wasm.br");

const SHARED_ACCOUNT: &[u8] = include_bytes!(
    "../../../../contracts/target/wasm32-unknown-unknown/release/shared_account.wasm.br"
);

const TOKEN: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/token.wasm.br");

const AMM: &[u8] =
    include_bytes!("../../../../contracts/target/wasm32-unknown-unknown/release/amm.wasm.br");

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
                    Some("kontor".to_string()),
                    &ContractAddress {
                        name: name.to_string(),
                        height,
                        tx_index,
                    },
                    "init()".to_string(),
                )
                .await?;
        }
    }
    Ok(())
}

pub async fn load_native_contracts(runtime: &Runtime) -> Result<()> {
    load_contracts(
        runtime,
        &[
            ("arith", ARITH),
            ("crypto", CRYPTO),
            ("fib", FIB),
            ("proxy", PROXY),
            ("shared-account", SHARED_ACCOUNT),
            ("token", TOKEN),
            ("amm", AMM),
        ],
    )
    .await
}
