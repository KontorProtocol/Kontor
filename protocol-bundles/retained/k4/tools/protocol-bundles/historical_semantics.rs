//! Test-only oracle installed in the qualified pre-extraction checkout.

use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::serialize;
use bitcoin::{BlockHash, hashes::Hash};
use indexer_types::{Block, BlockRow, ContractAddress, TransactionRow};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[path = "protocol_qualification/fixture.rs"]
mod fixture;

use crate::bitcoin_client::Client;
use crate::built_info::GIT_COMMIT_HASH;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database::connection::new_connection;
use crate::database::queries::{insert_block, insert_block_execution_usage, insert_transaction};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::v1::committee::build_validator_set;
use crate::reactor::executor::{Executor, RuntimeExecutor};
use crate::runtime::ownership::OwnerService;
use crate::runtime::{
    ComponentCache, Decimal, ExecutionError, GenesisParameters, GenesisValidator, Runtime, Storage,
};
use fixture::{COUNTER, HEIGHT, NETWORK, OP_COUNT, PROXY, TX_INDEX, genesis, state, transaction};

async fn view(runtime: &mut Runtime, expression: &str) -> Result<Value> {
    let conn = runtime.get_storage_conn();
    let height = runtime.storage.height;
    let allowance = runtime.gas_limit_for_non_procs;
    runtime.storage.savepoint().await?;
    runtime.storage.height = 1;
    runtime.gas_limit_for_non_procs = DEFAULT_VIEW_GAS_LIMIT;
    let selection = select_legacy_p1(&conn, NETWORK, ApplicationPosition::View).await?;
    let result = runtime
        .bind_selection(&selection)?
        .execute(
            None,
            None,
            &ContractAddress {
                name: "staking".into(),
                height: 0,
                tx_index: 0,
            },
            expression,
        )
        .await
        .map_err(|error| {
            (
                matches!(&error, ExecutionError::Deterministic(_)),
                format!("{error:?}"),
            )
        });
    runtime.storage.rollback().await?;
    runtime.storage.height = height;
    runtime.gas_limit_for_non_procs = allowance;
    Ok(serde_json::to_value(result)?)
}

#[tokio::test]
#[ignore = "records the bounded pre-extraction semantic oracle"]
async fn historical_semantic_supplement() -> Result<()> {
    let output = env::var("KONTOR_SEMANTIC_ORACLE").context("set oracle output path")?;
    let dir = TempDir::new()?;
    let conn = new_connection(dir.path(), "oracle.db").await?;
    for height in 0..=1 {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(BlockHash::from_byte_array([height as u8; 32]))
                .relevant(true)
                .build(),
        )
        .await?;
    }
    let mut runtime = Runtime::new(
        ComponentCache::new(),
        Storage::builder().height(0).conn(conn.clone()).build(),
    )
    .await?;
    runtime.network = NETWORK;
    let (sigma, validators) = genesis();
    let genesis = GenesisParameters {
        sigma_min: Decimal::from(sigma.as_str()),
        validators: validators
            .into_iter()
            .map(|(x_only_pubkey, stake, ed25519_pubkey)| GenesisValidator {
                x_only_pubkey,
                stake: Decimal::from(stake.as_str()),
                ed25519_pubkey,
            })
            .collect(),
    };
    let service = OwnerService::new();
    runtime
        .publish_native_contracts_owned(&genesis, &service)
        .await?;
    let initialized = state(&conn).await?;
    ensure!(initialized["contracts"].0 == 5 && initialized["contract_provenance"].0 == 5);
    runtime
        .publish_native_contracts_owned(&genesis, &service)
        .await?;
    ensure!(state(&conn).await? == initialized, "resume changed genesis");
    let active_set = view(&mut runtime, "get-active-set()").await?;
    let missing = view(&mut runtime, "missing-function()").await?;
    ensure!(
        state(&conn).await? == initialized,
        "view changed canonical state"
    );

    runtime.storage.savepoint().await?;
    let committee = build_validator_set(&mut runtime).await?;
    runtime.storage.rollback().await?;
    ensure!(committee.validators.len() == 1);

    let executor = RuntimeExecutor::new(Client::new(
        "http://127.0.0.1:1".into(),
        String::new(),
        String::new(),
    )?);
    let block = Block {
        height: 2,
        hash: BlockHash::from_byte_array([2; 32]),
        prev_hash: BlockHash::from_byte_array([1; 32]),
        transactions: vec![],
    };
    let selection = select_legacy_p1(
        &conn,
        NETWORK,
        ApplicationPosition::Block {
            height: 2,
            hash: block.hash,
            consensus_height: 2,
        },
    )
    .await?;
    let malformed = executor.decode_simulation(&selection, &[0xff]).unwrap_err();
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    runtime.storage.savepoint().await?;
    insert_block(
        &conn,
        BlockRow::builder().height(2).hash(block.hash).build(),
    )
    .await?;
    let previous = runtime.start_usage();
    executor
        .run_block_lifecycle(&selection, &mut runtime, &block)
        .await?;
    let usage = runtime.finish_usage(previous)?;
    insert_block_execution_usage(&conn, block.height, usage).await?;
    let lifecycle = state(&conn).await?;
    lease.drain(&runtime).await?;
    runtime.storage.commit().await?;
    lease.complete(&mut runtime).await?;

    let raw = transaction()?;
    let bytes = serialize(&raw);
    let selection = select_legacy_p1(
        &conn,
        NETWORK,
        ApplicationPosition::Block {
            height: HEIGHT,
            hash: BlockHash::from_byte_array([3; 32]),
            consensus_height: HEIGHT,
        },
    )
    .await?;
    let mut parsed = executor
        .parse_transaction(&selection, &raw)
        .context("missing signed fixture")?;
    ensure!(parsed.inputs.len() == 1 && parsed.inputs[0].insts.ops.len() == OP_COUNT);
    let recognition = json!({"txid":parsed.txid.to_string(),
        "batchable":executor.is_batchable(&selection, &parsed),
        "inputs":parsed.inputs.iter().map(|input| (input.input_index, input.insts.ops.len() as u64)).collect::<Vec<_>>()});
    parsed.index = TX_INDEX;
    let mut lease = service.begin_canonical(&mut runtime, false).await?;
    runtime.storage.savepoint().await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(HEIGHT)
            .hash(BlockHash::from_byte_array([3; 32]))
            .build(),
    )
    .await?;
    let tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(HEIGHT)
            .tx_index(TX_INDEX)
            .txid(parsed.txid.to_string())
            .build(),
    )
    .await?;
    let failures = executor
        .execute_transaction(&selection, &mut runtime, HEIGHT, tx_id, &parsed)
        .await?;
    let failures: Vec<Vec<Option<String>>> = failures
        .into_iter()
        .map(|input| {
            input
                .into_iter()
                .map(|error| error.map(|error| format!("{error:#}")))
                .collect()
        })
        .collect();
    ensure!(failures.len() == 1 && failures[0].len() == OP_COUNT);
    for (index, failure) in failures[0].iter().enumerate() {
        ensure!(
            failure.is_some() == matches!(index, 5 | 6 | 10),
            "unexpected operation {index}: {failure:?}"
        );
    }
    let row = conn.query("SELECT user_fuel, system_fuel, deposit_fuel FROM transaction_execution_usage WHERE tx_id = ?", [tx_id]).await?
        .next().await?.context("missing transaction usage")?;
    let usage: (i64, i64, i64) = (row.get(0)?, row.get(1)?, row.get(2)?);
    let executed = json!({"failures":failures,"usage":usage,"state":state(&conn).await?});
    lease.drain(&runtime).await?;
    runtime.storage.commit().await?;
    lease.complete(&mut runtime).await?;
    ensure!(conn.is_autocommit() && service.active_roots().await == 0);
    service.shutdown();
    let report = json!({"schema":1, "historical_source":GIT_COMMIT_HASH.context("missing source revision")?,
        "inputs":{"raw_sha256":hex::encode(Sha256::digest(&bytes)),
            "counter_sha256":hex::encode(Sha256::digest(COUNTER)), "proxy_sha256":hex::encode(Sha256::digest(PROXY))},
        "observations":{"genesis":initialized,"active_set":active_set,"missing_function":missing,
            "committee":committee,"malformed_transaction":malformed,"lifecycle":lifecycle,
            "recognition":recognition,"transaction":executed}});
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?
        .write_all(&serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}
