use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::consensus::serialize as bitcoin_bytes;
use bitcoin::{BlockHash, Witness, hashes::Hash};
use indexer_types::{BlockRow, TransactionRow};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::fixture::{COUNTER, HEIGHT, OP_COUNT, PROXY, TX_INDEX, transaction};
use super::{NETWORK, state};
use crate::database::queries::{insert_block, insert_transaction};
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, execute_transaction, finish_canonical_unit, recognize_transaction,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::HostFailure;
use crate::runtime::pool::LinkedSession;

pub(super) async fn run(service: &OwnerService, session: &LinkedSession) -> Result<Value> {
    let conn = &session.conn;
    let raw = transaction()?;
    let bytes = bitcoin_bytes(&raw);
    let before = state(conn).await?;
    let preparation = select_legacy_p1(
        conn,
        NETWORK,
        ApplicationPosition::Preparation {
            anchor_height: HEIGHT - 1,
            anchor_hash: Some(BlockHash::from_byte_array([2; 32])),
        },
    )
    .await?;
    let recognized =
        recognize_transaction(&session.executor, &preparation, NETWORK, bytes.clone())?
            .map_err(|e| anyhow!(e))?
            .context("qualification transaction was not recognized")?;
    ensure!(
        recognized.txid == raw.compute_txid(),
        "recognition changed txid"
    );
    ensure!(
        recognized.inputs == [(0, OP_COUNT as u64)],
        "recognition changed operation positions"
    );
    let mut trailing = bytes.clone();
    trailing.push(1);
    ensure!(
        recognize_transaction(&session.executor, &preparation, NETWORK, trailing)?.is_err(),
        "trailing data accepted"
    );
    let mut ordinary = raw.clone();
    ordinary.input[0].witness = Witness::new();
    ensure!(
        recognize_transaction(
            &session.executor,
            &preparation,
            NETWORK,
            bitcoin_bytes(&ordinary)
        )?
        .map_err(|e| anyhow!(e))?
        .is_none(),
        "ordinary Bitcoin input recognized as Kontor"
    );

    let mut observations: Vec<Value> = Vec::new();
    let mut inspected = None;
    for (simulation, commit) in [(true, false), (false, false), (false, true)] {
        let selection = select_legacy_p1(
            conn,
            NETWORK,
            if simulation {
                ApplicationPosition::Simulation { height: HEIGHT }
            } else {
                ApplicationPosition::Block {
                    height: HEIGHT,
                    hash: BlockHash::from_byte_array([3; 32]),
                    consensus_height: HEIGHT,
                }
            },
        )
        .await?;
        ensure!(
            execute_transaction(session, &selection, NETWORK, &recognized, TX_INDEX, 1)
                .await
                .is_err(),
            "unadmitted transaction ran"
        );
        let lease = begin_canonical_unit(service, session, &selection, NETWORK, simulation).await?;
        let result = async {
            insert_block(conn, BlockRow::builder().height(HEIGHT).hash(BlockHash::from_byte_array([3; 32])).build()).await?;
            let tx_id = insert_transaction(conn, TransactionRow::builder().height(HEIGHT).tx_index(TX_INDEX)
                .txid(recognized.txid.to_string()).build()).await?;
            ensure!((session.executor.operations.transaction)(session.executor.owner.clone(), selection.envelope(), Arc::new(()), TX_INDEX, tx_id).await.is_err(),
                    "unrelated parsed transaction accepted");
            let failures = execute_transaction(session, &selection, NETWORK, &recognized, TX_INDEX, tx_id).await?;
            ensure!(failures.len() == 1 && failures[0].len() == OP_COUNT, "transaction result positions differ");
            for (index, failure) in failures[0].iter().enumerate() {
                ensure!(failure.is_some() == matches!(index, 5 | 6 | 10), "unexpected operation {index} result: {failure:?}");
            }
            let contract_error = conn.query("SELECT status FROM contract_results WHERE tx_id = ? AND op_index = 4 AND func = 'set-blob-then-fail'", [tx_id]).await?
                .next().await?.context("missing contract-error receipt")?;
            ensure!(contract_error.get::<String>(0)? == "ContractErr", "contract result error lost its receipt classification");
            let usage = conn.query("SELECT user_fuel, system_fuel, deposit_fuel FROM transaction_execution_usage WHERE tx_id = ?", [tx_id]).await?
                .next().await?.context("missing transaction usage")?;
            let usage: (i64, i64, i64) = (usage.get(0)?, usage.get(1)?, usage.get(2)?);
            ensure!(usage.0 > 0 && usage.1 > 0 && usage.2 > 0, "transaction did not exercise all fuel categories: {usage:?}");
            if simulation {
                let result = (session.executor.operations.inspect)(session.executor.owner.clone(), selection.envelope(), recognized.payload(&selection, NETWORK)?, TX_INDEX)
                    .await.map_err(HostFailure::from)?;
                inspected = Some(serde_json::from_slice::<Value>(&result)?);
            }
            Ok(json!({"failures":failures,"usage":usage,"state":state(conn).await?}))
        }.await;
        let observed = finish_canonical_unit(lease, result, commit).await?;
        ensure!(conn.is_autocommit(), "transaction retained SQL authority");
        ensure!(
            service.active_roots().await == 0,
            "transaction retained owner root"
        );
        if !commit {
            ensure!(
                state(conn).await? == before,
                "simulation or rollback changed canonical state"
            );
        }
        if let Some(previous) = observations.first() {
            ensure!(
                &observed == previous,
                "simulation, rollback replay and commit disagree"
            );
        }
        observations.push(observed);
    }
    Ok(
        json!({"raw_sha256":hex::encode(Sha256::digest(&bytes)),"counter_sha256":hex::encode(Sha256::digest(COUNTER)),"proxy_sha256":hex::encode(Sha256::digest(PROXY)),
        "recognition":{"txid":recognized.txid.to_string(),"batchable":recognized.batchable,"inputs":recognized.inputs},
        "inspection":inspected,"executions":observations}),
    )
}
