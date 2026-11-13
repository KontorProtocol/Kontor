use anyhow::{Context, Result, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::{
    Amount, Block, OutPoint, ScriptBuf, Transaction, TxOut, Witness, consensus::serialize,
    hashes::Hash,
};
use indexer_types::{ContractAddress, Inst, InstKind, Insts};
use libsql::Connection;
use serde_json::{Value, json};
use stdlib::to_wave_expr;
use tempfile::TempDir;

use super::fixture::{append, open, snapshot};
use crate::database::certified_history::{self, completion};
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::{get_transaction_by_txid, get_transaction_execution_usage};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::certified::qualification::fixture::raw_transaction_at_with_lock_time;
use crate::reactor::execution::ExecutionStep;
use crate::runtime::Decimal;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) fn transaction() -> Result<Transaction> {
    let mut previous = OutPoint::null();
    previous.vout = 0;
    transaction_at(previous, LockTime::ZERO)
}

pub(super) fn transaction_at(previous: OutPoint, lock_time: LockTime) -> Result<Transaction> {
    raw_transaction_at_with_lock_time(
        Insts::direct(vec![
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: ContractAddress {
                        name: "token".into(),
                        height: 0,
                        tx_index: 0,
                    },
                    expr: format!("mint({})", to_wave_expr(Decimal::from("1"))),
                },
            },
        ]),
        previous,
        lock_time,
    )
}

pub(super) fn finish_block(block: &mut Block) -> Result<()> {
    block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
    let commitment = Block::compute_witness_commitment(
        &block.witness_root().context("confirmation witness root")?,
        &[0; 32],
    );
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block
        .compute_merkle_root()
        .context("confirmation merkle root")?;
    Ok(())
}

async fn transaction_receipts(conn: &Connection, tx_id: u64) -> Result<Vec<Vec<String>>> {
    let mut rows = conn
        .query(
            "SELECT * FROM contract_results WHERE tx_id = ?1 ORDER BY id",
            [tx_id],
        )
        .await?;
    let columns = rows.column_count();
    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        let mut values = Vec::new();
        for column in 0..columns {
            values.push(format!("{:?}", row.get_value(column)?));
        }
        result.push(values);
    }
    Ok(result)
}

pub(super) async fn assert_paid_mint(conn: &Connection, tx_id: u64) -> Result<()> {
    let mut receipts = conn
        .query(
            "SELECT count(*) FROM contract_results WHERE tx_id = ?1 AND op_index = 1
         AND func = 'mint' AND payer_signer_id IS NOT NULL AND gas > 0 AND status = 'Ok'",
            [tx_id],
        )
        .await?;
    ensure!(
        receipts
            .next()
            .await?
            .context("paid mint receipt count")?
            .get::<i64>(0)?
            == 1,
        "fixture must execute the paid mint, issuance alone is insufficient"
    );
    Ok(())
}

// Branch from the existing H=2 activation fixture so this check does not change
// the unconfirmed transaction needed by the source scenario's finality rollback.
pub(super) async fn run(
    source: &Connection,
    service: &OwnerService,
    activation_block: &Block,
    transaction: &Transaction,
    first: ExecutionIdentity,
    second: ExecutionIdentity,
) -> Result<Value> {
    let replacement = Box::pin(super::replacement::run(
        source,
        service,
        activation_block,
        transaction,
        second,
    ))
    .await?;
    let directory = TempDir::new()?;
    snapshot(source, directory.path()).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let txid = transaction.compute_txid().to_string();
    let original = get_transaction_by_txid(&conn, &txid)
        .await?
        .context("P1 batch transaction")?;
    ensure!(
        original.height == 1
            && original.batch_height == Some(2)
            && original.confirmed_height.is_none()
    );
    let usage = get_transaction_execution_usage(&conn, original.id)
        .await?
        .context("P1 gas usage")?;
    ensure!(
        usage.user_fuel > 0,
        "fixture must exercise charged contract work"
    );
    assert_paid_mint(&conn, original.id).await?;
    let before = full_state(&conn).await?;
    let original_receipts = transaction_receipts(&conn, original.id).await?;

    let batch = ExactInput::batch(
        execution.protocol_context,
        2,
        activation_block.block_hash(),
        &[],
    );
    let batch_height = append(&conn, batch?).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let mut applications = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut old_batch = false;
    let mut new_batch = false;
    while let Some(row) = applications.next().await? {
        let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        if let ApplicationSource::Batch { exclusions, .. } = application.source {
            if exclusions.consensus_height == 2 {
                ensure!(application.execution == first);
                old_batch = true;
            } else if exclusions.consensus_height == batch_height {
                ensure!(application.execution == second);
                new_batch = true;
            }
        }
    }
    ensure!(
        old_batch && new_batch,
        "Batch(H) did not select P2 after the P1 batch"
    );
    let mut block = activation_block.clone();
    block.header.prev_blockhash = activation_block.block_hash();
    block.header.nonce = block.header.nonce.wrapping_add(1);
    block.txdata.push(transaction.clone());
    finish_block(&mut block)?;
    let input = ExactInput::block(execution.protocol_context, 3, serialize(&block));
    let height = append(&conn, input.context("confirmation block encoding")?).await?;
    let mut confirmed = false;
    for _ in 0..16 {
        match execution.step_certified_closure(height).await? {
            ExecutionStep::Block(applied) => {
                ensure!(applied.block.transactions.len() == 1);
                ensure!(
                    applied.unbatched_count == 0 && applied.executed_ops == 0,
                    "confirmation executed the earlier P1 transaction again"
                );
                confirmed = true;
            }
            ExecutionStep::Complete => break,
            _ => {}
        }
    }
    ensure!(confirmed && certified_history::frontier(&conn).await?.closed_height == height);
    let after = get_transaction_by_txid(&conn, &txid)
        .await?
        .context("confirmed transaction")?;
    ensure!(
        after.id == original.id
            && after.height == original.height
            && after.batch_height == original.batch_height
    );
    ensure!(
        after.confirmed_height == Some(3)
            && get_confirmation_position(&conn, &txid).await? == Some(1)
    );
    ensure!(get_transaction_execution_usage(&conn, original.id).await? == Some(usage));
    let final_state = full_state(&conn).await?;
    ensure!(
        transaction_receipts(&conn, original.id).await? == original_receipts,
        "confirmation changed the original transaction receipts"
    );
    for table in ["transaction_execution_usage"] {
        ensure!(
            before[table] == final_state[table],
            "confirmation changed {table}"
        );
    }
    let closed = completion::completed(&conn, height).await?;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(full_state(&reopened.db_conn()).await? == final_state);
    ensure!(completion::completed(&reopened.db_conn(), height).await? == closed);
    ensure!(service.active_roots().await == 0);
    Ok(json!({"p1_paid_transaction": true, "p2_batch_at_h": true,
        "confirmation_without_execution": true, "unchanged_usage_and_receipts": true,
        "reopened_state_matches": true, "confirmation_height": 3, "closed_decisions": height,
        "replacement": replacement}))
}
