use anyhow::{Context, Result, ensure};
use bitcoin::{Block, Transaction, absolute::LockTime, consensus::serialize};
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::confirmation::{assert_paid_mint, finish_block};
use super::fixture::{append, open, snapshot};
use crate::database::certified_history::{self, activation};
use crate::database::queries::{get_transaction_by_txid, get_transaction_execution_usage};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) async fn run(
    source: &Connection,
    service: &OwnerService,
    activation_block: &Block,
    original: &Transaction,
    second: ExecutionIdentity,
) -> Result<Value> {
    let directory = TempDir::new()?;
    snapshot(source, directory.path()).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let before = activation::current(&conn)
        .await?
        .context("initial migration")?;
    let original_txid = original.compute_txid().to_string();
    let original_row = get_transaction_by_txid(&conn, &original_txid)
        .await?
        .context("unconfirmed original")?;
    ensure!(original_row.confirmed_height.is_none() && original_row.batch_height.is_some());
    assert_paid_mint(&conn, original_row.id).await?;

    // The Bitcoin ingestion boundary supplies an already accepted replacement.
    // This checks Kontor's execution/finality behavior, not Bitcoin mempool policy
    // or script validation (the shared transaction fixture has a dummy signature).
    let mut replacement = original.clone();
    replacement.lock_time = LockTime::from_height(1)?;
    let replacement_txid = replacement.compute_txid().to_string();
    ensure!(replacement_txid != original_txid);
    ensure!(replacement.input[0].previous_output == original.input[0].previous_output);
    let mut block = activation_block.clone();
    for height in 3..=7 {
        let parent = block.block_hash();
        block = activation_block.clone();
        block.header.prev_blockhash = parent;
        block.header.nonce = block.header.nonce.wrapping_add(height as u32);
        if height == 3 {
            block.txdata.push(replacement.clone());
            finish_block(&mut block)?;
        }
        let input = ExactInput::block(execution.protocol_context, height, serialize(&block))?;
        append(&conn, input).await?;
        ensure!(execution.recover(&Shutdown::new().signal()).await?);
    }
    ensure!(
        get_transaction_by_txid(&conn, &original_txid)
            .await?
            .is_none()
    );
    let row = get_transaction_by_txid(&conn, &replacement_txid)
        .await?
        .context("canonical replacement")?;
    ensure!(row.height == 3 && row.confirmed_height == Some(3) && row.batch_height.is_none());
    assert_paid_mint(&conn, row.id).await?;
    ensure!(
        get_transaction_execution_usage(&conn, row.id)
            .await?
            .context("replacement usage")?
            .user_fuel
            > 0
    );
    let mut charges = conn
        .query("SELECT count(*) FROM transaction_execution_usage", ())
        .await?;
    ensure!(
        charges
            .next()
            .await?
            .context("canonical charge count")?
            .get::<i64>(0)?
            == 1
    );
    let after = activation::current(&conn)
        .await?
        .context("replayed migration")?;
    ensure!(after.application.migration_key()? != before.application.migration_key()?);
    let mut applications = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut selected = false;
    while let Some(row) = applications.next().await? {
        let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        if matches!(
            application.source,
            ApplicationSource::BlockLifecycle { height: 3, .. }
        ) {
            ensure!(application.execution == second);
            selected = true;
        }
    }
    ensure!(selected);
    let expected = full_state(&conn).await?;
    let closed = certified_history::frontier(&conn).await?.closed_height;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(full_state(&reopened.db_conn()).await? == expected);
    Ok(
        json!({"same_outpoint_replacement": true, "original_removed": true,
        "p2_replacement_execution": true, "one_canonical_charge": true,
        "migration_replayed": true, "reopened_state_matches": true,
        "replacement_height": 3, "finality_height": 7, "closed_decisions": closed}),
    )
}
