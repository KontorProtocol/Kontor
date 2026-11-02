use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use bitcoin::Network;
use indexer_types::{Block, BlockRow, ContractAddress, OpKind, ResultRow, TransactionRow};
use libsql::Connection;
use serde_json::{Value, json};

use super::{GAS_LIMIT, Snapshot, receipts, state};
use crate::block::TxWalker;
use crate::built_info::GIT_COMMIT_HASH;
use crate::database::Writer;
use crate::database::queries::{
    footprint_cache_get, get_transaction_by_txid, get_transaction_execution_usage, insert_batch,
    insert_block, insert_transaction, live_deposit_gas_sum, select_latest_consensus_height,
};
use crate::runtime::fuel::ExecutionUsage;
use crate::runtime::numerics::{integer_to_string, mul_decimal, sub_decimal};
use crate::runtime::pricing::Pricing;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ComponentCache, Decimal, ExecutionError, Integer, Runtime, Storage, TransactionContext,
};

pub(super) struct Diagnostic {
    pub report: Value,
    rows: Vec<ResultRow>,
    usage: ExecutionUsage,
}

pub(super) fn money(value: Decimal) -> Result<String> {
    ensure!(value >= Decimal::default(), "negative diagnostic quantity");
    if value == Decimal::default() {
        return Ok("0".to_owned());
    }
    // Decimal's wire limbs are an integer coefficient at scale 18. Render
    // directly so small fees never acquire scientific notation in the schema.
    let digits = integer_to_string(Integer {
        r0: value.r0,
        r1: value.r1,
        r2: value.r2,
        r3: value.r3,
        sign: value.sign,
    });
    let padded = format!("{digits:0>19}");
    let (whole, fractional) = padded.split_at(padded.len() - 18);
    let fractional = fractional.trim_end_matches('0');
    Ok(if fractional.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fractional}")
    })
}

async fn balance(runtime: &mut Runtime, holder: HolderRef) -> Result<Decimal> {
    Ok(token::balance(runtime, holder).await?.unwrap_or_default())
}

async fn floor(conn: &Connection, signer_id: u64) -> Result<Decimal> {
    let actual = live_deposit_gas_sum(conn, signer_id).await?;
    ensure!(footprint_cache_get(conn, signer_id).await?.unwrap_or(0) == actual);
    Pricing::storage_collateral(actual)
}

impl Diagnostic {
    pub(super) async fn compare(&self, conn: &Connection, rows: &[ResultRow]) -> Result<()> {
        let txid = self.rows[0].txid.as_deref().context("diagnostic txid")?;
        let paid: Vec<_> = rows
            .iter()
            .filter(|row| row.txid.as_deref() == Some(txid))
            .collect();
        ensure!(
            paid.len() == self.rows.len(),
            "diagnostic receipt count differs"
        );
        for (actual, expected) in paid.iter().zip(&self.rows) {
            ensure!(
                serde_json::to_value(actual)? == serde_json::to_value(expected)?,
                "independent numeric diagnostic receipt differs from full block"
            );
        }
        let transaction = get_transaction_by_txid(conn, txid)
            .await?
            .context("missing replay transaction")?;
        let usage = get_transaction_execution_usage(conn, transaction.id)
            .await?
            .context("missing replay usage")?;
        // Materializing these direct calls and setting their contexts performs
        // database work only. No metered VM work sits outside the three scopes.
        ensure!(
            usage == self.usage,
            "per-operation usage differs from transaction usage"
        );
        Ok(())
    }
}

pub(super) async fn generate(
    snapshot: &Snapshot,
    directory: &Path,
    block: &Block,
    addresses: &[ContractAddress; 2],
    raw_block_sha256: &str,
) -> Result<Diagnostic> {
    snapshot.copy_to(&directory.join("numeric.db"))?;
    let writer = Writer::new(directory, "numeric.db").await?;
    let conn = writer.connection();
    let storage = Storage::builder()
        .height(
            block
                .height
                .checked_sub(1)
                .context("missing anchor height")?,
        )
        .conn(conn.clone())
        .build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.network = Network::Regtest;
    ensure!(runtime.gas_to_fuel_multiplier == 1000);
    runtime.storage.savepoint().await?;
    let next = select_latest_consensus_height(&conn)
        .await?
        .unwrap_or(0)
        .checked_add(1)
        .context("diagnostic consensus height overflow")?;
    insert_batch(
        &conn,
        next,
        block.height,
        &block.hash.to_string(),
        &[],
        true,
    )
    .await?;
    insert_block(&conn, BlockRow::from(block)).await?;
    ensure!(block.transactions.len() == 1);
    let transaction = &block.transactions[0];
    ensure!(transaction.inputs.len() == 1);
    let input = &transaction.inputs[0];
    ensure!(!input.insts.is_aggregate() && input.insts.ops.len() == 3);
    let tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(block.height)
            .tx_index(0)
            .confirmed_height(block.height)
            .txid(transaction.txid.to_string())
            .build(),
    )
    .await?;
    runtime.storage.height = block.height;
    let identity = runtime
        .get_or_create_identity(&input.x_only_pubkey.to_string())
        .await?;
    let signer = Signer::Id(identity);
    let signer_id = signer.signer_id().context("diagnostic signer")?;
    let mut walker = TxWalker::new();
    let mut operations = Vec::new();
    let mut usage_sum = ExecutionUsage::default();
    for (op_index, instruction) in input.insts.ops.iter().enumerate() {
        let op = walker.materialize(input, op_index, signer_id, None, instruction)?;
        let OpKind::Call { contract, expr, .. } = &op.kind else {
            bail!("numeric diagnostic only supports the three direct calls");
        };
        ensure!(op.metadata.signer_id == signer_id && op.metadata.payment.signer_id == signer_id);
        ensure!(op.metadata.payment.gas_limit == GAS_LIMIT);
        let payer_before = balance(&mut runtime, HolderRef::SignerId(signer_id)).await?;
        let burner_before = balance(&mut runtime, HolderRef::Burner).await?;
        let floor_before = floor(&conn, signer_id).await?;
        runtime
            .set_context(
                block.height,
                Some(TransactionContext {
                    tx_id: Some(tx_id),
                    tx_index: transaction.index,
                    input_index: input.input_index,
                    op_index: u32::try_from(op_index)?,
                    txid: transaction.txid,
                }),
                Some(input.previous_output),
                transaction.op_return_raw.clone(),
            )
            .await;
        let previous = runtime.start_usage();
        let result = runtime
            .execute(
                Some(&signer),
                Some(op.metadata.payment.clone()),
                contract,
                expr,
            )
            .await;
        let usage = runtime.finish_usage(previous)?;
        let error_message = match result {
            Ok(_) => None,
            Err(ExecutionError::Deterministic(error)) => Some(format!("{error:#}")),
            Err(ExecutionError::NonDeterministic(error)) => return Err(error),
        };
        let payer_after = balance(&mut runtime, HolderRef::SignerId(signer_id)).await?;
        let burner_after = balance(&mut runtime, HolderRef::Burner).await?;
        let floor_after = floor(&conn, signer_id).await?;
        let current = receipts(&conn, block.height).await?;
        ensure!(
            current.len() == op_index + 1,
            "unexpected diagnostic result rows"
        );
        let row = current.last().context("missing numeric receipt")?;
        ensure!(usage.deposit_fuel % 1000 == 0);
        let reserved = usage.deposit_fuel / 1000;
        ensure!(row.gas >= reserved && row.gas <= GAS_LIMIT);
        ensure!(
            row.gas
                == usage
                    .user_fuel
                    .checked_add(usage.deposit_fuel)
                    .context("fuel overflow")?
                    .div_ceil(1000)
                    .max(1)
        );
        let fee = mul_decimal(
            Decimal::try_from(row.gas - reserved)?,
            Decimal::from("0.000000001"),
        )?;
        ensure!(runtime.pricing.execution_fee(row.gas - reserved)? == fee);
        ensure!(sub_decimal(payer_before, payer_after)? == fee);
        ensure!(sub_decimal(burner_after, burner_before)? == fee);
        let storage_state = state(&mut runtime, contract).await?;
        if op_index == 1 {
            ensure!(reserved > 0 && floor_after == floor_before);
            ensure!(storage_state == [0, 0, 0, 0]);
            ensure!(state(&mut runtime, &addresses[0]).await? == [1, 0, 0, 1]);
        }
        operations.push(json!({
            "txid":transaction.txid.to_string(), "tx_index":transaction.index,
            "input_index":input.input_index, "op_index":op_index, "contract":contract.to_string(),
            "expression":expr, "status":row.status, "value":row.value, "gas":row.gas,
            "user_fuel":usage.user_fuel,"system_fuel":usage.system_fuel,"deposit_fuel":usage.deposit_fuel,
            "reserved_deposit_gas":reserved,"payer_before":money(payer_before)?,"payer_after":money(payer_after)?,
            "burner_before":money(burner_before)?,"burner_after":money(burner_after)?,
            "floor_before":money(floor_before)?,"floor_after":money(floor_after)?,
            "execution_fee":money(fee)?,"error_message":error_message,"storage_state":storage_state,
        }));
        usage_sum.user_fuel = usage_sum
            .user_fuel
            .checked_add(usage.user_fuel)
            .context("user fuel overflow")?;
        usage_sum.system_fuel = usage_sum
            .system_fuel
            .checked_add(usage.system_fuel)
            .context("system fuel overflow")?;
        usage_sum.deposit_fuel = usage_sum
            .deposit_fuel
            .checked_add(usage.deposit_fuel)
            .context("deposit fuel overflow")?;
    }
    let rows = receipts(&conn, block.height).await?;
    runtime.storage.commit().await?;
    Ok(Diagnostic {
        report: json!({"schema_version":1, "snapshot_sha256":snapshot.sha256,
            "raw_block_sha256":raw_block_sha256,"source_commit":GIT_COMMIT_HASH,"operations":operations}),
        rows,
        usage: usage_sum,
    })
}
