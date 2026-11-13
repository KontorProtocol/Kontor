use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bitcoin::{
    Block, OutPoint, Transaction,
    blockdata::constants::genesis_block,
    consensus::serialize,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use indexer_types::{ContractAddress, Inst, InstKind, Insts};
use libsql::{Connection, params};
use serde_json::{Value, json};
use stdlib::{KeyElement, KeyPath, to_wave_expr};
use tempfile::TempDir;

use super::NETWORK;
use super::fixture::{append, open, seed};
use crate::database::certified_history::{self, control};
use crate::database::queries::get_transaction_by_txid;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::v2::FIXTURE_NAME;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::certified::qualification::fixture::raw_transaction_at;
use crate::reactor::execution::ExecutionContext;
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::Decimal;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

fn transaction(expressions: &[&str], issuance: bool, previous: OutPoint) -> Result<Transaction> {
    let mut instructions = Vec::new();
    if issuance {
        instructions.push(Inst {
            gas_limit: 100_000,
            kind: InstKind::Issuance,
        });
    }
    instructions.extend(expressions.iter().map(|expr| Inst {
        gas_limit: 100_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "token".into(),
                height: 0,
                tx_index: 0,
            },
            expr: (*expr).into(),
        },
    }));
    raw_transaction_at(Insts::direct(instructions), previous)
}

async fn batch(
    execution: &mut ExecutionContext<RuntimeExecutor>,
    block: &Block,
    bitcoin_height: u64,
    transaction: &Transaction,
    results: usize,
    failures: usize,
) -> Result<()> {
    let conn = execution.db_conn();
    let input = ExactInput::batch(
        execution.protocol_context,
        bitcoin_height,
        block.block_hash(),
        std::slice::from_ref(transaction),
    )?;
    append(&conn, input).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let row = get_transaction_by_txid(&conn, &transaction.compute_txid().to_string())
        .await?
        .context("token fixture transaction missing")?;
    let mut receipts = conn.query(
        "SELECT status, gas, payer_signer_id, func, value FROM contract_results WHERE tx_id = ?1 ORDER BY id",
        [row.id],
    ).await?;
    let (mut count, mut failed, mut charged) = (0, 0, 0);
    let mut observations = Vec::new();
    while let Some(receipt) = receipts.next().await? {
        count += 1;
        failed += usize::from(receipt.get::<String>(0)? != "Ok");
        charged +=
            usize::from(receipt.get::<i64>(1)? > 0 && receipt.get::<Option<i64>>(2)?.is_some());
        observations.push((receipt.get::<String>(3)?, receipt.get::<Option<String>>(4)?));
    }
    ensure!(
        count == results && failed == failures && charged > 0,
        "token calls did not execute as intended: expected {results} receipts/{failures} failures, got {count}/{failed}, {charged} paid; {observations:?}"
    );
    Ok(())
}

// The public balances API omits system holders. Read the full persisted ledger
// independently so a missing burner/core/pool adjustment cannot pass this check.
async fn ledger(conn: &Connection, migrated: bool) -> Result<BTreeMap<String, Decimal>> {
    let prefix = KeyPath::new().push_interned(0);
    let count_key = KeyPath::new().push_interned(5);
    let mut rows = conn
        .query(
            "SELECT s.path, s.value FROM current_contract_state c JOIN contract_state s
         ON s.contract_id = c.contract_id AND s.path = c.path AND s.height = c.height
         WHERE c.contract_id = 1 AND s.deleted = 0 ORDER BY s.path",
            (),
        )
        .await?;
    let mut balances = BTreeMap::new();
    while let Some(row) = rows.next().await? {
        let key = row.get::<Vec<u8>>(0)?;
        let value = row.get::<Vec<u8>>(1)?;
        if key == count_key.as_bytes() {
            bail!("qualification migration changed the token schema");
        } else if let Some(holder) = key.strip_prefix(prefix.as_bytes()) {
            let (holder, tail) = String::decode_from(holder)
                .map_err(|error| anyhow!("invalid stored holder: {error:?}"))?;
            ensure!(tail.is_empty());
            let encoded = postcard::from_bytes::<Vec<u8>>(&value)?;
            let (balance, tail) = Decimal::decode_from(&encoded)
                .map_err(|error| anyhow!("invalid stored balance: {error:?}"))?;
            ensure!(tail.is_empty());
            balances.insert(holder, balance);
        }
    }
    let marker = conn.query(
        "SELECT s.value FROM contracts k JOIN current_contract_state c ON c.contract_id = k.id
         JOIN contract_state s ON s.contract_id = c.contract_id AND s.path = c.path AND s.height = c.height
         WHERE k.name = ?1 AND k.tx_index = 4294967295 AND s.path = ?2 AND s.deleted = 0",
        params![FIXTURE_NAME, KeyPath::new().push_interned(0).as_bytes()],
    ).await?.next().await?.map(|row| row.get::<Vec<u8>>(0)).transpose()?;
    ensure!(
        marker == migrated.then_some(vec![2]),
        "fixture initialization differs"
    );
    ensure!(
        balances.get("core").copied().unwrap_or_default() == Decimal::default(),
        "gas escrow was not refunded"
    );
    Ok(balances)
}

pub(super) async fn run(service: &OwnerService) -> Result<Value> {
    let directory = TempDir::new()?;
    let target = seed(directory.path(), service, 2).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let first = genesis_block(NETWORK);
    let initial = transaction(
        &[
            &format!("mint({})", to_wave_expr(Decimal::from("20"))),
            &format!("attach(0, {})", to_wave_expr(Decimal::from("5"))),
        ],
        true,
        OutPoint {
            vout: 0,
            ..OutPoint::null()
        },
    )?;
    batch(&mut execution, &first, 1, &initial, 3, 0).await?;
    let before = ledger(&conn, false).await?;
    let original_utxo = format!("{}:0", initial.compute_txid());
    ensure!(before.get(&original_utxo) == Some(&Decimal::from("5")));
    ensure!(
        before
            .get("burn")
            .is_some_and(|amount| *amount > Decimal::default())
    );

    let mut block = first;
    block.header.prev_blockhash = block.block_hash();
    block.header.nonce = block.header.nonce.wrapping_add(1);
    let input = ExactInput::block(execution.protocol_context, 2, serialize(&block))?;
    let height = certified_history::frontier(&conn).await?.closed_height + 1;
    let transition = control::expected_transition(
        &conn,
        execution.protocol_context,
        &input.descriptor().command,
        height,
    )
    .await?
    .context("qualification contract transition")?;
    append(&conn, input.with_transition(transition.descriptor)?).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    ensure!(execution.protocol_context.protocol == target);
    let migrated = ledger(&conn, true).await?;
    ensure!(migrated.get(&original_utxo) == before.get(&original_utxo));

    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[38; 32])?);
    let self_transfer = format!(
        "transfer(x-only-pubkey(\"{}\"), {})",
        key.x_only_public_key().0,
        to_wave_expr(Decimal::from("1"))
    );
    let calls = transaction(
        &[
            &format!("mint({})", to_wave_expr(Decimal::from("10"))),
            &format!(
                "transfer(ordering-pool, {})",
                to_wave_expr(Decimal::from("2"))
            ),
            &self_transfer,
            &format!("burn({})", to_wave_expr(Decimal::from("1"))),
        ],
        false,
        OutPoint {
            txid: initial.compute_txid(),
            vout: 1,
        },
    )?;
    batch(&mut execution, &block, 2, &calls, 4, 0).await?;
    let after_calls = ledger(&conn, true).await?;
    ensure!(
        after_calls
            .get("ordering_pool")
            .is_some_and(|amount| *amount >= Decimal::from("2"))
    );

    let attached = transaction(
        &[&format!("attach(0, {})", to_wave_expr(Decimal::from("3")))],
        false,
        OutPoint {
            txid: calls.compute_txid(),
            vout: 0,
        },
    )?;
    batch(&mut execution, &block, 2, &attached, 1, 0).await?;
    let after_attach = ledger(&conn, true).await?;
    let attached_utxo = format!("{}:0", attached.compute_txid());
    ensure!(after_attach.get(&attached_utxo) == Some(&Decimal::from("3")));

    let detached = transaction(
        &["detach()"],
        false,
        OutPoint {
            txid: attached.compute_txid(),
            vout: 0,
        },
    )?;
    batch(&mut execution, &block, 2, &detached, 1, 0).await?;
    let after_detach = ledger(&conn, true).await?;
    ensure!(
        after_detach
            .get(&attached_utxo)
            .copied()
            .unwrap_or_default()
            == Decimal::default()
    );
    ensure!(after_detach.get(&original_utxo) == Some(&Decimal::from("5")));

    let failed = transaction(
        &[&format!(
            "transfer(storage-pool, {})",
            to_wave_expr(Decimal::from("1000000"))
        )],
        false,
        OutPoint {
            txid: detached.compute_txid(),
            vout: 0,
        },
    )?;
    batch(&mut execution, &block, 2, &failed, 1, 1).await?;
    let final_ledger = ledger(&conn, true).await?;
    ensure!(final_ledger.get("storage_pool") == after_detach.get("storage_pool"));
    let expected = full_state(&conn).await?;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(full_state(&reopened.db_conn()).await? == expected);
    ensure!(ledger(&reopened.db_conn(), true).await? == final_ledger);
    ensure!(service.active_roots().await == 0);
    Ok(
        json!({"migration_from_populated_p1": true, "paid_mint_transfer_burn": true,
              "self_transfer": true, "gas_escrow_refunded": true,
              "utxo_attach_detach": true, "failed_call_consistent": true,
              "fixture_initialized": true, "common_token_schema_preserved": true, "reopened_state_matches": true,
              "checked_snapshots": 7, "closed_decisions": 7}),
    )
}
