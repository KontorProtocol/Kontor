use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{BlockHash, Transaction};
use indexer_types::{Inst, InstKind, Insts};
use libsql::{Connection, Value, params};
use malachitebft_core_types::Round;
use malachitebft_engine::host::Next;
use malachitebft_engine::node::NodeRef;
use tempfile::TempDir;
use testlib::sample_provenance;
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::Reactor;
use super::certified_fixture;
use super::execution::ExecutionStep;
use super::executor::RuntimeExecutor;
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Ctx, Height, Value as ConsensusValue};
use crate::database::certified_history;
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::get_transaction_by_txid;
use crate::database::receipt_stream::{recovery_boundary, stream_state};
use crate::runtime::{ContractAddress, Decimal, GenesisValidator, Runtime, from_wave_expr};
use crate::test_utils::{signed_confirmation_call, test_genesis};

#[cfg(feature = "protocol-qualification")]
mod parity;

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

async fn effects(conn: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
    let mut snapshot = Vec::new();
    for table in [
        "contracts",
        "contract_provenance",
        "contract_state",
        "current_contract_state",
        "contract_results",
        "transaction_execution_usage",
        "depositor_footprint",
    ] {
        // Certified blocks also run native lifecycle operations. Compare all
        // transaction effects, excluding lifecycle-only writes and receipts.
        let predicate = match table {
            "contract_state" | "contract_results" => "WHERE tx_id IS NOT NULL",
            "current_contract_state" => {
                "WHERE contract_id IN (SELECT id FROM contracts WHERE name = 'confirmation-fixture')"
            }
            _ => "",
        };
        let mut rows = conn
            .query(
                &format!("SELECT * FROM {table} {predicate} ORDER BY 1, 2"),
                (),
            )
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..count)
                    .map(|column| row.get_value(column))
                    .collect::<libsql::Result<Vec<_>>>()?,
            );
        }
        snapshot.push(values);
    }
    Ok(snapshot)
}

async fn assert_successful_write(
    runtime: &mut Runtime,
    txid: &str,
    address: &ContractAddress,
) -> Result<()> {
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT r.status, r.value, r.func, r.gas FROM contract_results r
         JOIN transactions t ON t.id = r.tx_id WHERE t.txid = ?",
            params![txid],
        )
        .await?;
    let row = rows.next().await?.context("successful write receipt")?;
    assert_eq!(row.get::<String>(0)?, "Ok");
    assert_eq!(row.get::<String>(1)?, "\"é\\n\"");
    assert_eq!(row.get::<String>(2)?, "write-result-payload");
    assert!(row.get::<u64>(3)? > 0);
    assert!(rows.next().await?.is_none());
    let state: Vec<u64> = from_wave_expr(
        &runtime
            .execute(None, None, address, "storage-state()")
            .await?,
    );
    assert_eq!(state, [1, 0, 0, 1]);
    Ok(())
}

async fn start_decision(
    reactor: &mut Reactor<RuntimeExecutor>,
    value: ConsensusValue,
) -> Result<(u64, oneshot::Receiver<Next<Ctx>>)> {
    let height = certified_history::frontier(&reactor.db_conn())
        .await?
        .authenticated_height
        + 1;
    let round = Round::new(0);
    let proof = certified_fixture::certificate(
        &PrivateKey::from([17; 32]),
        &value,
        Height::new(height),
        round,
    );
    certified_fixture::proposal(reactor, value, Height::new(height), round);
    let (reply, received) = oneshot::channel();
    reactor
        .consensus
        .receive_decision(&reactor.db_conn(), proof.clone(), reply)
        .await?;
    received.await?;
    let (reply, next) = oneshot::channel();
    reactor.handle_finalized(proof, reply).await?;
    Ok((height, next))
}

async fn finish_decision(
    reactor: &mut Reactor<RuntimeExecutor>,
    height: u64,
    next: oneshot::Receiver<Next<Ctx>>,
) -> Result<Vec<(usize, u64)>> {
    let mut blocks = Vec::new();
    loop {
        match reactor.execution.step_certified_closure(height).await? {
            ExecutionStep::Complete => break,
            ExecutionStep::Block(applied) => {
                blocks.push((applied.unbatched_count, applied.executed_ops))
            }
            _ => {}
        }
    }
    reactor.advance().await?;
    assert!(
        matches!(next.await?, Next::Start(next_height, _) if next_height == Height::new(height + 1))
    );
    Ok(blocks)
}

fn certified_confirmation_block(
    tx: &Transaction,
    position: usize,
    parent: BlockHash,
) -> BlockInput {
    assert!(position >= 2);
    let mut transactions = Vec::new();
    for index in 1..position {
        let mut unrelated = tx.clone();
        unrelated.input[0].witness.clear();
        unrelated.lock_time = LockTime::from_consensus(index as u32);
        transactions.push(unrelated);
    }
    transactions.push(tx.clone());
    certified_fixture::block(2, parent, position as u32, transactions)
}

async fn run_case(batched: bool) -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[71; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
    let conn = reactor.db_conn();
    let result = async {
        let setup = certified_fixture::transaction(
            &owner,
            Insts::direct(vec![
                Inst {
                    gas_limit: 100_000,
                    kind: InstKind::Issuance,
                },
                Inst {
                    gas_limit: 100_000,
                    kind: InstKind::Publish {
                        name: "confirmation-fixture".into(),
                        bytes: include_bytes!(
                            "../../../../test-contracts/binaries/error_test.wasm.br"
                        )
                        .to_vec(),
                        provenance: sample_provenance(),
                    },
                },
            ]),
            0,
        )?;
        let block = certified_fixture::block(
            1,
            certified_fixture::empty_block(1).prev_hash,
            0,
            vec![setup],
        );
        let anchor = block.hash;
        let value =
            ConsensusValue::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        assert_eq!(finish_decision(&mut reactor, height, next).await?, [(1, 2)]);
        let address = ContractAddress {
            name: "confirmation-fixture".into(),
            height: 1,
            tx_index: 1,
        };
        let raw = signed_confirmation_call(&owner, address.clone())?;
        let txid = raw.compute_txid().to_string();
        let original = effects(&conn).await?;
        if batched {
            let value = ConsensusValue::new_batch_raw(
                reactor.consensus.protocol_context,
                1,
                anchor,
                vec![raw.clone()],
            )?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            assert_eq!(height, 2);
            assert!(
                finish_decision(&mut reactor, height, next)
                    .await?
                    .is_empty()
            );
            let row = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("batch executed")?;
            assert_eq!(row.height, 1);
            assert_eq!(row.batch_height, Some(2));
            assert_eq!(row.confirmed_height, None);
            assert_eq!(get_confirmation_position(&conn, &txid).await?, None);
            assert_successful_write(
                &mut *reactor.execution.test_runtime().await,
                &txid,
                &address,
            )
            .await?;
        }
        let before_confirmation = effects(&conn).await?;
        let before_block_stream = stream_state(&conn).await?;
        let block = certified_confirmation_block(&raw, 2, anchor);
        let value =
            ConsensusValue::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        assert_eq!(
            finish_decision(&mut reactor, height, next).await?,
            [(usize::from(!batched), u64::from(!batched))]
        );
        let row = get_transaction_by_txid(&conn, &txid)
            .await?
            .context("confirmed transaction")?;
        assert_eq!(row.confirmed_height, Some(2));
        assert_eq!(row.tx_index, Some(0));
        assert_eq!(get_confirmation_position(&conn, &txid).await?, Some(2));
        assert_successful_write(
            &mut *reactor.execution.test_runtime().await,
            &txid,
            &address,
        )
        .await?;
        let applied = effects(&conn).await?;
        assert_ne!(applied, original);
        if batched {
            assert_eq!(
                applied, before_confirmation,
                "confirmation must not execute or charge again"
            );
            let before_stream = stream_state(&conn).await?;
            let replacement = certified_confirmation_block(&raw, 4, anchor);
            assert_ne!(replacement.hash, block.hash);
            let value = ConsensusValue::from_input(
                replacement.exact_input(reactor.consensus.protocol_context)?,
            )?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            assert!(matches!(
                reactor.execution.step_certified_closure(height).await?,
                ExecutionStep::RolledBack(1)
            ));
            let after_stream = stream_state(&conn).await?;
            let recovery = recovery_boundary(
                &conn,
                &after_stream,
                before_stream.generation,
                before_stream.max_result_id,
            )
            .await?
            .expect("confirmation rollback must notify receipt consumers");
            assert_eq!(recovery.cursor, before_block_stream.max_result_id);
            assert_eq!(recovery.surviving_height, 1);
            let rolled_back = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("batch survives reorg")?;
            assert_eq!(rolled_back.id, row.id);
            assert_eq!(rolled_back.height, 1);
            assert_eq!(rolled_back.batch_height, Some(2));
            assert_eq!(rolled_back.confirmed_height, None);
            assert_eq!(get_confirmation_position(&conn, &txid).await?, None);
            assert_eq!(effects(&conn).await?, applied);
            assert_eq!(finish_decision(&mut reactor, height, next).await?, [(0, 0)]);
            assert_eq!(get_confirmation_position(&conn, &txid).await?, Some(4));
            let reconfirmed = get_transaction_by_txid(&conn, &txid).await?.unwrap();
            assert_eq!(reconfirmed.id, row.id);
            assert_eq!(reconfirmed.tx_index, Some(0));
            assert_eq!(effects(&conn).await?, applied);
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn unbatched_raw_confirmation_position_differs_from_legacy_ordinal() -> Result<()> {
    run_case(false).await
}

#[tokio::test]
async fn batched_confirmation_reorg_and_reconfirmation_preserve_execution_effects() -> Result<()> {
    run_case(true).await
}
