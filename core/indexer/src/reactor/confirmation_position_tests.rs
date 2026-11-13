use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
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
use crate::database::certified_history::{self, closure, reconcile, work};
use crate::database::confirmation::get_confirmation_position;
use crate::database::connection::new_connection;
use crate::database::queries::{executed_wtxid, get_transaction_by_txid};
use crate::database::receipt_stream::{recovery_boundary, stream_state};
use crate::runtime::numerics::sub_decimal;
use crate::runtime::token::api as token_api;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, GenesisValidator, Runtime, from_wave_expr};
use crate::test_utils::{signed_confirmation_call, signed_launch_transaction, test_genesis};

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

async fn token_balances(
    reactor: &mut Reactor<RuntimeExecutor>,
    owner: &Keypair,
) -> Result<(Decimal, Decimal)> {
    let mut runtime = reactor.execution.test_runtime().await;
    let payer = token_api::balance(
        &mut runtime,
        HolderRef::XOnlyPubkey(owner.x_only_public_key().0.to_string()),
    )
    .await?
    .context("payer balance unavailable")?;
    let burner = token_api::balance(&mut runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    Ok((payer, burner))
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
    certified_fixture::proposal(reactor, value, Height::new(height), round).await?;
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
        unrelated.input[0].previous_output.vout = index as u32;
        unrelated.lock_time = LockTime::from_consensus(index as u32);
        transactions.push(unrelated);
    }
    transactions.push(tx.clone());
    certified_fixture::block(2, parent, position as u32, transactions)
}

async fn run_case(batched: bool, conflict: bool) -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[71; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine.legacy_handle().actor.clone());
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
        let baseline_balances = if conflict {
            assert!(batched);
            Some(token_balances(&mut reactor, &owner).await?)
        } else {
            None
        };
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
        if conflict {
            let (payer_before, burner_before) = baseline_balances.context("missing baseline")?;
            let (payer_paid, burner_paid) = token_balances(&mut reactor, &owner).await?;
            let gas_fee = sub_decimal(payer_before, payer_paid)?;
            assert!(gas_fee > Decimal::from("0"));
            assert_eq!(sub_decimal(burner_paid, burner_before)?, gas_fee);

            let mut competing = raw.clone();
            competing.input[0].witness.clear();
            competing.output[0].value = Amount::from_sat(1);
            let block = certified_confirmation_block(&competing, 2, anchor);
            let value =
                ConsensusValue::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
            assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
            assert_eq!(effects(&conn).await?, original);
            assert_eq!(
                token_balances(&mut reactor, &owner).await?,
                (payer_before, burner_before)
            );

            let replacement = certified_fixture::block(2, anchor, 9, vec![]);
            let value = ConsensusValue::from_input(
                replacement.exact_input(reactor.consensus.protocol_context)?,
            )?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
            assert!(get_transaction_by_txid(&conn, &txid).await?.is_some());
            assert_eq!(effects(&conn).await?, before_confirmation);
            assert_eq!(
                token_balances(&mut reactor, &owner).await?,
                (payer_paid, burner_paid)
            );
            return Ok(());
        }
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
        &mut reactor.consensus.engine.legacy_handle_mut().handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn unbatched_raw_confirmation_position_differs_from_legacy_ordinal() -> Result<()> {
    run_case(false, false).await
}

#[tokio::test]
async fn batched_confirmation_reorg_and_reconfirmation_preserve_execution_effects() -> Result<()> {
    run_case(true, false).await
}

#[tokio::test]
async fn paid_conflict_rolls_back_fee_and_receipt_until_reorg() -> Result<()> {
    run_case(true, true).await
}

async fn run_conflict_case(replace_conflict: bool, resume_planner: bool) -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[72; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine.legacy_handle().actor.clone());
    let conn = reactor.db_conn();
    let result = async {
        let first =
            certified_fixture::block(1, certified_fixture::empty_block(1).prev_hash, 0, vec![]);
        let anchor = first.hash;
        let value =
            ConsensusValue::from_input(first.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;

        let issuance = Insts::direct(vec![Inst {
            gas_limit: 100_000,
            kind: InstKind::Issuance,
        }]);
        let victim = certified_fixture::transaction(&owner, issuance.clone(), 0)?;
        let second_victim = signed_launch_transaction(
            &owner,
            issuance.clone(),
            OutPoint {
                txid: Txid::from_byte_array([2; 32]),
                vout: 0,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            },
        )?;
        let unrelated = certified_fixture::transaction(&owner, issuance.clone(), 1)?;
        let mut replacement = signed_launch_transaction(
            &owner,
            issuance.clone(),
            victim.input[0].previous_output,
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            },
        )?;
        let second_replacement = signed_launch_transaction(
            &owner,
            issuance,
            second_victim.input[0].previous_output,
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            },
        )?;
        replacement.input.push(second_replacement.input[0].clone());
        assert_ne!(victim.compute_txid(), replacement.compute_txid());
        let victim_id = victim.compute_txid().to_string();
        let second_victim_id = second_victim.compute_txid().to_string();
        let unrelated_id = unrelated.compute_txid().to_string();
        let replacement_id = replacement.compute_txid().to_string();
        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![victim, second_victim, unrelated],
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        assert!(get_transaction_by_txid(&conn, &victim_id).await?.is_some());
        assert!(
            get_transaction_by_txid(&conn, &second_victim_id)
                .await?
                .is_some()
        );
        assert!(
            get_transaction_by_txid(&conn, &unrelated_id)
                .await?
                .is_some()
        );

        let conflict = certified_fixture::block(2, anchor, 0, vec![replacement]);
        let conflict_hash = conflict.hash;
        let value =
            ConsensusValue::from_input(conflict.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        if resume_planner {
            assert!(matches!(
                reactor.execution.step_certified_closure(height).await?,
                ExecutionStep::Planning
            ));
            let reopened = new_connection(dir.path(), "certified-fixture.db").await?;
            let frozen = closure::recover(&reopened, height).await?;
            for _ in 0..5 {
                assert!(!reconcile::step(&reopened, height).await?);
            }
            assert!(
                work::for_origin(&reopened, frozen.work_origin()?)
                    .await?
                    .cursor()
                    .is_err()
            );
            assert_eq!(closure::recover(&conn, height).await?, frozen);
            let mut rolled_back = false;
            for _ in 0..16 {
                if matches!(
                    reactor.execution.step_certified_closure(height).await?,
                    ExecutionStep::RolledBack(_)
                ) {
                    rolled_back = true;
                    break;
                }
            }
            assert!(rolled_back, "recovered work never reached rollback");
            assert_eq!(
                closure::recover(&reopened, height).await?,
                closure::progress(&conn, height).await?
            );
        }
        finish_decision(&mut reactor, height, next).await?;
        assert!(get_transaction_by_txid(&conn, &victim_id).await?.is_none());
        assert!(
            get_transaction_by_txid(&conn, &second_victim_id)
                .await?
                .is_none()
        );
        assert!(
            get_transaction_by_txid(&conn, &unrelated_id)
                .await?
                .is_some()
        );
        assert!(
            get_transaction_by_txid(&conn, &replacement_id)
                .await?
                .is_some()
        );

        if replace_conflict {
            let replacement_block = certified_fixture::block(2, anchor, 1, vec![]);
            let value = ConsensusValue::from_input(
                replacement_block.exact_input(reactor.consensus.protocol_context)?,
            )?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
            assert!(get_transaction_by_txid(&conn, &victim_id).await?.is_some());
            assert!(
                get_transaction_by_txid(&conn, &second_victim_id)
                    .await?
                    .is_some()
            );
            assert!(
                get_transaction_by_txid(&conn, &unrelated_id)
                    .await?
                    .is_some()
            );
            assert!(
                get_transaction_by_txid(&conn, &replacement_id)
                    .await?
                    .is_none()
            );
        } else {
            let mut parent = conflict_hash;
            for bitcoin_height in 3..=7 {
                let block = certified_fixture::block(bitcoin_height, parent, 0, vec![]);
                parent = block.hash;
                let value = ConsensusValue::from_input(
                    block.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
            }
            assert!(get_transaction_by_txid(&conn, &victim_id).await?.is_none());
            assert!(
                get_transaction_by_txid(&conn, &second_victim_id)
                    .await?
                    .is_none()
            );
            assert!(
                get_transaction_by_txid(&conn, &unrelated_id)
                    .await?
                    .is_none()
            );
            assert!(
                get_transaction_by_txid(&conn, &replacement_id)
                    .await?
                    .is_some()
            );
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine.legacy_handle_mut().handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn conflict_exclusion_survives_unrelated_deadline_replay() -> Result<()> {
    run_conflict_case(false, false).await
}

#[tokio::test]
async fn conflict_exclusion_expires_when_proving_block_is_replaced() -> Result<()> {
    run_conflict_case(true, false).await
}

#[tokio::test]
async fn frozen_conflict_plan_resumes_from_reopened_connection() -> Result<()> {
    run_conflict_case(true, true).await
}

#[derive(Clone, Copy)]
enum DeadlineCase {
    ExactReorg,
    WrongWitness,
    Late,
    IneligibleAnchor,
}

async fn run_deadline_case(case: DeadlineCase) -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[73; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine.legacy_handle().actor.clone());
    let conn = reactor.db_conn();
    let result = async {
        let first =
            certified_fixture::block(1, certified_fixture::empty_block(1).prev_hash, 0, vec![]);
        let anchor = first.hash;
        let value =
            ConsensusValue::from_input(first.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;

        let victim = certified_fixture::transaction(
            &owner,
            Insts::direct(vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            }]),
            0,
        )?;
        let txid = victim.compute_txid().to_string();
        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![victim.clone()],
        )?;
        let (batch_decision, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, batch_decision, next).await?;
        assert!(get_transaction_by_txid(&conn, &txid).await?.is_some());

        let mut parent = anchor;
        let mut deadline_parent = anchor;
        for bitcoin_height in 2..=7 {
            if bitcoin_height == 7 {
                deadline_parent = parent;
            }
            let block = certified_fixture::block(bitcoin_height, parent, 0, vec![]);
            parent = block.hash;
            let value =
                ConsensusValue::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
        }
        assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
        let excluded = conn
            .query(
                "SELECT 1 FROM excluded_batch_txids WHERE batch_height = ?1 AND txid = ?2",
                params![batch_decision, txid.clone()],
            )
            .await?
            .next()
            .await?
            .is_some();
        assert!(excluded);

        if matches!(case, DeadlineCase::IneligibleAnchor) {
            let replacement_anchor =
                certified_fixture::block(1, certified_fixture::empty_block(1).prev_hash, 1, vec![]);
            let mut replacement_parent = replacement_anchor.hash;
            let value = ConsensusValue::from_input(
                replacement_anchor.exact_input(reactor.consensus.protocol_context)?,
            )?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
            assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
            for bitcoin_height in 2..=6 {
                let block = certified_fixture::block(bitcoin_height, replacement_parent, 0, vec![]);
                replacement_parent = block.hash;
                let value = ConsensusValue::from_input(
                    block.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
            }
            let block = certified_fixture::block(7, replacement_parent, 0, vec![victim]);
            let value =
                ConsensusValue::from_input(block.exact_input(reactor.consensus.protocol_context)?)?;
            let (height, next) = start_decision(&mut reactor, value).await?;
            finish_decision(&mut reactor, height, next).await?;
            let executed = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("eligible block execution missing")?;
            assert_eq!(executed.batch_height, None);
            assert_eq!(executed.confirmed_height, Some(7));
            return Ok(());
        }

        match case {
            DeadlineCase::ExactReorg => {
                let exact = certified_fixture::block(7, deadline_parent, 1, vec![victim]);
                let value = ConsensusValue::from_input(
                    exact.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
                let healed = get_transaction_by_txid(&conn, &txid)
                    .await?
                    .context("exact inclusion did not restore the batch execution")?;
                assert_eq!(healed.batch_height, Some(batch_decision));
                assert_eq!(healed.confirmed_height, Some(7));

                let replacement = certified_fixture::block(7, deadline_parent, 2, vec![]);
                let value = ConsensusValue::from_input(
                    replacement.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
                assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
            }
            DeadlineCase::WrongWitness => {
                let mut wrong = victim;
                let mut stack = wrong.input[0]
                    .witness
                    .iter()
                    .map(|item| item.to_vec())
                    .collect::<Vec<_>>();
                stack[0][0] ^= 1;
                wrong.input[0].witness = Witness::from_slice(&stack);
                assert_eq!(wrong.compute_txid().to_string(), txid);
                let block = certified_fixture::block(7, deadline_parent, 1, vec![wrong]);
                let value = ConsensusValue::from_input(
                    block.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
                assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
            }
            DeadlineCase::Late => {
                let block = certified_fixture::block(8, parent, 0, vec![victim]);
                let value = ConsensusValue::from_input(
                    block.exact_input(reactor.consensus.protocol_context)?,
                )?;
                let (height, next) = start_decision(&mut reactor, value).await?;
                finish_decision(&mut reactor, height, next).await?;
                let executed = get_transaction_by_txid(&conn, &txid)
                    .await?
                    .context("late canonical execution missing")?;
                assert_eq!(executed.batch_height, None);
                assert_eq!(executed.confirmed_height, Some(8));
            }
            DeadlineCase::IneligibleAnchor => unreachable!(),
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine.legacy_handle_mut().handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn exact_deadline_inclusion_heals_and_reorg_restores_exclusion() -> Result<()> {
    run_deadline_case(DeadlineCase::ExactReorg).await
}

#[tokio::test]
async fn different_witness_at_deadline_does_not_heal_excluded_batch() -> Result<()> {
    run_deadline_case(DeadlineCase::WrongWitness).await
}

#[tokio::test]
async fn late_exact_inclusion_executes_as_new_block_work() -> Result<()> {
    run_deadline_case(DeadlineCase::Late).await
}

#[tokio::test]
async fn ineligible_batch_anchor_cannot_heal_on_exact_block_inclusion() -> Result<()> {
    run_deadline_case(DeadlineCase::IneligibleAnchor).await
}

#[tokio::test]
async fn optimistic_batches_reserve_spent_outpoints_before_a_block() -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[74; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine.legacy_handle().actor.clone());
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
        let first = signed_confirmation_call(&owner, address.clone())?;
        let competing = signed_launch_transaction(
            &owner,
            Insts::direct(vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: address.clone(),
                    expr: "write-result-payload(1)".into(),
                },
            }]),
            first.input[0].previous_output,
            TxOut {
                value: Amount::from_sat(899_999),
                script_pubkey: ScriptBuf::new(),
            },
        )?;
        assert_ne!(first.compute_txid(), competing.compute_txid());
        let first_id = first.compute_txid().to_string();
        let competing_id = competing.compute_txid().to_string();
        let outpoint = first.input[0].previous_output;
        let baseline_effects = effects(&conn).await?;
        let baseline_balances = token_balances(&mut reactor, &owner).await?;

        assert_eq!(
            reactor
                .consensus
                .validate_batch(
                    &conn,
                    1,
                    anchor,
                    &[first.clone(), competing.clone()],
                    1,
                    anchor
                )
                .await?,
            Some("contains duplicate Bitcoin outpoints")
        );
        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![first.clone(), competing.clone()],
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        assert!(get_transaction_by_txid(&conn, &first_id).await?.is_none());
        assert!(
            get_transaction_by_txid(&conn, &competing_id)
                .await?
                .is_none()
        );
        assert!(!marker_exists(&conn, outpoint).await?);
        assert_eq!(effects(&conn).await?, baseline_effects);
        assert_eq!(
            token_balances(&mut reactor, &owner).await?,
            baseline_balances
        );

        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![first.clone()],
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        let first_row = get_transaction_by_txid(&conn, &first_id)
            .await?
            .context("first optimistic execution missing")?;
        assert_eq!(first_row.batch_height, Some(height));
        assert_successful_write(
            &mut *reactor.execution.test_runtime().await,
            &first_id,
            &address,
        )
        .await?;
        assert!(marker_exists(&conn, outpoint).await?);
        assert_eq!(
            executed_wtxid(&conn, first_row.id).await?,
            Some(first.compute_wtxid())
        );
        let paid_effects = effects(&conn).await?;
        let paid_balances = token_balances(&mut reactor, &owner).await?;
        let fee = sub_decimal(baseline_balances.0, paid_balances.0)?;
        assert!(fee > Decimal::from("0"));
        assert_eq!(sub_decimal(paid_balances.1, baseline_balances.1)?, fee);

        assert_eq!(
            reactor
                .consensus
                .validate_batch(&conn, 1, anchor, &[competing.clone()], 1, anchor)
                .await?,
            Some("contains already-executed Bitcoin outpoints")
        );
        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![competing],
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        assert!(
            get_transaction_by_txid(&conn, &competing_id)
                .await?
                .is_none()
        );
        assert_eq!(
            get_transaction_by_txid(&conn, &first_id).await?.unwrap().id,
            first_row.id
        );
        assert_eq!(
            executed_wtxid(&conn, first_row.id).await?,
            Some(first.compute_wtxid())
        );
        assert_eq!(effects(&conn).await?, paid_effects);
        assert_eq!(token_balances(&mut reactor, &owner).await?, paid_balances);
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine.legacy_handle_mut().handle,
    )
    .await??;
    result
}

async fn marker_exists(conn: &Connection, outpoint: OutPoint) -> Result<bool> {
    Ok(conn
        .query(
            "SELECT 1 FROM executed_outpoints WHERE prev_txid = ?1 AND prev_vout = ?2",
            params![outpoint.txid.to_byte_array().to_vec(), outpoint.vout],
        )
        .await?
        .next()
        .await?
        .is_some())
}

async fn run_unrecognized_conflict_case(same_txid: bool) -> Result<()> {
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[74; 32])?);
    let key = PrivateKey::from([17; 32]);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let dir = TempDir::new()?;
    let mut reactor = certified_fixture::reactor(dir.path(), &genesis, key, 1).await?;
    let cleanup = StopEngine(reactor.consensus.engine.legacy_handle().actor.clone());
    let conn = reactor.db_conn();
    let result = async {
        let first =
            certified_fixture::block(1, certified_fixture::empty_block(1).prev_hash, 0, vec![]);
        let anchor = first.hash;
        let value =
            ConsensusValue::from_input(first.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        let before_batch = effects(&conn).await?;

        let victim = certified_fixture::transaction(
            &owner,
            Insts::direct(vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            }]),
            0,
        )?;
        let outpoint = victim.input[0].previous_output;
        let txid = victim.compute_txid().to_string();
        let child = signed_launch_transaction(
            &owner,
            Insts::direct(vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            }]),
            OutPoint {
                txid: victim.compute_txid(),
                vout: 0,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            },
        )?;
        let child_id = child.compute_txid().to_string();
        let child_outpoint = child.input[0].previous_output;
        let value = ConsensusValue::new_batch_raw(
            reactor.consensus.protocol_context,
            1,
            anchor,
            vec![victim.clone(), child],
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        let after_batch = effects(&conn).await?;
        assert_ne!(after_batch, before_batch);
        assert!(marker_exists(&conn, outpoint).await?);
        assert!(marker_exists(&conn, child_outpoint).await?);
        assert!(get_transaction_by_txid(&conn, &child_id).await?.is_some());

        let mut competing = victim;
        if same_txid {
            let mut stack = competing.input[0]
                .witness
                .iter()
                .map(|item| item.to_vec())
                .collect::<Vec<_>>();
            stack[0][0] ^= 1;
            competing.input[0].witness = Witness::from_slice(&stack);
            assert_eq!(competing.compute_txid().to_string(), txid);
        } else {
            competing.input[0].witness.clear();
            competing.output[0].value = Amount::from_sat(1);
            assert_ne!(competing.compute_txid().to_string(), txid);
        }
        let conflict = certified_fixture::block(2, anchor, 0, vec![competing]);
        let value =
            ConsensusValue::from_input(conflict.exact_input(reactor.consensus.protocol_context)?)?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        assert!(get_transaction_by_txid(&conn, &txid).await?.is_none());
        assert!(get_transaction_by_txid(&conn, &child_id).await?.is_none());
        assert!(!marker_exists(&conn, outpoint).await?);
        assert!(!marker_exists(&conn, child_outpoint).await?);
        assert_eq!(effects(&conn).await?, before_batch);

        let replacement = certified_fixture::block(2, anchor, 1, vec![]);
        let value = ConsensusValue::from_input(
            replacement.exact_input(reactor.consensus.protocol_context)?,
        )?;
        let (height, next) = start_decision(&mut reactor, value).await?;
        finish_decision(&mut reactor, height, next).await?;
        assert!(get_transaction_by_txid(&conn, &txid).await?.is_some());
        assert!(get_transaction_by_txid(&conn, &child_id).await?.is_some());
        assert!(marker_exists(&conn, outpoint).await?);
        assert!(marker_exists(&conn, child_outpoint).await?);
        assert_eq!(effects(&conn).await?, after_batch);
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine.legacy_handle_mut().handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn same_txid_different_witness_cannot_confirm_optimistic_effects() -> Result<()> {
    run_unrecognized_conflict_case(true).await
}

#[tokio::test]
async fn plain_spend_removes_optimistic_effects_until_reorg() -> Result<()> {
    run_unrecognized_conflict_case(false).await
}
