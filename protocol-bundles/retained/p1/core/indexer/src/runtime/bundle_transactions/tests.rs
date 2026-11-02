use std::sync::Arc;

use anyhow::{Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize as bitcoin_bytes;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction as BitcoinTransaction, TxIn, TxOut,
    Witness, XOnlyPublicKey,
};
use indexer_types::{BlockRow, Inst, InstKind, Insts, TransactionRow, serialize};
use libsql::{AuthAction, AuthContext, Authorization, Connection, Value};
use stdlib::to_wave_expr;

use super::*;
use crate::bitcoin_client::Client;
use crate::database::queries::{insert_block, insert_transaction};
use crate::protocol::coordinator::linked::{
    TransactionRecognizer, begin_unit, execute_transaction, link_runtime, recognize_transaction,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::reactor::executor::{Executor, RuntimeExecutor};
use crate::runtime::ownership::OwnerService;
use crate::runtime::pool::LinkedSession;
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
use crate::runtime::{Decimal, TransactionContext};
use crate::test_utils::{
    PublicKey as TestPublicKey, build_inscription, new_mock_block_hash, new_mock_transaction,
    test_runtime_with_genesis,
};

fn raw_transaction(public: XOnlyPublicKey) -> Result<BitcoinTransaction> {
    let insts = Insts::direct(
        [
            format!("mint({})", to_wave_expr(Decimal::from("1"))),
            "missing-function()".into(),
        ]
        .into_iter()
        .map(|expr| Inst {
            gas_limit: 100_000,
            kind: InstKind::Call {
                contract: token_address(),
                expr,
            },
        })
        .collect(),
    );
    let script = build_inscription(serialize(&insts)?, TestPublicKey::Taproot(&public))?;
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&Secp256k1::new(), public)
        .map_err(|_| anyhow!("taproot finalize failed"))?;
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();
    let mut witness = Witness::new();
    witness.push([0u8; 64]);
    witness.push(script.as_bytes());
    witness.push(control.serialize());
    Ok(BitcoinTransaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    })
}

async fn snapshot(conn: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
    let mut snapshot = Vec::new();
    for table in [
        "blocks",
        "transactions",
        "contract_state",
        "contract_results",
        "depositor_footprint",
        "transaction_execution_usage",
        "signers",
    ] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY rowid"), ())
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..rows.column_count())
                    .map(|i| row.get_value(i))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        snapshot.push(values);
    }
    Ok(snapshot)
}

async fn insert_unit(conn: &Connection, txid: String) -> Result<u64> {
    insert_block(
        conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;
    Ok(insert_transaction(
        conn,
        TransactionRow::builder()
            .height(2)
            .tx_index(7)
            .txid(txid)
            .build(),
    )
    .await?)
}

#[tokio::test]
async fn recognized_transaction_preserves_execution_and_simulation() -> Result<()> {
    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[38; 32])?);
    let public = key.x_only_public_key().0;
    let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[]).await?;
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::XOnlyPubkey(public.to_string()),
        Decimal::from("100"),
    )
    .await??;
    let conn = runtime.storage.conn.clone();
    let raw = raw_transaction(public)?;
    let bytes = bitcoin_bytes(&raw);
    let parsed = transactions::filter_map((7, raw.clone())).unwrap();
    let before = snapshot(&conn).await?;
    let block_position = ApplicationPosition::Block {
        height: 2,
        hash: new_mock_block_hash(2),
        consensus_height: 2,
    };
    let selection = select_legacy_p1(&conn, Network::Regtest, block_position.clone()).await?;
    runtime.storage.savepoint().await?;
    let tx_id = insert_unit(&conn, parsed.txid.to_string()).await?;
    let executor = RuntimeExecutor::new(Client::new(String::new(), String::new(), String::new())?);
    let failures = executor
        .execute_transaction(&selection, &mut runtime, 2, tx_id, &parsed)
        .await?;
    let expected_failures = failures
        .into_iter()
        .map(|input| {
            input
                .into_iter()
                .map(|e| e.map(|e| format!("{e:#}")))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_failures.len(), 1);
    assert!(expected_failures[0][0].is_none());
    assert!(expected_failures[0][1].is_some());
    let expected = snapshot(&conn).await?;
    assert_ne!(expected, before);
    runtime.storage.rollback().await?;
    assert_eq!(snapshot(&conn).await?, before);

    let prior_context = TransactionContext {
        tx_id: None,
        tx_index: 8,
        input_index: 9,
        op_index: 10,
        txid: new_mock_transaction(12).txid,
    };
    let prior_output = OutPoint {
        txid: prior_context.txid,
        vout: 3,
    };
    runtime
        .set_context(
            1,
            Some(prior_context.clone()),
            Some(prior_output),
            Some(vec![8, 7]),
        )
        .await;
    let prior_ids = runtime.id_generation_counter.clone();
    let prior_results = runtime.result_id_counter.clone();
    prior_ids.increment().await;
    prior_results.increment().await;
    prior_results.increment().await;
    let session = LinkedSession::new(conn.clone(), link_runtime(runtime, true));
    let retained = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong executor session"))?;
    let preparation = select_legacy_p1(
        &conn,
        Network::Regtest,
        ApplicationPosition::Preparation {
            anchor_height: 1,
            anchor_hash: Some(new_mock_block_hash(1)),
        },
    )
    .await?;
    let recognizer = TransactionRecognizer::new(
        session.origin(),
        Network::Regtest,
        session.executor.operations.recognize.clone(),
    );
    let mut prepared = executor
        .parse_mempool(&recognizer, &preparation, vec![raw.clone()])
        .await?;
    let recognized = prepared.remove(0).parsed.unwrap();
    assert_eq!(recognized.txid, raw.compute_txid());
    assert!(recognized.batchable);
    assert_eq!(recognized.inputs, [(0, 2)]);
    let mut trailing = bytes.clone();
    trailing.push(1);
    assert!(
        recognize_transaction(&session.executor, &preparation, Network::Regtest, trailing)?
            .is_err()
    );
    assert!(
        recognize_transaction(&session.executor, &preparation, Network::Regtest, vec![1])?.is_err()
    );
    let mut ordinary = raw.clone();
    ordinary.input[0].witness = Witness::new();
    assert!(
        recognize_transaction(
            &session.executor,
            &preparation,
            Network::Regtest,
            bitcoin_bytes(&ordinary)
        )?
        .unwrap()
        .is_none()
    );
    let mut foreign = preparation.envelope();
    foreign.0 += 1;
    assert!((session.executor.operations.recognize)(foreign, bytes).is_err());
    let service = OwnerService::new();
    for (simulation, commit) in [(true, false), (false, false), (false, true)] {
        let selection = select_legacy_p1(
            &conn,
            Network::Regtest,
            if simulation {
                ApplicationPosition::Simulation { height: 2 }
            } else {
                block_position.clone()
            },
        )
        .await?;
        let capacity = service.reserve_root_capacity().await?;
        let mut lease = service
            .begin_linked_canonical_reserved(&session, capacity, selection.clone(), simulation)
            .await?;
        begin_unit(&session, &selection, Network::Regtest).await?;
        let tx_id = insert_unit(&conn, parsed.txid.to_string()).await?;
        assert_eq!(retained.runtime.lock().await.simulating, simulation);
        assert!(
            (session.executor.operations.transaction)(
                session.executor.owner.clone(),
                selection.envelope(),
                Arc::new(()),
                7,
                tx_id
            )
            .await
            .is_err()
        );
        let observed = execute_transaction(
            &session,
            &selection,
            Network::Regtest,
            &recognized,
            7,
            tx_id,
        )
        .await?;
        assert_eq!(observed, expected_failures);
        assert_eq!(snapshot(&conn).await?, expected);
        lease.drain().await?;
        lease.settle(commit).await?;
        lease.complete().await?;
        assert!(conn.is_autocommit());
        assert_eq!(
            snapshot(&conn).await?,
            if commit {
                expected.clone()
            } else {
                before.clone()
            }
        );
        assert!(
            execute_transaction(
                &session,
                &selection,
                Network::Regtest,
                &recognized,
                7,
                tx_id
            )
            .await
            .is_err()
        );
        let recovered = retained.runtime.lock().await;
        assert!(!recovered.simulating);
        if simulation {
            assert_eq!(recovered.storage.height, 1);
            assert_eq!(recovered.storage.tx_context, Some(prior_context.clone()));
            assert_eq!(recovered.previous_output, Some(prior_output));
            assert_eq!(recovered.op_return_data.as_deref(), Some([8, 7].as_slice()));
            assert_eq!(recovered.id_generation_counter.get().await, 1);
            assert_eq!(recovered.result_id_counter.get().await, 2);
            recovered.id_generation_counter.increment().await;
            recovered.result_id_counter.increment().await;
            assert_eq!(prior_ids.get().await, 2);
            assert_eq!(prior_results.get().await, 3);
        }
        assert_eq!(service.active_roots().await, 0);
    }
    Ok(())
}

#[tokio::test]
async fn simulation_restores_context_after_infrastructure_failure() -> Result<()> {
    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[38; 32])?);
    let public = key.x_only_public_key().0;
    let (mut runtime, _dir, _name) = test_runtime_with_genesis(&[]).await?;
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::XOnlyPubkey(public.to_string()),
        Decimal::from("100"),
    )
    .await??;
    let conn = runtime.storage.conn.clone();
    let prior = TransactionContext {
        tx_id: None,
        tx_index: 3,
        input_index: 4,
        op_index: 5,
        txid: new_mock_transaction(12).txid,
    };
    runtime
        .set_context(1, Some(prior.clone()), None, Some(vec![3, 2, 1]))
        .await;
    runtime.simulating = true;
    let ids = runtime.id_generation_counter.clone();
    ids.increment().await;
    let session = LinkedSession::new(conn.clone(), link_runtime(runtime, true));
    let retained = session
        .executor
        .owner
        .clone()
        .downcast::<BundleSession>()
        .map_err(|_| anyhow!("wrong executor session"))?;
    let before = snapshot(&conn).await?;
    let selection = select_legacy_p1(
        &conn,
        Network::Regtest,
        ApplicationPosition::Simulation { height: 2 },
    )
    .await?;
    let recognized = recognize_transaction(
        &session.executor,
        &selection,
        Network::Regtest,
        bitcoin_bytes(&raw_transaction(public)?),
    )?
    .map_err(|e| anyhow!(e))?
    .unwrap();
    let service = OwnerService::new();
    let capacity = service.reserve_root_capacity().await?;
    let mut lease = service
        .begin_linked_canonical_reserved(&session, capacity, selection.clone(), true)
        .await?;
    begin_unit(&session, &selection, Network::Regtest).await?;
    let tx_id = insert_unit(&conn, recognized.txid.to_string()).await?;
    conn.authorizer(Some(Arc::new(|context: &AuthContext<'_>| {
        if matches!(
            context.action,
            AuthAction::Insert {
                table_name: "contract_results"
            }
        ) {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    })))?;
    let failure = execute_transaction(
        &session,
        &selection,
        Network::Regtest,
        &recognized,
        7,
        tx_id,
    )
    .await;
    conn.authorizer(None)?;
    assert!(failure.is_err());
    lease.drain().await?;
    lease.settle(false).await?;
    lease.complete().await?;
    assert!(conn.is_autocommit());
    assert_eq!(snapshot(&conn).await?, before);
    let recovered = retained.runtime.lock().await;
    assert!(recovered.simulating);
    assert_eq!(recovered.storage.height, 1);
    assert_eq!(recovered.storage.tx_context, Some(prior));
    assert_eq!(
        recovered.op_return_data.as_deref(),
        Some([3, 2, 1].as_slice())
    );
    assert_eq!(recovered.id_generation_counter.get().await, 1);
    recovered.id_generation_counter.increment().await;
    assert_eq!(ids.get().await, 2);
    assert!(recovered.gauge.is_none());
    assert!(recovered.selected_context.is_none());
    assert_eq!(service.active_roots().await, 0);
    Ok(())
}
