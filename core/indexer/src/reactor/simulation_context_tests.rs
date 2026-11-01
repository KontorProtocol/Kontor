use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, ensure};
use bitcoin::OutPoint;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use indexer_types::{Input, Inst, InstKind, Insts, OpStatus};
use libsql::{AuthAction, AuthContext, Authorization};
use stdlib::to_wave_expr;
use tokio::time::timeout;

use super::aggregate_error_tests::{reactor, snapshot};
use crate::consensus::signing::PrivateKey;
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, GenesisValidator, TransactionContext};
use crate::test_utils::{new_mock_transaction, test_runtime_with_genesis};

async fn restores_context(
    contract_error: bool,
    outer_error: bool,
    was_simulating: bool,
) -> Result<()> {
    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[38; 32])?);
    let public = key.x_only_public_key().0;
    let (mut runtime, directory, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: public.to_string(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::XOnlyPubkey(public.to_string()),
        Decimal::from("100"),
    )
    .await??;
    let mut trial = reactor(runtime, &directory).await?;
    let prior = TransactionContext {
        tx_id: None,
        tx_index: 7,
        input_index: 8,
        op_index: 9,
        txid: new_mock_transaction(987).txid,
    };
    let prior_output = OutPoint {
        txid: prior.txid,
        vout: 4,
    };
    trial
        .execution
        .test_runtime()
        .await
        .set_context(
            1,
            Some(prior.clone()),
            Some(prior_output),
            Some(vec![8, 7, 6]),
        )
        .await;
    trial.execution.test_runtime().await.simulating = was_simulating;
    let ids = trial
        .execution
        .test_runtime()
        .await
        .id_generation_counter
        .clone();
    let results = trial
        .execution
        .test_runtime()
        .await
        .result_id_counter
        .clone();
    for _ in 0..2 {
        ids.increment().await;
    }
    for _ in 0..3 {
        results.increment().await;
    }
    let mut tx = new_mock_transaction(123);
    tx.op_return_raw = Some(vec![1, 2, 3]);
    tx.inputs = vec![Input {
        previous_output: OutPoint {
            txid: new_mock_transaction(456).txid,
            vout: 2,
        },
        input_index: 0,
        x_only_pubkey: public,
        insts: Insts {
            aggregate: None,
            ops: vec![Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: token_address(),
                    expr: if contract_error {
                        format!("burn({})", to_wave_expr(Decimal::from("1000")))
                    } else {
                        format!("mint({})", to_wave_expr(Decimal::from("1")))
                    },
                },
            }],
        },
    }];
    let conn = trial.db_conn();
    let before = snapshot(&conn).await?;
    let denials = Arc::new(AtomicUsize::new(0));
    if outer_error {
        let observed = denials.clone();
        conn.authorizer(Some(Arc::new(move |context: &AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "contract_results"
                }
            ) {
                observed.fetch_add(1, Ordering::SeqCst);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        })))?;
    }
    let outcome = trial.simulate(tx).await;
    conn.authorizer(None)?;
    ensure!(trial.execution.test_runtime().await.storage.height == 1);
    ensure!(trial.execution.test_runtime().await.storage.tx_context == Some(prior));
    ensure!(trial.execution.test_runtime().await.previous_output == Some(prior_output));
    ensure!(
        trial
            .execution
            .test_runtime()
            .await
            .op_return_data
            .as_deref()
            == Some([8, 7, 6].as_slice())
    );
    ensure!(trial.execution.test_runtime().await.simulating == was_simulating);
    ensure!(ids.get().await == 2 && results.get().await == 3);
    ensure!(
        trial
            .execution
            .test_runtime()
            .await
            .id_generation_counter
            .get()
            .await
            == 2
    );
    ensure!(
        trial
            .execution
            .test_runtime()
            .await
            .result_id_counter
            .get()
            .await
            == 3
    );
    trial
        .execution
        .test_runtime()
        .await
        .id_generation_counter
        .increment()
        .await;
    trial
        .execution
        .test_runtime()
        .await
        .result_id_counter
        .increment()
        .await;
    ensure!(ids.get().await == 3 && results.get().await == 4);
    if outer_error {
        ensure!(denials.load(Ordering::SeqCst) > 0);
        ensure!(outcome.is_err(), "database failure must remain fatal");
        ensure!(
            conn.is_autocommit(),
            "simulation error left a transaction open"
        );
        ensure!(
            trial
                .execution
                .test_runtime()
                .await
                .storage
                .savepoint_stack
                .is_empty()
                .await
        );
        ensure!(snapshot(&conn).await? == before);
    } else {
        let outcome = outcome?;
        ensure!(outcome.len() == 1);
        ensure!(outcome[0].result().is_some_and(|row| row.status
            == if contract_error {
                OpStatus::ContractErr
            } else {
                OpStatus::Ok
            }));
        ensure!(snapshot(&conn).await? == before);
        ensure!(trial.execution.test_runtime().await.stack.is_empty().await);
        ensure!(
            trial
                .execution
                .test_runtime()
                .await
                .storage
                .savepoint_stack
                .is_empty()
                .await
        );
    }
    trial.consensus.engine_handle.actor.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut trial.consensus.engine_handle.handle,
    )
    .await??;
    Ok(())
}

#[tokio::test]
async fn simulation_restores_context_after_success() -> Result<()> {
    restores_context(false, false, false).await
}

#[tokio::test]
async fn simulation_restores_context_after_contract_error() -> Result<()> {
    restores_context(true, false, false).await
}

#[tokio::test]
async fn simulation_restores_context_after_outer_error() -> Result<()> {
    restores_context(false, true, false).await
}

#[tokio::test]
async fn simulation_preserves_existing_simulation_flag() -> Result<()> {
    restores_context(false, false, true).await
}
