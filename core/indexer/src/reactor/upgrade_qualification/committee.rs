use anyhow::{Context, Result, ensure};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{OutPoint, Transaction, blockdata::constants::genesis_block, consensus::serialize};
use indexer_types::{ContractAddress, Inst, InstKind, Insts};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::NETWORK;
use super::confirmation::finish_block;
use super::fixture::{append, open, seed_with_validator};
use crate::database::certified_history::{
    self, activation, closure, completion, control, eras, registrations,
};
use crate::database::queries::get_transaction_by_txid;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::certified::qualification::fixture::raw_transaction_at;
use crate::reactor::consensus_state::certified_startup;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) fn exit_transaction() -> Result<Transaction> {
    let mut previous = OutPoint::null();
    previous.vout = 0;
    raw_transaction_at(
        Insts::direct(vec![
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: ContractAddress {
                        name: "staking".into(),
                        height: 0,
                        tx_index: 0,
                    },
                    expr: "leave-validation()".into(),
                },
            },
        ]),
        previous,
    )
}

// Exit is an ordinary paid staking call. Its twelve-block delay expires in H's
// old-protocol lifecycle, immediately before the scheduled migration.
pub(super) async fn run(service: &OwnerService) -> Result<Value> {
    let directory = TempDir::new()?;
    let key = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[38; 32])?);
    let target = seed_with_validator(
        directory.path(),
        service,
        13,
        &key.x_only_public_key().0.to_string(),
    )
    .await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let context = execution.protocol_context;
    let exit = exit_transaction()?;
    let mut block = genesis_block(NETWORK);
    append(
        &conn,
        ExactInput::batch(context, 1, block.block_hash(), std::slice::from_ref(&exit))?,
    )
    .await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let row = get_transaction_by_txid(&conn, &exit.compute_txid().to_string())
        .await?
        .context("validator exit transaction")?;
    let mut receipts = conn.query("SELECT count(*) FROM contract_results WHERE tx_id = ?1 AND func = 'leave-validation' AND status = 'Ok' AND gas > 0 AND payer_signer_id IS NOT NULL", [row.id]).await?;
    ensure!(
        receipts
            .next()
            .await?
            .context("exit receipt")?
            .get::<i64>(0)?
            == 1,
        "validator exit did not execute"
    );
    drop(receipts);
    let mut final_decision = 0;
    for height in 2..=13 {
        let parent = block.block_hash();
        block = genesis_block(NETWORK);
        block.header.prev_blockhash = parent;
        block.header.nonce = height as u32;
        if height == 2 {
            block.txdata.push(exit.clone());
            finish_block(&mut block)?;
        }
        let input = ExactInput::block(context, height, serialize(&block))?;
        let decision = certified_history::frontier(&conn).await?.closed_height + 1;
        let input = match control::expected_transition(
            &conn,
            context,
            &input.descriptor().command,
            decision,
        )
        .await?
        {
            Some(transition) => input.with_transition(transition.descriptor)?,
            None => input,
        };
        final_decision = append(&conn, input).await?;
        let result = execution.recover(&Shutdown::new().signal()).await;
        if height < 13 {
            ensure!(result?);
        } else {
            let error = result
                .err()
                .context("empty successor unexpectedly completed")?;
            ensure!(
                error.is::<completion::InvalidNextAuthority>(),
                "unexpected completion error: {error:#}"
            );
        }
    }
    ensure!(final_decision == 14);
    ensure!(
        get_transaction_by_txid(&conn, &exit.compute_txid().to_string())
            .await?
            .context("confirmed exit")?
            .confirmed_height
            == Some(2)
    );
    ensure!(
        activation::current(&conn)
            .await?
            .context("migration must commit before the authority gate")?
            .target()?
            .id()?
            == target
    );
    let observation = registrations::latest(&conn)
        .await?
        .context("final registration observation")?;
    ensure!(observation.committee.is_empty());
    ensure!(observation.entries.len() == 1 && observation.entries[0].generation.is_none());
    ensure!(
        observation.entries[0]
            .value
            .as_ref()
            .context("exited registration")?
            .1
            == 0
    );
    let progress = closure::recover(&conn, final_decision).await?;
    ensure!(progress.remaining.is_empty());
    let frontier = certified_history::frontier(&conn).await?;
    ensure!(
        frontier.closed_height == 13
            && frontier.authenticated_height == 14
            && frontier.context == Some(context)
    );
    ensure!(certified_history::committee(&conn, 15).await.is_err());
    ensure!(completion::completed(&conn, 14).await.is_err());
    ensure!(eras::at(&conn, 14).await?.is_none());
    ensure!(certified_startup(&conn).await.is_err());
    let expected = full_state(&conn).await?;
    let retained = certified_history::load(&conn, 14).await?;
    let proof = retained.proof().to_vec();
    let id = retained.decision().id()?;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    let error = reopened
        .recover(&Shutdown::new().signal())
        .await
        .err()
        .context("reopened empty successor unexpectedly completed")?;
    ensure!(
        error.is::<completion::InvalidNextAuthority>(),
        "unexpected recovery error: {error:#}"
    );
    ensure!(full_state(&reopened.db_conn()).await? == expected);
    ensure!(closure::recover(&conn, 14).await? == progress);
    ensure!(registrations::latest(&conn).await? == Some(observation));
    ensure!(certified_history::frontier(&conn).await? == frontier);
    let retained = certified_history::load(&conn, 14).await?;
    ensure!(retained.proof() == proof && retained.decision().id()? == id);
    ensure!(certified_startup(&conn).await.is_err());
    ensure!(service.active_roots().await == 0);
    Ok(
        json!({"paid_exit_confirmed": true, "activation_committed": true,
        "empty_successor_gated": true, "reopen_preserves_gate": true,
        "retained_certificate_unchanged": true, "activation_height": 13,
        "authenticated_decisions": 14, "closed_decisions": 13}),
    )
}
