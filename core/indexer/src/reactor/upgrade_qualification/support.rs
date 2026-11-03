use anyhow::{Context, Result, ensure};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{blockdata::constants::genesis_block, consensus::serialize};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::NETWORK;
use super::committee::exit_transaction;
use super::confirmation::finish_block;
use super::fixture::{append_signed, certify, initialize_parameters, open};
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{self, control};
use crate::database::queries::get_transaction_by_txid;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;

pub(super) async fn run(service: &OwnerService) -> Result<Value> {
    let directory = TempDir::new()?;
    let keys = [
        PrivateKey::from([7; 32]),
        PrivateKey::from([8; 32]),
        PrivateKey::from([9; 32]),
    ];
    let mut validators = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let bitcoin_key = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[38 + index as u8; 32])?,
        );
        validators.push(GenesisValidator {
            x_only_pubkey: bitcoin_key.x_only_public_key().0.to_string(),
            ed25519_pubkey: key.public_key().as_bytes().to_vec(),
            stake: Decimal::from(if index == 0 { "200" } else { "100" }),
        });
    }
    let target = initialize_parameters(
        directory.path(),
        service,
        Some(13),
        GenesisParameters {
            sigma_min: Decimal::from("1"),
            validators,
        },
        false,
        &keys[..2],
    )
    .await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let initial = execution.protocol_context;
    let old = certified_history::committee(&conn, 2).await?;
    ensure!(old.members.len() == 3 && old.validate()? == 400);
    let signed_power: u64 = old
        .members
        .iter()
        .filter(|member| {
            keys[..2]
                .iter()
                .any(|key| member.key == *key.public_key().as_bytes())
        })
        .map(|member| member.power)
        .sum();
    ensure!(signed_power == 300);
    let exit = exit_transaction()?;
    let mut block = genesis_block(NETWORK);
    append_signed(
        &conn,
        ExactInput::batch(initial, 1, block.block_hash(), std::slice::from_ref(&exit))?,
        &keys[..2],
    )
    .await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    for height in 2..=13 {
        let parent = block.block_hash();
        block = genesis_block(NETWORK);
        block.header.prev_blockhash = parent;
        block.header.nonce = height as u32;
        if height == 2 {
            block.txdata.push(exit.clone());
            finish_block(&mut block)?;
        }
        let input = ExactInput::block(initial, height, serialize(&block))?;
        let decision = certified_history::frontier(&conn).await?.closed_height + 1;
        let input = match control::expected_transition(
            &conn,
            initial,
            &input.descriptor().command,
            decision,
        )
        .await?
        {
            Some(transition) => input.with_transition(transition.descriptor)?,
            None => input,
        };
        // The absent third member is unnecessary for this real old-quorum proof.
        append_signed(&conn, input, &keys[..2]).await?;
        ensure!(execution.recover(&Shutdown::new().signal()).await?);
    }
    ensure!(execution.protocol_context.protocol == target);
    let exit_row = get_transaction_by_txid(&conn, &exit.compute_txid().to_string())
        .await?
        .context("confirmed exit")?;
    ensure!(exit_row.confirmed_height == Some(2));
    let mut receipts = conn.query("SELECT count(*) FROM contract_results WHERE tx_id = ?1 AND func = 'leave-validation' AND status = 'Ok' AND gas > 0 AND payer_signer_id IS NOT NULL", [exit_row.id]).await?;
    ensure!(
        receipts
            .next()
            .await?
            .context("paid exit receipt")?
            .get::<i64>(0)?
            == 1
    );
    let frontier = certified_history::frontier(&conn).await?;
    ensure!(frontier.closed_height == 14);
    ensure!(certified_history::committee(&conn, 14).await?.members == old.members);
    let next = certified_history::committee(&conn, 15).await?;
    ensure!(next.members.len() == 2 && next.validate()? == 200);
    ensure!(
        next.members
            .iter()
            .all(|member| member.power == 100 && member.key != *keys[0].public_key().as_bytes())
    );
    let input = ExactInput::batch(execution.protocol_context, 13, block.block_hash(), &[])?;
    // Missing support of key9 is a scenario assumption. The separate unsupported
    // node case exercises real refusal; this case exercises its quorum consequence.
    ensure!(certify(&conn, input.clone(), &keys[1..2]).await.is_err());
    let enough = certify(&conn, input, &keys[1..]).await?;
    ensure!(enough.decision().height == 15 && enough.decision().committee == next.id()?);
    ensure!(certified_history::frontier(&conn).await? == frontier);
    let expected = full_state(&conn).await?;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(certified_history::committee(&conn, 15).await? == next);
    ensure!(certified_history::frontier(&conn).await? == frontier);
    ensure!(full_state(&conn).await? == expected);
    Ok(
        json!({"scope": "composed support assumption, not live mixed binaries",
        "old_quorum_certificate": true, "paid_exit_in_h_lifecycle": true,
        "nonempty_changed_successor": true, "insufficient_subset_rejected": true,
        "full_successor_accepted": true, "reopen_preserves_committee_and_frontier": true,
        "activation_height": 13, "closed_decisions": 14,
        "old_signed_power": 300, "old_total_power": 400,
        "supporting_successor_power": 100, "successor_total_power": 200}),
    )
}
