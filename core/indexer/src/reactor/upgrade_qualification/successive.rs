use anyhow::{Context, Result, ensure};
use bitcoin::Block;
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::authorization::{block_input, execute};
use super::fixture::{open, snapshot, unscheduled};
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{self, activation, completion, control, eras};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::certified_decision::AuthenticatedDecision;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{
    ApprovalSigner, ControlAction, ControlOperation, UpgradeControl, validate_target,
};
use crate::protocol::coordinator::{registry, successor};
use crate::protocol_qualification::snapshot::full_state;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

async fn migrations(conn: &Connection) -> Result<Vec<CanonicalApplication>> {
    let mut rows = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().await? {
        let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        if matches!(application.source, ApplicationSource::Migration { .. }) {
            result.push(application);
        }
    }
    Ok(result)
}

fn without_local_epoch(mut state: Value) -> Result<Value> {
    // Fresh databases deliberately generate different receipt-stream identities.
    // Preserve the generation and unsupported flags in the full-state comparison.
    let rows = state
        .get_mut("receipt_stream_state")
        .and_then(Value::as_array_mut)
        .context("receipt stream state")?;
    ensure!(rows.len() == 1);
    let mut row: Vec<Value> = serde_json::from_str(rows[0].as_str().context("receipt row")?)?;
    ensure!(
        row.len() == 4
            && row[1][0] == "text"
            && row[1][1].as_str().is_some_and(|value| value.len() == 64)
    );
    row[1] = json!(["text", "node-local epoch"]);
    rows[0] = Value::String(serde_json::to_string(&row)?);
    Ok(state)
}

pub(super) async fn run(
    source: &Connection,
    service: &OwnerService,
    first_block: &Block,
) -> Result<Value> {
    let directory = TempDir::new()?;
    let replay_directory = TempDir::new()?;
    snapshot(source, directory.path()).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let second = execution.protocol_context;
    let second_manifest = successor::manifest(second.chain)?;
    ensure!(second.protocol == second_manifest.id()?);
    let third_manifest = successor::qualification_third(second.chain)?;
    let third_id = third_manifest.id()?;
    ensure!(third_manifest.executor == second_manifest.executor);
    ensure!(third_manifest.consensus == second_manifest.consensus);
    ensure!(validate_target(&third_manifest, &Baseline::for_node(second.chain)?.manifest).is_err());
    let mut altered = third_manifest.clone();
    altered.native_contracts_root[0] ^= 1;
    ensure!(registry::resolve(&altered).is_err());
    let first_activation = activation::current(&conn)
        .await?
        .context("first activation")?;
    let first_key = first_activation.application.migration_key()?;
    let state = control::admission::state(&conn, second).await?;
    ensure!(state.pending.is_none());
    let frontier = certified_history::frontier(&conn).await?;
    let reference = completion::completed(&conn, frontier.closed_height).await?;
    let authority = certified_history::committee(&conn, frontier.closed_height + 1).await?;
    let key = PrivateKey::from([7; 32]);
    let member = authority
        .members
        .iter()
        .find(|member| member.key == *key.public_key().as_bytes())
        .context("second approval authority")?;
    let first_height = execution.last_height;
    let activation_height = first_height + 1008;
    let action = ControlAction {
        context: second,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: None,
        reference_height: frontier.closed_height,
        reference_decision: reference.decision,
        expires_at: first_height + 100,
        operation: ControlOperation::Schedule {
            manifest: third_manifest,
            activation: activation_height,
        },
    };
    let envelope = UpgradeControl {
        approvals: vec![ApprovalSigner::new(key).sign(&action, member.generation)?],
        action,
    };
    let input = ExactInput::control(second, first_height, first_block.block_hash(), &envelope)?;
    control::admission::verify(
        &conn,
        &input,
        frontier.closed_height + 1,
        control::Position {
            decision: frontier.closed_height + 1,
            stage: 0,
        },
    )
    .await?;
    execute(&mut execution, input).await?;
    let mut block = first_block.clone();
    for height in first_height + 1..=activation_height {
        block.header.prev_blockhash = block.block_hash();
        block.header.nonce = block.header.nonce.wrapping_add(1);
        let input = block_input(&execution, height, &block).await?;
        ensure!(input.descriptor().transition.is_some() == (height == activation_height));
        execute(&mut execution, input).await?;
        if height < activation_height {
            ensure!(execution.protocol_context == second);
        }
        if height % 256 == 0 {
            eprintln!("second authorized notice window: {height}/{activation_height}");
        }
    }
    let third = execution.protocol_context;
    ensure!(third.protocol == third_id && third != second);
    let last_activation = activation::current(&conn)
        .await?
        .context("second activation")?;
    ensure!(last_activation.application.migration_key()? != first_key);
    ensure!(last_activation.application.execution != first_activation.application.execution);
    ensure!(last_activation.application.lineage()? != first_activation.application.lineage()?);
    ensure!(
        last_activation
            .before
            .pending
            .as_ref()
            .context("second plan")?
            .id
            != first_activation
                .before
                .pending
                .as_ref()
                .context("first plan")?
                .id
    );
    let applied = migrations(&conn).await?;
    ensure!(
        applied.len() == 2,
        "expected two distinct migration applications"
    );
    let final_height = certified_history::frontier(&conn).await?.closed_height;
    let expected = full_state(&conn).await?;
    let expected_era = eras::at(&conn, final_height).await?;
    drop(execution);
    let mut reopened = open(directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(full_state(&reopened.db_conn()).await? == expected);
    ensure!(migrations(&reopened.db_conn()).await? == applied);
    drop(reopened);

    // Rebuild from genesis using retained certificates and each height's verified
    // committee, rather than treating a post-activation snapshot as replay proof.
    unscheduled(replay_directory.path(), service).await?;
    let mut replay = open(replay_directory.path(), service).await?;
    ensure!(replay.recover(&Shutdown::new().signal()).await?);
    let replay_conn = replay.db_conn();
    ensure!(
        certified_history::load(&replay_conn, 1)
            .await?
            .decision()
            .id()?
            == certified_history::load(&conn, 1).await?.decision().id()?
    );
    for height in 2..=final_height {
        let retained = certified_history::load(&conn, height).await?;
        let authority = certified_history::committee(&replay_conn, height).await?;
        let verified = AuthenticatedDecision::verify(
            retained.decision().clone(),
            retained.input().clone(),
            retained.proof().to_vec(),
            &authority,
        )?;
        certified_history::append(&replay_conn, &verified).await?;
        ensure!(replay.recover(&Shutdown::new().signal()).await?);
        if height % 256 == 0 {
            eprintln!("two-upgrade historical replay: {height}/{final_height}");
        }
    }
    ensure!(replay.protocol_context == third);
    ensure!(
        without_local_epoch(full_state(&replay_conn).await?)? == without_local_epoch(expected)?
    );
    ensure!(eras::at(&replay_conn, final_height).await? == expected_era);
    ensure!(migrations(&replay_conn).await? == applied);
    ensure!(activation::current(&replay_conn).await? == Some(last_activation));
    Ok(
        json!({"qualification_only_p3": true, "fresh_second_approval": true,
        "second_notice_blocks": 1008, "activation_heights": [first_height, activation_height],
        "protocols": [hex::encode(Baseline::for_node(second.chain)?.context.protocol.0),
            hex::encode(second.protocol.0), hex::encode(third.protocol.0)],
        "p2_p3_share_executor": true, "migration_applications": applied.len(),
        "reopen_and_genesis_replay_match": true, "node_local_epoch_excluded": true,
        "closed_decisions": final_height}),
    )
}
