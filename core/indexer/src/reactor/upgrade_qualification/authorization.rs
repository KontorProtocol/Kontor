use anyhow::{Context, Result, ensure};
use bitcoin::{Block, blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::NETWORK;
use super::confirmation::{assert_paid_mint, finish_block, transaction};
use super::fixture::{append, open, snapshot, unscheduled};
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{
    self, activation, completion, control, eras, replay as history_replay,
};
use crate::database::queries::get_transaction_by_txid;
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{
    ApprovalSigner, ControlAction, ControlOperation, UpgradeControl,
};
use crate::protocol::coordinator::successor;
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::execution::{ExecutionContext, ExecutionStep};
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

const ACTIVATION_HEIGHT: u64 = 1009;

async fn execute(
    execution: &mut ExecutionContext<RuntimeExecutor>,
    input: ExactInput,
) -> Result<u64> {
    let height = append(&execution.db_conn(), input).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    Ok(height)
}

async fn block_input(
    execution: &ExecutionContext<RuntimeExecutor>,
    height: u64,
    block: &Block,
) -> Result<ExactInput> {
    let conn = execution.db_conn();
    let input = ExactInput::block(execution.protocol_context, height, serialize(block))?;
    let decision = certified_history::frontier(&conn).await?.closed_height + 1;
    Ok(
        match control::expected_transition(
            &conn,
            execution.protocol_context,
            &input.descriptor().command,
            decision,
        )
        .await?
        {
            Some(transition) => input.with_transition(transition.descriptor)?,
            None => input,
        },
    )
}

async fn exercise(service: &OwnerService) -> Result<Value> {
    let directory = TempDir::new()?;
    let interrupted_directory = TempDir::new()?;
    let target = unscheduled(directory.path(), service).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let initial = execution.protocol_context;
    ensure!(control::current(&conn).await?.is_none());
    let state = control::admission::state(&conn, initial).await?;
    let reference = completion::completed(&conn, 1).await?;
    let authority = certified_history::committee(&conn, 2).await?;
    let key = PrivateKey::from([7; 32]);
    let member = authority
        .members
        .iter()
        .find(|member| member.key == *key.public_key().as_bytes())
        .context("approval member")?;
    let action = ControlAction {
        context: initial,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: None,
        reference_height: 1,
        reference_decision: reference.decision,
        expires_at: 101,
        operation: ControlOperation::Schedule {
            manifest: successor::manifest(initial.chain)?,
            activation: ACTIVATION_HEIGHT,
        },
    };
    let action_id = action.id()?;
    let envelope = UpgradeControl {
        approvals: vec![ApprovalSigner::new(key).sign(&action, member.generation)?],
        action,
    };
    let schedule = ExactInput::control(
        initial,
        1,
        execution.last_hash.context("first block")?,
        &envelope,
    )?;
    control::admission::verify(
        &conn,
        &schedule,
        2,
        control::Position {
            decision: 2,
            stage: 0,
        },
    )
    .await?;
    execute(&mut execution, schedule.clone()).await?;
    ensure!(
        control::current(&conn)
            .await?
            .context("accepted schedule")?
            .pending
            .is_some()
    );

    let mut blocks = vec![genesis_block(NETWORK)];
    for height in 2..=ACTIVATION_HEIGHT {
        let mut block = blocks.last().context("prior block")?.clone();
        block.header.prev_blockhash = block.block_hash();
        block.header.nonce = block.header.nonce.wrapping_add(1);
        let input = block_input(&execution, height, &block).await?;
        ensure!(input.descriptor().transition.is_some() == (height == ACTIVATION_HEIGHT));
        execute(&mut execution, input)
            .await
            .with_context(|| format!("authorized block {height}"))?;
        blocks.push(block);
        if height < ACTIVATION_HEIGHT {
            ensure!(execution.protocol_context.protocol == initial.protocol);
        }
        if height % 128 == 0 {
            eprintln!("authorized notice window: {height}/{ACTIVATION_HEIGHT}");
        }
    }
    ensure!(execution.protocol_context.protocol == target);
    ensure!(
        activation::current(&conn)
            .await?
            .context("authorized activation")?
            .target()?
            .id()?
            == target
    );
    let second = execution.protocol_context;
    let paid = transaction()?;
    let mut missing = paid.clone();
    missing.input[0].previous_output.vout = 1;
    let batch = ExactInput::batch(
        second,
        ACTIVATION_HEIGHT,
        execution.last_hash.context("activation hash")?,
        &[paid.clone(), missing.clone()],
    )?;
    let batch_height = execute(&mut execution, batch.clone()).await?;
    let retained = certified_history::load(&conn, batch_height).await?;
    let retained_id = retained.decision().id()?;
    let retained_proof = retained.proof().to_vec();

    // Revisit the original Bitcoin branch after undoing its scheduling action.
    // Its old certificate remains evidence, but is not a fresh approval.
    let mut replacement = blocks[0].clone();
    replacement.header.nonce = replacement.header.nonce.wrapping_add(20_000);
    let input = block_input(&execution, 1, &replacement).await?;
    execute(&mut execution, input).await?;
    ensure!(
        execution.protocol_context.protocol == initial.protocol
            && execution.protocol_context != initial
    );
    ensure!(
        control::current(&conn).await?.is_none() && activation::current(&conn).await?.is_none()
    );
    let rollback_height = certified_history::frontier(&conn).await?.closed_height;
    ensure!(
        control::is_retracted(
            &conn,
            action_id,
            control::Position {
                decision: rollback_height,
                stage: u64::MAX
            }
        )
        .await?
    );
    drop(execution);
    execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let input = block_input(&execution, 1, &blocks[0]).await?;
    execute(&mut execution, input).await?;
    for (index, block) in blocks.iter().enumerate().skip(1) {
        let height = index as u64 + 1;
        let input = block_input(&execution, height, block).await?;
        ensure!(input.descriptor().transition.is_none());
        execute(&mut execution, input)
            .await
            .with_context(|| format!("restored P1 block {height}"))?;
        ensure!(execution.protocol_context.protocol == initial.protocol);
        if height % 128 == 0 {
            eprintln!("restored P1 branch: {height}/{ACTIVATION_HEIGHT}");
        }
    }
    let restored_height = certified_history::frontier(&conn).await?.closed_height;
    ensure!(
        history_replay::eligible(&conn, restored_height, batch_height)
            .await?
            .is_none(),
        "returning Bitcoin hashes revived an orphaned P2 batch"
    );
    ensure!(
        get_transaction_by_txid(&conn, &paid.compute_txid().to_string())
            .await?
            .is_none()
    );
    // The old branch's certificate is retained evidence, not permission to
    // execute its batch again. A fresh decision submits these inputs under P1.
    let fresh_batch = ExactInput::batch(
        execution.protocol_context,
        ACTIVATION_HEIGHT,
        execution.last_hash.context("restored activation hash")?,
        &[paid.clone(), missing.clone()],
    )?;
    let fresh_batch_height = execute(&mut execution, fresh_batch).await?;
    let mut block = blocks.last().context("activation block")?.clone();
    let mut final_height = 0;
    for height in ACTIVATION_HEIGHT + 1..=ACTIVATION_HEIGHT + 6 {
        let parent = block.block_hash();
        block = genesis_block(NETWORK);
        block.header.prev_blockhash = parent;
        block.header.nonce = height as u32;
        if height == ACTIVATION_HEIGHT + 1 {
            block.txdata.push(paid.clone());
            finish_block(&mut block)?;
        }
        let input = block_input(&execution, height, &block).await?;
        final_height = append(&conn, input).await?;
        if height < ACTIVATION_HEIGHT + 6 {
            ensure!(execution.recover(&Shutdown::new().signal()).await?);
        }
    }
    snapshot(&conn, interrupted_directory.path()).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let first_identity = ExecutionIdentity::Protocol {
        protocol: initial.protocol,
        execution: state.current_manifest.executor,
    };
    let mut rows = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut replayed = false;
    while let Some(row) = rows.next().await? {
        let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        if let ApplicationSource::Batch { exclusions, .. } = application.source {
            ensure!(
                exclusions.consensus_height != batch_height,
                "orphaned P2 batch entered canonical applications"
            );
            if exclusions.consensus_height == fresh_batch_height {
                ensure!(application.execution == first_identity);
                ensure!(
                    exclusions
                        .effective
                        .contains(&missing.compute_txid().to_byte_array())
                );
                ensure!(
                    !exclusions
                        .effective
                        .contains(&paid.compute_txid().to_byte_array())
                );
                replayed = true;
            }
        }
    }
    ensure!(replayed, "fresh P1 batch was not reconstructed by finality");
    let transaction = get_transaction_by_txid(&conn, &paid.compute_txid().to_string())
        .await?
        .context("replayed paid transaction")?;
    assert_paid_mint(&conn, transaction.id).await?;
    ensure!(
        transaction.batch_height == Some(fresh_batch_height)
            && transaction.confirmed_height == Some(ACTIVATION_HEIGHT + 1)
    );
    ensure!(
        control::current(&conn).await?.is_none() && activation::current(&conn).await?.is_none()
    );
    ensure!(certified_history::load(&conn, 2).await?.input() == &schedule);
    let after = certified_history::load(&conn, batch_height).await?;
    ensure!(
        after.input() == &batch
            && after.decision().id()? == retained_id
            && after.proof() == retained_proof
    );
    let expected = full_state(&conn).await?;
    let expected_era = eras::at(&conn, final_height).await?;
    drop(execution);

    let mut interrupted = open(interrupted_directory.path(), service).await?;
    let cancelled = Shutdown::new();
    cancelled.cancel();
    ensure!(!interrupted.recover(&cancelled.signal()).await?);
    let mut rolled_back = false;
    for _ in 0..64 {
        match interrupted.step_certified_closure(final_height).await? {
            ExecutionStep::RolledBack(height) if height == ACTIVATION_HEIGHT - 1 => {
                rolled_back = true;
                break;
            }
            ExecutionStep::Complete => break,
            _ => {}
        }
    }
    ensure!(
        rolled_back,
        "finality did not reconstruct the retained batch"
    );
    drop(interrupted);
    let mut reopened = open(interrupted_directory.path(), service).await?;
    ensure!(reopened.recover(&Shutdown::new().signal()).await?);
    ensure!(full_state(&reopened.db_conn()).await? == expected);
    ensure!(eras::at(&reopened.db_conn(), final_height).await? == expected_era);
    ensure!(service.active_roots().await == 0);
    Ok(
        json!({"schema": 1, "authorization_test": true, "notice_blocks": 1008,
        "activation_height": ACTIVATION_HEIGHT, "closed_decisions": final_height,
        "schedule_retracted": true, "orphaned_p2_batch_not_replayed": true,
        "fresh_p1_batch_replayed": true,
        "certificates_unchanged": true, "reopened_state_matches": true}),
    )
}

pub(crate) async fn run() -> Result<Value> {
    let service = OwnerService::new();
    let result = exercise(&service).await;
    service.shutdown();
    result
}
