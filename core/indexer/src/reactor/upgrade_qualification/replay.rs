use anyhow::{Context, Result, ensure};
use bitcoin::{blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use libsql::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::NETWORK;
use super::fixture::{append, open, seed, snapshot};
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{self, activation, closure, completion, control, eras};
use crate::protocol::canonical_application::{ApplicationSource, CanonicalApplication};
use crate::protocol::coordinator::application_closure::StageOutcome;
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{
    ApprovalSigner, ControlAction, ControlOperation, UpgradeControl,
};
use crate::protocol::identity::ExecutionIdentity;
use crate::protocol_qualification::snapshot::full_state;
use crate::reactor::certified::qualification::fixture::issuance_transaction;
use crate::reactor::execution::{ExecutionContext, ExecutionStep};
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    SurvivingSchedule,
    UndoCancel,
    UndoPostpone,
}

pub(super) async fn change_plan(
    execution: &ExecutionContext<RuntimeExecutor>,
    postpone: bool,
) -> Result<ExactInput> {
    let conn = execution.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    let reference = completion::completed(&conn, frontier.closed_height).await?;
    let state = control::admission::state(&conn, execution.protocol_context).await?;
    let plan = state
        .pending
        .as_ref()
        .context("fixture schedule disappeared")?;
    let authority = certified_history::committee(&conn, frontier.closed_height + 1).await?;
    let key = PrivateKey::from([7; 32]);
    let member = authority
        .members
        .iter()
        .find(|member| member.key == *key.public_key().as_bytes())
        .context("approval member")?;
    let operation = if postpone {
        ControlOperation::Postpone {
            target: plan.manifest.id()?,
            previous_activation: plan.activation,
            activation: reference.bitcoin_height + 1008,
        }
    } else {
        ControlOperation::Cancel {
            target: plan.manifest.id()?,
            activation: plan.activation,
        }
    };
    let action = ControlAction {
        context: state.context,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: Some(plan.id),
        reference_height: reference.height,
        reference_decision: reference.decision,
        expires_at: reference.bitcoin_height + 100,
        operation,
    };
    let envelope = UpgradeControl {
        approvals: vec![ApprovalSigner::new(key).sign(&action, member.generation)?],
        action,
    };
    let input = ExactInput::control(
        execution.protocol_context,
        execution.last_height,
        execution.last_hash.context("Bitcoin tip")?,
        &envelope,
    )?;
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
    Ok(input)
}

async fn execute(
    execution: &mut ExecutionContext<RuntimeExecutor>,
    input: ExactInput,
) -> Result<u64> {
    let height = append(&execution.db_conn(), input).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    Ok(height)
}

async fn assert_application_selection(
    conn: &Connection,
    first: ExecutionIdentity,
    second: ExecutionIdentity,
) -> Result<()> {
    let mut rows = conn
        .query(
            "SELECT record FROM canonical_applications ORDER BY ordinal",
            (),
        )
        .await?;
    let mut old_lifecycle = false;
    let mut migration = false;
    let mut new_lifecycle = false;
    while let Some(row) = rows.next().await? {
        let application = CanonicalApplication::decode(&row.get::<Vec<u8>>(0)?)?;
        match application.source {
            ApplicationSource::BlockLifecycle { height: 2, .. } => {
                ensure!(!migration && application.execution == first);
                old_lifecycle = true;
            }
            ApplicationSource::Migration {
                anchor_height: 2, ..
            } => {
                ensure!(old_lifecycle && application.execution == second);
                migration = true;
            }
            ApplicationSource::BlockLifecycle { height: 3..=7, .. } => {
                ensure!(migration && application.execution == second);
                new_lifecycle = true;
            }
            _ => {}
        }
    }
    ensure!(old_lifecycle && migration && new_lifecycle);
    Ok(())
}

async fn scenario(service: &OwnerService, scenario: Scenario) -> Result<Value> {
    let directory = TempDir::new()?;
    let interrupted_dir = TempDir::new()?;
    let target = seed(directory.path(), service, 2).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let conn = execution.db_conn();
    let initial = execution.protocol_context;
    let first_manifest = certified_history::protocol(&conn, initial.protocol).await?;
    let seeded = control::current(&conn).await?.context("seeded schedule")?;
    let pending = seeded.pending.as_ref().context("seeded pending plan")?;
    let first_identity = ExecutionIdentity::Protocol {
        protocol: initial.protocol,
        execution: first_manifest.executor,
    };
    let second_identity = ExecutionIdentity::Protocol {
        protocol: target,
        execution: pending.manifest.executor,
    };
    let issuance = if matches!(scenario, Scenario::SurvivingSchedule) {
        super::confirmation::transaction()?
    } else {
        issuance_transaction()?
    };
    let batch = ExactInput::batch(
        initial,
        1,
        execution.last_hash.context("first hash")?,
        &[issuance.clone()],
    )?;
    execute(&mut execution, batch).await?;
    let changed = match scenario {
        Scenario::SurvivingSchedule => None,
        Scenario::UndoCancel | Scenario::UndoPostpone => {
            let input = change_plan(&execution, matches!(scenario, Scenario::UndoPostpone)).await?;
            let height = execute(&mut execution, input.clone()).await?;
            Some((height, input))
        }
    };
    let mut block = genesis_block(NETWORK);
    let mut original_activation = None;
    let mut confirmation = None;
    let mut activation_input = None;
    let mut last = 0;
    for bitcoin_height in 2..=7 {
        block.header.prev_blockhash = block.block_hash();
        block.header.nonce = block.header.nonce.wrapping_add(1);
        let context = execution.protocol_context;
        let input = ExactInput::block(context, bitcoin_height, serialize(&block))?;
        let height = certified_history::frontier(&conn).await?.closed_height + 1;
        let input =
            match control::expected_transition(&conn, context, &input.descriptor().command, height)
                .await?
            {
                Some(transition) => input.with_transition(transition.descriptor)?,
                None => input,
            };
        if bitcoin_height == 2 {
            ensure!(input.descriptor().transition.is_some() == changed.is_none());
            activation_input = Some(input.clone());
        }
        last = append(&conn, input).await?;
        if bitcoin_height < 7 {
            ensure!(execution.recover(&Shutdown::new().signal()).await?);
            if bitcoin_height == 2 {
                original_activation = activation::current(&conn).await?;
                ensure!(original_activation.is_some() == changed.is_none());
                if matches!(scenario, Scenario::SurvivingSchedule) {
                    confirmation = Some(
                        super::confirmation::run(
                            &conn,
                            service,
                            &block,
                            &issuance,
                            first_identity,
                            second_identity,
                        )
                        .await?,
                    );
                }
            }
        }
    }
    snapshot(&conn, interrupted_dir.path()).await?;
    let retained = certified_history::load(&conn, last)
        .await?
        .decision()
        .id()?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let active = activation::current(&conn)
        .await?
        .context("reconstructed activation")?;
    ensure!(active.target()?.id()? == target);
    let original_input = activation_input.context("H input")?;
    let ApplicationSource::Migration { anchor_hash, .. } = active.application.source else {
        anyhow::bail!("activation lacks migration source");
    };
    ensure!(
        original_input
            .descriptor()
            .command
            .position()
            .1
            .to_byte_array()
            == anchor_hash,
        "reconstruction changed the activation block hash"
    );
    if let Some(original) = original_activation {
        ensure!(original.application.parent_lineage != active.application.parent_lineage);
        ensure!(original.application.migration_key()? != active.application.migration_key()?);
        let ApplicationSource::Migration {
            anchor_hash: previous,
            ..
        } = original.application.source
        else {
            anyhow::bail!("original activation lacks migration source");
        };
        ensure!(
            previous == anchor_hash,
            "test changed H instead of only its prestate"
        );
    }
    assert_application_selection(&conn, first_identity, second_identity).await?;
    let expected = full_state(&conn).await?;
    let expected_closure = completion::completed(&conn, last).await?;
    let expected_era = eras::at(&conn, last).await?;
    drop(execution);

    let mut interrupted = open(interrupted_dir.path(), service).await?;
    let cancelled = Shutdown::new();
    cancelled.cancel();
    ensure!(!interrupted.recover(&cancelled.signal()).await?);
    let mut undone = false;
    for _ in 0..64 {
        match interrupted.step_certified_closure(last).await? {
            ExecutionStep::RolledBack(0) => {
                undone = true;
                break;
            }
            ExecutionStep::Complete => {
                anyhow::bail!("finality failed to roll back the unconfirmed batch")
            }
            _ => {}
        }
    }
    ensure!(undone);
    let reopened_conn = interrupted.db_conn();
    ensure!(activation::current(&reopened_conn).await?.is_none());
    ensure!(control::current(&reopened_conn).await? == Some(seeded));
    if let Some((_, input)) = &changed {
        ensure!(
            control::is_retracted(
                &reopened_conn,
                input.upgrade_control()?.action.id()?,
                control::Position {
                    decision: last,
                    stage: u64::MAX
                }
            )
            .await?
        );
    }
    drop(interrupted);
    let mut interrupted = open(interrupted_dir.path(), service).await?;
    ensure!(interrupted.recover(&Shutdown::new().signal()).await?);
    ensure!(
        full_state(&reopened_conn).await? == expected,
        "finality recovery differs from uninterrupted execution"
    );
    ensure!(completion::completed(&reopened_conn, last).await? == expected_closure);
    ensure!(eras::at(&reopened_conn, last).await? == expected_era);
    ensure!(
        certified_history::load(&reopened_conn, last)
            .await?
            .decision()
            .id()?
            == retained
    );
    if let Some((height, input)) = changed {
        ensure!(
            certified_history::load(&reopened_conn, height)
                .await?
                .input()
                == &input
        );
        let progress = closure::progress(&reopened_conn, last).await?;
        let mut retracted = false;
        for index in 1..=progress.stage {
            if closure::stage(&reopened_conn, last, index).await?.outcome
                == StageOutcome::RetractedControl
            {
                retracted = true;
            }
        }
        ensure!(
            retracted,
            "retained cancellation/postponement was not explicitly skipped"
        );
    }
    ensure!(service.active_roots().await == 0);
    let mut result = json!({"scenario": format!("{scenario:?}"), "closed_decisions": last,
        "same_bitcoin_history": true, "reopened_state_matches": true,
        "actual_p2_activation": true, "retained_decisions_unchanged": true});
    if let Some(confirmation) = confirmation {
        result["confirmation"] = confirmation;
    }
    Ok(result)
}

pub(super) async fn run(service: &OwnerService) -> Result<Value> {
    let mut cases = Vec::new();
    for case in [
        Scenario::SurvivingSchedule,
        Scenario::UndoCancel,
        Scenario::UndoPostpone,
    ] {
        cases.push(
            scenario(service, case)
                .await
                .with_context(|| format!("finality scenario {case:?}"))?,
        );
    }
    Ok(json!(cases))
}
