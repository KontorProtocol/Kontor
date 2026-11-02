use super::consensus_state::PendingProposal;
use crate::consensus::Height;
use crate::upgrade_control::{
    PrepareUpgrade, RequestedUpgrade, SubmissionError, SubmitUpgrade, UpgradeSubmission,
    decode_submission, prepare, snapshot,
};
use malachitebft_core_types::Round;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use anyhow::{Context, Result};
use bitcoin::Network;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use indexer_types::{Inst, InstKind, Insts};
use tempfile::TempDir;

use super::PruneConfig;
use super::certified_fixture;
use super::create_executor_session;
use super::execution::{ExecutionContext, ExecutionStep};
use super::executor::RuntimeExecutor;
use crate::bitcoin_client::Client;
use crate::consensus::signing::PrivateKey;
use crate::database::Writer;
use crate::database::canonical_history;
use crate::database::certified_history::{self, closure, completion, control};
use crate::migration_rehearsal::{self, MigrationRehearsalArgs};
use crate::protocol::coordinator::certified_decision::tests::proof;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{
    ApprovalSigner, ControlAction, ControlOperation, UpgradeControl,
};
use crate::protocol::identity::ExecutionDefinitionId;
use crate::protocol::v1::migration_definition;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::test_genesis;
use crate::upgrade_approval_cli::{
    self, ApprovalOutput, UpgradeApprovalArgs, UpgradeApprovalCommand,
};

#[path = "upgrade_control_tests/committee.rs"]
mod committee;

async fn open(
    directory: &Path,
    genesis: &GenesisParameters,
) -> Result<ExecutionContext<RuntimeExecutor>> {
    let writer = Writer::new(directory, "upgrade-control.db").await?;
    let service = OwnerService::new();
    let (executor, session, height, hash) = Box::pin(create_executor_session(
        1,
        &writer,
        &service,
        Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?,
        genesis,
        Network::Regtest,
    ))
    .await?;
    let context = certified_history::frontier(&session.conn)
        .await?
        .context
        .context("protocol context")?;
    Ok(ExecutionContext::new(
        executor,
        session,
        Network::Regtest,
        service,
        context,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        height,
        hash,
    ))
}

async fn append(
    execution: &ExecutionContext<RuntimeExecutor>,
    input: ExactInput,
    key: &PrivateKey,
) -> Result<u64> {
    let conn = execution.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    let height = frontier.authenticated_height + 1;
    let authority = certified_history::committee(&conn, height).await?;
    let decision = Decision {
        height,
        predecessor: frontier.authenticated_id.context("predecessor")?,
        committee: authority.id()?,
        descriptor: input.descriptor().clone(),
    };
    let certificate = proof(&decision, &[key.clone()], &[0], 0);
    certified_history::append(
        &conn,
        &AuthenticatedDecision::verify(decision, input, certificate, &authority)?,
    )
    .await?;
    Ok(height)
}

async fn finish(execution: &mut ExecutionContext<RuntimeExecutor>, height: u64) -> Result<()> {
    for _ in 0..200 {
        if matches!(
            execution.step_certified_closure(height).await?,
            ExecutionStep::Complete
        ) {
            return Ok(());
        }
    }
    anyhow::bail!("bounded fixture did not complete closure")
}

async fn schedule(
    execution: &ExecutionContext<RuntimeExecutor>,
    key: &PrivateKey,
) -> Result<ExactInput> {
    let conn = execution.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    let reference = completion::completed(&conn, frontier.closed_height).await?;
    let state = control::admission::state(&conn, execution.protocol_context).await?;
    let authority = certified_history::committee(&conn, frontier.closed_height + 1).await?;
    let mut manifest = state.current_manifest.clone();
    manifest.protocol_number += 1;
    manifest.predecessor = state.context.protocol;
    let action = ControlAction {
        context: state.context,
        head: state.head,
        nonce: state.nonce + 1,
        expected_pending: state.pending.as_ref().map(|plan| plan.id),
        reference_height: reference.height,
        reference_decision: reference.decision,
        expires_at: reference.bitcoin_height + 100,
        operation: ControlOperation::Schedule {
            manifest,
            activation: reference.bitcoin_height + 1008,
        },
    };
    let member = authority
        .members
        .iter()
        .find(|member| member.key == *key.public_key().as_bytes())
        .context("approval member")?;
    let control = UpgradeControl {
        approvals: vec![ApprovalSigner::new(key.clone()).sign(&action, member.generation)?],
        action,
    };
    Ok(ExactInput::control(
        execution.protocol_context,
        execution.last_height,
        execution.last_hash.context("Bitcoin tip")?,
        &control,
    )?)
}

#[tokio::test]
async fn finality_undo_restart_and_fresh_approval_match_cold_reconstruction() -> Result<()> {
    let directory = TempDir::new()?;
    let cold_directory = TempDir::new()?;
    let key = PrivateKey::from([17; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[71; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let mut execution = open(directory.path(), &genesis).await?;
    let context = execution.protocol_context;
    let mut history = Vec::new();
    let first = certified_fixture::empty_block(1);
    let input = first.exact_input(context)?;
    let height = append(&execution, input.clone(), &key).await?;
    history.push(input);
    finish(&mut execution, height).await?;

    let issuance = certified_fixture::transaction(
        &owner,
        Insts::direct(vec![Inst {
            gas_limit: 100_000,
            kind: InstKind::Issuance,
        }]),
        0,
    )?;
    let input = ExactInput::batch(context, 1, first.hash, &[issuance])?;
    let height = append(&execution, input.clone(), &key).await?;
    history.push(input);
    finish(&mut execution, height).await?;
    let original = schedule(&execution, &key).await?;
    let original_action = original.upgrade_control()?.action.id()?;
    let height = append(&execution, original.clone(), &key).await?;
    history.push(original.clone());
    finish(&mut execution, height).await?;
    assert!(
        control::current(&execution.db_conn())
            .await?
            .unwrap()
            .pending
            .is_some()
    );

    let mut parent = first.hash;
    for bitcoin_height in 2..=7 {
        let block = certified_fixture::block(bitcoin_height, parent, 0, vec![]);
        parent = block.hash;
        let input = block.exact_input(context)?;
        let height = append(&execution, input.clone(), &key).await?;
        history.push(input);
        if bitcoin_height < 7 {
            finish(&mut execution, height).await?;
        }
    }
    let rollback_decision = history.len() as u64;
    let mut undone = false;
    for _ in 0..100 {
        match execution.step_certified_closure(rollback_decision).await? {
            ExecutionStep::RolledBack(0) => {
                undone = true;
                break;
            }
            ExecutionStep::Complete => anyhow::bail!("finality did not undo unconfirmed batch"),
            _ => {}
        }
    }
    assert!(undone);
    assert!(control::current(&execution.db_conn()).await?.is_none());
    assert!(
        control::is_retracted(
            &execution.db_conn(),
            original_action,
            control::Position {
                decision: rollback_decision,
                stage: u64::MAX
            }
        )
        .await?
    );
    assert_eq!(execution.owner_service.active_roots().await, 0);
    execution.owner_service.shutdown();
    drop(execution);

    let mut execution = open(directory.path(), &genesis).await?;
    assert!(execution.recover(&Shutdown::new().signal()).await?);
    assert_eq!(execution.last_height, 7);
    assert!(control::current(&execution.db_conn()).await?.is_none());
    let at = control::Position {
        decision: rollback_decision + 1,
        stage: 0,
    };
    assert_eq!(
        control::reference_floor(&execution.db_conn(), at).await?,
        rollback_decision
    );
    assert!(
        control::admission::verify(&execution.db_conn(), &original, at.decision, at)
            .await
            .is_err()
    );
    let envelope = original.upgrade_control()?;
    let reanchored = ExactInput::control(context, 7, parent, &envelope)?;
    assert!(
        control::admission::verify(&execution.db_conn(), &reanchored, at.decision, at)
            .await
            .is_err()
    );
    // Historical application remains verifiable after its canonical effect vanished.
    closure::recover(&execution.db_conn(), 3).await?;
    assert_eq!(
        certified_history::load(&execution.db_conn(), 3)
            .await?
            .input(),
        &original
    );

    let mut cold = open(cold_directory.path(), &genesis).await?;
    for input in &history {
        let height = append(&cold, input.clone(), &key).await?;
        finish(&mut cold, height).await?;
    }
    assert_eq!(
        completion::completed(&execution.db_conn(), rollback_decision).await?,
        completion::completed(&cold.db_conn(), rollback_decision).await?
    );
    assert_eq!(control::current(&cold.db_conn()).await?, None);
    assert_eq!(
        control::reference_floor(&cold.db_conn(), at).await?,
        rollback_decision
    );

    let fresh = schedule(&execution, &key).await?;
    assert_ne!(fresh.upgrade_control()?.action.id()?, original_action);
    control::admission::verify(&execution.db_conn(), &fresh, at.decision, at).await?;
    for execution in [&mut execution, &mut cold] {
        let height = append(execution, fresh.clone(), &key).await?;
        finish(execution, height).await?;
    }
    assert_eq!(
        control::current(&execution.db_conn()).await?,
        control::current(&cold.db_conn()).await?
    );
    assert!(
        control::current(&execution.db_conn())
            .await?
            .unwrap()
            .pending
            .is_some()
    );
    assert_eq!(
        completion::completed(&execution.db_conn(), at.decision).await?,
        completion::completed(&cold.db_conn(), at.decision).await?
    );
    execution.owner_service.shutdown();
    cold.owner_service.shutdown();
    Ok(())
}

#[tokio::test]
async fn operator_queue_proposes_exact_approval_before_pending_block_and_drops_consumed_action()
-> Result<()> {
    let directory = TempDir::new()?;
    let key = PrivateKey::from([19; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[73; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let mut reactor = Box::pin(certified_fixture::reactor_with_consensus(
        directory.path(),
        &genesis,
        key.clone(),
        1,
        true,
    ))
    .await?;
    let first = certified_fixture::empty_block(1);
    let height = append(
        &reactor.execution,
        first.exact_input(reactor.execution.protocol_context)?,
        &key,
    )
    .await?;
    assert!(
        snapshot(&reactor.db_conn())
            .await
            .unwrap_err()
            .is::<SubmissionError>()
    );
    finish(&mut reactor.execution, height).await?;
    reactor.consensus.current_height = Height::new(2);
    let state = snapshot(&reactor.db_conn()).await?;
    assert_eq!(state.reference_height, "1");
    assert_eq!(state.inclusion_height, "2");
    assert_eq!(state.bitcoin_height, "1");
    assert_eq!(state.nonce, "0");
    assert!(state.pending.is_none());
    assert_eq!(
        state.committee[0].key,
        hex::encode(key.public_key().as_bytes())
    );

    let original = schedule(&reactor.execution, &key).await?;
    let envelope = original.upgrade_control()?;
    let decoded = decode_submission(SubmitUpgrade {
        envelope_hex: hex::encode(envelope.encode()?),
    })?;
    assert_eq!(decoded, envelope);
    let mut wrong_codec = envelope.clone();
    wrong_codec.action.context.codec = 2;
    let wrong_codec = decode_submission(SubmitUpgrade {
        envelope_hex: hex::encode(wrong_codec.encode()?),
    })?;
    let (reply, result) = oneshot::channel();
    reactor
        .submit_upgrade(UpgradeSubmission {
            envelope: wrong_codec,
            reply,
        })
        .await?;
    assert!(matches!(result.await?, Err(SubmissionError::Invalid(_))));

    let mut bad = envelope.clone();
    bad.approvals[0].signature[0] ^= 1;
    let (reply, result) = oneshot::channel();
    reactor
        .submit_upgrade(UpgradeSubmission {
            envelope: bad,
            reply,
        })
        .await?;
    assert!(matches!(result.await?, Err(SubmissionError::Invalid(_))));

    for _ in 0..2 {
        let (reply, result) = oneshot::channel();
        reactor
            .submit_upgrade(UpgradeSubmission {
                envelope: envelope.clone(),
                reply,
            })
            .await?;
        let queued = result.await??;
        assert_eq!(queued.status, "queued");
        assert_eq!(queued.action_id, hex::encode(envelope.action.id()?));
    }
    let mut competing = envelope.clone();
    competing.action.expires_at -= 1;
    competing.approvals[0] = ApprovalSigner::new(key.clone())
        .sign(&competing.action, competing.approvals[0].generation)?;
    let (reply, result) = oneshot::channel();
    reactor
        .submit_upgrade(UpgradeSubmission {
            envelope: competing,
            reply,
        })
        .await?;
    assert!(matches!(result.await?, Err(SubmissionError::Busy)));

    let batch = ExactInput::batch(reactor.execution.protocol_context, 1, first.hash, &[])?;
    let height = append(&reactor.execution, batch, &key).await?;
    assert!(
        reactor
            .pending_control
            .input(&reactor.db_conn(), 3)
            .await?
            .is_none()
    );
    finish(&mut reactor.execution, height).await?;
    reactor.consensus.current_height = Height::new(3);
    assert_eq!(
        reactor
            .pending_control
            .input(&reactor.db_conn(), 3)
            .await?
            .unwrap(),
        original
    );

    let block = certified_fixture::block(2, first.hash, 0, vec![]);
    reactor.consensus.pending_blocks.insert(2, block);
    let (reply, proposed) = oneshot::channel();
    reactor.consensus.pending_proposal = Some(PendingProposal {
        height: Height::new(3),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now() + Duration::from_secs(5),
    });
    assert!(reactor.try_fulfill_pending_proposal().await?);
    let proposed = proposed.await?;
    assert_eq!(proposed.value.input(), &original);
    assert!(reactor.consensus.pending_blocks.contains_key(&2));
    let height = append(&reactor.execution, proposed.value.input().clone(), &key).await?;
    // A certified but unfinished decision must not erase a valid pending entry.
    assert!(
        reactor
            .pending_control
            .input(&reactor.db_conn(), 4)
            .await?
            .is_none()
    );
    finish(&mut reactor.execution, height).await?;
    reactor.consensus.current_height = Height::new(4);
    assert!(
        reactor
            .pending_control
            .input(&reactor.db_conn(), 4)
            .await?
            .is_none()
    );
    let (reply, result) = oneshot::channel();
    reactor
        .submit_upgrade(UpgradeSubmission { envelope, reply })
        .await?;
    assert!(matches!(result.await?, Err(SubmissionError::Invalid(_))));
    let state = snapshot(&reactor.db_conn()).await?;
    assert_eq!(state.nonce, "1");
    assert!(state.pending.is_some());
    assert!(
        reactor
            .consensus
            .engine
            .stop(Duration::from_secs(5))
            .await?
    );
    reactor.execution.owner_service.shutdown();
    Ok(())
}

async fn prepared_input(
    execution: &ExecutionContext<RuntimeExecutor>,
    key: &PrivateKey,
    operation: RequestedUpgrade,
) -> Result<ExactInput> {
    let conn = execution.db_conn();
    let prepared = prepare(
        &conn,
        PrepareUpgrade {
            expires_at: (execution.last_height + 100).to_string(),
            operation,
        },
    )
    .await?;
    let action = ControlAction::decode(&hex::decode(&prepared.action_hex)?)?;
    assert_eq!(prepared.action_id, hex::encode(action.id()?));
    let frontier = certified_history::frontier(&conn).await?;
    let authority = certified_history::committee(&conn, frontier.closed_height + 1).await?;
    let member = authority
        .members
        .iter()
        .find(|member| member.key == *key.public_key().as_bytes())
        .context("approval member")?;
    let files = TempDir::new()?;
    let preparation = files.path().join("preparation.json");
    let key_file = files.path().join("fixture.key");
    fs::write(&preparation, serde_json::to_vec(&prepared)?)?;
    fs::write(&key_file, hex::encode(key.inner().to_bytes()))?;
    let approval = upgrade_approval_cli::run(UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Sign {
            preparation: preparation.clone(),
            key_file,
            registration_generation: hex::encode(member.generation),
            expected_action_id: prepared.action_id,
        },
    })?;
    let approval_file = files.path().join("approval.json");
    fs::write(&approval_file, serde_json::to_vec(&approval)?)?;
    let ApprovalOutput::Assemble(assembled) = upgrade_approval_cli::run(UpgradeApprovalArgs {
        command: UpgradeApprovalCommand::Assemble {
            preparation,
            approval_files: vec![approval_file],
        },
    })?
    else {
        anyhow::bail!("expected assembled approval envelope");
    };
    let envelope = UpgradeControl::decode(&hex::decode(&assembled.envelope_hex)?)?;
    assert_eq!(envelope.action, action);
    Ok(ExactInput::control(
        execution.protocol_context,
        execution.last_height,
        execution.last_hash.context("Bitcoin tip")?,
        &envelope,
    )?)
}

async fn assert_boundary_rejected(
    execution: &ExecutionContext<RuntimeExecutor>,
    key: &PrivateKey,
    activation: u64,
) -> Result<()> {
    let conn = execution.db_conn();
    let frontier = certified_history::frontier(&conn).await?;
    let state = control::current(&conn).await?;
    let candidate = certified_fixture::block(
        activation,
        execution.last_hash.context("Bitcoin tip")?,
        0,
        vec![],
    );
    // This candidate also has a height gap. Require the specific boundary error
    // to prove append stops at the guard, before recording or branch mutation.
    let error = append(
        execution,
        candidate.exact_input(execution.protocol_context)?,
        key,
    )
    .await
    .unwrap_err();
    assert!(error.is::<control::ActivationRequired>(), "{error:#}");
    assert_eq!(certified_history::frontier(&conn).await?, frontier);
    assert_eq!(control::current(&conn).await?, state);
    Ok(())
}

#[tokio::test]
async fn prepared_controls_and_bitcoin_reorg_restore_postponed_then_original_schedule() -> Result<()>
{
    let directory = TempDir::new()?;
    let key = PrivateKey::from([23; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[79; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let mut execution = open(directory.path(), &genesis).await?;
    let first = certified_fixture::empty_block(1);
    let height = append(
        &execution,
        first.exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    let conn = execution.db_conn();
    let before = certified_history::frontier(&conn).await?;
    let state = control::admission::state(&conn, execution.protocol_context).await?;
    let mut manifest = state.current_manifest.clone();
    manifest.protocol_number += 1;
    manifest.predecessor = state.context.protocol;
    let manifest_hex = hex::encode(manifest.encode()?);
    assert!(
        prepare(
            &conn,
            PrepareUpgrade {
                expires_at: "101".into(),
                operation: RequestedUpgrade::Schedule {
                    manifest_hex: manifest_hex.clone(),
                    activation_height: "2".into(),
                }
            }
        )
        .await
        .unwrap_err()
        .is::<SubmissionError>()
    );
    assert!(
        prepare(
            &conn,
            PrepareUpgrade {
                expires_at: "101".into(),
                operation: RequestedUpgrade::Cancel
            }
        )
        .await
        .is_err()
    );
    let schedule = prepared_input(
        &execution,
        &key,
        RequestedUpgrade::Schedule {
            manifest_hex: manifest_hex.clone(),
            activation_height: "4000".into(),
        },
    )
    .await?;
    assert_eq!(certified_history::frontier(&conn).await?, before);
    assert_eq!(
        control::admission::state(&conn, execution.protocol_context).await?,
        state
    );
    let height = append(&execution, schedule, &key).await?;
    finish(&mut execution, height).await?;
    let scheduled = control::current(&conn).await?.context("scheduled state")?;
    assert_boundary_rejected(&execution, &key, 4000).await?;
    assert!(
        prepare(
            &conn,
            PrepareUpgrade {
                expires_at: "101".into(),
                operation: RequestedUpgrade::Schedule {
                    manifest_hex,
                    activation_height: "5000".into(),
                }
            }
        )
        .await
        .is_err()
    );

    let second = certified_fixture::block(2, first.hash, 0, vec![]);
    let height = append(
        &execution,
        second.exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    let postpone = prepared_input(
        &execution,
        &key,
        RequestedUpgrade::Postpone {
            activation_height: "5000".into(),
        },
    )
    .await?;
    let postpone_height = append(&execution, postpone.clone(), &key).await?;
    finish(&mut execution, postpone_height).await?;
    let postponed = control::current(&conn).await?.context("postponed state")?;
    assert_eq!(postponed.pending.as_ref().unwrap().activation, 5000);
    assert_boundary_rejected(&execution, &key, 5000).await?;

    let third = certified_fixture::block(3, second.hash, 0, vec![]);
    let height = append(
        &execution,
        third.exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    let cancel = prepared_input(&execution, &key, RequestedUpgrade::Cancel).await?;
    let cancel_height = append(&execution, cancel.clone(), &key).await?;
    finish(&mut execution, cancel_height).await?;
    assert!(control::current(&conn).await?.unwrap().pending.is_none());

    let replacement = certified_fixture::block(3, second.hash, 1, vec![]);
    let height = append(
        &execution,
        replacement.exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    assert_eq!(control::current(&conn).await?, Some(postponed));
    let replacement = certified_fixture::block(2, first.hash, 2, vec![]);
    let height = append(
        &execution,
        replacement.exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    assert_eq!(control::current(&conn).await?, Some(scheduled));
    assert_boundary_rejected(&execution, &key, 4000).await?;
    for original in [&postpone, &cancel] {
        let reanchored = ExactInput::control(
            execution.protocol_context,
            2,
            replacement.hash,
            &original.upgrade_control()?,
        )?;
        assert!(
            control::admission::verify(
                &conn,
                &reanchored,
                height + 1,
                control::Position {
                    decision: height + 1,
                    stage: 0
                }
            )
            .await
            .is_err()
        );
    }
    closure::recover(&conn, postpone_height).await?;
    closure::recover(&conn, cancel_height).await?;
    assert_eq!(
        snapshot(&conn).await?.minimum_reference_height,
        height.to_string()
    );

    let fresh = prepared_input(
        &execution,
        &key,
        RequestedUpgrade::Postpone {
            activation_height: "5000".into(),
        },
    )
    .await?;
    assert_ne!(
        fresh.upgrade_control()?.action.id()?,
        postpone.upgrade_control()?.action.id()?
    );
    let height = append(&execution, fresh, &key).await?;
    finish(&mut execution, height).await?;
    assert_eq!(
        control::current(&conn)
            .await?
            .unwrap()
            .pending
            .unwrap()
            .activation,
        5000
    );
    execution.owner_service.shutdown();
    Ok(())
}

#[tokio::test]
async fn migration_rehearsal_reports_real_snapshot_without_mutating_source() -> Result<()> {
    let directory = TempDir::new()?;
    let key = PrivateKey::from([23; 32]);
    let owner = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[79; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let mut execution = open(directory.path(), &genesis).await?;
    let height = append(
        &execution,
        certified_fixture::empty_block(1).exact_input(execution.protocol_context)?,
        &key,
    )
    .await?;
    finish(&mut execution, height).await?;
    let conn = execution.db_conn();
    let before = certified_history::frontier(&conn).await?;
    let canonical = canonical_history::state(&conn).await?;
    let state = control::admission::state(&conn, execution.protocol_context).await?;
    let mut target = state.current_manifest.clone();
    target.protocol_number += 1;
    target.predecessor = state.context.protocol;
    let path = directory.path().join("upgrade-control.db");
    let database_bytes = fs::read(&path)?;
    let wal_path = directory.path().join("upgrade-control.db-wal");
    let wal_bytes = fs::read(&wal_path).ok();
    let target_file = directory.path().join("target.json");
    for case in 0..4 {
        let mut target = target.clone();
        let mut definition = migration_definition::noop(target.executor);
        if case == 1 {
            definition.routine = "not-installed".into();
        }
        if case == 2 {
            target.executor = ExecutionDefinitionId([254; 32]);
            definition.execution = target.executor;
        }
        if case == 3 {
            target.consensus = [253; 32];
        }
        target.migration = definition.id()?;
        fs::write(
            &target_file,
            serde_json::to_vec(&serde_json::json!({
                "manifest_hex":hex::encode(target.encode()?),
                "migration_definition_hex":hex::encode(definition.encode()?),
            }))?,
        )?;
        let report = Box::pin(migration_rehearsal::run(MigrationRehearsalArgs {
            database: path.clone(),
            target: target_file.clone(),
            network: Network::Regtest,
        }))
        .await?;
        assert_eq!(
            report.outcome,
            if case == 0 || case == 3 {
                "succeeded"
            } else {
                "failed"
            }
        );
        assert_eq!(report.target_protocol_id, hex::encode(target.id()?.0));
        assert_eq!(report.decision_height, before.closed_height.to_string());
        assert_eq!(
            report.source_protocol_id,
            hex::encode(state.context.protocol.0)
        );
        assert_eq!(
            report.work_consumed.as_ref().unwrap().computation_steps,
            "0"
        );
        assert!(!report.authorizes_upgrade);
        assert_eq!(report.target_support.executor_registered, case != 2);
        assert_eq!(report.target_support.consensus_registered, case != 3);
        assert_eq!(
            report.target_support.migration_registered,
            if case == 2 { None } else { Some(case != 1) }
        );
        if case == 0 || case == 3 {
            assert_ne!(report.output_lineage.as_ref(), Some(&report.input_lineage));
            assert!(report.error.is_none());
        } else {
            assert!(report.output_lineage.is_none());
            assert!(report.error.as_ref().unwrap().contains(if case == 1 {
                "not registered"
            } else {
                "not linked"
            }));
        }
        assert_eq!(certified_history::frontier(&conn).await?, before);
        assert_eq!(canonical_history::state(&conn).await?, canonical);
        assert_eq!(
            control::admission::state(&conn, execution.protocol_context).await?,
            state
        );
        assert_eq!(fs::read(&path)?, database_bytes);
        assert_eq!(fs::read(&wal_path).ok(), wal_bytes);
    }
    Ok(())
}
