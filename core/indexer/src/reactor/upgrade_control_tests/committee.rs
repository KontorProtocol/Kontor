use anyhow::{Context, Result};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use indexer_types::{Inst, InstKind, Insts};
use tempfile::TempDir;

use super::{append, finish, open, schedule};
use crate::consensus::signing::PrivateKey;
use crate::database::certified_history::{self, completion, control, registrations};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::control::{ApprovalSigner, ControlError};
use crate::reactor::certified_fixture;
use crate::reactor::execution::ExecutionStep;
use crate::runtime::staking::{self, api::wave::register_validator_call_expr};
use crate::runtime::{Decimal, GenesisValidator};
use crate::stopper::Shutdown;
use crate::test_utils::test_genesis;

#[tokio::test]
async fn committee_registration_reorg_preserves_unrelated_consent_and_invalidates_reused_key()
-> Result<()> {
    let directory = TempDir::new()?;
    let cold_directory = TempDir::new()?;
    let stable_key = PrivateKey::from([17; 32]);
    let joining_key = PrivateKey::from([18; 32]);
    let stable_owner =
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[71; 32])?);
    let joining_owner =
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[72; 32])?);
    let genesis = test_genesis(&[GenesisValidator {
        x_only_pubkey: stable_owner.x_only_public_key().0.to_string(),
        ed25519_pubkey: stable_key.public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }]);
    let registration = certified_fixture::transaction(
        &joining_owner,
        Insts::direct(vec![
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Issuance,
            },
            Inst {
                gas_limit: 100_000,
                kind: InstKind::Call {
                    contract: staking::address(),
                    expr: register_validator_call_expr(
                        joining_key.public_key().as_bytes().to_vec(),
                        Decimal::from("5"),
                    ),
                },
            },
        ]),
        1,
    )?;
    let mut execution = open(directory.path(), &genesis).await?;
    let context = execution.protocol_context;
    let first = certified_fixture::empty_block(1);
    let mut parent = first.prev_hash;
    let mut history = Vec::new();
    let mut original = first;
    for bitcoin_height in 1..=14 {
        let block = certified_fixture::block(
            bitcoin_height,
            parent,
            0,
            if bitcoin_height == 2 {
                vec![registration.clone()]
            } else {
                vec![]
            },
        );
        parent = block.hash;
        let input = block.exact_input(context)?;
        let height = append(&execution, input.clone(), &stable_key).await?;
        finish(&mut execution, height).await?;
        history.push(input);
        original = block;
    }
    let before = registrations::latest(&execution.db_conn())
        .await?
        .context("registration observation")?;
    let committee = before.authority()?;
    assert_eq!(
        committee.members.len(),
        2,
        "real registration must activate"
    );
    let joining = committee
        .members
        .iter()
        .find(|member| member.key == *joining_key.public_key().as_bytes())
        .context("activated member")?;
    let stable = committee
        .members
        .iter()
        .find(|member| member.key == *stable_key.public_key().as_bytes())
        .context("stable member")?;
    let stable_only = schedule(&execution, &stable_key).await?.upgrade_control()?;
    let mut both = stable_only.clone();
    both.approvals
        .push(ApprovalSigner::new(joining_key.clone()).sign(&both.action, joining.generation)?);
    both.approvals.sort_by_key(|approval| approval.key);
    let mut previous_generation = joining.generation;
    let replacement = certified_fixture::block(14, original.prev_hash, 1, vec![]);

    for (index, block) in [replacement, original].into_iter().enumerate() {
        let input = block.exact_input(context)?;
        let height = append(&execution, input.clone(), &stable_key).await?;
        history.push(input);
        let mut saw_inactive = false;
        for _ in 0..200 {
            match execution.step_certified_closure(height).await? {
                ExecutionStep::RolledBack(13) => {
                    let observation = registrations::latest(&execution.db_conn())
                        .await?
                        .context("rollback observation")?;
                    let entry = observation
                        .entries
                        .iter()
                        .find(|entry| entry.holder == joining.holder)
                        .context("watched joining holder")?;
                    assert_eq!(entry.value.as_ref().unwrap().1, 2, "pending join restored");
                    assert!(entry.generation.is_none());
                    saw_inactive = true;
                    break;
                }
                ExecutionStep::Complete => anyhow::bail!("replacement skipped rollback"),
                _ => {}
            }
        }
        assert!(saw_inactive);
        if index == 0 {
            execution.owner_service.shutdown();
            drop(execution);
            execution = open(directory.path(), &genesis).await?;
            assert!(execution.recover(&Shutdown::new().signal()).await?);
        } else {
            finish(&mut execution, height).await?;
        }
        let after = registrations::latest(&execution.db_conn())
            .await?
            .context("replacement observation")?;
        let authority = after.authority()?;
        let restored = authority
            .members
            .iter()
            .find(|member| member.key == joining.key)
            .context("replayed member")?;
        assert_ne!(restored.generation, previous_generation);
        assert_ne!(restored.generation, joining.generation);
        previous_generation = restored.generation;
        assert_eq!(
            authority
                .members
                .iter()
                .find(|member| member.key == stable.key)
                .unwrap()
                .generation,
            stable.generation,
        );
        assert_eq!(after.committee, before.committee);
        let at = control::Position {
            decision: height + 1,
            stage: 0,
        };
        // The unsigned action and stable member's approval have not changed.
        // Re-anchoring the transport does not reauthorize the departed member.
        let input = ExactInput::control(context, 14, block.hash, &stable_only)?;
        control::admission::verify(&execution.db_conn(), &input, at.decision, at).await?;
        let input = ExactInput::control(context, 14, block.hash, &both)?;
        let error = control::admission::verify(&execution.db_conn(), &input, at.decision, at)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<ControlError>(),
                Some(ControlError::Approval)
            ),
            "{error:#}"
        );
        let mut fresh = stable_only.clone();
        fresh.approvals.push(
            ApprovalSigner::new(joining_key.clone()).sign(&fresh.action, restored.generation)?,
        );
        fresh.approvals.sort_by_key(|approval| approval.key);
        let input = ExactInput::control(context, 14, block.hash, &fresh)?;
        control::admission::verify(&execution.db_conn(), &input, at.decision, at).await?;
    }

    let mut cold = open(cold_directory.path(), &genesis).await?;
    for input in history {
        let height = append(&cold, input, &stable_key).await?;
        finish(&mut cold, height).await?;
        let expected = completion::completed(&execution.db_conn(), height).await?;
        assert_eq!(
            completion::completed(&cold.db_conn(), height).await?,
            expected
        );
        for stage in 1..=expected.stages {
            assert_eq!(
                registrations::at(&cold.db_conn(), height, stage).await?,
                registrations::at(&execution.db_conn(), height, stage).await?,
            );
        }
    }
    assert_eq!(
        certified_history::frontier(&cold.db_conn())
            .await?
            .closed_height,
        16
    );
    for execution in [&cold, &execution] {
        assert_eq!(execution.owner_service.active_roots().await, 0);
        execution.owner_service.shutdown();
    }
    Ok(())
}
