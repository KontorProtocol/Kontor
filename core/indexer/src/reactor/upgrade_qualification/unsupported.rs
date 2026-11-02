use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow, ensure};
use bitcoin::blockdata::constants::genesis_block;
use malachitebft_core_types::Round;
use serde_json::{Value as Json, json};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{sleep, timeout};

use super::crash::configuration;
use super::fixture::{genesis, open, seed_unsupported};
use super::replay::change_plan;
use super::{DATABASE, NETWORK};
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::{Height, ProposalData, Value};
use crate::database::certified_history::{self, branch, control, eras};
use crate::database::connection::new_read_only_connection;
use crate::protocol::coordinator::registry::UnavailableProtocol;
use crate::reactor::engine::NodeCoordinator;
use crate::reactor::mempool_fee_index::MempoolFeeIndex;
use crate::reactor::{Reactor, start_linked_consensus};
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;
use crate::upgrade_control::UpgradeSubmission;

pub(super) async fn run(service: &OwnerService) -> Result<Json> {
    let directory = TempDir::new()?;
    let target = seed_unsupported(directory.path(), service).await?;
    let mut execution = open(directory.path(), service).await?;
    ensure!(execution.recover(&Shutdown::new().signal()).await?);
    let context = execution.protocol_context;
    let config = configuration(directory.path());
    let (coordinator, _reader, _writer) =
        NodeCoordinator::open_database(&config, DATABASE, NETWORK, 1, &genesis()).await?;
    let consensus = start_linked_consensus(
        config.clone(),
        Some(&coordinator),
        &execution.session,
        service,
        NETWORK,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let (_blocks_tx, blocks) = mpsc::channel(1);
    let (_mempool_tx, mempool) = mpsc::channel(1);
    let (address_tx, _addresses) = watch::channel(None);
    let shutdown = Shutdown::new();
    let mut reactor = Reactor::from_execution(
        execution,
        blocks,
        mempool,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        address_tx,
    );
    reactor.coordinator = Some(coordinator);
    reactor.engine_config = Some(config);
    let mut block = genesis_block(NETWORK);
    block.header.prev_blockhash = block.block_hash();
    block.header.nonce += 1;
    let block_hash = block.block_hash();
    let pending = BlockInput::from_bitcoin(2, block_hash, block);
    let input = pending.exact_input(context)?;
    let transition =
        control::expected_transition(&reactor.db_conn(), context, &input.descriptor().command, 2)
            .await?
            .context("missing due transition")?;
    ensure!(transition.descriptor.target == target);
    ensure!(
        transition
            .require_installed()
            .unwrap_err()
            .is::<UnavailableProtocol>()
    );
    let value = Value::from_input(input.with_transition(transition.descriptor)?)?;
    reactor.consensus.pending_blocks.insert(2, pending);
    ensure!(
        reactor.pending_block_value().await?.is_none(),
        "unsupported block was proposed"
    );
    let (reply, response) = oneshot::channel();
    reactor
        .validate_and_accept_proposal(
            &ProposalData::new(value),
            reactor.consensus.address,
            Height::new(2),
            Round::new(0),
            reply,
        )
        .await?;
    ensure!(
        response.await?.is_none(),
        "unsupported activation was accepted for voting"
    );
    let cancel = change_plan(&reactor.execution, false).await?;
    let action = cancel.upgrade_control()?.action.id()?;
    let (reply, response) = oneshot::channel();
    reactor
        .submit_upgrade(UpgradeSubmission {
            envelope: cancel.upgrade_control()?,
            reply,
        })
        .await?;
    response.await??;
    let observer = new_read_only_connection(directory.path(), DATABASE).await?;
    let observed = async {
        timeout(Duration::from_secs(45), async {
            loop {
                let frontier = certified_history::frontier(&observer).await?;
                if frontier.closed_height >= 3
                    && branch::tip(&observer).await? == Some((2, block_hash))
                {
                    ensure!(frontier.context == Some(context));
                    let decision = certified_history::load(&observer, 2).await?;
                    ensure!(
                        decision.input().upgrade_control()?.action.id()? == action,
                        "Cancel did not win before the blocked activation"
                    );
                    ensure!(
                        control::current(&observer)
                            .await?
                            .context("cancelled control")?
                            .pending
                            .is_none()
                    );
                    ensure!(eras::at(&observer, 3).await?.is_none());
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
            Ok::<_, Error>(())
        })
        .await
        .context("unsupported upgrade Cancel did not make progress")?
    };
    let stopped = shutdown.signal();
    let observe = async {
        let result = tokio::select! { result = observed => result, _ = stopped.cancelled() => Err(anyhow!("reactor stopped before Cancel completed")) };
        shutdown.cancel();
        result
    };
    let running = async {
        let result = reactor.run().await;
        if result.is_err() {
            shutdown.cancel();
        }
        result
    };
    let (running, observed) = tokio::join!(running, observe);
    running?;
    observed?;
    ensure!(reactor.consensus.engine.stop(Duration::ZERO).await?);
    ensure!(service.active_roots().await == 0);
    Ok(
        json!({"unsupported_block_not_proposed": true, "unsupported_proposal_rejected": true,
        "signed_cancel_certified": true, "bitcoin_progress_resumed": true,
        "old_protocol_preserved": true, "validators": 1}),
    )
}
