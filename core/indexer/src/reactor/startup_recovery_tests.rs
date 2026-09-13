use std::collections::HashSet;
use std::mem;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow, ensure};
use malachitebft_app_channel::app::streaming::StreamContent;
use malachitebft_app_channel::{AppMsg, Channels, NetworkMsg};
use malachitebft_core_consensus::Role;
use malachitebft_core_types::Round;
use tokio::sync::{Barrier, mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use super::ReactorCluster;
use crate::consensus::{Ctx, Height, ProposalPart};

#[derive(Clone)]
pub(super) struct StartupFaults {
    round_zero: Arc<Barrier>,
    dropped_parts: Arc<AtomicUsize>,
    delayed_proposers: Arc<AtomicUsize>,
    retry_failed: watch::Sender<bool>,
}

impl StartupFaults {
    pub(super) fn install(&self, channels: &mut Channels<Ctx>) -> JoinSet<()> {
        let mut tasks = JoinSet::new();
        let (tx, rx) = mpsc::channel(32);
        let mut incoming = mem::replace(&mut channels.consensus, rx);
        let faults = self.clone();
        tasks.spawn(async move {
            while let Some(msg) = incoming.recv().await {
                if let AppMsg::StartedRound {
                    height,
                    round,
                    role,
                    ..
                } = &msg
                    && *height == Height::new(1)
                {
                    if *round == Round::new(0) {
                        // Initialization speed must not determine the fault:
                        // start all round-zero timers only after every node is up.
                        faults.round_zero.wait().await;
                    } else if *round == Round::new(1) && *role == Role::Proposer {
                        // Peers start their 10.5s proposal timers first. A 3s
                        // proposer delay exceeds the old 20% dissemination margin.
                        faults.delayed_proposers.fetch_add(1, Ordering::SeqCst);
                        sleep(Duration::from_secs(3)).await;
                    } else if *round > Round::new(1) {
                        let _ = faults.retry_failed.send(true);
                    }
                }
                if tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        let (tx, mut outgoing) = mpsc::channel(32);
        let network = mem::replace(&mut channels.network, tx);
        let dropped_parts = self.dropped_parts.clone();
        tasks.spawn(async move {
            let mut dropped_streams = HashSet::new();
            while let Some(msg) = outgoing.recv().await {
                let NetworkMsg::PublishProposalPart(part) = &msg;
                if let StreamContent::Data(ProposalPart::Init(init)) = &part.content
                    && init.height == Height::new(1)
                    && init.round == Round::new(0)
                {
                    dropped_streams.insert(part.stream_id.clone());
                }
                if dropped_streams.contains(&part.stream_id) {
                    // Match the missing proposal-parts publication in the CI
                    // trace while leaving normal votes and later proposals alone.
                    dropped_parts.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                if network.send(msg).await.is_err() {
                    break;
                }
            }
        });
        tasks
    }
}

#[tokio::test]
async fn lost_startup_proposal_recovers_with_a_late_retry_proposer() -> Result<()> {
    let (retry_failed, mut failure) = watch::channel(false);
    let faults = StartupFaults {
        round_zero: Arc::new(Barrier::new(3)),
        dropped_parts: Arc::new(AtomicUsize::new(0)),
        delayed_proposers: Arc::new(AtomicUsize::new(0)),
        retry_failed,
    };
    let mut cluster = ReactorCluster::start_with_faults(3, 3, None, Some(faults.clone())).await?;
    let result = timeout(Duration::from_secs(40), async {
        let mut decided = HashSet::new();
        let mut first_value = None;
        while decided.len() < 3 {
            tokio::select! {
                changed = failure.changed() => {
                    changed?;
                    ensure!(!*failure.borrow(), "the first retry also failed after losing the startup proposal");
                }
                msg = cluster.decided_rx.recv() => {
                    let decision = msg.ok_or_else(|| anyhow!("decision channel closed"))?;
                    if decision.consensus_height != Height::new(1) { continue; }
                    let value = decision.value.id();
                    if let Some(expected) = first_value { assert_eq!(value, expected); }
                    else { first_value = Some(value); }
                    decided.insert(decision.validator_index.expect("validator decision"));
                }
            }
        }
        ensure!(faults.dropped_parts.load(Ordering::SeqCst) >= 4, "initial proposal was not dropped");
        ensure!(faults.delayed_proposers.load(Ordering::SeqCst) == 1, "retry proposer was not delayed");
        ensure!(cluster.reactor_errors.lock().unwrap().is_empty(), "a reactor exited");
        Ok(())
    }).await;
    cluster.shutdown().await;
    result?
}
