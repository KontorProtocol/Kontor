use std::time::{Duration, Instant};

use malachitebft_core_types::Round;
use tokio::sync::oneshot;
use tokio::time::Instant as TimerInstant;

use super::{DEBOUNCE, PendingProposal, ProposalBuilder};
use crate::consensus::Height;

#[test]
fn requests_own_their_debounce_and_keep_absolute_deadlines() {
    let mut builder = ProposalBuilder::default();
    let now = TimerInstant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    builder.on_mempool_activity(now);
    assert!(builder.debounce_deadline().is_none());
    let (reply, mut first) = oneshot::channel();
    builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: deadline,
    });
    builder.on_mempool_activity(now);
    assert_eq!(builder.debounce_deadline(), Some(now + DEBOUNCE));
    builder.on_round(Height::new(2), Round::new(0));
    assert_eq!(builder.request().unwrap().hard_deadline, deadline);
    assert!(first.try_recv().is_err());
    builder.consume_debounce();
    assert!(builder.debounce_deadline().is_none());
    builder.on_mempool_activity(now);
    let (reply, mut second) = oneshot::channel();
    builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(1),
        reply,
        hard_deadline: deadline,
    });
    assert_eq!(first.try_recv(), Err(oneshot::error::TryRecvError::Closed));
    assert!(builder.debounce_deadline().is_none());
    builder.on_mempool_activity(now + Duration::from_secs(1));
    assert_eq!(
        builder.debounce_deadline(),
        Some(now + Duration::from_secs(1) + DEBOUNCE)
    );
    builder.on_round(Height::new(2), Round::new(2));
    assert!(builder.request().is_none());
    assert!(builder.debounce_deadline().is_none());
    assert_eq!(second.try_recv(), Err(oneshot::error::TryRecvError::Closed));
}

#[test]
fn abandoned_receiver_does_not_change_the_request_lifecycle() {
    let mut builder = ProposalBuilder::default();
    let (reply, receive) = oneshot::channel();
    builder.start_request(PendingProposal {
        height: Height::new(2),
        round: Round::new(0),
        reply,
        hard_deadline: Instant::now(),
    });
    drop(receive);
    builder.on_mempool_activity(TimerInstant::now());
    assert!(builder.request().is_some());
    assert!(builder.debounce_deadline().is_some());
    let request = builder.take_request().unwrap();
    assert!(request.reply.is_closed());
    assert!(builder.request().is_none());
    assert!(builder.debounce_deadline().is_none());
}
