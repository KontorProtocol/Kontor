use std::collections::BTreeMap;

use tokio::sync::oneshot::Sender;

use crate::api::{ReplyKind, ReplyToken, Response};

pub(crate) use crate::api::{Delivery, ReplyError};

trait PendingReply: Send {
    fn is_closed(&self) -> bool;
    fn send(self: Box<Self>, response: Response) -> Result<Delivery, ReplyError>;
}

struct Pending<T, F> {
    sender: Sender<T>,
    decode: F,
}

impl<T, F> PendingReply for Pending<T, F>
where
    T: Send,
    F: FnOnce(Response) -> Result<T, String> + Send,
{
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    fn send(self: Box<Self>, response: Response) -> Result<Delivery, ReplyError> {
        let value = (self.decode)(response).map_err(ReplyError::Malformed)?;
        // In particular, a GetValue receiver may expire between lookup and send.
        // Normal round progress must not fault the engine in that race.
        Ok(match self.sender.send(value) {
            Ok(()) => Delivery::Delivered,
            Err(_) => Delivery::Expired,
        })
    }
}

struct Entry {
    operation: ReplyKind,
    reply: Box<dyn PendingReply>,
}

pub(crate) struct Replies {
    generation: u64,
    next: u64,
    capacity: usize,
    retired: bool,
    pending: BTreeMap<u64, Entry>,
}

impl Replies {
    pub(crate) fn new(generation: u64, capacity: usize) -> Result<Self, String> {
        if generation == 0 || capacity == 0 {
            return Err("invalid engine reply registry".into());
        }
        Ok(Self {
            generation,
            next: 1,
            capacity,
            retired: false,
            pending: BTreeMap::new(),
        })
    }

    pub(crate) fn insert<T, F>(
        &mut self,
        operation: ReplyKind,
        sender: Sender<T>,
        decode: F,
    ) -> Result<ReplyToken, String>
    where
        T: Send + 'static,
        F: FnOnce(Response) -> Result<T, String> + Send + 'static,
    {
        if self.retired {
            return Err("engine generation retired".into());
        }
        // GetValue can expire while the application waits for transactions.
        // Reclaim only replies whose receiver the engine has already abandoned.
        self.pending.retain(|_, entry| !entry.reply.is_closed());
        if self.pending.len() >= self.capacity {
            return Err("engine reply capacity exhausted".into());
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or("engine reply token exhausted")?;
        let token = self.next;
        self.next = next;
        self.pending.insert(
            token,
            Entry {
                operation,
                reply: Box::new(Pending { sender, decode }),
            },
        );
        Ok(ReplyToken {
            generation: self.generation,
            id: token,
        })
    }

    pub(crate) fn respond(
        &mut self,
        token: ReplyToken,
        response: Response,
    ) -> Result<Delivery, ReplyError> {
        if self.retired || token.generation != self.generation {
            return Err(ReplyError::StaleGeneration);
        }
        if matches!(response, Response::Abandon) {
            return Ok(if self.pending.remove(&token.id).is_some() {
                Delivery::Delivered
            } else {
                Delivery::Expired
            });
        }
        let entry = self
            .pending
            .get(&token.id)
            .ok_or(ReplyError::UnknownToken)?;
        if Some(entry.operation) != response.kind() {
            return Err(ReplyError::WrongOperation);
        }
        // Once dispatched, even a malformed payload consumes the capability.
        // The caller must fault the engine on error, never retry a different reply.
        self.pending
            .remove(&token.id)
            .expect("entry exists")
            .reply
            .send(response)
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;

    fn height(response: Response) -> Result<u64, String> {
        match response {
            Response::HistoryMinHeight(value) if value > 0 => Ok(value),
            _ => Err("invalid height".into()),
        }
    }

    #[test]
    fn stale_or_wrong_kind_does_not_consume_current_reply() {
        let mut replies = Replies::new(7, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        assert_eq!(
            replies.respond(
                ReplyToken {
                    generation: 6,
                    ..token
                },
                Response::HistoryMinHeight(1)
            ),
            Err(ReplyError::StaleGeneration)
        );
        assert_eq!(
            replies.respond(token, Response::Decided),
            Err(ReplyError::WrongOperation)
        );
        assert!(receiver.try_recv().is_err());
        replies
            .respond(token, Response::HistoryMinHeight(1))
            .unwrap();
        assert_eq!(receiver.try_recv(), Ok(1));
        assert_eq!(
            replies.respond(token, Response::HistoryMinHeight(1)),
            Err(ReplyError::UnknownToken)
        );
    }

    #[test]
    fn explicit_abandon_closes_receiver_and_never_consumes_another_generation() {
        let mut replies = Replies::new(7, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        let stale = ReplyToken {
            generation: 6,
            id: token.id,
        };
        assert_eq!(
            replies.respond(stale, Response::Abandon),
            Err(ReplyError::StaleGeneration)
        );
        assert_eq!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert_eq!(
            replies.respond(token, Response::Abandon),
            Ok(Delivery::Delivered)
        );
        assert_eq!(
            receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
        assert_eq!(
            replies.respond(token, Response::Abandon),
            Ok(Delivery::Expired)
        );
        let (sender, mut receiver) = oneshot::channel();
        let next = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        assert_ne!(token, next);
        assert_eq!(
            replies.respond(token, Response::Abandon),
            Ok(Delivery::Expired)
        );
        replies
            .respond(next, Response::HistoryMinHeight(9))
            .unwrap();
        assert_eq!(receiver.try_recv(), Ok(9));
    }

    #[test]
    fn retired_generation_cannot_reply_or_admit_more_work() {
        let mut old = Replies::new(7, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = old
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        old.retire();
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            old.respond(token, Response::HistoryMinHeight(1)),
            Err(ReplyError::StaleGeneration)
        );
        let (sender, _receiver) = oneshot::channel();
        assert!(
            old.insert(ReplyKind::HistoryMinHeight, sender, height)
                .is_err()
        );
        let mut new = Replies::new(8, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let next = new
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        assert_eq!(next.id, token.id);
        assert_eq!(
            new.respond(token, Response::HistoryMinHeight(1)),
            Err(ReplyError::StaleGeneration)
        );
        new.respond(next, Response::HistoryMinHeight(1)).unwrap();
        assert_eq!(receiver.try_recv(), Ok(1));
    }

    #[test]
    fn abandoned_calls_release_capacity_without_reusing_tokens() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, receiver) = oneshot::channel();
        let first = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        let (sender, _other) = oneshot::channel();
        assert!(
            replies
                .insert(ReplyKind::HistoryMinHeight, sender, height)
                .is_err()
        );
        drop(receiver);
        let (sender, mut receiver) = oneshot::channel();
        let second = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            replies.respond(first, Response::HistoryMinHeight(1)),
            Err(ReplyError::UnknownToken)
        );
        replies
            .respond(second, Response::HistoryMinHeight(1))
            .unwrap();
        assert_eq!(receiver.try_recv(), Ok(1));
    }

    #[test]
    fn receiver_expiration_after_registration_is_not_malformed_input() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, receiver) = oneshot::channel();
        let token = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        drop(receiver);
        assert_eq!(
            replies.respond(token, Response::HistoryMinHeight(1)),
            Ok(Delivery::Expired)
        );
        assert!(replies.pending.is_empty());
    }

    #[test]
    fn invalid_response_is_consumed_and_token_overflow_never_wraps() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = replies
            .insert(ReplyKind::HistoryMinHeight, sender, height)
            .unwrap();
        assert!(matches!(
            replies.respond(token, Response::HistoryMinHeight(0)),
            Err(ReplyError::Malformed(_))
        ));
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            replies.respond(token, Response::HistoryMinHeight(1)),
            Err(ReplyError::UnknownToken)
        );
        replies.next = u64::MAX;
        let (sender, _receiver) = oneshot::channel();
        assert!(
            replies
                .insert(ReplyKind::HistoryMinHeight, sender, height)
                .is_err()
        );
        assert_eq!(replies.next, u64::MAX);
        assert!(replies.pending.is_empty());
    }
}
