use std::collections::BTreeMap;

use tokio::sync::oneshot::Sender;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyError {
    StaleGeneration,
    UnknownToken,
    WrongOperation,
    Malformed(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    Delivered,
    Expired,
}

trait PendingReply: Send {
    fn is_closed(&self) -> bool;
    fn send(self: Box<Self>, payload: &[u8]) -> Result<Delivery, ReplyError>;
}

struct Pending<T, F> {
    sender: Sender<T>,
    decode: F,
}

impl<T, F> PendingReply for Pending<T, F>
where
    T: Send,
    F: FnOnce(&[u8]) -> Result<T, String> + Send,
{
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    fn send(self: Box<Self>, payload: &[u8]) -> Result<Delivery, ReplyError> {
        let value = (self.decode)(payload).map_err(ReplyError::Malformed)?;
        // In particular, a GetValue receiver may expire between lookup and send.
        // Normal round progress must not fault the engine in that race.
        Ok(match self.sender.send(value) {
            Ok(()) => Delivery::Delivered,
            Err(_) => Delivery::Expired,
        })
    }
}

struct Entry {
    operation: u8,
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
        operation: u8,
        sender: Sender<T>,
        decode: F,
    ) -> Result<u64, String>
    where
        T: Send + 'static,
        F: FnOnce(&[u8]) -> Result<T, String> + Send + 'static,
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
        Ok(token)
    }

    pub(crate) fn respond(
        &mut self,
        generation: u64,
        token: u64,
        operation: u8,
        payload: &[u8],
    ) -> Result<Delivery, ReplyError> {
        if self.retired || generation != self.generation {
            return Err(ReplyError::StaleGeneration);
        }
        let entry = self.pending.get(&token).ok_or(ReplyError::UnknownToken)?;
        if entry.operation != operation {
            return Err(ReplyError::WrongOperation);
        }
        // Once dispatched, even a malformed payload consumes the capability.
        // The caller must fault the engine on error, never retry a different reply.
        self.pending
            .remove(&token)
            .expect("entry exists")
            .reply
            .send(payload)
    }

    pub(crate) fn retire(&mut self) {
        self.retired = true;
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::{Delivery, Replies};

    fn ack(payload: &[u8]) -> Result<(), String> {
        if payload.is_empty() {
            Ok(())
        } else {
            Err("invalid acknowledgement".into())
        }
    }

    #[test]
    fn stale_or_wrong_operation_does_not_consume_current_reply() {
        let mut replies = Replies::new(7, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = replies.insert(3, sender, ack).unwrap();
        assert!(replies.respond(6, token, 3, &[]).is_err());
        assert!(replies.respond(7, token, 4, &[]).is_err());
        assert!(receiver.try_recv().is_err());
        replies.respond(7, token, 3, &[]).unwrap();
        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(replies.respond(7, token, 3, &[]).is_err());
    }

    #[test]
    fn retired_generation_cannot_reply_or_admit_more_work() {
        let mut old = Replies::new(7, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = old.insert(3, sender, ack).unwrap();
        old.retire();
        assert!(receiver.try_recv().is_err());
        assert!(old.respond(7, token, 3, &[]).is_err());
        let (sender, _receiver) = oneshot::channel();
        assert!(old.insert(3, sender, ack).is_err());
        let mut new = Replies::new(8, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        assert_eq!(new.insert(3, sender, ack).unwrap(), token);
        assert!(new.respond(7, token, 3, &[]).is_err());
        new.respond(8, token, 3, &[]).unwrap();
        assert_eq!(receiver.try_recv(), Ok(()));
    }

    #[test]
    fn abandoned_calls_release_capacity_without_reusing_tokens() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, receiver) = oneshot::channel();
        let first = replies.insert(1, sender, ack).unwrap();
        let (sender, _other) = oneshot::channel();
        assert!(replies.insert(1, sender, ack).is_err());
        drop(receiver);
        let (sender, mut receiver) = oneshot::channel();
        let second = replies.insert(1, sender, ack).unwrap();
        assert_ne!(first, second);
        assert!(replies.respond(1, first, 1, &[]).is_err());
        replies.respond(1, second, 1, &[]).unwrap();
        assert_eq!(receiver.try_recv(), Ok(()));
    }

    #[test]
    fn receiver_expiration_after_registration_is_not_malformed_input() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, receiver) = oneshot::channel();
        let token = replies.insert(1, sender, ack).unwrap();
        drop(receiver);
        assert_eq!(replies.respond(1, token, 1, &[]), Ok(Delivery::Expired));
        assert!(replies.pending.is_empty());
    }

    #[test]
    fn malformed_reply_is_consumed_and_token_overflow_never_wraps() {
        let mut replies = Replies::new(1, 1).unwrap();
        let (sender, mut receiver) = oneshot::channel();
        let token = replies.insert(1, sender, ack).unwrap();
        assert!(replies.respond(1, token, 1, &[1]).is_err());
        assert!(receiver.try_recv().is_err());
        assert!(replies.respond(1, token, 1, &[]).is_err());
        replies.next = u64::MAX;
        let (sender, _receiver) = oneshot::channel();
        assert!(replies.insert(1, sender, ack).is_err());
        assert_eq!(replies.next, u64::MAX);
        assert!(replies.pending.is_empty());
    }
}
