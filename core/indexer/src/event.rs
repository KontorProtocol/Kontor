use anyhow::Result;
use indexer_types::Event;
use tokio::{
    sync::{
        broadcast::{self},
        mpsc,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct EventSubscriber {
    pub sender: broadcast::Sender<Event>,
}

impl EventSubscriber {
    pub fn new() -> Self {
        Self {
            sender: broadcast::Sender::new(100),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    pub fn run(
        &self,
        cancel_token: CancellationToken,
        mut rx: mpsc::Receiver<Event>,
    ) -> JoinHandle<Result<()>> {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        let _ = sender.send(event);
                    }
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                }
            }
            Ok(())
        })
    }
}
