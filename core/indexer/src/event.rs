use crate::stopper::ShutdownSignal;
use anyhow::Result;
use indexer_types::Event;
use tokio::{
    sync::{
        broadcast::{self},
        mpsc,
    },
    task::JoinHandle,
};

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
        shutdown: ShutdownSignal,
        mut rx: mpsc::Receiver<Event>,
    ) -> JoinHandle<Result<()>> {
        let sender = self.sender.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        let _ = sender.send(event);
                    }
                    _ = shutdown.cancelled() => {
                        break;
                    }
                }
            }
            Ok(())
        })
    }
}
