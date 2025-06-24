use anyhow::Result;
use bitcoin::BlockHash;
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::events::Event;
use crate::block::Tx;

#[derive(Debug)]
pub struct StartMessage<T: Tx> {
    pub start_height: u64,
    pub last_hash: Option<BlockHash>,
    pub event_tx: Sender<Event<T>>,
}

#[derive(Clone)]
pub struct CtrlChannel<T: Tx> {
    ctrl_tx: Sender<StartMessage<T>>,
}

impl<T: Tx + 'static> CtrlChannel<T> {
    pub fn create() -> (Self, Receiver<StartMessage<T>>) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(1);

        (Self { ctrl_tx }, ctrl_rx)
    }

    pub async fn start(
        self,
        start_height: u64,
        last_hash: Option<BlockHash>,
    ) -> Result<Receiver<Event<T>>> {
        let (event_tx, event_rx) = mpsc::channel(10);

        self.ctrl_tx
            .send(StartMessage {
                start_height,
                last_hash,
                event_tx,
            })
            .await?;

        Ok(event_rx)
    }
}
