use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use libsql::Connection;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::database::{queries::get_contract_result, types::ContractResultId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResultEvent {
    Ok { value: Option<String> },
    Err { message: Option<String> },
}

#[derive(Debug, Clone)]
pub struct ResultSubscription {
    count: usize,
    sender: broadcast::Sender<ResultEvent>,
}

impl Default for ResultSubscription {
    fn default() -> Self {
        Self {
            count: 0,
            sender: broadcast::Sender::new(100),
        }
    }
}

impl ResultSubscription {
    pub fn subscribe(&mut self) -> broadcast::Receiver<ResultEvent> {
        self.count += 1;
        self.sender.subscribe()
    }

    pub fn unsubscribe(&mut self) {
        if self.count > 0 {
            self.count -= 1;
        }
    }

    pub fn count(&self) -> usize {
        self.count
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResultSubscriptions {
    pub subscriptions: HashMap<ContractResultId, ResultSubscription>,
}

impl ResultSubscriptions {
    pub async fn subscribe(
        &mut self,
        conn: &Connection,
        id: &ContractResultId,
    ) -> Result<broadcast::Receiver<ResultEvent>> {
        let receiver = self
            .subscriptions
            .entry(id.clone())
            .or_default()
            .subscribe();
        if let Some(row) = get_contract_result(conn, id).await? {
            self.dispatch(
                id,
                if row.ok {
                    ResultEvent::Ok { value: row.value }
                } else {
                    ResultEvent::Err { message: None }
                },
            );
        }
        Ok(receiver)
    }

    pub fn unsubscribe(&mut self, id: &ContractResultId) -> bool {
        if let Some(sub) = self.subscriptions.get_mut(id) {
            sub.unsubscribe();
            if sub.count() == 0 {
                self.subscriptions.remove(id);
            }
            true
        } else {
            false
        }
    }

    pub fn dispatch(&mut self, id: &ContractResultId, result: ResultEvent) {
        if let Some(sub) = self.subscriptions.remove(id) {
            let _ = sub.sender.send(result);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResultSubscriber {
    subscriptions: Arc<Mutex<ResultSubscriptions>>,
}

impl ResultSubscriber {
    pub async fn subscribe(
        &mut self,
        conn: &Connection,
        id: &ContractResultId,
    ) -> Result<broadcast::Receiver<ResultEvent>> {
        let mut subs = self.subscriptions.lock().await;
        subs.subscribe(conn, id).await
    }

    pub async fn unsubscribe(&mut self, id: &ContractResultId) -> bool {
        let mut subs = self.subscriptions.lock().await;
        subs.unsubscribe(id)
    }

    pub fn run(
        &self,
        cancel_token: CancellationToken,
        mut rx: mpsc::Receiver<(ContractResultId, ResultEvent)>,
    ) -> JoinHandle<()> {
        let self_ = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some((id, event)) = rx.recv() => {
                        let mut subs = self_.subscriptions.lock().await;
                        subs.dispatch(&id, event);
                    }
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                }
            }
        })
    }
}
