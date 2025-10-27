use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, anyhow};
use bon::Builder;
use libsql::Connection;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    database::{
        queries::{get_contract_id_from_address, get_op_result},
        types::OpResultId,
    },
    runtime::ContractAddress,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResultEvent {
    Ok { value: String },
    Err { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Builder)]
pub struct ResultEventWrapper {
    #[builder(default = 1)]
    pub contract_id: i64,
    #[builder(default = "".to_string())]
    pub func_name: String,
    pub op_result_id: Option<OpResultId>,
    pub event: ResultEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResultEventFilter {
    All,
    Contract {
        contract_address: ContractAddress,
        func_name: Option<String>,
    },
    OpResultId(OpResultId),
}

impl From<OpResultId> for ResultEventFilter {
    fn from(op_result_id: OpResultId) -> Self {
        ResultEventFilter::OpResultId(op_result_id)
    }
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

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

type SubscriptionsTree = (
    ResultSubscription,
    HashMap<i64, (ResultSubscription, HashMap<String, ResultSubscription>)>,
);

#[derive(Debug, Clone, Default)]
pub struct ResultSubscriptions {
    pub subscription_ids: HashMap<Uuid, ResultEventFilter>,
    pub recurring_subscriptions: SubscriptionsTree,
    pub one_shot_subscriptions: HashMap<OpResultId, ResultSubscription>,
}

impl ResultSubscriptions {
    pub async fn subscribe_one_shot(
        &mut self,
        conn: &Connection,
        id: &OpResultId,
    ) -> Result<broadcast::Receiver<ResultEvent>> {
        let receiver = self
            .one_shot_subscriptions
            .entry(id.clone())
            .or_default()
            .subscribe();
        if let Some(row) = get_op_result(conn, id).await? {
            self.dispatch_one_shot(
                id,
                if let Some(value) = row.value {
                    ResultEvent::Ok { value }
                } else {
                    ResultEvent::Err {
                        message: "Procedure failed. Error messages are ephemeral.".to_string(),
                    }
                },
            );
        }
        Ok(receiver)
    }

    pub fn unsubscribe_one_shot(&mut self, id: &OpResultId) -> bool {
        if let Some(sub) = self.one_shot_subscriptions.get_mut(id) {
            sub.unsubscribe();
            if sub.count() == 0 {
                self.one_shot_subscriptions.remove(id);
            }
            true
        } else {
            false
        }
    }

    pub fn dispatch_one_shot(&mut self, id: &OpResultId, result: ResultEvent) {
        if let Some(sub) = self.one_shot_subscriptions.remove(id) {
            let _ = sub.sender.send(result);
        }
    }

    pub async fn subscribe(
        &mut self,
        conn: &Connection,
        filter: ResultEventFilter,
    ) -> Result<(Uuid, broadcast::Receiver<ResultEvent>)> {
        let subscription_id = Uuid::new_v4();
        let subscription = match &filter {
            ResultEventFilter::All => Ok(self.recurring_subscriptions.0.subscribe()),
            ResultEventFilter::Contract {
                contract_address,
                func_name,
            } => {
                let contract_id = get_contract_id_from_address(conn, contract_address)
                    .await?
                    .ok_or(anyhow!("Contract not found: {}", contract_address))?;
                let entry = self
                    .recurring_subscriptions
                    .1
                    .entry(contract_id)
                    .or_default();
                Ok(match func_name {
                    None => entry.0.subscribe(),
                    Some(func_name) => entry
                        .1
                        .entry(func_name.to_string())
                        .or_default()
                        .subscribe(),
                })
            }
            ResultEventFilter::OpResultId(op_result_id) => {
                self.subscribe_one_shot(conn, op_result_id).await
            }
        }?;
        self.subscription_ids.insert(subscription_id, filter);
        Ok((subscription_id, subscription))
    }

    pub async fn unsubscribe(&mut self, conn: &Connection, id: Uuid) -> Result<bool> {
        if let Some(filter) = self.subscription_ids.remove(&id) {
            return Ok(match filter {
                ResultEventFilter::All => {
                    self.recurring_subscriptions.0.unsubscribe();
                    true
                }
                ResultEventFilter::Contract {
                    contract_address,
                    func_name,
                } => {
                    let contract_id = get_contract_id_from_address(conn, &contract_address)
                        .await?
                        .ok_or(anyhow!("Contract not found: {}", contract_address))?;
                    match self.recurring_subscriptions.1.get_mut(&contract_id) {
                        Some(entry) => {
                            let unsubscribed = match &func_name {
                                None => {
                                    entry.0.unsubscribe();
                                    true
                                }
                                Some(func_name) => match entry.1.get_mut(func_name) {
                                    Some(subscription) => {
                                        subscription.unsubscribe();
                                        if subscription.is_empty() {
                                            entry.1.remove(func_name);
                                        }
                                        true
                                    }
                                    None => false,
                                },
                            };
                            if entry.0.is_empty() && entry.1.is_empty() {
                                self.recurring_subscriptions.1.remove(&contract_id);
                            }
                            unsubscribed
                        }
                        None => false,
                    }
                }
                ResultEventFilter::OpResultId(op_result_id) => {
                    self.unsubscribe_one_shot(&op_result_id)
                }
            });
        }
        Ok(false)
    }

    pub async fn dispatch(&mut self, wrapper: ResultEventWrapper) -> Result<()> {
        if let Some(op_result_id) = wrapper.op_result_id {
            self.dispatch_one_shot(&op_result_id, wrapper.event.clone());
        }

        let _ = self
            .recurring_subscriptions
            .0
            .sender
            .send(wrapper.event.clone());
        if let Some(entry) = self.recurring_subscriptions.1.get(&wrapper.contract_id) {
            let _ = entry.0.sender.send(wrapper.event.clone());
            if let Some(entry) = entry.1.get(&wrapper.func_name) {
                let _ = entry.sender.send(wrapper.event.clone());
            }
        }

        Ok(())
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
        filter: ResultEventFilter,
    ) -> Result<(Uuid, broadcast::Receiver<ResultEvent>)> {
        let mut subs = self.subscriptions.lock().await;
        subs.subscribe(conn, filter).await
    }

    pub async fn unsubscribe(&mut self, conn: &Connection, id: Uuid) -> Result<bool> {
        let mut subs = self.subscriptions.lock().await;
        subs.unsubscribe(conn, id).await
    }

    pub fn run(
        &self,
        cancel_token: CancellationToken,
        mut rx: mpsc::Receiver<ResultEventWrapper>,
    ) -> JoinHandle<()> {
        let self_ = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(wrapper) = rx.recv() => {
                        let mut subs = self_.subscriptions.lock().await;
                        let _ = subs.dispatch(wrapper).await;
                    }
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                }
            }
        })
    }
}
