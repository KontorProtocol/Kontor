use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const MAX_CAPACITY: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub contract_address: String,
    pub event_signature: String,
    pub topic_keys: Vec<String>,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum EventFilter {
    All,
    Contract {
        contract_address: String,
        event_signature: Option<EventSignatureFilter>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventSignatureFilter {
    pub signature: String,
    pub topic_values: Option<Vec<Value>>,
}

#[derive(Debug)]
pub struct TopicTree {
    pub sender: broadcast::Sender<Event>,
    pub sub_ids: Vec<usize>,
    pub children: HashMap<Value, TopicTree>,
}

impl TopicTree {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(MAX_CAPACITY);
        TopicTree {
            sender,
            sub_ids: Vec::new(),
            children: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sub_ids.is_empty() && self.children.is_empty()
    }

    fn add_recursive(
        &mut self,
        id: usize,
        topic_values: &[Value],
        depth: usize,
    ) -> broadcast::Sender<Event> {
        if depth == topic_values.len() {
            self.sub_ids.push(id);
            return self.sender.clone();
        }
        let next_tree = self
            .children
            .entry(topic_values[depth].clone())
            .or_default();
        next_tree.add_recursive(id, topic_values, depth + 1)
    }

    pub fn add(&mut self, id: usize, topic_values: &[Value]) -> broadcast::Receiver<Event> {
        let sender = self.add_recursive(id, topic_values, 0);
        sender.subscribe()
    }

    fn remove_leaf(&mut self, id: usize) -> (bool, bool) {
        let n = self.sub_ids.len();
        self.sub_ids.retain(|&sub_id| sub_id != id);
        (self.is_empty(), n != self.sub_ids.len())
    }

    pub fn remove_recursive(
        &mut self,
        id: usize,
        topic_values: &[Value],
        depth: usize,
    ) -> (bool, bool) {
        if depth == topic_values.len() {
            return self.remove_leaf(id);
        }
        let value = &topic_values[depth];
        let mut removed = false;
        if let Some(next_tree) = self.children.get_mut(value) {
            let (remove_child, leaf_removed) =
                next_tree.remove_recursive(id, topic_values, depth + 1);
            removed = leaf_removed;
            if remove_child {
                self.children.remove(value);
            }
        }
        (self.is_empty(), removed)
    }

    pub fn remove(&mut self, id: usize, topic_values: &[Value], depth: usize) -> bool {
        let (_, removed) = self.remove_recursive(id, topic_values, depth);
        removed
    }

    pub fn dispatch(&self, event: &Event, topic_values: &[Value], depth: usize) {
        if let Some(data) = event.data.as_object() {
            if !self.sub_ids.is_empty() {
                let _ = self.sender.send(event.clone());
            }
            if depth < event.topic_keys.len() && depth < topic_values.len() {
                let value = &topic_values[depth];
                if let Some(next_tree) = self.children.get(&Value::Null) {
                    next_tree.dispatch(event, topic_values, depth + 1);
                }
                let key = &event.topic_keys[depth];
                if let Some(data_value) = data.get(key) {
                    if data_value == value {
                        if let Some(next_tree) = self.children.get(value) {
                            next_tree.dispatch(event, topic_values, depth + 1);
                        }
                    }
                }
            }
        }
    }
}

impl Default for TopicTree {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ContractSubscriptions {
    no_topics: Option<broadcast::Sender<Event>>,
    no_topics_count: usize,
    with_topics: HashMap<String, TopicTree>,
}

impl ContractSubscriptions {
    pub fn new() -> Self {
        ContractSubscriptions {
            no_topics: None,
            no_topics_count: 0,
            with_topics: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.no_topics_count == 0 && self.with_topics.is_empty()
    }

    pub fn subscribe(
        &mut self,
        id: usize,
        event_signature: &Option<EventSignatureFilter>,
    ) -> broadcast::Receiver<Event> {
        match event_signature {
            None
            | Some(EventSignatureFilter {
                topic_values: None, ..
            }) => {
                self.no_topics_count += 1;
                let sender = self.no_topics.get_or_insert_with(|| {
                    let (sender, _) = broadcast::channel(MAX_CAPACITY);
                    sender
                });
                sender.subscribe()
            }
            Some(EventSignatureFilter {
                signature,
                topic_values: Some(values),
            }) => {
                let tree = self.with_topics.entry(signature.clone()).or_default();
                tree.add(id, values)
            }
        }
    }

    pub fn unsubscribe(
        &mut self,
        id: usize,
        event_signature: &Option<EventSignatureFilter>,
    ) -> bool {
        match event_signature {
            None
            | Some(EventSignatureFilter {
                topic_values: None, ..
            }) => {
                if self.no_topics.is_some() {
                    self.no_topics_count -= 1;
                    if self.no_topics_count == 0 {
                        self.no_topics = None;
                    }
                    true
                } else {
                    false
                }
            }
            Some(EventSignatureFilter {
                signature,
                topic_values: Some(values),
            }) => {
                if let Some(tree) = self.with_topics.get_mut(signature) {
                    let removed = tree.remove(id, values, 0);
                    if removed && tree.is_empty() {
                        self.with_topics.remove(signature);
                    }
                    removed
                } else {
                    false
                }
            }
        }
    }

    pub fn dispatch(&self, event: &Event) {
        if let Some(sender) = &self.no_topics {
            let _ = sender.send(event.clone());
        }
        if let Some(tree) = self.with_topics.get(&event.event_signature) {
            let topic_values = event
                .topic_keys
                .iter()
                .map(|key| event.data.get(key).cloned().unwrap_or(Value::Null))
                .collect::<Vec<Value>>();
            tree.dispatch(event, &topic_values, 0);
        }
    }
}

impl Default for ContractSubscriptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Subscriptions {
    all_contracts: Option<broadcast::Sender<Event>>,
    all_count: usize,
    by_contract: HashMap<String, ContractSubscriptions>,
    filters: HashMap<usize, EventFilter>,
}

impl Subscriptions {
    pub fn new() -> Self {
        Subscriptions {
            all_contracts: None,
            all_count: 0,
            by_contract: HashMap::new(),
            filters: HashMap::new(),
        }
    }

    pub fn subscribe(&mut self, id: usize, filter: EventFilter) -> broadcast::Receiver<Event> {
        let receiver = match &filter {
            EventFilter::All => {
                self.all_count += 1;
                let sender = self.all_contracts.get_or_insert_with(|| {
                    let (sender, _) = broadcast::channel(MAX_CAPACITY);
                    sender
                });
                sender.subscribe()
            }
            EventFilter::Contract {
                contract_address,
                event_signature,
            } => {
                let contract_subs = self
                    .by_contract
                    .entry(contract_address.clone())
                    .or_default();
                contract_subs.subscribe(id, event_signature)
            }
        };
        self.filters.insert(id, filter);
        receiver
    }

    pub fn unsubscribe(&mut self, id: usize) -> bool {
        if let Some(filter) = self.filters.remove(&id) {
            match filter {
                EventFilter::All => {
                    self.all_count -= 1;
                    if self.all_count == 0 {
                        self.all_contracts = None;
                    }
                    true
                }
                EventFilter::Contract {
                    contract_address,
                    event_signature,
                } => {
                    if let Some(contract_subs) = self.by_contract.get_mut(&contract_address) {
                        let removed = contract_subs.unsubscribe(id, &event_signature);
                        if contract_subs.is_empty() {
                            self.by_contract.remove(&contract_address);
                        }
                        removed
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        }
    }

    pub fn dispatch(&self, event: &Event) {
        if let Some(sender) = &self.all_contracts {
            let _ = sender.send(event.clone());
        }
        if let Some(contract_subs) = self.by_contract.get(&event.contract_address) {
            contract_subs.dispatch(event);
        }
    }
}

impl Default for Subscriptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct EventSubscriber {
    subscriptions: Arc<Mutex<Subscriptions>>,
    next_id: usize,
}

impl EventSubscriber {
    pub fn new() -> Self {
        EventSubscriber {
            subscriptions: Arc::new(Mutex::new(Subscriptions::new())),
            next_id: 0,
        }
    }

    pub async fn subscribe(&mut self, filter: EventFilter) -> (usize, broadcast::Receiver<Event>) {
        let mut subs = self.subscriptions.lock().await;
        let id = self.next_id;
        self.next_id += 1;
        let receiver = subs.subscribe(id, filter);
        (id, receiver)
    }

    pub async fn unsubscribe(&mut self, id: usize) -> bool {
        let mut subs = self.subscriptions.lock().await;
        subs.unsubscribe(id)
    }

    pub fn run(
        &self,
        cancel_token: CancellationToken,
        mut rx: mpsc::Receiver<Event>,
    ) -> JoinHandle<()> {
        let subs = self.subscriptions.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(event) = rx.recv() => {
                        let subs = subs.lock().await;
                        subs.dispatch(&event);
                    }
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                }
            }
        })
    }
}

impl Default for EventSubscriber {
    fn default() -> Self {
        Self::new()
    }
}
