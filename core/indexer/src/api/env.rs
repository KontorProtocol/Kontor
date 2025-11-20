use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::{
    bitcoin_client::Client, config::Config, database, event::EventSubscriber, runtime::Runtime,
};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub available: Arc<RwLock<bool>>,
    pub reader: database::Reader,
    pub event_subscriber: EventSubscriber,
    pub bitcoin: Client,
    pub runtime: Arc<Mutex<Runtime>>,
}
