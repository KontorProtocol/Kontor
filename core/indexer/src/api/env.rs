use std::{path::Path, sync::Arc};

use anyhow::Result;
use deadpool::managed::Pool;
use tokio::sync::{RwLock, mpsc::Sender};
use tokio_util::sync::CancellationToken;

use crate::{
    bitcoin_client::Client, config::Config, database, event::EventSubscriber, reactor::Simulation,
    runtime,
};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub available: Arc<RwLock<bool>>,
    pub reader: database::Reader,
    pub event_subscriber: EventSubscriber,
    pub bitcoin: Client,
    pub runtime_pool: Pool<runtime::pool::Manager>,
    pub simulate_tx: Sender<Simulation>,
}

impl Env {
    pub async fn new_test(
        reader: database::Reader,
        db_path: &Path,
        db_name: String,
    ) -> Result<Self> {
        let (simulate_tx, _) = tokio::sync::mpsc::channel(10);
        Ok(Self {
            bitcoin: Client::new("".to_string(), "".to_string(), "".to_string())?,
            config: Config::new_na(),
            cancel_token: CancellationToken::new(),
            available: Arc::new(RwLock::new(true)),
            event_subscriber: EventSubscriber::new(),
            runtime_pool: runtime::pool::new(db_path.to_path_buf(), db_name).await?,
            reader,
            simulate_tx,
        })
    }
}
