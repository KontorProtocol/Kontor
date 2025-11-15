use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::{
    bitcoin_client::Client, config::Config, database, reactor::results::ResultSubscriber,
    runtime::Runtime,
};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub available: Arc<RwLock<bool>>,
    pub reader: database::Reader,
    pub result_subscriber: ResultSubscriber,
    pub bitcoin: Client,
    pub runtime: Arc<Mutex<Runtime>>,
}
