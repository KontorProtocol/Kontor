use tokio_util::sync::CancellationToken;

use crate::{bitcoin_client::Client, config::Config, database, reactor::results::ResultSubscriber};

#[derive(Clone, Debug)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub reader: database::Reader,
    pub result_subscriber: ResultSubscriber,
    pub bitcoin: Client,
}
