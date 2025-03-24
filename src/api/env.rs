use tokio_util::sync::CancellationToken;

use crate::{config::Config, database};

#[derive(Clone)]
pub struct Env {
    pub config: Config,
    pub cancel_token: CancellationToken,
    pub reader: database::Reader,
}
