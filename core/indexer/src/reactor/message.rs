use malachitebft_app_channel::AppMsg;
use malachitebft_engine::host::Next;
use tokio::sync::oneshot;

use crate::consensus::{CommitCertificate, Ctx};

pub(crate) enum Message {
    Application(AppMsg<Ctx>),
    Finalized {
        certificate: CommitCertificate<Ctx>,
        evidence: String,
        reply: oneshot::Sender<Next<Ctx>>,
    },
}

impl From<AppMsg<Ctx>> for Message {
    fn from(message: AppMsg<Ctx>) -> Self {
        Self::Application(message)
    }
}
