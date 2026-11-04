use malachitebft_app_channel::AppMsg;
#[cfg(kontor_consensus_runtime)]
use malachitebft_engine::host::Next;
#[cfg(kontor_consensus_runtime)]
use tokio::sync::oneshot;

#[cfg(kontor_consensus_runtime)]
use crate::consensus::CommitCertificate;
use crate::consensus::Ctx;

pub(crate) enum Message {
    Application(AppMsg<Ctx>),
    #[cfg(kontor_consensus_runtime)]
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
