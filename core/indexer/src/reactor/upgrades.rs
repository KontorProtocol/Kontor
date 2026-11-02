use anyhow::Result;

use super::{Reactor, executor::Executor};
use crate::consensus::Value;
use crate::upgrade_control::UpgradeSubmission;

impl<E: Executor> Reactor<E> {
    pub(super) async fn submit_upgrade(&mut self, submission: UpgradeSubmission) -> Result<()> {
        let conn = self.db_conn();
        let queued = self
            .pending_control
            .submit(
                &conn,
                self.consensus.current_height.as_u64(),
                submission.envelope,
            )
            .await?;
        let _ = submission.reply.send(queued);
        Ok(())
    }

    pub(super) async fn pending_upgrade_value(&mut self) -> Result<Option<Value>> {
        let Some(proposal) = self.consensus.pending_proposal.as_ref() else {
            return Ok(None);
        };
        let inclusion = proposal.height.as_u64();
        let conn = self.db_conn();
        self.pending_control
            .input(&conn, inclusion)
            .await?
            .map(Value::from_input)
            .transpose()
            .map_err(Into::into)
    }
}
