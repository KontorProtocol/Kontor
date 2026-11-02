use std::sync::Arc;

use crate::protocol::execution::SelectionEnvelope;
use crate::protocol::migration_input::InputCallbacks;
use crate::protocol::operations::{MigrationCall, MigrationFuture, OperationFuture, SessionOwner};

// The frozen executor's interface cannot report work after failure. Keep the
// adapter typed and preserve that absence rather than manufacturing zero usage.
pub(crate) type LegacyMigrationCall = Arc<
    dyn Fn(
            SessionOwner,
            SelectionEnvelope,
            Vec<u8>,
            InputCallbacks,
        ) -> OperationFuture<Result<[u64; 5], u8>>
        + Send
        + Sync,
>;

pub(crate) trait MigrationExport: Send + Sync + 'static {
    fn into_current(self) -> MigrationCall;
}

impl MigrationExport for MigrationCall {
    fn into_current(self) -> MigrationCall {
        self
    }
}

impl MigrationExport for LegacyMigrationCall {
    fn into_current(self) -> MigrationCall {
        Arc::new(move |owner, selection, definition, input| {
            adapt(self(owner, selection, definition, input))
        })
    }
}

fn adapt(future: OperationFuture<Result<[u64; 5], u8>>) -> MigrationFuture {
    Box::pin(async move {
        future
            .await
            .map(|outcome| outcome.map_err(|tag| (tag, None)))
            .map_err(|(tag, message)| (tag, message, None))
    })
}

#[cfg(test)]
mod tests {
    use super::adapt;

    #[tokio::test]
    async fn legacy_migration_preserves_outcomes_without_inventing_failed_work() {
        assert_eq!(
            adapt(Box::pin(async { Ok(Ok([1, 2, 3, 4, 5])) })).await,
            Ok(Ok([1, 2, 3, 4, 5]))
        );
        for tag in [0, 1, 2, 255] {
            assert_eq!(
                adapt(Box::pin(async move { Ok(Err(tag)) })).await,
                Ok(Err((tag, None)))
            );
            assert_eq!(
                adapt(Box::pin(async move { Err((tag, "host failure".into())) })).await,
                Err((tag, "host failure".into(), None))
            );
        }
    }
}
