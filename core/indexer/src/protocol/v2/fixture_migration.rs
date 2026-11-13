use stdlib::KeyPath;

use super::FIXTURE_NAME;
use super::native::FIXTURE;
use crate::protocol::v1::migration::{MigrationContext, MigrationFailure};

pub(crate) async fn install(context: &mut MigrationContext) -> Result<(), MigrationFailure> {
    let id = context.install_contract(FIXTURE_NAME, FIXTURE).await?;
    // The fixture's public initializer does not write state. Its single scalar is
    // initialized only by this atomic migration, using the ordinary storage codec.
    let key = KeyPath::new().push_interned(0);
    let value = postcard::to_allocvec(&2u64)
        .map_err(|_| MigrationFailure::InvalidOperation("fixture version encoding failed"))?;
    context.set(id, &key, &value, (None, None)).await
}
