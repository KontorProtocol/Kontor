use sha2::{Digest, Sha256};

use crate::protocol::v1::native::TOKEN_CONTRACT_ID;

pub(crate) const TOKEN: &[u8] = include_bytes!("native/token.wasm.br");

pub(crate) fn replacement(contract_id: u64) -> Option<&'static [u8]> {
    (contract_id == TOKEN_CONTRACT_ID).then_some(TOKEN)
}

pub(crate) fn artifact_hash(contract_id: u64) -> Option<[u8; 32]> {
    replacement(contract_id).map(|bytes| Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use futures_util::TryStreamExt;
    use stdlib::{KeyElement, KeyPath};

    use super::*;
    use crate::protocol::execution::ExecutorVersion;
    use crate::protocol::v1::native as p1_native;
    use crate::runtime::token::api;
    use crate::runtime::wit::Signer;
    use crate::runtime::wit::kontor::built_in::context::{HolderRef, OutPoint};
    use crate::runtime::{Decimal, Runtime};
    use crate::test_utils::test_runtime;

    #[tokio::test]
    async fn selected_native_bytes_wit_and_calls_preserve_publication_and_p1_cache() -> Result<()> {
        let (mut p1, _dir, _name) = test_runtime().await?;
        let id = TOKEN_CONTRACT_ID;
        assert_eq!(
            p1.storage.contract_bytes(id).await?.unwrap(),
            p1_native::TOKEN
        );
        assert!(
            !p1.storage
                .component_wit(id)
                .await?
                .contains("positive-balance-count")
        );
        assert!(api::positive_balance_count(&mut p1).await.is_err());
        let mut p2 = Runtime::new_for_version(
            p1.engine.clone(),
            p1.linkers.clone(),
            p1.component_cache.clone(),
            p1.storage.clone(),
            ExecutorVersion::P2,
        )
        .await?;
        assert_eq!(
            p2.storage.contract_bytes(id).await?.unwrap(),
            p1_native::TOKEN
        );
        assert_eq!(
            p2.storage.stored_component_bytes(id).await.ok().unwrap(),
            TOKEN
        );
        assert_eq!(
            artifact_hash(id),
            Some(Sha256::digest(p2.storage.stored_component_bytes(id).await.ok().unwrap()).into())
        );
        assert!(
            p2.storage
                .component_wit(id)
                .await?
                .contains("positive-balance-count")
        );
        assert_eq!(
            p2.storage
                .component_bytes(p1_native::STAKING_CONTRACT_ID)
                .await?,
            p1.storage
                .component_bytes(p1_native::STAKING_CONTRACT_ID)
                .await?,
        );
        // This fixture seeds the derived field directly to isolate execution and
        // cache selection. Activation tests exercise the registered migration.
        let entries: Vec<_> = p2
            .storage
            .find_live_subtree(id, &KeyPath::new().push_interned(0))
            .await?
            .try_collect()
            .await?;
        let mut count = 0u64;
        for row in entries {
            let stored = p2.storage.get(1024, id, &row.path).await?.unwrap();
            let encoded: Vec<u8> = postcard::from_bytes(&stored)?;
            let (amount, tail) = Decimal::decode_from(&encoded).unwrap();
            assert!(tail.is_empty());
            count += u64::from(amount > Decimal::default());
        }
        p2.storage
            .set(
                id,
                &KeyPath::new().push_interned(5),
                &postcard::to_allocvec(&count)?,
                None,
                None,
            )
            .await?;
        assert_eq!(api::positive_balance_count(&mut p2).await?, count);
        let core = Signer::Core(Box::new(Signer::Nobody));
        for holder in [
            HolderRef::SignerId(100),
            HolderRef::Utxo(OutPoint {
                txid: "ab".repeat(32),
                vout: 7,
            }),
        ] {
            api::issue_to(&mut p2, &core, holder.clone(), Decimal::from("10")).await??;
            count += 1;
            assert_eq!(api::positive_balance_count(&mut p2).await?, count);
            api::issue_to(&mut p2, &core, holder, Decimal::from("10")).await??;
            assert_eq!(api::positive_balance_count(&mut p2).await?, count);
        }
        assert_eq!(
            p2.storage.contract_bytes(id).await?.unwrap(),
            p1_native::TOKEN
        );
        assert!(api::positive_balance_count(&mut p1).await.is_err());
        assert!(
            !p1.storage
                .component_wit(id)
                .await?
                .contains("positive-balance-count")
        );
        Ok(())
    }
}
