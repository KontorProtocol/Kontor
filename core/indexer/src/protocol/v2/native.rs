pub(crate) const FIXTURE: &[u8] = include_bytes!("native/upgrade_fixture.wasm.br");

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::protocol::execution::ExecutorVersion;
    use crate::protocol::v1::native::NATIVE_CONTRACTS;
    use crate::runtime::Runtime;
    use crate::test_utils::test_runtime;

    #[tokio::test]
    async fn common_native_artifacts_and_interfaces_match_with_a_shared_cache() -> Result<()> {
        let (p1, _dir, _name) = test_runtime().await?;
        let p2 = Runtime::new_for_version(
            p1.engine.clone(),
            p1.linkers.clone(),
            p1.component_cache.clone(),
            p1.storage.clone(),
            ExecutorVersion::P2,
        )
        .await?;
        for (index, (_, bytes)) in NATIVE_CONTRACTS.iter().enumerate() {
            let id = index as u64 + 1;
            assert_eq!(
                p1.storage.contract_bytes(id).await?.as_deref(),
                Some(*bytes)
            );
            assert_eq!(
                p2.storage.component_bytes(id).await?,
                p1.storage.component_bytes(id).await?
            );
            assert_eq!(
                p2.storage.component_wit(id).await?,
                p1.storage.component_wit(id).await?
            );
        }
        Ok(())
    }
}
