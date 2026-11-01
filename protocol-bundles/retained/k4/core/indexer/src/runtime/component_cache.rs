use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use moka::future::Cache;
use sha2::{Digest, Sha256};
use wasmtime::{Engine, EngineWeak, component::Component};

use crate::protocol::execution::ExecutorVersion;

/// Total-weight bound for the cache, where each entry weighs its encoded
/// component binary size (the best cheap proxy for the compiled machine
/// code's memory footprint — `Component` exposes no in-memory size). An
/// entry-count bound alone lets a handful of pathological contracts pin
/// unbounded memory (#434); 256 MiB is far above any legitimate working
/// set while keeping the worst case bounded.
const COMPONENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct ComponentSource {
    contract_id: u64,
    stored_sha256: [u8; 32],
}

impl ComponentSource {
    pub(crate) fn new(contract_id: u64, stored_bytes: &[u8]) -> Self {
        Self {
            contract_id,
            stored_sha256: Sha256::digest(stored_bytes).into(),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct CacheKey {
    source: ComponentSource,
    executor: ExecutorVersion,
    engine: u64,
}

#[derive(Default)]
struct Engines {
    next: u64,
    live: Vec<(u64, EngineWeak)>,
}

#[derive(Clone)]
pub struct ComponentCache {
    inner: Cache<CacheKey, (Component, u32, bool)>,
    engines: Arc<Mutex<Engines>>,
}

impl ComponentCache {
    #[cfg(test)]
    pub(crate) async fn workload_metrics(&self) -> (u64, u64) {
        self.inner.run_pending_tasks().await;
        (self.inner.entry_count(), self.inner.weighted_size())
    }

    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                // Weight 0 would make an entry invisible to the bound —
                // floor at 1.
                .weigher(
                    |_key, (_component, size, _admitted): &(Component, u32, bool)| (*size).max(1),
                )
                .max_capacity(COMPONENT_CACHE_MAX_BYTES)
                .support_invalidation_closures()
                .build(),
            engines: Arc::new(Mutex::new(Engines::default())),
        }
    }

    fn key(
        &self,
        source: ComponentSource,
        executor: ExecutorVersion,
        engine: &Engine,
    ) -> Result<CacheKey> {
        let mut engines = self
            .engines
            .lock()
            .map_err(|_| anyhow!("cache engine registry poisoned"))?;
        engines.live.retain(|(_, weak)| weak.upgrade().is_some());
        let existing = engines.live.iter().find_map(|(id, weak)| {
            weak.upgrade()
                .filter(|candidate| Engine::same(candidate, engine))
                .map(|_| *id)
        });
        let id = match existing {
            Some(id) => id,
            None => {
                let id = engines.next;
                engines.next = id
                    .checked_add(1)
                    .context("cache engine identity exhausted")?;
                engines.live.push((id, engine.weak()));
                id
            }
        };
        Ok(CacheKey {
            source,
            executor,
            engine: id,
        })
    }

    // These test-only inspectors deliberately search all namespaces. Production
    // lookup must resolve the source from its own snapshot and use get_selected.
    #[cfg(test)]
    pub(crate) async fn get(&self, key: &u64) -> Option<Component> {
        self.get_weighted(key)
            .await
            .map(|(_, component, _, _)| component)
    }

    #[cfg(test)]
    pub(crate) async fn get_admitted(&self, key: &u64) -> Option<Component> {
        self.get_weighted(key)
            .await
            .and_then(|(_, component, _, admitted)| admitted.then_some(component))
    }

    pub(crate) async fn get_selected(
        &self,
        source: ComponentSource,
        executor: ExecutorVersion,
        engine: &Engine,
    ) -> Result<Option<Component>> {
        let key = self.key(source, executor, engine)?;
        Ok(self
            .inner
            .get(&key)
            .await
            .and_then(|(component, _, admitted)| admitted.then_some(component)))
    }

    /// Entry with its recorded weight — for callers that re-`put` entries into
    /// another cache and must preserve the weight (test prewarming).
    pub(crate) async fn get_weighted(
        &self,
        contract_id: &u64,
    ) -> Option<(ComponentSource, Component, u32, bool)> {
        for (key, _) in self.inner.iter() {
            if key.source.contract_id == *contract_id
                && let Some((component, size, admitted)) = self.inner.get(key.as_ref()).await
            {
                return Some((key.source, component, size, admitted));
            }
        }
        None
    }

    /// Only call after `validate_no_starts`: this bit is the cache hit's proof
    /// that the component passed the current guest-entry admission rule.
    pub(crate) async fn put_selected(
        &self,
        source: ComponentSource,
        executor: ExecutorVersion,
        value: Component,
        size_bytes: usize,
    ) -> Result<()> {
        let key = self.key(source, executor, value.engine())?;
        let weight = u32::try_from(size_bytes).unwrap_or(u32::MAX);
        self.inner.insert(key, (value, weight, true)).await;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn put_unchecked(
        &self,
        source: ComponentSource,
        executor: ExecutorVersion,
        value: Component,
        size_bytes: usize,
    ) -> Result<()> {
        let key = self.key(source, executor, value.engine())?;
        let weight = u32::try_from(size_bytes).unwrap_or(u32::MAX);
        self.inner.insert(key, (value, weight, false)).await;
        Ok(())
    }

    /// Evict speculative publications across namespaces after a failed publish.
    pub async fn invalidate(&self, key: u64) {
        self.inner
            .invalidate_entries_if(move |entry, _| entry.source.contract_id == key)
            .expect("invalidation closures enabled at cache construction");
    }

    /// Retain the existing reorg/cancellation policy of discarding warmed code.
    pub fn clear(&self) {
        self.inner.invalidate_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engines_and_sources_have_distinct_entries_with_one_weight_budget() -> Result<()> {
        let cache = ComponentCache::new();
        let first = Engine::default();
        let second = Engine::default();
        let source = ComponentSource::new(9, b"original");
        let replaced = ComponentSource::new(9, b"replacement");
        let version = ExecutorVersion::LegacyP1;
        let a = Component::new(&first, "(component)")?;
        let b = Component::new(&second, "(component)")?;
        let weight = 100 * 1024 * 1024;
        cache
            .put_selected(source, version, a.clone(), weight)
            .await?;
        assert!(
            cache
                .get_selected(source, version, &second)
                .await?
                .is_none()
        );
        assert!(
            cache
                .get_selected(replaced, version, &first)
                .await?
                .is_none()
        );
        cache.put_selected(source, version, b, weight).await?;
        assert!(Engine::same(
            cache
                .get_selected(source, version, &first)
                .await?
                .unwrap()
                .engine(),
            &first
        ));
        assert!(Engine::same(
            cache
                .get_selected(source, version, &second)
                .await?
                .unwrap()
                .engine(),
            &second
        ));
        cache.put_selected(replaced, version, a, weight).await?;
        cache.inner.run_pending_tasks().await;
        assert!(cache.inner.weighted_size() <= COMPONENT_CACHE_MAX_BYTES);
        cache.invalidate(9).await;
        assert!(cache.get_selected(source, version, &first).await?.is_none());
        assert!(
            cache
                .get_selected(source, version, &second)
                .await?
                .is_none()
        );
        assert!(
            cache
                .get_selected(replaced, version, &first)
                .await?
                .is_none()
        );
        Ok(())
    }
}
