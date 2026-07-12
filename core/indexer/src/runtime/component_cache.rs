use moka::future::Cache;
use wasmtime::component::Component;

/// Total-weight bound for the cache, where each entry weighs its encoded
/// component binary size (the best cheap proxy for the compiled machine
/// code's memory footprint — `Component` exposes no in-memory size). An
/// entry-count bound alone lets a handful of pathological contracts pin
/// unbounded memory (#434); 256 MiB is far above any legitimate working
/// set while keeping the worst case bounded.
const COMPONENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct ComponentCache {
    inner: Cache<u64, (Component, u32)>,
}

impl ComponentCache {
    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                // Weight 0 would make an entry invisible to the bound —
                // floor at 1.
                .weigher(|_key, (_component, size): &(Component, u32)| (*size).max(1))
                .max_capacity(COMPONENT_CACHE_MAX_BYTES)
                .build(),
        }
    }

    pub async fn get(&self, key: &u64) -> Option<Component> {
        self.inner.get(key).await.map(|(component, _)| component)
    }

    /// Entry with its recorded weight — for callers that re-`put` entries into
    /// another cache and must preserve the weight (test prewarming).
    pub async fn get_weighted(&self, key: &u64) -> Option<(Component, u32)> {
        self.inner.get(key).await
    }

    /// Cache a compiled component, weighed by `size_bytes` — the encoded
    /// component binary length the caller already has in hand.
    pub async fn put(&self, key: u64, value: Component, size_bytes: usize) {
        let weight = u32::try_from(size_bytes).unwrap_or(u32::MAX);
        self.inner.insert(key, (value, weight)).await
    }

    /// Drop a cached component. Used when a publish rolls back: the contract id
    /// may be reused by a later publish with different bytes, so a stale entry
    /// must not survive.
    pub async fn invalidate(&self, key: u64) {
        self.inner.invalidate(&key).await
    }

    /// Drop every cached component. Used on reorg, where cascade-deleted
    /// contracts free their ids for reuse by replayed publishes — a stale entry
    /// would otherwise let `load_component` serve the wrong WASM for a reused id.
    pub fn clear(&self) {
        self.inner.invalidate_all()
    }
}
