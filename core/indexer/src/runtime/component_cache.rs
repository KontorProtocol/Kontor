use moka::future::Cache;
use wasmtime::component::Component;

const COMPONENT_CACHE_CAPACITY: u64 = 64;

#[derive(Clone)]
pub struct ComponentCache {
    inner: Cache<u64, Component>,
}

impl ComponentCache {
    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(COMPONENT_CACHE_CAPACITY)
                .build(),
        }
    }

    pub async fn get(&self, key: &u64) -> Option<Component> {
        self.inner.get(key).await
    }

    pub async fn put(&self, key: u64, value: Component) {
        self.inner.insert(key, value).await
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
