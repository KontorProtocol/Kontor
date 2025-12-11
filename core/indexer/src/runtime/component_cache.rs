use moka::future::Cache;
use wasmtime::component::Component;

const COMPONENT_CACHE_CAPACITY: u64 = 64;

#[derive(Clone)]
pub struct ComponentCache {
    inner: Cache<i64, Component>,
}

impl ComponentCache {
    pub fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(COMPONENT_CACHE_CAPACITY)
                .build(),
        }
    }

    pub async fn get(&self, key: &i64) -> Option<Component> {
        self.inner.get(key).await
    }

    pub async fn put(&self, key: i64, value: Component) {
        self.inner.insert(key, value).await
    }
}
