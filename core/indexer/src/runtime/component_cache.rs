use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use lru::LruCache;
use wasmtime::component::Component;

const COMPONENT_CACHE_CAPACITY: usize = 64;

#[derive(Clone)]
pub struct ComponentCache {
    cache: Arc<Mutex<LruCache<i64, Component>>>,
}

impl ComponentCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(COMPONENT_CACHE_CAPACITY).expect("capacity must be non-zero"),
            ))),
        }
    }

    pub fn get(&self, key: &i64) -> Option<Component> {
        self.cache.lock().unwrap().get(key).cloned()
    }

    pub fn put(&self, key: i64, value: Component) {
        self.cache.lock().unwrap().put(key, value);
    }
}
