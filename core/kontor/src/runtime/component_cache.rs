use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use lru::LruCache;
use wasmtime::component::Component;

const COMPONENT_CACHE_CAPACITY: usize = 64;

#[derive(Clone)]
pub struct ComponentCache {
    cache: Arc<Mutex<LruCache<String, Component>>>,
}

impl ComponentCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(COMPONENT_CACHE_CAPACITY).unwrap(),
            ))),
        }
    }

    pub fn get(&self, key: &str) -> Option<Component> {
        self.cache.lock().unwrap().get(key).cloned()
    }

    pub fn put(&self, key: String, value: Component) {
        self.cache.lock().unwrap().put(key, value);
    }
}
