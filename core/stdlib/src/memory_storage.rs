use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};
use anyhow::Result;
use super::storage_interface::Storage;

static STORAGE: LazyLock<Mutex<HashMap<String, Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct MemoryStorage;

impl MemoryStorage {
    pub fn new() -> Self {
        Self
    }
}

impl Storage for MemoryStorage {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>> {
        let storage = STORAGE.lock().unwrap();
        Ok(storage.get(&key).cloned())
    }

    fn set(&self, key: String, value: Vec<u8>) -> Result<()> {
        let mut storage = STORAGE.lock().unwrap();
        storage.insert(key, value);
        Ok(())
    }

    fn delete(&self, key: String) -> Result<bool> {
        let mut storage = STORAGE.lock().unwrap();
        Ok(storage.remove(&key).is_some())
    }
} 