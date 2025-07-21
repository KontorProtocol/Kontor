use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};
use super::storage_interface::Storage;

static STRING_STORAGE: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static U64_STORAGE: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct MemoryStorage;

impl MemoryStorage {
    pub fn new() -> Self {
        Self
    }
}

impl Storage for MemoryStorage {
    fn get_str(&self, path: String) -> Option<String> {
        let storage = STRING_STORAGE.lock().unwrap();
        storage.get(&path).cloned()
    }

    fn set_str(&self, path: String, value: String) {
        let mut storage = STRING_STORAGE.lock().unwrap();
        storage.insert(path, value);
    }

    fn get_u64(&self, path: String) -> Option<u64> {
        let storage = U64_STORAGE.lock().unwrap();
        storage.get(&path).copied()
    }

    fn set_u64(&self, path: String, value: u64) {
        let mut storage = U64_STORAGE.lock().unwrap();
        storage.insert(path, value);
    }

    fn exists(&self, path: String) -> bool {
        let string_storage = STRING_STORAGE.lock().unwrap();
        let u64_storage = U64_STORAGE.lock().unwrap();
        string_storage.contains_key(&path) || u64_storage.contains_key(&path)
    }
} 