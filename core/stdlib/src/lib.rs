pub mod memory_storage;
pub mod storage_interface;
use self::storage_interface::Storage;

pub fn store_and_return_int<S: Storage>(storage: &S, path: String, x: u64) -> u64 {
    storage.set_u64(path.clone(), x);
    
    let retrieved = storage.get_u64(path);
    retrieved.unwrap_or(0)
}

