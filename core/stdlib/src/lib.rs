pub mod memory_storage;
pub mod storage_interface;
use self::storage_interface::Storage;

pub fn store_and_return_int<S: Storage>(storage: &S, key: String, x: u64) -> u64 {
    let value = x.to_le_bytes().to_vec();
    storage.set(key.clone(), value).unwrap();
    
    let retrieved = storage.get(key).unwrap();
    match retrieved {
        Some(bytes) => {
            let array: [u8; 8] = bytes.try_into().unwrap();
            u64::from_le_bytes(array)
        }
        None => 0,
    }
}

