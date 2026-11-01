extern crate alloc;

use stdlib::Model;

type Map<K, V> = stdlib::StorageMap<K, V, ()>;

#[derive(Model)]
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
