extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

type Map<K, V> = stdlib::StorageMap<K, V, ()>;

#[derive(stdlib::Storage)]
struct FibValue {
    pub value: u64,
}

#[derive(Model)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
