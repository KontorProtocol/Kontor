mod dot_path_buf;
mod storage_interface;

pub use dot_path_buf::*;
pub use storage_interface::*;

#[derive(Clone)]
pub struct Map<K: ToString + Clone, V: Store> {
    pub entries: Vec<(K, V)>,
}

impl<K: ToString + Clone, V: Store> Map<K, V> {
    pub fn new(entries: &[(K, V)]) -> Self {
        Map {
            entries: entries.to_vec(),
        }
    }
}

impl<K: ToString + Clone, V: Store> Store for Map<K, V> {
    fn __set(&self, storage: &impl WriteStorage, base_path: DotPathBuf) {
        for (k, v) in self.entries.iter() {
            v.__set(storage, base_path.push(k.to_string()))
        }
    }
}
