mod dot_path_buf;
mod storage_interface;

pub use dot_path_buf::*;
pub use macros::{
    Root, Storage, StorageRoot, Store, Wavey, Wrapper, contract, impls, import, interface,
};
pub use storage_interface::*;
pub use wasm_wave;

impl FromString for String {
    fn from_string(s: String) -> Self {
        s
    }
}

impl FromString for u64 {
    fn from_string(s: String) -> Self {
        s.parse::<u64>().unwrap()
    }
}

#[derive(Clone)]
pub struct Map<K: ToString + FromString + Clone, V: Store> {
    pub entries: Vec<(K, V)>,
}

impl<K: ToString + FromString + Clone, V: Store> Map<K, V> {
    pub fn new(entries: &[(K, V)]) -> Self {
        Map {
            entries: entries.to_vec(),
        }
    }
}

impl<K: ToString + FromString + Clone, V: Store> Default for Map<K, V> {
    fn default() -> Self {
        Self {
            entries: Default::default(),
        }
    }
}

impl<K: ToString + FromString + Clone, V: Store> Store for Map<K, V> {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Map<K, V>) {
        for (k, v) in value.entries.into_iter() {
            ctx.__set(base_path.push(k.to_string()), v)
        }
    }
}

impl Store for u64 {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: u64) {
        ctx.__set_u64(&path, value);
    }
}

impl Store for i64 {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: i64) {
        ctx.__set_s64(&path, value);
    }
}

impl Store for &str {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: &str) {
        ctx.__set_str(&path, value);
    }
}

impl Store for String {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: String) {
        ctx.__set_str(&path, &value);
    }
}

impl Store for bool {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: bool) {
        ctx.__set_bool(&path, value);
    }
}

impl Store for () {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, _: ()) {
        ctx.__set_void(&path);
    }
}

impl Retrieve for u64 {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.__get_u64(&path)
    }
}

impl Retrieve for i64 {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.__get_s64(&path)
    }
}

impl Retrieve for String {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.__get_str(&path)
    }
}

impl Retrieve for bool {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.__get_bool(&path)
    }
}

impl Retrieve for () {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.__get_void(&path)
    }
}

