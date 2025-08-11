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
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Map<K, V>) {
        for (k, v) in value.entries.into_iter() {
            ctx.__set(base_path.push(k.to_string()), v)
        }
    }
}

impl Store for u64 {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: u64) {
        ctx.set_u64(&path, value);
    }
}

impl Store for i64 {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: i64) {
        ctx.set_s64(&path, value);
    }
}

impl Store for &str {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: &str) {
        ctx.set_str(&path, value);
    }
}

impl Store for String {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, value: String) {
        ctx.set_str(&path, &value);
    }
}

impl Store for () {
    fn __set(ctx: &impl WriteContext, path: DotPathBuf, _: ()) {
        ctx.set_void(&path);
    }
}

impl Retrieve for u64 {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.get_u64(&path)
    }
}

impl Retrieve for i64 {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.get_s64(&path)
    }
}

impl Retrieve for String {
    fn __get(ctx: &impl ReadContext, path: DotPathBuf) -> Option<Self> {
        ctx.get_str(&path)
    }
}
