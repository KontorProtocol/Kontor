use crate::DotPathBuf;

pub trait ReadContext {
    fn get_str(&self, path: &str) -> Option<String>;
    fn get_u64(&self, path: &str) -> Option<u64>;
    fn get_s64(&self, path: &str) -> Option<i64>;
    fn exists(&self, path: &str) -> bool;
    fn is_void(&self, path: &str) -> bool;
    fn matching_path(&self, regexp: &str) -> Option<String>;
    fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T>;
}

pub trait WriteContext {
    fn set_str(&self, path: &str, value: &str);
    fn set_u64(&self, path: &str, value: u64);
    fn set_s64(&self, path: &str, value: i64);
    fn set_void(&self, path: &str);
    fn __set<T: Store>(&self, path: DotPathBuf, value: T);
}

pub trait ReadWriteContext: ReadContext + WriteContext {}

pub trait Store: Clone {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Self);
}

pub trait Retrieve: Clone {
    fn __get(ctx: &impl ReadContext, base_path: DotPathBuf) -> Option<Self>;
}
