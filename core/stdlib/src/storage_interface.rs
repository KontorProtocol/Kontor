use crate::DotPathBuf;

pub trait ReadStorage {
    fn get_str(&self, path: &str) -> Option<String>;
    fn get_u64(&self, path: &str) -> Option<u64>;
    fn get_s64(&self, path: &str) -> Option<i64>;
    fn exists(&self, path: &str) -> bool;
    fn is_void(&self, path: &str) -> bool;
    fn matching_path(&self, regexp: &str) -> Option<String>;
}

pub trait WriteStorage {
    fn set_str(&self, path: &str, value: &str);
    fn set_u64(&self, path: &str, value: u64);
    fn set_s64(&self, path: &str, value: i64);
    fn set_void(&self, path: &str);
}

pub trait ReadWriteStorage: ReadStorage + WriteStorage {}

pub trait ReadContext {
    fn read_storage(&self) -> impl ReadStorage;
}

pub trait WriteContext {
    fn write_storage(&self) -> impl WriteStorage;
}

pub trait ReadWriteContext: ReadContext + WriteContext {}

pub trait Store: Clone {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf);
}

impl Store for u64 {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.write_storage().set_u64(&path, *self);
    }
}

impl Store for i64 {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.write_storage().set_s64(&path, *self);
    }
}

impl Store for &str {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.write_storage().set_str(&path, self);
    }
}

impl Store for String {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.write_storage().set_str(&path, self);
    }
}
