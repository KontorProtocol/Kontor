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
}

pub trait ReadWriteContext: ReadContext + WriteContext {}

pub trait Store: Clone {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf);
}

impl Store for u64 {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.set_u64(&path, *self);
    }
}

impl Store for i64 {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.set_s64(&path, *self);
    }
}

impl Store for &str {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.set_str(&path, self);
    }
}

impl Store for String {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.set_str(&path, self);
    }
}

impl Store for () {
    fn __set(&self, ctx: &impl WriteContext, path: DotPathBuf) {
        ctx.set_void(&path);
    }
}

pub trait Retrieve: Clone {
    fn __get(ctx: &impl ReadContext, base_path: DotPathBuf) -> Option<Self>;
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
