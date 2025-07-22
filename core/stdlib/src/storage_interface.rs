use crate::DotPathBuf;

pub trait ReadStorage {
    fn get_str(&self, path: &str) -> Option<String>;
    fn get_u64(&self, path: &str) -> Option<u64>;
    fn exists(&self, path: &str) -> bool;
}

pub trait WriteStorage {
    fn set_str(&self, path: &str, value: &str);
    fn set_u64(&self, path: &str, value: u64);
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
    fn __set(&self, storage: &impl WriteStorage, base_path: DotPathBuf);
}
