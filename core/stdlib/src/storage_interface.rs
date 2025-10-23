use crate::DotPathBuf;

pub trait FromString {
    fn from_string(s: String) -> Self;
}

pub trait ReadContext {
    fn __get_str(&self, path: &str) -> Option<String>;
    fn __get_u64(&self, path: &str) -> Option<u64>;
    fn __get_s64(&self, path: &str) -> Option<i64>;
    fn __get_bool(&self, path: &str) -> Option<bool>;
    fn __get_keys<'a, T: ToString + FromString + Clone + 'a>(
        &self,
        path: &'a str,
    ) -> impl Iterator<Item = T> + 'a;
    fn __exists(&self, path: &str) -> bool;
    fn __extend_path_with_match(&self, path: &str, variants: &[&str]) -> Option<String>;
    fn __get<T: Retrieve>(&self, path: DotPathBuf) -> Option<T>;
}

pub trait WriteContext {
    fn __set_str(&self, path: &str, value: &str);
    fn __set_u64(&self, path: &str, value: u64);
    fn __set_s64(&self, path: &str, value: i64);
    fn __set_bool(&self, path: &str, value: bool);
    fn __set_void(&self, path: &str);
    fn __set<T: Store>(&self, path: DotPathBuf, value: T);
    fn __delete_matching_paths(&self, regexp: &str) -> u64;
    fn generate_id(&self) -> String;
}

pub trait ReadWriteContext: ReadContext + WriteContext {}

pub trait Store: Clone {
    fn __set(ctx: &impl WriteContext, base_path: DotPathBuf, value: Self);
}

pub trait Retrieve: Clone {
    fn __get(ctx: &impl ReadContext, base_path: DotPathBuf) -> Option<Self>;
}
