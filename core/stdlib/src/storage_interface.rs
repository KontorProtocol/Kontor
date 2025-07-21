pub trait Storage {
    fn get_str(&self, path: String) -> Option<String>;
    fn set_str(&self, path: String, value: String);
    fn get_u64(&self, path: String) -> Option<u64>;
    fn set_u64(&self, path: String, value: u64);
    fn exists(&self, path: String) -> bool;
} 