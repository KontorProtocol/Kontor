use anyhow::Result;

pub trait Storage {
    fn get(&self, key: String) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: String, value: Vec<u8>) -> Result<()>;
    fn delete(&self, key: String) -> Result<bool>;
} 