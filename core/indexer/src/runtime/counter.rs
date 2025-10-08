use std::sync::Arc;

use bon::Builder;
use tokio::sync::Mutex;

#[derive(Debug, Builder, Clone, Default)]
pub struct Counter {
    #[builder(default = Arc::new(Mutex::new(0)))]
    value: Arc<Mutex<u64>>,
}

impl Counter {
    pub fn new() -> Self {
        Counter {
            value: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn reset(&self) {
        let mut value = self.value.lock().await;
        *value = 0;
    }

    pub async fn increment(&self) -> u64 {
        let mut value = self.value.lock().await;
        *value += 1;
        *value
    }

    pub async fn get(&self) -> u64 {
        *self.value.lock().await
    }
}
