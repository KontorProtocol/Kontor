use std::sync::Arc;

use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Queue<T: Send> {
    inner: Arc<Mutex<Vec<T>>>,
}

impl<T: Send> Queue<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn push(&self, item: T) {
        let mut guard = self.inner.lock().await;
        guard.push(item);
    }

    pub async fn take_all(&self) -> Vec<T> {
        let mut guard = self.inner.lock().await;
        std::mem::take(&mut *guard)
    }

    pub async fn replace_last(&self, item: T) {
        let mut guard = self.inner.lock().await;
        if guard.is_empty() {
            guard.push(item);
        } else {
            let last_index = guard.len() - 1;
            guard[last_index] = item;
        }
    }
}
