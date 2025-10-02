use bon::Builder;
use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum StackError {
    #[error("reentrancy prevented: contract with database id {0} already exists in the stack")]
    CycleDetected(String),
}

#[derive(Clone, Debug, Builder)]
pub struct Stack<T> {
    #[builder(default = Arc::new(Mutex::new(Vec::new())))]
    inner: Arc<Mutex<Vec<T>>>,
}

impl<T: Send + PartialEq + Debug + Clone> Stack<T> {
    pub fn new() -> Self {
        Stack {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn clear(&self) {
        let mut stack = self.inner.lock().await;
        stack.clear();
    }

    pub async fn push(&self, item: T) -> Result<(), StackError> {
        let mut stack = self.inner.lock().await;

        if stack.contains(&item) {
            return Err(StackError::CycleDetected(format!("{:?}", item)));
        }

        stack.push(item);
        Ok(())
    }

    pub async fn pop(&self) -> Option<T> {
        let mut stack = self.inner.lock().await;
        stack.pop()
    }

    pub async fn peek(&self) -> Option<T> {
        let stack = self.inner.lock().await;
        stack.last().cloned()
    }

    pub async fn is_empty(&self) -> bool {
        let stack = self.inner.lock().await;
        stack.is_empty()
    }
}
