use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Error, Debug)]
pub enum StackError {
    #[error("reentrancy prevented: contract with database id {0} already exists in the stack")]
    CycleDetected(String),
}

#[derive(Clone, Debug)]
pub struct Stack<T> {
    inner: Arc<Mutex<Vec<T>>>,
}

impl<T: Send + PartialEq + Debug> Stack<T> {
    pub fn new() -> Self {
        Stack {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
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
}
