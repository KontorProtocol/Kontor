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

/// One frame on the cross-contract call stack — the contract being
/// executed plus whether its dispatch is a proc (mutating) or view
/// (read-only). The runtime's host functions read the top frame's
/// `is_proc` to decide whether DB-mutating side effects are allowed
/// (e.g. `Runtime::get_or_create_identity` skips writes inside a view
/// frame even if the outer caller is a proc).
///
/// `PartialEq` compares **only `contract_id`** because the only
/// PartialEq use in `Stack` is the re-entrancy / cycle detector — a
/// contract that's already on the stack must not be re-entered
/// regardless of whether the new entry would be a proc or view.
#[derive(Clone, Copy, Debug)]
pub struct CallFrame {
    pub contract_id: u64,
    pub is_proc: bool,
    /// The depositor (signer_id; `None` = no deposit settled for this op) to stamp
    /// on this frame's storage writes — the op's payer, set on the outermost frame
    /// and INHERITED by nested frames. Lives on the frame (not a shared atomic) so
    /// it follows the call's push/pop discipline: a nested or sub-op (hold/settle)
    /// frame can't clobber the op's depositor, it just carries its own (`None`) and
    /// pops away.
    pub depositor: Option<u64>,
}

impl PartialEq for CallFrame {
    fn eq(&self, other: &Self) -> bool {
        self.contract_id == other.contract_id
    }
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
