use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use wasmtime::{Error, ResourceLimiter, Result};

use super::ExecutionError;

#[derive(Debug)]
pub(crate) struct GuestMemoryLimitExceeded;

impl fmt::Display for GuestMemoryLimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("guest memory limit exceeded")
    }
}

impl std::error::Error for GuestMemoryLimitExceeded {}

#[derive(Clone, Copy)]
pub(crate) struct GuestMemoryLimits {
    pub per_root: usize,
    pub memories: usize,
    pub instances: usize,
    pub tables: usize,
    pub table_elements: usize,
}

struct RootBudget {
    admitted: AtomicUsize,
    failure_flags: AtomicU8,
    limit: usize,
}

const QUOTA_DENIED: u8 = 1;
const BACKING_FAILED: u8 = 2;

pub(crate) struct GuestMemoryLimiter {
    root: Arc<RootBudget>,
    // Count permitted growth until Store teardown: Wasmtime cannot identify
    // which reservation a later growth-failure callback should release.
    local_admitted: usize,
    limits: GuestMemoryLimits,
}

impl GuestMemoryLimiter {
    pub(crate) fn new_root(limits: GuestMemoryLimits) -> Self {
        Self {
            root: Arc::new(RootBudget {
                admitted: AtomicUsize::new(0),
                failure_flags: AtomicU8::new(0),
                limit: limits.per_root,
            }),
            local_admitted: 0,
            limits,
        }
    }

    pub(crate) fn new_child(&self) -> Self {
        Self {
            root: self.root.clone(),
            local_admitted: 0,
            limits: self.limits,
        }
    }

    pub(crate) fn quota_denied(&self) -> bool {
        self.root.failure_flags.load(Ordering::SeqCst) & QUOTA_DENIED != 0
    }

    pub(crate) fn backing_failed(&self) -> bool {
        self.root.failure_flags.load(Ordering::SeqCst) & BACKING_FAILED != 0
    }

    fn deny_growth(&self) -> Result<bool> {
        self.root
            .failure_flags
            .fetch_or(QUOTA_DENIED, Ordering::SeqCst);
        Err(GuestMemoryLimitExceeded.into())
    }

    #[cfg(test)]
    pub(crate) fn admitted(&self) -> usize {
        self.root.admitted.load(Ordering::SeqCst)
    }
}

impl Clone for GuestMemoryLimiter {
    fn clone(&self) -> Self {
        self.new_child()
    }
}

impl Drop for GuestMemoryLimiter {
    fn drop(&mut self) {
        let previous = self
            .root
            .admitted
            .fetch_sub(self.local_admitted, Ordering::SeqCst);
        debug_assert!(previous >= self.local_admitted);
    }
}

impl ResourceLimiter for GuestMemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool> {
        if maximum.is_some_and(|maximum| desired > maximum) {
            return Ok(false);
        }
        if desired < current {
            return self.deny_growth();
        }
        let delta = desired - current;
        let Some(local) = self.local_admitted.checked_add(delta) else {
            return self.deny_growth();
        };
        let mut used = self.root.admitted.load(Ordering::SeqCst);
        loop {
            let Some(next) = used.checked_add(delta) else {
                return self.deny_growth();
            };
            if next > self.root.limit {
                return self.deny_growth();
            }
            match self.root.admitted.compare_exchange_weak(
                used,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.local_admitted = local;
                    return Ok(true);
                }
                Err(actual) => used = actual,
            }
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        Ok(desired <= self.limits.table_elements)
    }

    fn memory_grow_failed(&mut self, error: Error) -> Result<()> {
        self.root
            .failure_flags
            .fetch_or(BACKING_FAILED, Ordering::SeqCst);
        Err(ExecutionError::NonDeterministic(error.into()).into())
    }

    fn instances(&self) -> usize {
        self.limits.instances
    }

    fn tables(&self) -> usize {
        self.limits.tables
    }

    fn memories(&self) -> usize {
        self.limits.memories
    }
}

#[cfg(test)]
mod tests;
