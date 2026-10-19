use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use thiserror::Error;
use wasmtime::{Error as WasmtimeError, ResourceLimiter, Result};

use super::ExecutionError;

#[derive(Debug, Error)]
#[error("guest memory limit exceeded")]
pub(crate) struct GuestMemoryLimitExceeded;

#[derive(Clone, Copy)]
pub(crate) struct GuestMemoryLimits {
    pub per_root: usize,
    pub memories: usize,
    pub instances: usize,
    pub tables: usize,
    pub table_elements: usize,
}

impl Default for GuestMemoryLimits {
    fn default() -> Self {
        // Consensus rules, independent of node hardware or operator settings.
        // The byte budget includes linear memory and GC capacity across nested
        // Stores. Object counts are per Store, and elements are per table.
        Self {
            per_root: 512 * 1024 * 1024,
            memories: 16,
            instances: 64,
            tables: 8,
            table_elements: 65_536,
        }
    }
}

struct RootBudget {
    // Each atomic contains its complete shared state. Stores can move between
    // executor threads, and guest completion orders the final failure check,
    // so relaxed ordering is sufficient.
    admitted: AtomicUsize,
    backing_failed: AtomicBool,
    limit: usize,
}

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
                backing_failed: AtomicBool::new(false),
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

    pub(crate) fn backing_failed(&self) -> bool {
        self.root.backing_failed.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn admitted(&self) -> usize {
        self.root.admitted.load(Ordering::Relaxed)
    }
}

impl Clone for GuestMemoryLimiter {
    fn clone(&self) -> Self {
        // Runtime clones share the budget, but must not release the original
        // Store's reservations when they are dropped.
        self.new_child()
    }
}

impl Drop for GuestMemoryLimiter {
    fn drop(&mut self) {
        if self.local_admitted == 0 {
            return;
        }
        let previous = self
            .root
            .admitted
            .fetch_sub(self.local_admitted, Ordering::Relaxed);
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
        let delta = desired
            .checked_sub(current)
            .ok_or(GuestMemoryLimitExceeded)?;
        let local = self
            .local_admitted
            .checked_add(delta)
            .ok_or(GuestMemoryLimitExceeded)?;
        self.root
            .admitted
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(delta)
                    .filter(|next| *next <= self.root.limit)
            })
            .map_err(|_| GuestMemoryLimitExceeded)?;
        self.local_admitted = local;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        Ok(desired <= self.limits.table_elements)
    }

    fn memory_grow_failed(&mut self, error: WasmtimeError) -> Result<()> {
        self.root.backing_failed.store(true, Ordering::Relaxed);
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
