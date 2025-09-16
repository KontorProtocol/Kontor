use std::cell::RefCell;

/// Generic resource table for managing WIT resources in thread-local storage.
/// 
/// This abstracts the common pattern of managing resource handles in a
/// thread-local Vec<Option<T>> and provides a clean API for allocation,
/// consumption, and inspection of resources.
pub struct ResourceTable<T> {
    table: RefCell<Vec<Option<T>>>,
}

impl<T> ResourceTable<T> {
    /// Create a new empty resource table
    pub const fn new() -> Self {
        Self {
            table: RefCell::new(Vec::new()),
        }
    }

    /// Allocate a new resource handle for the given data.
    /// Returns the handle (index) that can be used to retrieve the resource later.
    pub fn allocate(&self, data: T) -> u32 {
        let mut table = self.table.borrow_mut();
        // Find a free slot or add a new one
        let index = table.iter().position(|slot| slot.is_none())
            .unwrap_or_else(|| {
                table.push(None);
                table.len() - 1
            });
        table[index] = Some(data);
        index as u32
    }

    /// Take (consume) a resource by its handle.
    /// This removes the resource from the table and returns it.
    /// The resource cannot be accessed again after this call.
    pub fn take(&self, handle: u32) -> Result<T, String> {
        let mut table = self.table.borrow_mut();
        let idx = handle as usize;
        
        if idx >= table.len() {
            return Err("Invalid resource handle".to_string());
        }
        
        table[idx].take()
            .ok_or_else(|| "Resource already consumed or invalid".to_string())
    }

    /// Get a clone of a resource without consuming it.
    /// This requires T: Clone and is useful for inspection.
    pub fn get(&self, handle: u32) -> Result<T, String> 
    where 
        T: Clone 
    {
        let table = self.table.borrow();
        let idx = handle as usize;
        
        if idx >= table.len() {
            return Err("Invalid resource handle".to_string());
        }
        
        table[idx].clone()
            .ok_or_else(|| "Resource not found".to_string())
    }
}

impl<T> Default for ResourceTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

// For convenience, create a macro to declare a static resource table
#[macro_export]
macro_rules! resource_table {
    ($name:ident, $type:ty) => {
        thread_local! {
            static $name: $crate::ResourceTable<$type> = $crate::ResourceTable::new();
        }
    };
}
