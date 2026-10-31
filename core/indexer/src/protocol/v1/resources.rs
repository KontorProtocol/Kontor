pub(crate) const MAX_LIVE_INVOCATIONS: u32 = 64;

#[derive(Clone, Copy)]
pub(crate) struct GuestMemoryLimits {
    pub per_root: usize,
    pub table_elements_per_root: usize,
    pub memories: usize,
    pub instances: usize,
    pub tables: usize,
    pub table_elements: usize,
}

impl Default for GuestMemoryLimits {
    fn default() -> Self {
        // Consensus rules, independent of node hardware or operator settings.
        // Linear memory, GC capacity, and table slots are shared across nested
        // Stores. Object counts are per Store, and table_elements is per table.
        Self {
            per_root: 512 * 1024 * 1024,
            table_elements_per_root: 16 * 1024 * 1024,
            memories: 16,
            instances: 64,
            tables: 8,
            table_elements: 65_536,
        }
    }
}
