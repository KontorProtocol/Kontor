/// Whole-call ceiling for paid calls and public views, not a per-instruction cap.
pub(crate) const MAX_UNTRUSTED_GAS_LIMIT: u64 = 100_000;

pub(crate) const DEFAULT_NON_PROC_GAS_LIMIT: u64 = 100_000;
pub(crate) const GAS_TO_FUEL_MULTIPLIER: u64 = 1_000;

// Storage reads bind remaining fuel as a SQL i64 size budget, so u64::MAX
// would become negative. Trusted system calls retain the largest i64-safe value.
pub(crate) const SYSTEM_FUEL_CEILING: u64 = i64::MAX as u64;

pub(crate) const LIFT_VALUE_FUEL: u64 = 512;
pub(crate) const LIFT_STRING_BYTE_FUEL: u64 = 16;
pub(crate) const LIFT_METADATA_BYTE_FUEL: u64 = 16;
