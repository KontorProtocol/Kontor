//! Hand-written behavior on the shared built-in types — the former `impls.rs`
//! bodies, now written ONCE on types this crate owns and correct on BOTH
//! sides. Arithmetic delegates through [`numbers::backend`]; scalar numeric
//! storage and the context/resource plumbing have their own modules.

mod context;
mod numbers;
mod numeric_storage;
