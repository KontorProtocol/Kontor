//! Hand-written behavior on the shared built-in types — the former `impls.rs`
//! bodies, now written ONCE on types this crate owns and correct on BOTH
//! sides. Two domains, one file each: the numbers/error family (backed by
//! [`numbers::backend`]) and the context family (data types + the guest-side
//! resource plumbing).

mod context;
mod numbers;
