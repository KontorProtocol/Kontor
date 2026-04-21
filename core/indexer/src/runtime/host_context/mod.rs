use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;

mod core_context;
mod fall_context;
mod holder;
mod keys;
mod proc_context;
mod proc_storage;
mod runtime_ext;
mod signer;
mod transaction;
mod view_context;
mod view_storage;

impl built_in::context::Host for Runtime {}
