extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

#[derive(Model)]
pub struct Operand {
    pub y: u64,
}
