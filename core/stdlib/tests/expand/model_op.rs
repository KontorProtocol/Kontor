extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

#[derive(Model)]
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}

#[derive(Clone, stdlib::Model)]
struct Operand {
    y: u64,
}
