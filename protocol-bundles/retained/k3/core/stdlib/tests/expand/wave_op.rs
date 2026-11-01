extern crate alloc;

use stdlib::Wavey;

mod error {
    pub type Error = String;
}

#[derive(Wavey)]
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
