use stdlib::Wrapper;

#[derive(Wrapper)]
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
