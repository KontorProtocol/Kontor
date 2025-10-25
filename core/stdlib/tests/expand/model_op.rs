use stdlib::Model;

#[derive(Model)]
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
