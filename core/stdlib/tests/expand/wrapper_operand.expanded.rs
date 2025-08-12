use stdlib::Wrapper;
pub struct Operand {
    pub y: u64,
}
pub struct OperandWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for OperandWrapper {
    #[inline]
    fn clone(&self) -> OperandWrapper {
        OperandWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
#[allow(dead_code)]
impl OperandWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn y(&self, ctx: &impl stdlib::ReadContext) -> u64 {
        ctx.__get(self.base_path.push("y")).unwrap()
    }
    pub fn set_y(&self, ctx: &impl stdlib::WriteContext, value: u64) {
        ctx.__set(self.base_path.push("y"), value);
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Operand {
        Operand { y: self.y(ctx) }
    }
}
