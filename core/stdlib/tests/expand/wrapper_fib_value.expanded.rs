use stdlib::Wrapper;
struct FibValue {
    value: u64,
}
pub struct FibValueWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for FibValueWrapper {
    #[inline]
    fn clone(&self) -> FibValueWrapper {
        FibValueWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
#[allow(dead_code)]
impl FibValueWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn value(&self, ctx: &impl stdlib::ReadContext) -> u64 {
        ctx.__get(self.base_path.push("value")).unwrap()
    }
    pub fn set_value(&self, ctx: &impl stdlib::WriteContext, value: u64) {
        ctx.__set(self.base_path.push("value"), value);
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> FibValue {
        FibValue { value: self.value(ctx) }
    }
}
