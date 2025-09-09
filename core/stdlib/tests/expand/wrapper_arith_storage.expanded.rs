use stdlib::Wrapper;
struct ArithStorage {
    pub last_op: Option<Op>,
}
pub struct ArithStorageWrapper {
    pub base_path: stdlib::DotPathBuf,
}
#[automatically_derived]
impl ::core::clone::Clone for ArithStorageWrapper {
    #[inline]
    fn clone(&self) -> ArithStorageWrapper {
        ArithStorageWrapper {
            base_path: ::core::clone::Clone::clone(&self.base_path),
        }
    }
}
impl ArithStorageWrapper {
    pub fn new(_: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        Self { base_path }
    }
    pub fn last_op(&self, ctx: &impl stdlib::ReadContext) -> Option<OpWrapper> {
        let base_path = self.base_path.push("last_op");
        if ctx.__exists(&base_path.push("none")) {
            None
        } else {
            Some(OpWrapper::new(ctx, base_path.push("some")))
        }
    }
    pub fn set_last_op(&self, ctx: &impl stdlib::WriteContext, value: Option<Op>) {
        let base_path = self.base_path.push("last_op");
        ctx.__delete_matching_paths(
            &::alloc::__export::must_use({
                ::alloc::fmt::format(
                    format_args!(
                        "^{0}.({1})(\\..*|$)", base_path, ["none", "some"].join("|"),
                    ),
                )
            }),
        );
        match value {
            Some(inner) => ctx.__set(base_path.push("some"), inner),
            None => ctx.__set(base_path.push("none"), ()),
        }
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> ArithStorage {
        ArithStorage {
            last_op: self.last_op(ctx).map(|p| p.load(ctx)),
        }
    }
}
