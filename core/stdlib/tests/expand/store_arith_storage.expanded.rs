pub struct ArithStorage {
    pub last_op: Option<Op>,
}
#[automatically_derived]
impl stdlib::Store for ArithStorage {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: ArithStorage,
    ) {
        ctx.__delete_matching_paths(
            &::alloc::__export::must_use({
                ::alloc::fmt::format(
                    format_args!(
                        "^{0}.({1})(\\..*|$)", base_path.push("last_op"), ["none",
                        "some"].join("|"),
                    ),
                )
            }),
        );
        match value.last_op {
            Some(inner) => ctx.__set(base_path.push("last_op").push("some"), inner),
            None => ctx.__set(base_path.push("last_op").push("none"), ()),
        }
    }
}
