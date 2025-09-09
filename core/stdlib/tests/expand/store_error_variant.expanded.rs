use stdlib::Store;
enum Error {
    Message(String),
}
#[automatically_derived]
impl stdlib::Store for Error {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: Error,
    ) {
        ctx.__delete_matching_paths(
            &::alloc::__export::must_use({
                ::alloc::fmt::format(
                    format_args!("^{0}.({1})(\\..*|$)", base_path, ["message"].join("|")),
                )
            }),
        );
        match value {
            Error::Message(inner) => ctx.__set(base_path.push("message"), inner),
        }
    }
}
