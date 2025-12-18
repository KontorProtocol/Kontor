use stdlib::Store;
enum Error {
    Message(String),
    Overflow,
}
#[automatically_derived]
impl stdlib::Store<crate::context::ProcStorage> for Error {
    fn __set(
        ctx: &alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
        value: Error,
    ) {
        stdlib::WriteStorage::__delete_matching_paths(
            ctx,
            &base_path,
            &["message", "overflow"],
        );
        match value {
            Error::Message(inner) => {
                stdlib::WriteStorage::__set(ctx, base_path.push("message"), inner)
            }
            Error::Overflow => {
                stdlib::WriteStorage::__set(ctx, base_path.push("overflow"), ())
            }
        }
    }
}
