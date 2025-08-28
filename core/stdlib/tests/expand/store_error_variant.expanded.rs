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
        match value {
            Error::Message(inner) => ctx.__set(base_path.push("message"), inner),
        }
    }
}
