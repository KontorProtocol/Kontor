use stdlib::Wrapper;
enum Error {
    Message(String),
}
pub enum ErrorWrapper {
    Message(String),
}
#[automatically_derived]
impl ::core::clone::Clone for ErrorWrapper {
    #[inline]
    fn clone(&self) -> ErrorWrapper {
        match self {
            ErrorWrapper::Message(__self_0) => {
                ErrorWrapper::Message(::core::clone::Clone::clone(__self_0))
            }
        }
    }
}
impl ErrorWrapper {
    pub fn new(ctx: &impl stdlib::ReadContext, base_path: stdlib::DotPathBuf) -> Self {
        ctx.__extend_path_with_match(&base_path, &["message"])
            .map(|path| match path {
                p if p.starts_with(base_path.push("message").as_ref()) => {
                    ErrorWrapper::Message(ctx.__get(base_path.push("message")).unwrap())
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self, ctx: &impl stdlib::ReadContext) -> Error {
        match self {
            ErrorWrapper::Message(inner) => Error::Message(inner.clone()),
        }
    }
}
