use stdlib::Model;
enum Error {
    Message(String),
}
pub enum ErrorModel {
    Message(String),
}
impl ErrorModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        ctx.__extend_path_with_match(&base_path, &["message"])
            .map(|path| match path {
                p if p.starts_with(base_path.push("message").as_ref()) => {
                    ErrorModel::Message(ctx.__get(base_path.push("message")).unwrap())
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Error {
        match self {
            ErrorModel::Message(inner) => Error::Message(inner.clone()),
        }
    }
}
pub enum ErrorWriteModel {
    Message(String),
}
impl ErrorWriteModel {
    pub fn new(
        ctx: std::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::DotPathBuf,
    ) -> Self {
        ctx.__extend_path_with_match(&base_path, &["message"])
            .map(|path| match path {
                p if p.starts_with(base_path.push("message").as_ref()) => {
                    ErrorWriteModel::Message(
                        ctx.__get(base_path.push("message")).unwrap(),
                    )
                }
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Matching path not found"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Error {
        match self {
            ErrorWriteModel::Message(inner) => Error::Message(inner.clone()),
        }
    }
}
