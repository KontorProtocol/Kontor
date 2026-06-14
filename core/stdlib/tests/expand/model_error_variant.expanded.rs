use stdlib::Model;
enum Error {
    Message(String),
}
pub enum ErrorModel {
    Message(String),
}
impl ErrorModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ViewStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(&ctx, &base_path, &["message"])
            .map(|variant| match variant.as_str() {
                "message" => {
                    ErrorModel::Message(
                        stdlib::ReadStorage::__get(&ctx, base_path.push("message"))
                            .unwrap(),
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
            ErrorModel::Message(inner) => Error::Message(inner.clone()),
        }
    }
}
pub enum ErrorWriteModel {
    Message(String),
}
impl ErrorWriteModel {
    pub fn new(
        ctx: alloc::rc::Rc<crate::context::ProcStorage>,
        base_path: stdlib::KeyPath,
    ) -> Self {
        stdlib::ReadStorage::__extend_path_with_match(&ctx, &base_path, &["message"])
            .map(|variant| match variant.as_str() {
                "message" => {
                    ErrorWriteModel::Message(
                        stdlib::ReadStorage::__get(&ctx, base_path.push("message"))
                            .unwrap(),
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
