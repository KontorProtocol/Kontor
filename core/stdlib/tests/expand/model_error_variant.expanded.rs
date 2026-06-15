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
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &[stdlib::interned_element(0u8)],
            )
            .map(|__idx| match __idx {
                0u32 => {
                    ErrorModel::Message(
                        stdlib::ReadStorage::__get(&ctx, base_path.push_interned(0u8))
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
    pub fn with_index(
        self,
        _index_root: stdlib::KeyPath,
        _index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        alloc::vec::Vec::new()
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
        stdlib::ReadStorage::__extend_path_with_match(
                &ctx,
                &base_path,
                &[stdlib::interned_element(0u8)],
            )
            .map(|__idx| match __idx {
                0u32 => {
                    ErrorWriteModel::Message(
                        stdlib::ReadStorage::__get(&ctx, base_path.push_interned(0u8))
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
    pub fn with_index(
        self,
        _index_root: stdlib::KeyPath,
        _index_key: alloc::vec::Vec<u8>,
    ) -> Self {
        self
    }
    pub fn __index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        alloc::vec::Vec::new()
    }
}
