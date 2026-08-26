use stdlib::Model;
enum Error {
    Message(String),
}
pub enum ErrorModel<__S> {
    Message(String),
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __ErrorModelFor<__S> = ErrorModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> ErrorModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
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
            Self::__Phantom(_, i) => match *i {}
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
pub enum ErrorWriteModel<__S: stdlib::HasViewStorage> {
    Message(String),
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __ErrorWriteModelFor<__S> = ErrorWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> ErrorWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
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
            Self::__Phantom(_, i) => match *i {}
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
