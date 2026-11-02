extern crate alloc;
pub struct ArithStorage {
    pub last_op: Option<Op>,
}
#[automatically_derived]
impl<__S: stdlib::WriteStorage + stdlib::ReadStorage + ?Sized> stdlib::Store<__S>
for ArithStorage {
    const STORES_ROOT: bool = false;
    fn __set(ctx: &alloc::rc::Rc<__S>, base_path: stdlib::KeyPath, value: ArithStorage) {
        stdlib::WriteStorage::__set(ctx, base_path.push_interned(0u8), value.last_op);
    }
}
enum Op {
    Id,
}
#[automatically_derived]
impl ::core::clone::Clone for Op {
    #[inline]
    fn clone(&self) -> Op {
        Op::Id
    }
}
pub enum OpModel<__S> {
    Id,
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __OpModelFor<__S> = OpModel<__S>;
impl<__S: stdlib::ReadStorage + 'static> OpModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let variant = stdlib::ReadStorage::__get_keys::<
            stdlib::Interned,
        >(&ctx, &base_path)
            .next();
        variant
            .map(|stdlib::Interned(__idx)| match __idx {
                0u8 => OpModel::Id,
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Invalid enum storage tag"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpModel::Id => Op::Id,
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
pub enum OpWriteModel<__S: stdlib::HasViewStorage> {
    Id,
    #[doc(hidden)]
    __Phantom(core::marker::PhantomData<__S>, core::convert::Infallible),
}
#[doc(hidden)]
pub type __OpWriteModelFor<__S> = OpWriteModel<__S>;
impl<
    __S: stdlib::ReadStorage + stdlib::WriteStorage + stdlib::HasViewStorage + 'static,
> OpWriteModel<__S> {
    pub fn new(ctx: alloc::rc::Rc<__S>, base_path: stdlib::KeyPath) -> Self {
        let variant = stdlib::ReadStorage::__get_keys::<
            stdlib::Interned,
        >(&ctx, &base_path)
            .next();
        variant
            .map(|stdlib::Interned(__idx)| match __idx {
                0u8 => OpWriteModel::Id,
                _ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Invalid enum storage tag"),
                    );
                }
            })
            .unwrap()
    }
    pub fn load(&self) -> Op {
        match self {
            OpWriteModel::Id => Op::Id,
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
